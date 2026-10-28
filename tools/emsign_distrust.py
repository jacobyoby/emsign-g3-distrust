#!/usr/bin/env python3
"""Explicitly DISTRUST the eight compromised eMudhra/emSign G3 intermediates in this
host's trust stores (Mozilla Bug 2083449). Companion to emsign_trust_scanner.py.

This does NOT delete roots or touch anything else; it adds the eight intermediate
certificates to the platform's "disallowed/deny" set so a forged leaf chaining through
them is rejected even on a client that never checks their revocation.

Safety:
  * DRY-RUN by default — prints exactly what it would run and the undo command, changes nothing.
  * --apply executes (most stores need sudo / Administrator).
  * Every action prints its reverse so you can roll back.

It reads the eight fingerprint-verified PEMs from --certs-dir (default: ../certs next to
this script). Fingerprints are verified against indicators.csv via emsign_indicators.py.

Usage:
  python3 emsign_distrust.py                 # dry run, show the plan
  sudo python3 emsign_distrust.py --apply    # execute
  python3 emsign_distrust.py --undo          # show/execute the rollback (add --apply)
"""
import argparse
import glob
import os
import platform
import subprocess
import sys

from emsign_indicators import default_certs_dir, expected_pem_fingerprints


def _sha256_of_pem(path):
    import hashlib
    der = subprocess.run(["openssl", "x509", "-inform", "PEM", "-outform", "DER", "-in", path],
                         capture_output=True).stdout
    return hashlib.sha256(der).hexdigest() if der else None


def load_certs(certs_dir):
    certs = []
    expected = expected_pem_fingerprints()
    for path in sorted(glob.glob(os.path.join(certs_dir, "EM*.pem"))):
        name = os.path.splitext(os.path.basename(path))[0]
        fp = _sha256_of_pem(path)
        want = expected.get(name)
        if want and fp == want:
            certs.append((name, path, fp))
        else:
            print(f"  !! skip {name}: fingerprint mismatch or unknown ({fp})", file=sys.stderr)
    return certs


def plan_for_os(system, certs, undo):
    """Return list of (description, command-list, undo-command-str) per store."""
    steps = []
    if system == "Darwin":
        kc = "/Library/Keychains/System.keychain"
        for name, path, _ in certs:
            if undo:
                steps.append((f"macOS: remove distrust for {name}",
                              ["sudo", "security", "remove-trusted-cert", "-d", path],
                              f"re-run without --undo to re-apply"))
            else:
                steps.append((f"macOS: distrust {name} (admin System keychain)",
                              ["sudo", "security", "add-trusted-cert", "-d", "-r", "deny",
                               "-k", kc, path],
                              f"sudo security remove-trusted-cert -d {path}"))
    elif system == "Linux":
        # p11-kit / ca-certificates blocklist (RHEL family explicit; Debian honours p11-kit too)
        blk = "/etc/pki/ca-trust/source/blocklist" if os.path.isdir("/etc/pki/ca-trust") \
              else "/usr/local/share/ca-certificates/emsign-blocklist"
        update = ["sudo", "update-ca-trust"] if os.path.isdir("/etc/pki/ca-trust") \
                 else ["sudo", "update-ca-certificates"]
        for name, path, _ in certs:
            dst = os.path.join(blk, f"{name}.pem")
            if undo:
                steps.append((f"Linux: unblock {name}", ["sudo", "rm", "-f", dst],
                              f"restore by re-running without --undo"))
            else:
                steps.append((f"Linux: blocklist {name} -> {dst}",
                              ["sudo", "install", "-D", "-m", "644", path, dst],
                              f"sudo rm -f {dst} && {' '.join(update)}"))
        steps.append((f"Linux: refresh trust store", update, "(same command re-runs)"))
    elif system == "Windows":
        for name, path, _ in certs:
            if undo:
                steps.append((f"Windows: remove {name} from disallowed",
                              ["certutil", "-delstore", "disallowed", path],
                              "re-add with certutil -addstore -f disallowed"))
            else:
                steps.append((f"Windows: add {name} to disallowed store",
                              ["certutil", "-addstore", "-f", "disallowed", path],
                              f"certutil -delstore disallowed <serial-of-{name}>"))
    # NSS / Firefox profiles (any OS), if certutil (NSS) and profiles are present
    home = os.path.expanduser("~")
    for base in [os.path.join(home, ".mozilla", "firefox"),
                 os.path.join(home, "Library", "Application Support", "Firefox", "Profiles"),
                 os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles")]:
        if base and os.path.isdir(base):
            for d in os.listdir(base):
                prof = os.path.join(base, d)
                if os.path.exists(os.path.join(prof, "cert9.db")):
                    for name, path, _ in certs:
                        if undo:
                            steps.append((f"NSS {d}: delete distrust entry {name}",
                                          ["certutil", "-D", "-n", f"emSign-distrust-{name}",
                                           "-d", "sql:" + prof], "re-run without --undo"))
                        else:
                            steps.append((f"NSS {d}: mark {name} explicitly distrusted (p,p,p)",
                                          ["certutil", "-A", "-n", f"emSign-distrust-{name}",
                                           "-t", "p,p,p", "-d", "sql:" + prof, "-i", path],
                                          f"certutil -D -n emSign-distrust-{name} -d sql:{prof}"))
    return steps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true", help="execute (default: dry run)")
    ap.add_argument("--undo", action="store_true", help="roll back instead of distrust")
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--certs-dir", default=default_certs_dir())
    args = ap.parse_args()

    system = platform.system()
    certs = load_certs(args.certs_dir)
    if len(certs) != 8:
        print(f"WARNING: expected 8 verified intermediate PEMs, found {len(certs)} in "
              f"{args.certs_dir}. Proceeding with what verified.", file=sys.stderr)
    steps = plan_for_os(system, certs, args.undo)

    verb = "ROLLBACK" if args.undo else "DISTRUST"
    print(f"# emSign-G3 {verb} plan on {platform.node()} ({system}) — "
          f"{'APPLY' if args.apply else 'DRY RUN'}\n")
    if not steps:
        print("No supported trust store found to modify on this host.")
        return
    for desc, cmd, undo_hint in steps:
        print(f"* {desc}")
        print(f"    cmd:  {' '.join(cmd)}")
        if not args.undo:
            print(f"    undo: {undo_hint}")
        if args.apply:
            r = subprocess.run(cmd, capture_output=True, text=True)
            status = "ok" if r.returncode == 0 else f"FAILED rc={r.returncode}"
            print(f"    -> {status} {r.stderr.strip()[:160]}")
        print()
    if not args.apply:
        print("Dry run only. Re-run with --apply (likely under sudo/Administrator) to execute.")


if __name__ == "__main__":
    main()
