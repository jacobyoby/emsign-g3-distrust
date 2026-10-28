"""Explicitly distrust the eight compromised eMudhra/emSign G3 intermediates."""
from __future__ import annotations

import glob
import hashlib
import os
import platform
import subprocess
import sys
from pathlib import Path

from emsign_g3.indicators import expected_pem_fingerprints
from emsign_g3.paths import default_certs_dir


def sha256_of_pem(path: str | Path) -> str | None:
    der = subprocess.run(
        ["openssl", "x509", "-inform", "PEM", "-outform", "DER", "-in", str(path)],
        capture_output=True,
    ).stdout
    return hashlib.sha256(der).hexdigest() if der else None


def load_certs(certs_dir: str | Path) -> list[tuple[str, str, str]]:
    certs: list[tuple[str, str, str]] = []
    expected = expected_pem_fingerprints()
    for path in sorted(glob.glob(os.path.join(str(certs_dir), "EM*.pem"))):
        name = os.path.splitext(os.path.basename(path))[0]
        fp = sha256_of_pem(path)
        want = expected.get(name)
        if want and fp == want:
            certs.append((name, path, fp))
        else:
            print(f"  !! skip {name}: fingerprint mismatch or unknown ({fp})", file=sys.stderr)
    return certs


def plan_for_os(system: str, certs: list[tuple[str, str, str]], undo: bool):
    steps: list[tuple[str, list[str], str]] = []
    if system == "Darwin":
        kc = "/Library/Keychains/System.keychain"
        for name, path, _ in certs:
            if undo:
                steps.append(
                    (
                        f"macOS: remove distrust for {name}",
                        ["sudo", "security", "remove-trusted-cert", "-d", path],
                        "re-run without --undo to re-apply",
                    )
                )
            else:
                steps.append(
                    (
                        f"macOS: distrust {name} (admin System keychain)",
                        [
                            "sudo",
                            "security",
                            "add-trusted-cert",
                            "-d",
                            "-r",
                            "deny",
                            "-k",
                            kc,
                            path,
                        ],
                        f"sudo security remove-trusted-cert -d {path}",
                    )
                )
    elif system == "Linux":
        blk = (
            "/etc/pki/ca-trust/source/blocklist"
            if os.path.isdir("/etc/pki/ca-trust")
            else "/usr/local/share/ca-certificates/emsign-blocklist"
        )
        update = (
            ["sudo", "update-ca-trust"]
            if os.path.isdir("/etc/pki/ca-trust")
            else ["sudo", "update-ca-certificates"]
        )
        for name, path, _ in certs:
            dst = os.path.join(blk, f"{name}.pem")
            if undo:
                steps.append(
                    (
                        f"Linux: unblock {name}",
                        ["sudo", "rm", "-f", dst],
                        "restore by re-running without --undo",
                    )
                )
            else:
                steps.append(
                    (
                        f"Linux: blocklist {name} -> {dst}",
                        ["sudo", "install", "-D", "-m", "644", path, dst],
                        f"sudo rm -f {dst} && {' '.join(update)}",
                    )
                )
        steps.append(("Linux: refresh trust store", update, "(same command re-runs)"))
    elif system == "Windows":
        for name, path, _ in certs:
            if undo:
                steps.append(
                    (
                        f"Windows: remove {name} from disallowed",
                        ["certutil", "-delstore", "disallowed", path],
                        "re-add with certutil -addstore -f disallowed",
                    )
                )
            else:
                steps.append(
                    (
                        f"Windows: add {name} to disallowed store",
                        ["certutil", "-addstore", "-f", "disallowed", path],
                        f"certutil -delstore disallowed <serial-of-{name}>",
                    )
                )
    home = os.path.expanduser("~")
    for base in (
        os.path.join(home, ".mozilla", "firefox"),
        os.path.join(home, "Library", "Application Support", "Firefox", "Profiles"),
        os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles"),
    ):
        if base and os.path.isdir(base):
            for d in os.listdir(base):
                prof = os.path.join(base, d)
                if os.path.exists(os.path.join(prof, "cert9.db")):
                    for name, path, _ in certs:
                        if undo:
                            steps.append(
                                (
                                    f"NSS {d}: delete distrust entry {name}",
                                    [
                                        "certutil",
                                        "-D",
                                        "-n",
                                        f"emSign-distrust-{name}",
                                        "-d",
                                        "sql:" + prof,
                                    ],
                                    "re-run without --undo",
                                )
                            )
                        else:
                            steps.append(
                                (
                                    f"NSS {d}: mark {name} explicitly distrusted (p,p,p)",
                                    [
                                        "certutil",
                                        "-A",
                                        "-n",
                                        f"emSign-distrust-{name}",
                                        "-t",
                                        "p,p,p",
                                        "-d",
                                        "sql:" + prof,
                                        "-i",
                                        path,
                                    ],
                                    f"certutil -D -n emSign-distrust-{name} -d sql:{prof}",
                                )
                            )
    return steps


def run_distrust(
    *,
    apply: bool = False,
    undo: bool = False,
    certs_dir: str | Path | None = None,
) -> int:
    certs_path = Path(certs_dir) if certs_dir else default_certs_dir()
    system = platform.system()
    certs = load_certs(certs_path)
    if len(certs) != 8:
        print(
            f"WARNING: expected 8 verified intermediate PEMs, found {len(certs)} in "
            f"{certs_path}. Proceeding with what verified.",
            file=sys.stderr,
        )
    steps = plan_for_os(system, certs, undo)

    verb = "ROLLBACK" if undo else "DISTRUST"
    print(
        f"# emSign-G3 {verb} plan on {platform.node()} ({system}) — "
        f"{'APPLY' if apply else 'DRY RUN'}\n"
    )
    if not steps:
        print("No supported trust store found to modify on this host.")
        return 0
    for desc, cmd, undo_hint in steps:
        print(f"* {desc}")
        print(f"    cmd:  {' '.join(cmd)}")
        if not undo:
            print(f"    undo: {undo_hint}")
        if apply:
            r = subprocess.run(cmd, capture_output=True, text=True)
            status = "ok" if r.returncode == 0 else f"FAILED rc={r.returncode}"
            print(f"    -> {status} {r.stderr.strip()[:160]}")
        print()
    if not apply:
        print("Dry run only. Re-run with --apply (likely under sudo/Administrator) to execute.")
    return 0
