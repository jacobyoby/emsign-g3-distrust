#!/usr/bin/env python3
"""Scan a host's TLS trust stores for the compromised eMudhra/emSign G3 anchors.

A client is exposed to forgeries under the eight compromised eMudhra intermediates
(private keys trivially recoverable, Mozilla Bug 2083449) if it (1) still trusts one
of the anchor roots below, (2) has not received the distrust push (Firefox OneCRL /
Chrome CRLSet / an OS CA update), and (3) does not check the intermediate's own
revocation. This script settles (1) by inventorying the host's trust stores, prints
what it finds for (2), and leaves (3) to an active verify. It reads trust stores;
it changes nothing and needs no key material.

Run:  python3 emsign_trust_scanner.py            # human report
      python3 emsign_trust_scanner.py --json      # machine output for MDM collection
"""
import hashlib
import json
import os
import platform
import re
import subprocess
import sys

from emsign_indicators import (
    AAA_FINGERPRINT,
    anchor_roots,
    compromised_intermediates,
    scan_targets,
)

ANCHOR_ROOTS = anchor_roots()
COMPROMISED_INTERMEDIATES = compromised_intermediates()
TARGETS = scan_targets()

PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)


def _der_sha256(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _pem_blocks_to_ders(blob: bytes):
    import base64
    for m in PEM_RE.finditer(blob):
        try:
            yield base64.b64decode(re.sub(rb"\s+", b"", m.group(1)))
        except Exception:
            continue


def _scan_blob(blob: bytes):
    """Yield (fingerprint, name) for every TARGET cert present in a PEM/DER blob."""
    ders = list(_pem_blocks_to_ders(blob))
    if not ders:  # maybe a single DER file
        ders = [blob]
    for der in ders:
        fp = _der_sha256(der)
        if fp in TARGETS:
            yield fp, TARGETS[fp]


def _read(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except Exception:
        return None


def _candidate_bundles():
    """Common CA bundle file locations across OSes."""
    paths = [
        "/etc/ssl/certs/ca-certificates.crt",      # Debian/Ubuntu
        "/etc/pki/tls/certs/ca-bundle.crt",        # RHEL/Fedora
        "/etc/ssl/ca-bundle.pem",                   # SUSE
        "/etc/ssl/cert.pem",                        # macOS/BSD/openssl
        "/usr/local/etc/openssl/cert.pem",          # brew openssl
        "/opt/homebrew/etc/openssl@3/cert.pem",
    ]
    extra = os.environ.get("SSL_CERT_FILE")
    if extra:
        paths.insert(0, extra)
    return [p for p in paths if os.path.exists(p)]


def _run(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, timeout=60).stdout
    except Exception:
        return b""


def scan_stores():
    stores = []

    # 1. File bundles (Linux, macOS openssl, brew)
    for path in _candidate_bundles():
        blob = _read(path)
        if blob:
            found = list(_scan_blob(blob))
            stores.append({"store": "ca-bundle", "path": path, "found": found})

    system = platform.system()

    # 2. macOS keychains via `security`
    if system == "Darwin":
        for kc in ["/System/Library/Keychains/SystemRootCertificates.keychain",
                   "/Library/Keychains/System.keychain"]:
            if not os.path.exists(kc):
                continue
            pem = _run(["security", "find-certificate", "-a", "-p", kc])
            if pem:
                stores.append({"store": "macOS keychain", "path": kc,
                               "found": list(_scan_blob(pem))})

    # 3. Windows root store via certutil
    if system == "Windows":
        out = _run(["certutil", "-store", "root"])
        txt = out.decode(errors="replace").lower()
        hits = [(fp, nm) for fp, nm in TARGETS.items()
                if fp in txt.replace(" ", "")]
        stores.append({"store": "Windows root", "path": "certutil -store root",
                       "found": hits})

    # 4. NSS (Firefox/Thunderbird) via certutil, if the tool and a profile exist
    nss_dirs = []
    home = os.path.expanduser("~")
    for base in [os.path.join(home, ".mozilla", "firefox"),
                 os.path.join(home, "Library", "Application Support", "Firefox", "Profiles"),
                 os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles")]:
        if base and os.path.isdir(base):
            for d in os.listdir(base):
                p = os.path.join(base, d)
                if os.path.isdir(p) and (os.path.exists(os.path.join(p, "cert9.db"))):
                    nss_dirs.append(p)
    for p in nss_dirs:
        out = _run(["certutil", "-L", "-d", "sql:" + p])
        # certutil here is NSS's; if it's the Windows one output differs — ignore gracefully
        if b"emSign" in out or b"AAA Certificate" in out:
            stores.append({"store": "NSS profile", "path": p,
                           "found": [("(by name)", "emSign/AAA present — verify OneCRL")],
                           "note": "NSS distrust is enforced by OneCRL, not store removal"})

    return stores, system


def blocklist_hints(system):
    hints = []
    home = os.path.expanduser("~")
    # Chrome CRLSet component presence
    chrome_bases = {
        "Darwin": os.path.join(home, "Library", "Application Support", "Google", "Chrome"),
        "Linux": os.path.join(home, ".config", "google-chrome"),
        "Windows": os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data"),
    }.get(system)
    if chrome_bases and os.path.isdir(chrome_bases):
        crlset = os.path.join(chrome_bases, "CertificateRevocation")
        hints.append(f"Chrome present; CRLSet dir {'found' if os.path.isdir(crlset) else 'NOT found'} "
                     f"at {crlset} (CRLSet is how Chrome distrusts these intermediates)")
    hints.append("Firefox: distrust is via OneCRL (RemoteSettings). Confirm the profile has "
                 "pulled security.remote_settings and is on the Oct 2026 build or later.")
    hints.append("OS CA store: confirm the vendor CA update that distrusts emSign G3 is applied.")
    return hints


def main():
    as_json = "--json" in sys.argv
    stores, system = scan_stores()
    anchor_hits, inter_hits = [], []
    for s in stores:
        for fp, nm in s["found"]:
            rec = {"store": s["store"], "path": s["path"], "fingerprint": fp, "name": nm}
            (inter_hits if fp in COMPROMISED_INTERMEDIATES else anchor_hits).append(rec)

    # Tier the signal. A direct emSign-G3 anchor or a pinned compromised intermediate is a
    # live path. AAA Certificate Services is near-universal and only reaches eMudhra via the
    # Sectigo cross-signs, which Sectigo revoked 2026-10-19 — so AAA-only is conditional on
    # the client NOT checking Sectigo's revocation, not exposure on its own.
    direct = [h for h in anchor_hits if h["fingerprint"] != AAA_FINGERPRINT] + inter_hits
    aaa_only = [h for h in anchor_hits if h["fingerprint"] == AAA_FINGERPRINT]
    if direct:
        verdict = "EXPOSED: direct emSign-G3 trust path present — confirm OneCRL/CRLSet/OS-distrust is applied"
    elif aaa_only:
        verdict = ("CONDITIONAL: only AAA Certificate Services present (near-universal). The AAA->eMudhra "
                   "path uses Sectigo cross-signs revoked 2026-10-19, so exposed ONLY if this client does "
                   "not check Sectigo's CRL/OCSP. Verify revocation checking, not the store.")
    else:
        verdict = "No emSign-G3 / AAA anchor found in scanned stores"
    result = {
        "host": platform.node(),
        "os": f"{system} {platform.release()}",
        "direct_trust_path": bool(direct),
        "aaa_cross_sign_path_only": bool(aaa_only) and not direct,
        "anchor_roots_found": anchor_hits,
        "compromised_intermediates_found": inter_hits,
        "stores_scanned": [{"store": s["store"], "path": s["path"],
                            "hits": len(s["found"])} for s in stores],
        "blocklist_checks_needed": blocklist_hints(system),
        "verdict": verdict,
    }
    exposed = bool(direct)
    if as_json:
        print(json.dumps(result, indent=2))
        return
    print(f"# emSign-G3 trust scan — {result['host']} ({result['os']})\n")
    if not stores:
        print("No trust stores located on this host (unexpected); run with elevated access.")
    for s in result["stores_scanned"]:
        print(f"  scanned: {s['store']:16} {s['path']}  ({s['hits']} hit(s))")
    print()
    direct_names = {h["name"] for h in anchor_hits if h["fingerprint"] != AAA_FINGERPRINT}
    if direct_names or inter_hits:
        print("!! Direct emSign-G3 trust path present:")
        for h in anchor_hits:
            if h["name"] in direct_names:
                print(f"   - {h['name']}  [{h['store']}]")
        for h in inter_hits:
            print(f"   - {h['name']} (compromised intermediate pinned)  [{h['store']}]")
    if result["aaa_cross_sign_path_only"]:
        print("~ AAA Certificate Services present (near-universal). Secondary path only; "
              "Sectigo cross-signs revoked 2026-10-19.")
    if not anchor_hits and not inter_hits:
        print("No emSign G3 / AAA anchor found in the stores scanned here.")
    print(f"\nVERDICT: {result['verdict']}\n")
    print("Still verify (this script cannot):")
    for h in result["blocklist_checks_needed"]:
        print(f"   - {h}")
    print("\nActive test (no forging): openssl verify -crl_check_all against the real emSign "
          "chain using a known-revoked intermediate; acceptance = this client would accept a forgery.")


if __name__ == "__main__":
    main()
