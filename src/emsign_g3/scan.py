"""Scan host trust stores for compromised eMudhra/emSign G3 anchors."""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import re
import subprocess

from emsign_g3.indicators import (
    AAA_FINGERPRINT,
    compromised_intermediates,
    scan_targets,
)

PEM_RE = re.compile(rb"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.S)


def _der_sha256(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def _pem_blocks_to_ders(blob: bytes):
    for match in PEM_RE.finditer(blob):
        try:
            yield base64.b64decode(re.sub(rb"\s+", b"", match.group(1)))
        except Exception:
            continue


def scan_blob(blob: bytes, targets: dict[str, str] | None = None):
    """Yield (fingerprint, name) for every target cert present in a PEM/DER blob."""
    targets = targets or scan_targets()
    ders = list(_pem_blocks_to_ders(blob))
    if not ders:
        ders = [blob]
    for der in ders:
        fp = _der_sha256(der)
        if fp in targets:
            yield fp, targets[fp]


def _read(path: str) -> bytes | None:
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError:
        return None


def _candidate_bundles() -> list[str]:
    paths = [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        "/etc/ssl/ca-bundle.pem",
        "/etc/ssl/cert.pem",
        "/usr/local/etc/openssl/cert.pem",
        "/opt/homebrew/etc/openssl@3/cert.pem",
    ]
    extra = os.environ.get("SSL_CERT_FILE")
    if extra:
        paths.insert(0, extra)
    return [p for p in paths if os.path.exists(p)]


def _run(cmd: list[str]) -> bytes:
    try:
        return subprocess.run(cmd, capture_output=True, timeout=60).stdout
    except (OSError, subprocess.SubprocessError):
        return b""


def scan_stores():
    targets = scan_targets()
    compromised = compromised_intermediates()
    stores = []

    for path in _candidate_bundles():
        blob = _read(path)
        if blob:
            found = list(scan_blob(blob, targets))
            stores.append({"store": "ca-bundle", "path": path, "found": found})

    system = platform.system()

    if system == "Darwin":
        for kc in (
            "/System/Library/Keychains/SystemRootCertificates.keychain",
            "/Library/Keychains/System.keychain",
        ):
            if not os.path.exists(kc):
                continue
            pem = _run(["security", "find-certificate", "-a", "-p", kc])
            if pem:
                stores.append(
                    {
                        "store": "macOS keychain",
                        "path": kc,
                        "found": list(scan_blob(pem, targets)),
                    }
                )

    if system == "Windows":
        out = _run(["certutil", "-store", "root"])
        txt = out.decode(errors="replace").lower()
        hits = [(fp, nm) for fp, nm in targets.items() if fp in txt.replace(" ", "")]
        stores.append({"store": "Windows root", "path": "certutil -store root", "found": hits})

    home = os.path.expanduser("~")
    for base in (
        os.path.join(home, ".mozilla", "firefox"),
        os.path.join(home, "Library", "Application Support", "Firefox", "Profiles"),
        os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles"),
    ):
        if base and os.path.isdir(base):
            for d in os.listdir(base):
                prof = os.path.join(base, d)
                if os.path.isdir(prof) and os.path.exists(os.path.join(prof, "cert9.db")):
                    out = _run(["certutil", "-L", "-d", "sql:" + prof])
                    if b"emSign" in out or b"AAA Certificate" in out:
                        stores.append(
                            {
                                "store": "NSS profile",
                                "path": prof,
                                "found": [("(by name)", "emSign/AAA present — verify OneCRL")],
                                "note": "NSS distrust is enforced by OneCRL, not store removal",
                            }
                        )

    return stores, system, compromised


def blocklist_hints(system: str) -> list[str]:
    hints: list[str] = []
    home = os.path.expanduser("~")
    chrome_bases = {
        "Darwin": os.path.join(home, "Library", "Application Support", "Google", "Chrome"),
        "Linux": os.path.join(home, ".config", "google-chrome"),
        "Windows": os.path.join(
            os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data"
        ),
    }.get(system)
    if chrome_bases and os.path.isdir(chrome_bases):
        crlset = os.path.join(chrome_bases, "CertificateRevocation")
        hints.append(
            f"Chrome present; CRLSet dir {'found' if os.path.isdir(crlset) else 'NOT found'} "
            f"at {crlset} (CRLSet is how Chrome distrusts these intermediates)"
        )
    hints.append(
        "Firefox: distrust is via OneCRL (RemoteSettings). Confirm the profile has "
        "pulled security.remote_settings and is on the Oct 2026 build or later."
    )
    hints.append("OS CA store: confirm the vendor CA update that distrusts emSign G3 is applied.")
    return hints


def build_scan_result(as_json: bool = False) -> dict:
    stores, system, compromised = scan_stores()
    anchor_hits: list[dict] = []
    inter_hits: list[dict] = []
    for s in stores:
        for fp, nm in s["found"]:
            rec = {"store": s["store"], "path": s["path"], "fingerprint": fp, "name": nm}
            (inter_hits if fp in compromised else anchor_hits).append(rec)

    direct = [h for h in anchor_hits if h["fingerprint"] != AAA_FINGERPRINT] + inter_hits
    aaa_only = [h for h in anchor_hits if h["fingerprint"] == AAA_FINGERPRINT]
    if direct:
        verdict = (
            "EXPOSED: direct emSign-G3 trust path present — "
            "confirm OneCRL/CRLSet/OS-distrust is applied"
        )
    elif aaa_only:
        verdict = (
            "CONDITIONAL: only AAA Certificate Services present (near-universal). "
            "The AAA->eMudhra path uses Sectigo cross-signs revoked 2026-10-19, so exposed "
            "ONLY if this client does not check Sectigo's CRL/OCSP. Verify revocation checking, "
            "not the store."
        )
    else:
        verdict = "No emSign-G3 / AAA anchor found in scanned stores"

    return {
        "host": platform.node(),
        "os": f"{system} {platform.release()}",
        "direct_trust_path": bool(direct),
        "aaa_cross_sign_path_only": bool(aaa_only) and not direct,
        "anchor_roots_found": anchor_hits,
        "compromised_intermediates_found": inter_hits,
        "stores_scanned": [
            {"store": s["store"], "path": s["path"], "hits": len(s["found"])} for s in stores
        ],
        "blocklist_checks_needed": blocklist_hints(system),
        "verdict": verdict,
        "_direct": direct,
        "_aaa_only": aaa_only,
        "_anchor_hits": anchor_hits,
        "_inter_hits": inter_hits,
        "_stores_empty": not stores,
    }


def format_scan_report(result: dict) -> str:
    lines: list[str] = []
    lines.append(f"# emSign-G3 trust scan — {result['host']} ({result['os']})\n")
    if result["_stores_empty"]:
        lines.append("No trust stores located on this host (unexpected); run with elevated access.")
    for s in result["stores_scanned"]:
        lines.append(f"  scanned: {s['store']:16} {s['path']}  ({s['hits']} hit(s))")
    lines.append("")
    anchor_hits = result["_anchor_hits"]
    inter_hits = result["_inter_hits"]
    direct_names = {h["name"] for h in anchor_hits if h["fingerprint"] != AAA_FINGERPRINT}
    if direct_names or inter_hits:
        lines.append("!! Direct emSign-G3 trust path present:")
        for h in anchor_hits:
            if h["name"] in direct_names:
                lines.append(f"   - {h['name']}  [{h['store']}]")
        for h in inter_hits:
            lines.append(f"   - {h['name']} (compromised intermediate pinned)  [{h['store']}]")
    if result["aaa_cross_sign_path_only"]:
        lines.append(
            "~ AAA Certificate Services present (near-universal). Secondary path only; "
            "Sectigo cross-signs revoked 2026-10-19."
        )
    if not anchor_hits and not inter_hits:
        lines.append("No emSign G3 / AAA anchor found in the stores scanned here.")
    lines.append(f"\nVERDICT: {result['verdict']}\n")
    lines.append("Still verify (this script cannot):")
    for h in result["blocklist_checks_needed"]:
        lines.append(f"   - {h}")
    lines.append(
        "\nActive test (no forging): openssl verify -crl_check_all against the real emSign "
        "chain using a known-revoked intermediate; acceptance = this client would accept a forgery."
    )
    return "\n".join(lines)


def run_scan(*, as_json: bool = False) -> int:
    result = build_scan_result()
    public = {k: v for k, v in result.items() if not k.startswith("_")}
    if as_json:
        print(json.dumps(public, indent=2))
    else:
        print(format_scan_report(result))
    return 0
