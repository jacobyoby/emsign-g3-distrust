#!/usr/bin/env python3
"""Export Bug 2083449 indicators for SIEM / SOAR ingestion.

Reads indicators.csv (via emsign_indicators) and emits JSON for:
  - host trust-store matching (SHA-256 of cert DER)
  - Suricata alert correlation (sid + tls.cert_issuer match strings)
  - ticket correlation (Mozilla bug id, serial)

Usage:
  python3 export_siem_indicators.py              # pretty JSON to stdout
  python3 export_siem_indicators.py --ndjson     # one record per line (log shippers)
  python3 export_siem_indicators.py --verify     # exit 1 if PEMs disagree with CSV
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

from emsign_indicators import (
    ANCHOR_LABELS,
    ANCHOR_TYPES,
    COMPROMISED_TYPES,
    DEFAULT_CSV,
    default_certs_dir,
    expected_pem_fingerprints,
    load_rows,
)

GENERIC_SURICATA_SID = "92083409"


def _sha256_of_pem(path: str) -> str | None:
    der = subprocess.run(
        ["openssl", "x509", "-inform", "PEM", "-outform", "DER", "-in", path],
        capture_output=True,
    ).stdout
    return hashlib.sha256(der).hexdigest() if der else None


def verify_pems(certs_dir: str) -> list[str]:
    errors = []
    expected = expected_pem_fingerprints()
    for base, want in sorted(expected.items()):
        path = os.path.join(certs_dir, f"{base}.pem")
        if not os.path.isfile(path):
            errors.append(f"missing PEM: {path}")
            continue
        got = _sha256_of_pem(path)
        if got != want:
            errors.append(f"fingerprint mismatch for {base}: csv={want} pem={got}")
    return errors


def build_bundle(rows: list[dict]) -> dict:
    compromised = []
    anchors = []
    for row in rows:
        rec = {
            "common_name": row["ca_common_name"],
            "type": row["type"],
            "sha256_fingerprint": row["sha256_fingerprint"],
            "serial_hex": row.get("serial") or None,
            "issuer": row.get("issuer") or None,
            "mozilla_bug": row.get("bug_id") or "2083449",
        }
        if row["type"] in COMPROMISED_TYPES:
            rec["pem_basename"] = row.get("pem_basename")
            rec["suricata"] = {
                "sid": int(row["suricata_sid"]) if row.get("suricata_sid") else None,
                "tls_cert_issuer_match": row.get("tls_issuer_cn_match"),
                "rules_file": "tools/emsign-g3-distrust.rules",
            }
            rec["host_scan"] = {
                "match_field": "x509.sha256_fingerprint",
                "scanner": "tools/emsign_trust_scanner.py",
            }
            compromised.append(rec)
        elif row["type"] in ANCHOR_TYPES:
            rec["anchor_role"] = ANCHOR_LABELS.get(row["type"], row["ca_common_name"])
            rec["host_scan"] = {
                "match_field": "x509.sha256_fingerprint",
                "scanner": "tools/emsign_trust_scanner.py",
            }
            anchors.append(rec)

    return {
        "schema": "emsign-g3-distrust-indicators/v1",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_csv": "indicators.csv",
        "mozilla_bug": "2083449",
        "compromised_intermediates": compromised,
        "trust_anchors": anchors,
        "network_detection": {
            "engine": "suricata",
            "rules_file": "tools/emsign-g3-distrust.rules",
            "livefire_test": "tools/suricata_livefire_test.sh",
            "match_field": "tls.cert_issuer",
            "generic_backstop_sid": int(GENERIC_SURICATA_SID),
        },
        "host_hardening": {
            "scanner": "tools/emsign_trust_scanner.py --json",
            "distrust": "tools/emsign_distrust.py",
            "certs_dir": "certs/",
        },
    }


def to_ndjson(bundle: dict) -> str:
    lines = []
    meta = {
        "schema": bundle["schema"],
        "mozilla_bug": bundle["mozilla_bug"],
        "record_kind": "metadata",
    }
    lines.append(json.dumps(meta, separators=(",", ":")))
    for rec in bundle["compromised_intermediates"]:
        lines.append(
            json.dumps(
                {"record_kind": "compromised_intermediate", **rec},
                separators=(",", ":"),
            )
        )
    for rec in bundle["trust_anchors"]:
        lines.append(json.dumps({"record_kind": "trust_anchor", **rec}, separators=(",", ":")))
    lines.append(json.dumps({"record_kind": "network_detection", **bundle["network_detection"]}))
    return "\n".join(lines) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", default=DEFAULT_CSV, help="path to indicators.csv")
    ap.add_argument("--ndjson", action="store_true", help="newline-delimited JSON records")
    ap.add_argument("--verify", action="store_true", help="verify certs/*.pem match the CSV")
    ap.add_argument("--certs-dir", default=default_certs_dir())
    args = ap.parse_args()

    if args.verify:
        errs = verify_pems(args.certs_dir)
        if errs:
            for e in errs:
                print(e, file=sys.stderr)
            return 1
        print(f"OK: {len(expected_pem_fingerprints())} PEMs match {args.csv}")
        return 0

    rows = load_rows(args.csv)
    bundle = build_bundle(rows)
    if args.ndjson:
        sys.stdout.write(to_ndjson(bundle))
    else:
        json.dump(bundle, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
