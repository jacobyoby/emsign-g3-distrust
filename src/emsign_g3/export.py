"""Export Bug 2083449 indicators for SIEM / SOAR ingestion."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

from emsign_g3.indicators import (
    ANCHOR_LABELS,
    ANCHOR_TYPES,
    COMPROMISED_TYPES,
    expected_pem_fingerprints,
    load_rows,
)
from emsign_g3.paths import default_certs_dir, indicators_csv_path
from emsign_g3.sigma import render_sigma_bundle, write_sigma_rules

GENERIC_SURICATA_SID = "92083409"


def sha256_of_pem(path: str | Path) -> str | None:
    der = subprocess.run(
        ["openssl", "x509", "-inform", "PEM", "-outform", "DER", "-in", str(path)],
        capture_output=True,
    ).stdout
    return hashlib.sha256(der).hexdigest() if der else None


def verify_pems(certs_dir: str | Path) -> list[str]:
    errors: list[str] = []
    expected = expected_pem_fingerprints()
    for base, want in sorted(expected.items()):
        path = os.path.join(str(certs_dir), f"{base}.pem")
        if not os.path.isfile(path):
            errors.append(f"missing PEM: {path}")
            continue
        got = sha256_of_pem(path)
        if got != want:
            errors.append(f"fingerprint mismatch for {base}: csv={want} pem={got}")
    return errors


def build_bundle(rows: list[dict]) -> dict:
    compromised: list[dict] = []
    anchors: list[dict] = []
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
                "scanner": "emsign-g3 scan --json",
            }
            compromised.append(rec)
        elif row["type"] in ANCHOR_TYPES:
            rec["anchor_role"] = ANCHOR_LABELS.get(row["type"], row["ca_common_name"])
            rec["host_scan"] = {
                "match_field": "x509.sha256_fingerprint",
                "scanner": "emsign-g3 scan --json",
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
            "scanner": "emsign-g3 scan --json",
            "distrust": "emsign-g3 distrust",
            "certs_dir": "certs/",
        },
    }


def to_ndjson(bundle: dict) -> str:
    lines: list[str] = []
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


def run_export(
    *,
    csv_path: str | Path | None = None,
    fmt: str = "json",
    ndjson: bool = False,
    verify: bool = False,
    certs_dir: str | Path | None = None,
    output_dir: str | Path | None = None,
) -> int:
    csv_file = Path(csv_path) if csv_path else indicators_csv_path()
    certs_path = Path(certs_dir) if certs_dir else default_certs_dir()

    if verify:
        errs = verify_pems(certs_path)
        if errs:
            for err in errs:
                print(err, file=sys.stderr)
            return 1
        print(f"OK: {len(expected_pem_fingerprints())} PEMs match {csv_file}")
        return 0

    rows = load_rows(csv_file)
    export_fmt = "ndjson" if ndjson else fmt

    if export_fmt == "sigma":
        if output_dir:
            paths = write_sigma_rules(Path(output_dir), rows)
            print(f"Wrote {len(paths)} Sigma rule(s) to {output_dir}")
            for p in paths:
                print(f"  {p.name}")
        else:
            sys.stdout.write(render_sigma_bundle(rows))
        return 0

    bundle = build_bundle(rows)
    if export_fmt == "ndjson":
        sys.stdout.write(to_ndjson(bundle))
    elif export_fmt == "json":
        json.dump(bundle, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        print(f"unknown export format: {export_fmt}", file=sys.stderr)
        return 2
    return 0
