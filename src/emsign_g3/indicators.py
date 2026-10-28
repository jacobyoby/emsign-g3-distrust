"""Load eMudhra/emSign G3 compromise indicators from indicators.csv (Bug 2083449)."""
from __future__ import annotations

import csv
from pathlib import Path

from emsign_g3.paths import default_certs_dir, indicators_csv_path

COMPROMISED_TYPES = frozenset({"TLS", "CodeSigning"})
ANCHOR_TYPES = frozenset({"RootTLS", "RootCS", "CrossSign"})

ANCHOR_LABELS = {
    "RootTLS": "emSign Root TLS CA - G3 (TLS trust anchor)",
    "RootCS": "emSign Root CS CA - G3 (code-signing trust anchor)",
    "CrossSign": "AAA Certificate Services (Sectigo cross-sign path)",
}

AAA_FINGERPRINT = "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4"


def default_indicators_csv() -> Path:
    return indicators_csv_path()


def load_rows(path: str | Path | None = None) -> list[dict]:
    csv_path = Path(path) if path else indicators_csv_path()
    with csv_path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def compromised_intermediates(path: str | Path | None = None) -> dict[str, str]:
    return {
        row["sha256_fingerprint"]: row["ca_common_name"]
        for row in load_rows(path)
        if row["type"] in COMPROMISED_TYPES
    }


def anchor_roots(path: str | Path | None = None) -> dict[str, str]:
    out: dict[str, str] = {}
    for row in load_rows(path):
        if row["type"] not in ANCHOR_TYPES:
            continue
        label = ANCHOR_LABELS.get(row["type"], row["ca_common_name"])
        out[row["sha256_fingerprint"]] = label
    return out


def scan_targets(path: str | Path | None = None) -> dict[str, str]:
    return {**anchor_roots(path), **compromised_intermediates(path)}


def expected_pem_fingerprints(path: str | Path | None = None) -> dict[str, str]:
    return {
        row["pem_basename"]: row["sha256_fingerprint"]
        for row in load_rows(path)
        if row.get("pem_basename")
    }


__all__ = [
    "AAA_FINGERPRINT",
    "ANCHOR_LABELS",
    "ANCHOR_TYPES",
    "COMPROMISED_TYPES",
    "anchor_roots",
    "compromised_intermediates",
    "default_certs_dir",
    "default_indicators_csv",
    "expected_pem_fingerprints",
    "load_rows",
    "scan_targets",
]
