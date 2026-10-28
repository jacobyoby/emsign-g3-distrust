#!/usr/bin/env python3
"""Load eMudhra/emSign G3 compromise indicators from indicators.csv (Bug 2083449).

Single source of truth for host scanners, distrust tooling, and SIEM export.
"""
import csv
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CSV = os.path.join(_HERE, "..", "indicators.csv")

COMPROMISED_TYPES = frozenset({"TLS", "CodeSigning"})
ANCHOR_TYPES = frozenset({"RootTLS", "RootCS", "CrossSign"})

ANCHOR_LABELS = {
    "RootTLS": "emSign Root TLS CA - G3 (TLS trust anchor)",
    "RootCS": "emSign Root CS CA - G3 (code-signing trust anchor)",
    "CrossSign": "AAA Certificate Services (Sectigo cross-sign path)",
}

AAA_FINGERPRINT = "d7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4"


def load_rows(path: str | None = None) -> list[dict]:
    path = path or DEFAULT_CSV
    with open(path, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def compromised_intermediates(path: str | None = None) -> dict[str, str]:
    """SHA-256 (hex, lowercase) -> common name."""
    return {
        row["sha256_fingerprint"]: row["ca_common_name"]
        for row in load_rows(path)
        if row["type"] in COMPROMISED_TYPES
    }


def anchor_roots(path: str | None = None) -> dict[str, str]:
    """SHA-256 -> human-readable anchor label."""
    out = {}
    for row in load_rows(path):
        if row["type"] not in ANCHOR_TYPES:
            continue
        label = ANCHOR_LABELS.get(row["type"], row["ca_common_name"])
        out[row["sha256_fingerprint"]] = label
    return out


def scan_targets(path: str | None = None) -> dict[str, str]:
    return {**anchor_roots(path), **compromised_intermediates(path)}


def expected_pem_fingerprints(path: str | None = None) -> dict[str, str]:
    """PEM basename (e.g. EMDVTLSCAG3B) -> expected SHA-256."""
    return {
        row["pem_basename"]: row["sha256_fingerprint"]
        for row in load_rows(path)
        if row.get("pem_basename")
    }


def default_certs_dir() -> str:
    return os.path.join(_HERE, "..", "certs")
