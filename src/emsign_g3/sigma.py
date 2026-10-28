"""Generate Sigma rule stubs from Bug 2083449 indicators (Suricata EVE-oriented)."""
from __future__ import annotations

import json
import re
from pathlib import Path

from emsign_g3.indicators import COMPROMISED_TYPES, load_rows

MOZILLA_BUG = "2083449"
GENERIC_SID = 92083409

_SAFE = re.compile(r"[^a-zA-Z0-9_-]+")


def _slug(name: str) -> str:
    return _SAFE.sub("_", name).strip("_").lower()


def _yaml_str(value: str) -> str:
    return json.dumps(value)


def build_sigma_rule(row: dict) -> str:
    """One Sigma YAML document for a compromised intermediate."""
    cn = row["tls_issuer_cn_match"]
    sid = int(row["suricata_sid"])
    title = f"eMudhra emSign G3 compromised issuer {row['ca_common_name']}"
    lines = [
        "title: " + _yaml_str(title),
        "id: " + _yaml_str(f"emsign-g3-{row['pem_basename'].lower()}-2083449"),
        "status: experimental",
        "description: " + _yaml_str(
            "TLS leaf issued under a compromised eMudhra/emSign G3 intermediate "
            f"(serial {row.get('serial') or 'unknown'}). Private keys were recoverable; "
            "see Mozilla Bug 2083449. Tune field names to your Suricata EVE / SIEM mapping."
        ),
        "references:",
        f"  - https://bugzilla.mozilla.org/show_bug.cgi?id={MOZILLA_BUG}",
        "author: emsign-g3-distrust",
        "tags:",
        "  - attack.initial_access",
        "  - attack.t1553.004",
        "logsource:",
        "  category: network",
        "  product: suricata",
        "  service: eve",
        "detection:",
        "  selection_issuer:",
        f"    tls.issuerdn|contains: {_yaml_str(cn)}",
        "  selection_sid:",
        f"    alert.signature_id: {sid}",
        "  condition: selection_issuer or selection_sid",
        "falsepositives:",
        "  - Historical captures before distrust rollout",
        "level: high",
    ]
    return "\n".join(lines) + "\n"


def build_sigma_backstop() -> str:
    lines = [
        "title: " + _yaml_str("eMudhra emSign G3 compromised-family issuer (generic review)"),
        "id: " + _yaml_str("emsign-g3-generic-backstop-2083449"),
        "status: experimental",
        "description: " + _yaml_str(
            "Backstop for emSign G3 EM * CA - G3B/G3C issuer family (Suricata sid "
            f"{GENERIC_SID}). Review before blocking; prefer per-CA rules."
        ),
        "references:",
        f"  - https://bugzilla.mozilla.org/show_bug.cgi?id={MOZILLA_BUG}",
        "author: emsign-g3-distrust",
        "logsource:",
        "  category: network",
        "  product: suricata",
        "  service: eve",
        "detection:",
        "  selection:",
        f"    alert.signature_id: {GENERIC_SID}",
        "  condition: selection",
        "falsepositives:",
        "  - Requires analyst review",
        "level: medium",
    ]
    return "\n".join(lines) + "\n"


def sigma_rules_from_rows(rows: list[dict]) -> list[tuple[str, str]]:
    """Return (filename, yaml_content) for each compromised intermediate plus backstop."""
    out: list[tuple[str, str]] = []
    for row in rows:
        if row["type"] not in COMPROMISED_TYPES:
            continue
        base = row.get("pem_basename") or _slug(row["ca_common_name"])
        out.append((f"emsign_g3_{base.lower()}.yml", build_sigma_rule(row)))
    out.append(("emsign_g3_generic_backstop.yml", build_sigma_backstop()))
    return out


def render_sigma_bundle(rows: list[dict] | None = None) -> str:
    rows = rows if rows is not None else load_rows()
    parts = [content for _, content in sigma_rules_from_rows(rows)]
    return "\n---\n".join(parts)


def write_sigma_rules(output_dir: Path, rows: list[dict] | None = None) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    rows = rows if rows is not None else load_rows()
    for filename, content in sigma_rules_from_rows(rows):
        path = output_dir / filename
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return written
