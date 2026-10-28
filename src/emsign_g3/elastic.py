"""Generate Elastic KQL detection stubs from Bug 2083449 indicators."""
from __future__ import annotations

import re
from pathlib import Path

from emsign_g3.indicators import COMPROMISED_TYPES, load_rows

MOZILLA_BUG = "2083449"
GENERIC_SID = 92083409

_SAFE = re.compile(r"[^a-zA-Z0-9_-]+")


def _slug(name: str) -> str:
    return _SAFE.sub("_", name).strip("_").lower()


def build_elastic_kql_rule(row: dict) -> str:
    cn = row["tls_issuer_cn_match"]
    sid = int(row["suricata_sid"])
    serial = row.get("serial") or "unknown"
    lines = [
        f"// eMudhra emSign G3 compromised issuer: {row['ca_common_name']}",
        f"// Mozilla Bug {MOZILLA_BUG} | serial {serial} | Suricata sid {sid}",
        "// Starter KQL for Suricata EVE / ECS-normalized TLS events.",
        "// Adjust field names (e.g. suricata.eve.alert.signature_id) for your stack.",
        f'alert.signature_id == {sid} or tls.issuerdn : *"{cn}"*',
        "",
    ]
    return "\n".join(lines)


def build_elastic_kql_backstop() -> str:
    return "\n".join(
        [
            "// eMudhra emSign G3 compromised-family issuer (generic review)",
            f"// Mozilla Bug {MOZILLA_BUG} | Suricata sid {GENERIC_SID}",
            "// Review hits manually; prefer per-CA rules in this directory.",
            f"alert.signature_id == {GENERIC_SID}",
            "",
        ]
    )


def elastic_kql_from_rows(rows: list[dict]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for row in rows:
        if row["type"] not in COMPROMISED_TYPES:
            continue
        base = row.get("pem_basename") or _slug(row["ca_common_name"])
        out.append((f"emsign_g3_{base.lower()}.kql", build_elastic_kql_rule(row)))
    out.append(("emsign_g3_generic_backstop.kql", build_elastic_kql_backstop()))
    return out


def render_elastic_kql_bundle(rows: list[dict] | None = None) -> str:
    rows = rows if rows is not None else load_rows()
    parts = [content for _, content in elastic_kql_from_rows(rows)]
    return "\n".join(parts)


def write_elastic_kql_rules(output_dir: Path, rows: list[dict] | None = None) -> list[Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    rows = rows if rows is not None else load_rows()
    for filename, content in elastic_kql_from_rows(rows):
        path = output_dir / filename
        path.write_text(content, encoding="utf-8")
        written.append(path)
    return written
