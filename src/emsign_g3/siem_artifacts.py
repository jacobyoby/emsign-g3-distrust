"""Committed SIEM rule directories under rules/sigma and rules/elastic."""
from __future__ import annotations

from pathlib import Path

from emsign_g3.elastic import elastic_kql_from_rows
from emsign_g3.indicators import load_rows
from emsign_g3.paths import repo_root
from emsign_g3.sigma import sigma_rules_from_rows

SIGMA_SUBDIR = Path("rules") / "sigma"
ELASTIC_SUBDIR = Path("rules") / "elastic"


def _root() -> Path:
    root = repo_root()
    if root is None:
        raise FileNotFoundError("not running from a git checkout with pyproject.toml")
    return root


def refresh_committed_rules(root: Path | None = None) -> tuple[Path, Path]:
    root = root or _root()
    rows = load_rows()
    sigma_dir = root / SIGMA_SUBDIR
    elastic_dir = root / ELASTIC_SUBDIR
    sigma_dir.mkdir(parents=True, exist_ok=True)
    elastic_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in sigma_rules_from_rows(rows):
        (sigma_dir / filename).write_text(content, encoding="utf-8")
    for filename, content in elastic_kql_from_rows(rows):
        (elastic_dir / filename).write_text(content, encoding="utf-8")
    return sigma_dir, elastic_dir


def verify_committed_rules(root: Path | None = None) -> list[str]:
    root = root or _root()
    errors: list[str] = []
    rows = load_rows()
    for filename, content in sigma_rules_from_rows(rows):
        path = root / SIGMA_SUBDIR / filename
        if not path.is_file():
            errors.append(f"missing {path.relative_to(root)}")
            continue
        if path.read_text(encoding="utf-8") != content:
            errors.append(
                f"stale {path.relative_to(root)} (run tools/regenerate_detection_rules.sh)"
            )
    for filename, content in elastic_kql_from_rows(rows):
        path = root / ELASTIC_SUBDIR / filename
        if not path.is_file():
            errors.append(f"missing {path.relative_to(root)}")
            continue
        if path.read_text(encoding="utf-8") != content:
            errors.append(
                f"stale {path.relative_to(root)} (run tools/regenerate_detection_rules.sh)"
            )
    return errors
