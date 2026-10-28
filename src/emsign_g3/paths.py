"""Resolve indicators.csv and intermediate PEM directories (editable, wheel, env)."""
from __future__ import annotations

import os
from functools import lru_cache
from importlib import resources
from pathlib import Path

ENV_INDICATORS_CSV = "EMSIGN_G3_INDICATORS_CSV"
ENV_CERTS_DIR = "EMSIGN_G3_CERTS_DIR"


def _package_dir() -> Path:
    return Path(__file__).resolve().parent


@lru_cache
def repo_root() -> Path | None:
    """Git checkout root (contains pyproject.toml + indicators.csv), if present."""
    here = _package_dir()
    for candidate in (here, *here.parents):
        if (candidate / "pyproject.toml").is_file() and (candidate / "indicators.csv").is_file():
            return candidate
    return None


def indicators_csv_path() -> Path:
    override = os.environ.get(ENV_INDICATORS_CSV)
    if override:
        return Path(override)

    root = repo_root()
    if root is not None:
        return root / "indicators.csv"

    bundled = _package_dir() / "data" / "indicators.csv"
    if bundled.is_file():
        return bundled

    try:
        ref = resources.files("emsign_g3").joinpath("data/indicators.csv")
        with resources.as_file(ref) as path:
            return Path(path)
    except (FileNotFoundError, ModuleNotFoundError, TypeError):
        pass

    raise FileNotFoundError(
        "indicators.csv not found; set EMSIGN_G3_INDICATORS_CSV or install from a git checkout"
    )


def default_certs_dir() -> Path:
    override = os.environ.get(ENV_CERTS_DIR)
    if override:
        return Path(override)

    root = repo_root()
    if root is not None:
        candidate = root / "certs"
        if candidate.is_dir():
            return candidate

    bundled = _package_dir() / "data" / "certs"
    if bundled.is_dir() and any(bundled.glob("EM*.pem")):
        return bundled

    try:
        ref = resources.files("emsign_g3").joinpath("data/certs")
        with resources.as_file(ref) as path:
            p = Path(path)
            if p.is_dir():
                return p
    except (FileNotFoundError, ModuleNotFoundError, TypeError):
        pass

    raise FileNotFoundError(
        "certs directory not found; set EMSIGN_G3_CERTS_DIR or install from a git checkout"
    )
