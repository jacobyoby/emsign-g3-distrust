from pathlib import Path

from emsign_g3.indicators import (
    COMPROMISED_TYPES,
    anchor_roots,
    compromised_intermediates,
    expected_pem_fingerprints,
    load_rows,
)
from emsign_g3.paths import indicators_csv_path, repo_root

ROOT_CSV = repo_root() / "indicators.csv" if repo_root() else None
PACKAGED_CSV = Path(__file__).resolve().parents[1] / "src/emsign_g3/data/indicators.csv"

KNOWN_DV_G3B = "42c4accd12c4f59597925e1a08a7a90102608543809308d50ec427e118ba1493"


def test_csv_row_counts():
    rows = load_rows()
    compromised = [r for r in rows if r["type"] in COMPROMISED_TYPES]
    anchors = [r for r in rows if r["type"] not in COMPROMISED_TYPES]
    assert len(compromised) == 8
    assert len(anchors) == 3


def test_compromised_includes_dv_g3b():
    assert compromised_intermediates()[KNOWN_DV_G3B] == "EM DV TLS CA - G3B"


def test_pem_basenames_unique():
    basenames = list(expected_pem_fingerprints().keys())
    assert len(basenames) == 8
    assert len(set(basenames)) == 8


def test_anchor_roots_count():
    assert len(anchor_roots()) == 3


def test_root_and_packaged_indicators_match():
    if ROOT_CSV is None or not ROOT_CSV.is_file():
        return
    assert ROOT_CSV.read_text(encoding="utf-8") == PACKAGED_CSV.read_text(encoding="utf-8")


def test_indicators_csv_resolves():
    assert indicators_csv_path().is_file()
