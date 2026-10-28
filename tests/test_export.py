from emsign_g3.export import build_bundle, to_ndjson
from emsign_g3.indicators import load_rows


def test_build_bundle_schema():
    bundle = build_bundle(load_rows())
    assert bundle["schema"] == "emsign-g3-distrust-indicators/v1"
    assert bundle["mozilla_bug"] == "2083449"
    assert len(bundle["compromised_intermediates"]) == 8
    assert len(bundle["trust_anchors"]) == 3
    assert bundle["network_detection"]["generic_backstop_sid"] == 92083409


def test_ndjson_line_count():
    bundle = build_bundle(load_rows())
    lines = [ln for ln in to_ndjson(bundle).splitlines() if ln.strip()]
    # metadata + 8 intermediates + 3 anchors + network_detection
    assert len(lines) == 13
