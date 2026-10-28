from emsign_g3.indicators import load_rows
from emsign_g3.sigma import build_sigma_rule, render_sigma_bundle, sigma_rules_from_rows


def test_sigma_rule_count():
    rows = load_rows()
    files = sigma_rules_from_rows(rows)
    assert len(files) == 9  # eight intermediates + generic backstop


def test_sigma_rule_contains_sid_and_issuer():
    rows = load_rows()
    dv = next(r for r in rows if r["pem_basename"] == "EMDVTLSCAG3B")
    yaml = build_sigma_rule(dv)
    assert "92083401" in yaml
    assert "EM DV TLS CA - G3B" in yaml
    assert "2083449" in yaml


def test_sigma_bundle_separator():
    bundle = render_sigma_bundle()
    assert bundle.count("\n---\n") == 8
