from emsign_g3.elastic import build_elastic_kql_rule, elastic_kql_from_rows
from emsign_g3.indicators import load_rows


def test_elastic_kql_file_count():
    assert len(elastic_kql_from_rows(load_rows())) == 9


def test_elastic_kql_contains_sid_and_issuer():
    rows = load_rows()
    dv = next(r for r in rows if r["pem_basename"] == "EMDVTLSCAG3B")
    kql = build_elastic_kql_rule(dv)
    assert "92083401" in kql
    assert "EM DV TLS CA - G3B" in kql
