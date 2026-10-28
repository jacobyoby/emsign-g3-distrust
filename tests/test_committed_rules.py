from emsign_g3.siem_artifacts import verify_committed_rules


def test_committed_siem_rules_match_generators():
    errors = verify_committed_rules()
    assert errors == [], "\n".join(errors)
