from vuln_ai import demo_data


def test_demo_data_shapes():
    assert "vulnerabilities" in demo_data.DEMO_LLM_REPORT
    assert "scenarios" in demo_data.DEMO_SCENARIOS
    assert "mitigations" in demo_data.DEMO_MITIGATIONS
