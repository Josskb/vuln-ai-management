from vuln_ai.mitigations.mitigation_gen import MitigationGenerator


def test_mitigation_gen_fallback_to_demo(monkeypatch):
    gen = MitigationGenerator({"llm": {"provider": "ollama"}, "ollama": {"base_url": "http://localhost:11434"}})

    def fake_get(*_args, **_kwargs):
        raise RuntimeError("no server")

    monkeypatch.setattr("vuln_ai.mitigations.mitigation_gen.httpx.get", fake_get)
    mitigations = gen.generate([])
    assert "mitigations" in mitigations
    assert len(mitigations["mitigations"]) >= 1


def test_mitigation_gen_parse_fenced():
    gen = MitigationGenerator({"llm": {"provider": "openai"}})
    raw = """```json
    {"mitigations": []}
    ```"""
    data = gen._parse(raw)
    assert data["mitigations"] == []
