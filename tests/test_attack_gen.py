from vuln_ai.scenarios.attack_gen import AttackScenarioGenerator
from vuln_ai.parser.arch_parser import Architecture


def test_attack_gen_fallback_to_demo(monkeypatch):
    gen = AttackScenarioGenerator({"llm": {"provider": "ollama"}, "ollama": {"base_url": "http://localhost:11434"}})

    def fake_get(*_args, **_kwargs):
        raise RuntimeError("no server")

    monkeypatch.setattr("vuln_ai.scenarios.attack_gen.httpx.get", fake_get)
    arch = Architecture(name="Test", components=[], network_topology="unknown", raw_description="")
    scenarios = gen.generate([], arch)
    assert "scenarios" in scenarios
    assert len(scenarios["scenarios"]) >= 1


def test_attack_gen_parse_fenced():
    gen = AttackScenarioGenerator({"llm": {"provider": "openai"}})
    raw = """```json
    {"scenarios": []}
    ```"""
    data = gen._parse(raw)
    assert data["scenarios"] == []
