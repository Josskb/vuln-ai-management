import os

import pytest

from vuln_ai.analyzer.llm_analyzer import LLMAnalyzer
from vuln_ai.parser.arch_parser import Architecture


def test_parse_response_strips_fences():
    analyzer = LLMAnalyzer({})
    raw = """```json
{"vulnerabilities": [], "risk_score": 10, "summary": "ok"}
```"""
    data = analyzer._parse_response(raw)
    assert data["risk_score"] == 10
    assert data["vulnerabilities"] == []


def test_parse_response_trailing_comma():
    analyzer = LLMAnalyzer({})
    raw = """{
      "vulnerabilities": [],
      "risk_score": 1,
      "summary": "ok",
    }"""
    data = analyzer._parse_response(raw)
    assert data["summary"] == "ok"


def test_filter_low_confidence():
    analyzer = LLMAnalyzer({"output": {"confidence_threshold": 0.6}})
    report = {
        "vulnerabilities": [
            {"confidence_score": 0.5},
            {"confidence_score": 0.7},
        ]
    }
    filtered = analyzer._filter_low_confidence(report)
    assert len(filtered["vulnerabilities"]) == 1
    assert filtered["filtered_count"] == 1


def test_analyze_fallback_to_demo(monkeypatch):
    analyzer = LLMAnalyzer({"llm": {"provider": "ollama"}, "ollama": {"base_url": "http://localhost:11434"}})

    def fake_get(*_args, **_kwargs):
        raise RuntimeError("no server")

    monkeypatch.setattr("vuln_ai.analyzer.llm_analyzer.httpx.get", fake_get)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    arch = Architecture(name="Test", components=[], network_topology="unknown", raw_description="")
    report = analyzer.analyze(arch)
    assert "vulnerabilities" in report
    assert report.get("risk_score") is not None


def test_analyze_openai_success(monkeypatch):
    analyzer = LLMAnalyzer({"llm": {"provider": "openai"}, "output": {"confidence_threshold": 0.6}})

    def fake_call(_msg, _cfg, base_url=None):
        return (
            "{"
            "\"vulnerabilities\":[{\"confidence_score\":0.7,\"severity\":\"HIGH\"," \
            "\"type\":\"RCE\",\"cvss_score\":7.5,\"evidence\":\"evidence text\"}],"
            "\"risk_score\":12,\"summary\":\"ok\"}"
        )

    monkeypatch.setattr("vuln_ai.analyzer.llm_analyzer._call_openai_compatible", fake_call)
    arch = Architecture(name="Test", components=[], network_topology="unknown", raw_description="")
    report = analyzer.analyze(arch)
    assert report["risk_score"] == 12
