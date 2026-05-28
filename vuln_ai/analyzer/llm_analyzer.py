"""
Analyseur LLM — envoie l'architecture parsée au LLM, retourne un rapport de vulnérabilités en JSON.
Compatible Claude (Anthropic), Ollama et toute API OpenAI-compatible.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from vuln_ai.parser.arch_parser import Architecture


SYSTEM_PROMPT = """\
You are a senior cybersecurity expert specialising in architecture risk \
assessment and penetration testing. Your analysis must follow the rigour of \
a formal pentest report.

TASK
Given a textual description of an IT architecture, produce a structured JSON \
security report.

CHAIN-OF-THOUGHT (follow this order internally before writing the JSON):
1. List all exposed components and their attack surface.
2. For each component, identify applicable vulnerability classes.
3. Cross-reference known CVEs for the specific versions mentioned.
4. Rank by CVSS exploitability (AV:N, AC:L, PR:N preferred).

OUTPUT FORMAT — respond ONLY with valid JSON matching this schema exactly:
{
  "components_identified": ["list of components you detected"],
  "vulnerabilities": [
    {
      "id": "VULN-001",
      "component": "affected component name",
      "type": "SQLi | RCE | SSRF | Deserialisation | AuthBypass | IDOR | MiscConfig | WeakCrypto | InfoDisclosure | other",
      "severity": "CRITICAL | HIGH | MEDIUM | LOW",
      "cve_id": "CVE-XXXX-XXXXX or null",
      "cwe_id": "CWE-XXX or null",
      "cvss_score": 9.8,
      "description": "Technical explanation — what is vulnerable and why",
      "attack_vector": "How an attacker exploits this step-by-step",
      "confidence_score": 0.95
    }
  ],
  "risk_score": 87,
  "summary": "3-5 sentence executive summary of the overall risk posture"
}

CONFIDENCE SCORE RULES:
- 0.9–1.0: CVE confirmed for this exact component version
- 0.7–0.89: Strong evidence from component behaviour / known class
- 0.5–0.69: Plausible but requires confirmation
- Below 0.5: Speculative — avoid including unless severity is CRITICAL

FEW-SHOT EXAMPLES of good vulnerability entries:

Example 1 (confirmed CVE, high confidence):
{
  "id": "VULN-001",
  "component": "Mirth Connect 4.4.0",
  "type": "RCE",
  "severity": "CRITICAL",
  "cve_id": "CVE-2023-43208",
  "cwe_id": "CWE-502",
  "cvss_score": 9.8,
  "description": "Mirth Connect <= 4.4.0 is vulnerable to unauthenticated remote code execution via Java XStream deserialisation. No credentials required. The /api endpoint processes user-controlled XML that is deserialised without sanitisation.",
  "attack_vector": "Send crafted HTTP POST to /api with malicious XStream payload -> arbitrary OS command execution as the Mirth process user.",
  "confidence_score": 0.97
}

Example 2 (misconfiguration, no CVE):
{
  "id": "VULN-002",
  "component": "Redis 6.0 (no authentication)",
  "type": "MiscConfig",
  "severity": "CRITICAL",
  "cve_id": null,
  "cwe_id": "CWE-306",
  "cvss_score": 10.0,
  "description": "Redis instance has no requirepass set. On a flat network, any compromised host can connect directly. CONFIG SET allows writing arbitrary files to the filesystem, enabling crontab injection or SSH key implant for root access.",
  "attack_vector": "redis-cli -h <target> CONFIG SET dir /root/.ssh; CONFIG SET dbfilename authorized_keys; SET x '<attacker_pubkey>'; BGSAVE -> SSH as root.",
  "confidence_score": 0.99
}

Respond ONLY with the JSON object. No markdown fences, no preamble.
"""


def _build_user_message(arch: Architecture) -> str:
    lines = [f"Architecture name: {arch.name}", f"Network topology: {arch.network_topology}", ""]
    lines.append("Components:")
    for c in arch.components:
        lines.append(f"  - {c.name} (type={c.type}, version={c.version}, exposure={c.exposure})")
        if c.misconfigurations:
            for m in c.misconfigurations:
                lines.append(f"      misconfiguration: {m}")
        if c.ports:
            lines.append(f"      ports: {c.ports}")
    lines.append("")
    lines.append("Raw description (authoritative):")
    lines.append(arch.raw_description)
    return "\n".join(lines)


def _call_anthropic(user_msg: str, cfg: Dict[str, Any]) -> str:
    import anthropic  # type: ignore

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    client = anthropic.Anthropic(api_key=api_key)
    response = client.messages.create(
        model=cfg.get("model", "claude-sonnet-4-6"),
        max_tokens=cfg.get("max_tokens", 8192),
        temperature=cfg.get("temperature", 0.1),
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_msg}],
    )
    return response.content[0].text


def _call_openai_compatible(user_msg: str, cfg: Dict[str, Any], base_url: str = None) -> str:
    from openai import OpenAI  # type: ignore

    kwargs: dict = {}
    if base_url:
        kwargs["base_url"] = base_url
    api_key = os.environ.get("OPENAI_API_KEY", "ollama")
    client = OpenAI(api_key=api_key, **kwargs)
    response = client.chat.completions.create(
        model=cfg.get("model", "gpt-4o"),
        temperature=cfg.get("temperature", 0.1),
        max_tokens=cfg.get("max_tokens", 8192),
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user_msg},
        ],
    )
    return response.choices[0].message.content


class LLMAnalyzer:
    def __init__(self, config: Dict[str, Any]):
        self.cfg = config.get("llm", {})
        self.ollama_cfg = config.get("ollama", {})
        self.confidence_threshold = config.get("output", {}).get("confidence_threshold", 0.6)

    def analyze(self, arch: Architecture) -> Dict[str, Any]:
        user_msg = _build_user_message(arch)
        provider = self.cfg.get("provider", "anthropic")

        if provider == "anthropic":
            raw = _call_anthropic(user_msg, self.cfg)
        elif provider == "ollama":
            ollama_cfg = {**self.cfg, "model": self.ollama_cfg.get("model", "llama3:70b")}
            raw = _call_openai_compatible(
                user_msg, ollama_cfg,
                base_url=self.ollama_cfg.get("base_url", "http://localhost:11434") + "/v1",
            )
        else:
            raw = _call_openai_compatible(user_msg, self.cfg)

        report = self._parse_response(raw)
        report = self._filter_low_confidence(report)
        return report

    def _parse_response(self, raw: str) -> Dict[str, Any]:
        text = raw.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1]
            text = text.rsplit("```", 1)[0]
        return json.loads(text)

    def _filter_low_confidence(self, report: Dict[str, Any]) -> Dict[str, Any]:
        vulns: List[dict] = report.get("vulnerabilities", [])
        filtered = [v for v in vulns if v.get("confidence_score", 1.0) >= self.confidence_threshold]
        report["vulnerabilities"] = filtered
        report["filtered_count"] = len(vulns) - len(filtered)
        return report
