"""
Générateur de scénarios d'attaque — produit des kill chains alignées sur le framework MITRE ATT&CK
à partir de la liste de vulnérabilités enrichies.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from vuln_ai.parser.arch_parser import Architecture


SCENARIO_PROMPT = """\
You are a senior red-team operator writing a detailed attack report.

Given a list of enriched vulnerabilities and the target architecture, \
generate attack scenarios in JSON. Each scenario must follow the \
MITRE ATT&CK framework and describe a realistic multi-step kill chain.

OUTPUT FORMAT — respond ONLY with valid JSON:
{
  "scenarios": [
    {
      "id": "SCENARIO-A",
      "title": "Short scenario title",
      "objective": "What the attacker achieves",
      "threat_actor": "Opportunist | Targeted | APT",
      "entry_point_cve": "CVE-XXXX-XXXXX or null",
      "entry_point_component": "Component name",
      "kill_chain": [
        {
          "step": 1,
          "phase": "Initial Access | Execution | Persistence | Privilege Escalation | Defense Evasion | Credential Access | Discovery | Lateral Movement | Collection | Exfiltration",
          "technique_id": "T1190",
          "technique_name": "Exploit Public-Facing Application",
          "description": "What the attacker does",
          "commands": ["exact command 1", "exact command 2"],
          "tools": ["nmap", "redis-cli", ...],
          "iocs": ["log entry pattern", "network indicator"]
        }
      ],
      "prerequisites": ["No firewall on port 6379", "Flat network"],
      "impact": "CIA impact description",
      "detection_difficulty": "LOW | MEDIUM | HIGH",
      "cves_used": ["CVE-XXXX-XXXXX"],
      "dread_score": {
        "damage": 9,
        "reproducibility": 10,
        "exploitability": 10,
        "affected_users": 9,
        "discoverability": 9,
        "total": 9.4
      }
    }
  ]
}

Generate exactly the following 3 scenarios based on the vulnerabilities provided:
- Scenario A: Full compromise via Mirth Connect (CVE-2023-43208) + Pickle service chain
- Scenario B: SSRF via wkhtmltopdf -> AWS metadata -> S3 credentials theft
- Scenario C: Redis unauthenticated -> crontab injection -> lateral movement to MySQL

Use real MITRE ATT&CK technique IDs. Include exact tool commands. Be specific and technical.
Respond ONLY with the JSON object. No markdown fences.
"""


def _build_scenario_message(vulns: List[Dict], arch: Architecture) -> str:
    lines = [
        f"Target architecture: {arch.name}",
        f"Network topology: {arch.network_topology}",
        "",
        "Identified vulnerabilities (enriched):",
    ]
    for v in vulns:
        lines.append(
            f"  [{v.get('severity','?')}] {v.get('id')} — {v.get('component')} — "
            f"{v.get('type')} — CVE: {v.get('cve_id','none')} "
            f"(CVSS {v.get('cvss_score','?')}, confidence {v.get('confidence_score','?')})"
        )
    return "\n".join(lines)


class AttackScenarioGenerator:
    def __init__(self, config: Dict[str, Any]):
        self.cfg = config.get("llm", {})
        self.ollama_cfg = config.get("ollama", {})

    def generate(self, vulnerabilities: List[Dict], arch: Architecture) -> Dict[str, Any]:
        user_msg = _build_scenario_message(vulnerabilities, arch)
        provider = self.cfg.get("provider", "anthropic")

        if provider == "anthropic":
            raw = self._call_anthropic(user_msg)
        elif provider == "ollama":
            raw = self._call_openai_compatible(
                user_msg,
                model=self.ollama_cfg.get("model", "llama3:70b"),
                base_url=self.ollama_cfg.get("base_url", "http://localhost:11434") + "/v1",
            )
        else:
            raw = self._call_openai_compatible(user_msg, model=self.cfg.get("model", "gpt-4o"))

        return self._parse(raw)

    def _parse(self, raw: str) -> Dict[str, Any]:
        text = raw.strip()
        if text.startswith("```"):
            text = text.split("\n", 1)[1].rsplit("```", 1)[0]
        return json.loads(text)

    def _call_anthropic(self, user_msg: str) -> str:
        import anthropic  # type: ignore

        client = anthropic.Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY", ""))
        r = client.messages.create(
            model=self.cfg.get("model", "claude-sonnet-4-6"),
            max_tokens=self.cfg.get("max_tokens", 8192),
            temperature=self.cfg.get("temperature", 0.1),
            system=SCENARIO_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
        return r.content[0].text

    def _call_openai_compatible(self, user_msg: str, model: str, base_url: str = None) -> str:
        from openai import OpenAI  # type: ignore

        kwargs: dict = {}
        if base_url:
            kwargs["base_url"] = base_url
        client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY", "ollama"), **kwargs)
        r = client.chat.completions.create(
            model=model,
            temperature=self.cfg.get("temperature", 0.1),
            max_tokens=self.cfg.get("max_tokens", 8192),
            messages=[
                {"role": "system", "content": SCENARIO_PROMPT},
                {"role": "user", "content": user_msg},
            ],
        )
        return r.choices[0].message.content
