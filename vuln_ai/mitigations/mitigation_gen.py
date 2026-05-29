"""
Générateur de mitigations — produit des recommandations de correction avec
les commandes de vérification pour chaque vulnérabilité.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict, List
import httpx


MITIGATION_PROMPT = """\
You are a security architect writing an actionable remediation report.

For each vulnerability provided, generate a concrete mitigation with \
numbered implementation steps and a verification command. \
Mitigations must NOT break business-critical functionality.

GOOD mitigation example:
{
  "vulnerability_id": "VULN-010",
  "title": "Enable Redis authentication",
  "type": "Config",
  "priority": "IMMEDIATE",
  "effort": "LOW",
  "description": "Redis 6.0 has no requirepass set, allowing unauthenticated access on port 6379.",
  "implementation_steps": [
    "1. Edit /etc/redis/redis.conf: add line 'requirepass <strong_random_password>'",
    "2. Restart Redis: sudo systemctl restart redis",
    "3. Update application .env: REDIS_PASSWORD=<same_password>",
    "4. Verify with: redis-cli -a <password> ping  (should return PONG)"
  ],
  "verification": "redis-cli -a <password> ping  # must return PONG; redis-cli ping without -a must return NOAUTH",
  "references": ["CWE-306", "https://redis.io/docs/management/security/"],
  "business_impact": "None — application connects with password; clients must be updated simultaneously"
}

BAD mitigation example (too vague — avoid this):
{
  "title": "Secure Redis",
  "description": "Add authentication to Redis",
  "implementation_steps": ["Enable password"]
}

OUTPUT FORMAT — respond ONLY with valid JSON:
{
  "mitigations": [ <list of mitigation objects as shown above> ]
}

Respond ONLY with the JSON object. No markdown fences.
"""


def _build_mitigation_message(vulnerabilities: List[Dict]) -> str:
    lines = ["Vulnerabilities requiring mitigations:"]
    for v in vulnerabilities:
        lines.append(
            f"\n  ID: {v.get('id')}  Component: {v.get('component')}"
            f"\n  Type: {v.get('type')}  Severity: {v.get('severity')}"
            f"\n  CVE: {v.get('cve_id','none')}  CVSS: {v.get('cvss_score','?')}"
            f"\n  Description: {v.get('description','')[:300]}"
        )
    return "\n".join(lines)


class MitigationGenerator:
    def __init__(self, config: Dict[str, Any]):
        self.cfg = config.get("llm", {})
        self.ollama_cfg = config.get("ollama", {})

    def generate(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        user_msg = _build_mitigation_message(vulnerabilities)
        provider = self.cfg.get("provider", "anthropic")

        # If Ollama configured, check reachability and fallback if necessary
        if provider == "ollama":
            base = self.ollama_cfg.get("base_url", "http://localhost:11434")
            try:
                resp = httpx.get(base.rstrip("/") + "/v1/models", timeout=3.0)
                if resp.status_code != 200:
                    raise RuntimeError("unexpected status")
            except Exception:
                print(f"[warning] Ollama not reachable at {base}; attempting fallback providers...")
                if os.environ.get("OPENAI_API_KEY"):
                    provider = "openai"
                    print("[info] Falling back to OpenAI (OPENAI_API_KEY detected)")
                elif os.environ.get("ANTHROPIC_API_KEY"):
                    provider = "anthropic"
                    print("[info] Falling back to Anthropic (ANTHROPIC_API_KEY detected)")
                else:
                    print("[warning] No LLM API keys found — using demo mitigations")
                    from vuln_ai.demo_data import DEMO_MITIGATIONS
                    return DEMO_MITIGATIONS

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
            system=MITIGATION_PROMPT,
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
                {"role": "system", "content": MITIGATION_PROMPT},
                {"role": "user", "content": user_msg},
            ],
        )
        return r.choices[0].message.content
