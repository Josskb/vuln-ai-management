"""
Analyseur LLM — envoie l'architecture parsée au LLM, retourne un rapport de vulnérabilités en JSON.
Compatible Claude (Anthropic), Ollama et toute API OpenAI-compatible.
"""
from __future__ import annotations

import json
import os
import re
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
  "attack_surface": {
    "internet_exposed": ["components directly reachable from the internet"],
    "internal_only": ["components accessible only from internal network"],
    "critical_paths": ["highest-risk attack paths, e.g. Internet -> Nginx -> Mirth -> DB"]
  },
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
      "evidence": "Exact element from the architecture description that justifies this finding",
      "confidence_score": 0.95
    }
  ],
  "risk_score": 87,
  "risk_score_rationale": "2-sentence justification for the global score",
  "summary": "3-5 sentence executive summary of the overall risk posture"
}

CONFIDENCE SCORE RULES:
- 0.9-1.0: CVE confirmed for this exact component version
- 0.7-0.89: Strong evidence from component behaviour / known class
- 0.5-0.69: Plausible but requires confirmation
- Below 0.5: Speculative — avoid including unless severity is CRITICAL

EVIDENCE RULE:
Every vulnerability MUST include an "evidence" field quoting the specific element
(component name, version, misconfiguration, port, protocol) from the architecture
description that justifies the finding. If you cannot cite specific evidence, lower
the confidence_score below 0.5.

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
  "evidence": "Mirth Connect 4.4.0 listed as a component, version explicitly stated, exposed via reverse proxy from internet.",
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
  "evidence": "Redis 6.0 (no authentication) — component name explicitly states no auth; flat network noted in topology.",
  "confidence_score": 0.99
}

Respond ONLY with the JSON object. No markdown fences, no preamble.
"""


_KNOWN_VULN_TYPES = {
    "RCE", "SQLi", "XSS", "SSRF", "LFI", "RFI", "IDOR",
    "Deserialisation", "AuthBypass", "MiscConfig", "WeakCrypto",
    "InfoDisclosure", "CommandInjection", "PathTraversal", "JWT",
}

_SEVERITY_CVSS_RANGES = {
    "CRITICAL": (9.0, 10.0),
    "HIGH":     (7.0, 8.9),
    "MEDIUM":   (4.0, 6.9),
    "LOW":      (0.1, 3.9),
}


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
        self.max_retries = 3

    def analyze(self, arch: Architecture) -> Dict[str, Any]:
        user_msg = _build_user_message(arch)
        provider = self.cfg.get("provider", "anthropic")
        last_error: Exception = None

        for attempt in range(self.max_retries):
            try:
                msg = user_msg
                if attempt > 0:
                    msg += f"\n\n[RETRY {attempt}] Erreur precedente: {last_error}. Reponds UNIQUEMENT en JSON valide."

                if provider == "anthropic":
                    raw = _call_anthropic(msg, self.cfg)
                elif provider == "ollama":
                    ollama_cfg = {**self.cfg, "model": self.ollama_cfg.get("model", "llama3:70b")}
                    raw = _call_openai_compatible(
                        msg, ollama_cfg,
                        base_url=self.ollama_cfg.get("base_url", "http://localhost:11434") + "/v1",
                    )
                else:
                    raw = _call_openai_compatible(msg, self.cfg)

                report = self._parse_response(raw)
                self._validate_structure(report)
                report = self._validate_vulnerabilities(report)
                report = self._filter_low_confidence(report)
                return report

            except (json.JSONDecodeError, ValueError, KeyError) as exc:
                last_error = exc
                if attempt == self.max_retries - 1:
                    raise RuntimeError(
                        f"LLM n'a pas produit de JSON valide apres {self.max_retries} tentatives. "
                        f"Derniere erreur : {exc}"
                    ) from exc

        return {}

    def _parse_response(self, raw: str) -> Dict[str, Any]:
        s = re.sub(r"```json\s*", "", raw, flags=re.IGNORECASE)
        s = re.sub(r"```\s*", "", s).strip()

        try:
            return json.loads(s)
        except json.JSONDecodeError:
            pass

        start = s.find("{")
        if start == -1:
            raise ValueError("Aucun objet JSON trouve dans la reponse LLM")

        depth, in_str, escape = 0, False, False
        for i, c in enumerate(s[start:], start):
            if escape:
                escape = False
                continue
            if c == "\\" and in_str:
                escape = True
                continue
            if c == '"':
                in_str = not in_str
                continue
            if in_str:
                continue
            if c == "{":
                depth += 1
            if c == "}":
                depth -= 1
                if depth == 0:
                    candidate = s[start: i + 1]
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        fixed = re.sub(r",\s*([}\]])", r"\1", candidate)
                        fixed = re.sub(r"//[^\n]*", "", fixed)
                        return json.loads(fixed)

        raise ValueError(f"JSON incomplet dans la reponse LLM (profondeur finale : {depth})")

    def _validate_structure(self, data: Dict[str, Any]) -> None:
        for field in ("vulnerabilities", "risk_score", "summary"):
            if field not in data:
                raise KeyError(f"Champ obligatoire manquant dans la reponse LLM : {field}")

    def _validate_vulnerabilities(self, report: Dict[str, Any]) -> Dict[str, Any]:
        scored = []
        for vuln in report.get("vulnerabilities", []):
            score = 0

            if vuln.get("evidence") and len(str(vuln["evidence"])) > 10:
                score += 30

            if re.match(r"CWE-\d+", vuln.get("cwe_id") or ""):
                score += 20

            expected = _SEVERITY_CVSS_RANGES.get(vuln.get("severity", ""))
            if expected:
                try:
                    cvss = float(vuln.get("cvss_score") or 0)
                    if expected[0] <= cvss <= expected[1]:
                        score += 20
                except (TypeError, ValueError):
                    pass

            if vuln.get("type") in _KNOWN_VULN_TYPES:
                score += 30

            vuln["reliability_score"] = score
            scored.append(vuln)

        report["vulnerabilities"] = scored
        return report

    def _filter_low_confidence(self, report: Dict[str, Any]) -> Dict[str, Any]:
        vulns: List[dict] = report.get("vulnerabilities", [])
        filtered = [v for v in vulns if v.get("confidence_score", 1.0) >= self.confidence_threshold]
        report["vulnerabilities"] = filtered
        report["filtered_count"] = len(vulns) - len(filtered)
        return report
