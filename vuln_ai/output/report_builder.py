"""
Report builder — assembles the final JSON and HTML reports.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from jinja2 import Environment, FileSystemLoader


_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
_TEMPLATES_DIR = Path(__file__).parent / "templates"


class ReportBuilder:
    def __init__(self, config: Dict[str, Any]):
        out_cfg = config.get("output", {})
        self.output_dir = Path(out_cfg.get("directory", "output"))
        self.formats: List[str] = out_cfg.get("formats", ["json", "html"])
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def build(
        self,
        arch_name: str,
        vulnerabilities: List[Dict],
        scenarios: Dict[str, Any],
        mitigations: Dict[str, Any],
        risk_score: int,
        summary: str,
        cve_table: List[Dict],
    ) -> Dict[str, str]:
        """Assemble the full report and write all requested formats."""
        vulnerabilities = sorted(
            vulnerabilities,
            key=lambda v: _SEVERITY_ORDER.get(v.get("severity", "LOW"), 4),
        )

        report = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "architecture": arch_name,
            "risk_score": risk_score,
            "summary": summary,
            "vulnerability_count": len(vulnerabilities),
            "vulnerabilities": vulnerabilities,
            "cve_mapping_table": cve_table,
            "attack_scenarios": scenarios.get("scenarios", []),
            "mitigations": mitigations.get("mitigations", []),
        }

        paths: Dict[str, str] = {}

        if "json" in self.formats:
            p = self.output_dir / "report_raw.json"
            p.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            paths["json"] = str(p)

        if "html" in self.formats:
            p = self.output_dir / "report_mediconnect.html"
            html = self._render_html(report)
            p.write_text(html, encoding="utf-8")
            paths["html"] = str(p)

        return paths

    def _render_html(self, report: Dict[str, Any]) -> str:
        env = Environment(
            loader=FileSystemLoader(str(_TEMPLATES_DIR)),
            autoescape=True,
        )
        env.filters["severity_class"] = lambda s: s.lower()
        env.filters["truncate_str"] = lambda s, n=200: (s[:n] + "…") if len(s) > n else s
        tpl = env.get_template("report.html.j2")
        return tpl.render(**report)
