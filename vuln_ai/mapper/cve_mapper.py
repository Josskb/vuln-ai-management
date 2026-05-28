"""
CVE mapper — queries the NVD API v2 and enriches each vulnerability with
official CVE metadata (CVSS, CWE, description).
"""
from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import requests


NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Known CVE table for components present in MediConnect — avoids unnecessary
# API hits for well-known associations already documented in the report.
_KNOWN_CVES: Dict[str, List[str]] = {
    "Mirth Connect 4.4.0": ["CVE-2023-43208"],
    "PHP Laravel 8.x": ["CVE-2021-21236", "CVE-2022-31279"],
    "MySQL 5.7": ["CVE-2021-2154", "CVE-2021-2180"],
    "wkhtmltopdf 0.12.5": ["CVE-2022-35583"],
    "Redis 6.0": ["CVE-2022-0543"],
    "Nginx 1.18": ["CVE-2021-23017"],
}


class CVEMapper:
    def __init__(self, config: Dict[str, Any]):
        nvd_cfg = config.get("nvd", {})
        self.api_key: Optional[str] = nvd_cfg.get("api_key") or None
        self.min_cvss: float = nvd_cfg.get("min_cvss_score", 7.0)
        self.max_results: int = nvd_cfg.get("max_results_per_query", 5)
        self.delay: float = nvd_cfg.get("request_delay", 0.7)
        self.session = requests.Session()
        if self.api_key:
            self.session.headers["apiKey"] = self.api_key

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def enrich_report(self, vulnerabilities: List[Dict]) -> List[Dict]:
        enriched = []
        for vuln in vulnerabilities:
            cve_id = vuln.get("cve_id")
            component = vuln.get("component", "")

            cve_details: Optional[Dict] = None

            if cve_id:
                cve_details = self._get_cve_details(cve_id)
                time.sleep(self.delay)

            # If no direct CVE match but component is known, try keyword search
            if not cve_details:
                cves = self._find_known_cves(component)
                if cves:
                    cve_details = self._get_cve_details(cves[0])
                    if not vuln.get("cve_id"):
                        vuln["cve_id"] = cves[0]
                    time.sleep(self.delay)

            if cve_details:
                vuln["nvd_data"] = cve_details
                # Override CVSS if NVD provides one
                nvd_cvss = cve_details.get("cvss_score")
                if nvd_cvss:
                    vuln["cvss_score"] = nvd_cvss
                # Increase confidence since NVD confirmed the CVE
                vuln["confidence_score"] = min(1.0, vuln.get("confidence_score", 0.7) + 0.15)
                vuln["nvd_confirmed"] = True
            else:
                vuln["nvd_data"] = None
                vuln["nvd_confirmed"] = False

            enriched.append(vuln)

        return enriched

    def map_component_table(self) -> List[Dict]:
        """Return the reference CVE table for known MediConnect components."""
        rows = []
        for component, cve_list in _KNOWN_CVES.items():
            for cve_id in cve_list:
                details = self._get_cve_details(cve_id)
                time.sleep(self.delay)
                rows.append({
                    "component": component,
                    "cve_id": cve_id,
                    "cvss_score": details.get("cvss_score") if details else "N/A",
                    "cvss_vector": details.get("cvss_vector") if details else "N/A",
                    "cwe": details.get("cwe") if details else "N/A",
                    "description": (details.get("description") or "")[:200] if details else "",
                })
        return rows

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_cve_details(self, cve_id: str) -> Optional[Dict]:
        try:
            resp = self.session.get(
                NVD_BASE,
                params={"cveId": cve_id},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
            items = data.get("vulnerabilities", [])
            if not items:
                return None
            return self._extract_fields(items[0]["cve"])
        except Exception:
            return None

    def _find_known_cves(self, component: str) -> List[str]:
        component_lower = component.lower()
        for key, cves in _KNOWN_CVES.items():
            if any(part in component_lower for part in key.lower().split()):
                return cves
        return []

    def search_by_keyword(self, keyword: str) -> List[Dict]:
        try:
            params: Dict[str, Any] = {
                "keywordSearch": keyword,
                "resultsPerPage": self.max_results,
                "cvssV3Severity": "CRITICAL",
            }
            resp = self.session.get(NVD_BASE, params=params, timeout=15)
            resp.raise_for_status()
            vulns = resp.json().get("vulnerabilities", [])
            results = []
            for item in vulns:
                fields = self._extract_fields(item["cve"])
                if fields.get("cvss_score", 0) >= self.min_cvss:
                    results.append(fields)
            return results
        except Exception:
            return []

    @staticmethod
    def _extract_fields(cve_item: Dict) -> Dict:
        cve_id = cve_item.get("id", "")
        descriptions = cve_item.get("descriptions", [])
        desc_en = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")

        # CVSS v3
        metrics = cve_item.get("metrics", {})
        cvss_score = None
        cvss_vector = None
        for key in ("cvssMetricV31", "cvssMetricV30"):
            entries = metrics.get(key, [])
            if entries:
                cv = entries[0].get("cvssData", {})
                cvss_score = cv.get("baseScore")
                cvss_vector = cv.get("vectorString")
                break

        # CWE
        weaknesses = cve_item.get("weaknesses", [])
        cwe = None
        for w in weaknesses:
            for d in w.get("description", []):
                if d.get("value", "").startswith("CWE-"):
                    cwe = d["value"]
                    break
            if cwe:
                break

        return {
            "cve_id": cve_id,
            "description": desc_en,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "cwe": cwe,
            "published": cve_item.get("published", ""),
        }
