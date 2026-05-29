from pathlib import Path

from vuln_ai.output.report_builder import ReportBuilder


def test_report_builder_writes_files(tmp_path: Path):
    config = {
        "output": {
            "formats": ["json", "html"],
            "directory": str(tmp_path / "out"),
        }
    }
    builder = ReportBuilder(config)

    report_paths = builder.build(
        arch_name="TestArch",
        vulnerabilities=[
            {
                "id": "V-1",
                "component": "Redis 6.0",
                "type": "MiscConfig",
                "severity": "HIGH",
                "cve_id": "CVE-2022-0543",
                "cwe_id": "CWE-306",
                "cvss_score": 9.8,
                "description": "Redis test",
                "attack_vector": "redis-cli",
                "confidence_score": 0.9,
            }
        ],
        scenarios={"scenarios": []},
        mitigations={"mitigations": []},
        risk_score=42,
        summary="Summary",
        cve_table=[
            {
                "component": "Redis 6.0",
                "cve_id": "CVE-2022-0543",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/...",
                "cwe": "CWE-306",
                "description": "Redis CVE",
            }
        ],
    )

    html_path = Path(report_paths["html"])
    json_path = Path(report_paths["json"])
    assert html_path.exists()
    assert json_path.exists()

    html_text = html_path.read_text(encoding="utf-8")
    assert "CVE Mapping Table" in html_text
    assert "CVE-2022-0543" in html_text
