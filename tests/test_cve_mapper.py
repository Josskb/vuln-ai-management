from vuln_ai.mapper.cve_mapper import CVEMapper


def test_map_component_table_uses_details(monkeypatch):
    config = {"nvd": {"request_delay": 0}}
    mapper = CVEMapper(config)

    def fake_get_cve_details(_cve_id: str):
        return {
            "cve_id": _cve_id,
            "description": "Test CVE",
            "cvss_score": 9.9,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N",
            "cwe": "CWE-999",
            "published": "2025-01-01T00:00:00Z",
        }

    monkeypatch.setattr(mapper, "_get_cve_details", fake_get_cve_details)
    rows = mapper.map_component_table()
    assert rows
    assert rows[0]["cvss_score"] == 9.9
    assert rows[0]["cwe"] == "CWE-999"


def test_enrich_report_sets_nvd_fields(monkeypatch):
    config = {"nvd": {"request_delay": 0}}
    mapper = CVEMapper(config)

    def fake_get_cve_details(_cve_id: str):
        return {
            "cve_id": _cve_id,
            "description": "Test CVE",
            "cvss_score": 7.7,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N",
            "cwe": "CWE-999",
            "published": "2025-01-01T00:00:00Z",
        }

    monkeypatch.setattr(mapper, "_get_cve_details", fake_get_cve_details)
    vulns = [{"id": "V-1", "component": "Redis 6.0", "cve_id": "CVE-2022-0543", "confidence_score": 0.6}]
    enriched = mapper.enrich_report(vulns)
    assert enriched[0]["nvd_confirmed"] is True
    assert enriched[0]["nvd_data"]["cvss_score"] == 7.7


def test_search_by_keyword_filters_min_cvss(monkeypatch):
    config = {"nvd": {"request_delay": 0, "min_cvss_score": 7.0}}
    mapper = CVEMapper(config)

    class FakeResp:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-TEST-1",
                            "descriptions": [{"lang": "en", "value": "Test"}],
                            "metrics": {
                                "cvssMetricV31": [
                                    {"cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.1/AV:N"}}
                                ]
                            },
                            "weaknesses": [],
                        }
                    }
                ]
            }

    def fake_get(*_args, **_kwargs):
        return FakeResp()

    monkeypatch.setattr(mapper.session, "get", fake_get)
    results = mapper.search_by_keyword("test")
    assert results
    assert results[0]["cvss_score"] == 7.5
