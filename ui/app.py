from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

import sys

import streamlit as st
import yaml

# Ensure repo root is on sys.path when running via Streamlit
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from vuln_ai.analyzer.llm_analyzer import LLMAnalyzer
from vuln_ai.mapper.cve_mapper import CVEMapper
from vuln_ai.mitigations.mitigation_gen import MitigationGenerator
from vuln_ai.output.report_builder import ReportBuilder
from vuln_ai.parser.arch_parser import ArchitectureParser
from vuln_ai.scenarios.attack_gen import AttackScenarioGenerator


DEFAULT_CONFIG = REPO_ROOT / "config.yaml"
DEFAULT_ARCH = REPO_ROOT / "data" / "mediconnect_arch.txt"


def load_config(path: Path) -> Dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def run_pipeline(
    arch_text: str,
    config: Dict[str, Any],
    skip_cve: bool,
    skip_scenarios: bool,
    demo: bool,
) -> Dict[str, Any]:
    arch = ArchitectureParser().parse(arch_text)

    if demo:
        from vuln_ai.demo_data import DEMO_LLM_REPORT, DEMO_SCENARIOS, DEMO_MITIGATIONS
        llm_report = DEMO_LLM_REPORT
        scenarios = DEMO_SCENARIOS
        mitigations = DEMO_MITIGATIONS
        cve_table = []
    else:
        llm_report = LLMAnalyzer(config).analyze(arch)
        cve_table = []
        if not skip_cve:
            mapper = CVEMapper(config)
            vulns = llm_report.get("vulnerabilities", [])
            llm_report["vulnerabilities"] = mapper.enrich_report(vulns)
            cve_table = mapper.map_component_table()

        scenarios = {"scenarios": []}
        if not skip_scenarios:
            scenarios = AttackScenarioGenerator(config).generate(
                llm_report.get("vulnerabilities", []),
                arch,
            )

        mitigations = MitigationGenerator(config).generate(
            llm_report.get("vulnerabilities", []),
        )

    report_paths = ReportBuilder(config).build(
        arch_name=arch.name,
        vulnerabilities=llm_report.get("vulnerabilities", []),
        scenarios=scenarios,
        mitigations=mitigations,
        risk_score=llm_report.get("risk_score", 0),
        summary=llm_report.get("summary", ""),
        cve_table=cve_table,
    )

    return {
        "arch_name": arch.name,
        "report_paths": report_paths,
    }


st.set_page_config(page_title="VulnAI Management", page_icon="\U0001f6e1", layout="wide")

st.title("VulnAI Management")
st.caption("UI minimale pour lancer le pipeline et récupérer les rapports.")

with st.sidebar:
    st.header("Configuration")
    config_path = st.text_input("config.yaml", value=str(DEFAULT_CONFIG))
    demo = st.toggle("Mode demo (sans LLM/API)", value=False)
    skip_cve = st.toggle("Ignorer le mapping CVE (NVD)", value=False)
    skip_scenarios = st.toggle("Ignorer les scenarios", value=False)

st.subheader("Architecture")
arch_file = st.file_uploader("Fichier d'architecture (.txt)", type=["txt"])

if arch_file:
    arch_text = arch_file.read().decode("utf-8", errors="replace")
else:
    arch_text = DEFAULT_ARCH.read_text(encoding="utf-8")
    st.info("Aucun fichier fourni, utilisation de mediconnect_arch.txt.")

st.text_area("Contenu", value=arch_text, height=250)

col_run, col_open = st.columns([1, 2])

with col_run:
    if st.button("Lancer l'analyse", type="primary"):
        try:
            config = load_config(Path(config_path))
            result = run_pipeline(arch_text, config, skip_cve, skip_scenarios, demo)
            st.success("Rapports generes.")
            st.write(f"Architecture: {result['arch_name']}")

            report_paths = result["report_paths"]
            if "html" in report_paths:
                html_path = Path(report_paths["html"])
                st.download_button(
                    "Telecharger HTML",
                    data=html_path.read_bytes(),
                    file_name=html_path.name,
                    mime="text/html",
                )
                st.markdown(f"Ouvrir HTML: `{html_path}`")

            if "json" in report_paths:
                json_path = Path(report_paths["json"])
                st.download_button(
                    "Telecharger JSON",
                    data=json_path.read_bytes(),
                    file_name=json_path.name,
                    mime="application/json",
                )
                st.markdown(f"Ouvrir JSON: `{json_path}`")

        except Exception as exc:
            st.error(f"Erreur: {exc}")

with col_open:
    st.markdown("**Sorties**")
    st.markdown("Les rapports sont ecrits dans `output/` a chaque execution.")
