"""
vuln_ai -- point d'entree du pipeline.

    --arch PATH       chemin vers la description d'architecture (defaut : MediConnect)
    --config PATH     chemin vers config.yaml
    --skip-cve        passe l'enrichissement NVD
    --skip-scenarios  passe la generation de scenarios
    --demo            donnees pre-remplies, aucun appel LLM ni API
"""
from __future__ import annotations

import argparse
from pathlib import Path

import yaml
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from vuln_ai.analyzer.llm_analyzer import LLMAnalyzer
from vuln_ai.mapper.cve_mapper import CVEMapper
from vuln_ai.mitigations.mitigation_gen import MitigationGenerator
from vuln_ai.output.report_builder import ReportBuilder
from vuln_ai.parser.arch_parser import ArchitectureParser
from vuln_ai.scenarios.attack_gen import AttackScenarioGenerator


console = Console(highlight=False)

_DEFAULT_CONFIG = Path(__file__).parent.parent / "config.yaml"
_DEFAULT_ARCH = Path(__file__).parent.parent / "data" / "mediconnect_arch.txt"


def load_config(path: Path) -> dict:
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def _run_with_progress(label: str, fn):
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
                  console=console, transient=True) as p:
        t = p.add_task(label, total=None)
        result = fn()
        p.remove_task(t)
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description="VulnAI -- pipeline d'analyse de securite par LLM")
    ap.add_argument("--arch", default=str(_DEFAULT_ARCH), help="chemin vers la description d'architecture")
    ap.add_argument("--config", default=str(_DEFAULT_CONFIG), help="chemin vers config.yaml")
    ap.add_argument("--skip-cve", action="store_true", help="passer l'enrichissement NVD")
    ap.add_argument("--skip-scenarios", action="store_true", help="passer la generation de scenarios")
    ap.add_argument("--demo", action="store_true", help="donnees pre-remplies, aucun appel LLM ni API")
    args = ap.parse_args()

    config = load_config(Path(args.config))
    arch_text = Path(args.arch).read_text(encoding="utf-8")

    console.print(Panel(
        "[bold cyan]VulnAI -- Analyse de securite par LLM[/bold cyan]\n"
        f"[dim]Architecture: {args.arch}[/dim]"
        + (" [yellow](DEMO MODE)[/yellow]" if args.demo else ""),
        expand=False,
    ))

    arch = _run_with_progress("Lecture de l'architecture...", lambda: ArchitectureParser().parse(arch_text))
    console.print(f"[green]OK[/green] Architecture : [bold]{arch.name}[/bold] "
                  f"-- {len(arch.components)} composants -- reseau : {arch.network_topology}")

    if args.demo:
        from vuln_ai.demo_data import DEMO_LLM_REPORT
        llm_report = DEMO_LLM_REPORT
        console.print("[yellow]DEMO[/yellow] Donnees pre-remplies (pas d'appel LLM)")
    else:
        llm_report = _run_with_progress(
            "Analyse des vulnerabilites via LLM...",
            lambda: LLMAnalyzer(config).analyze(arch),
        )

    vulns = llm_report.get("vulnerabilities", [])
    risk_score = llm_report.get("risk_score", 0)
    summary = llm_report.get("summary", "")
    filtered = llm_report.get("filtered_count", 0)

    console.print(f"[green]OK[/green] {len(vulns)} vulnerabilites identifiees "
                  f"(score de risque [bold red]{risk_score}[/bold red]/100, {filtered} filtrees faible confiance)")
    _print_vuln_table(vulns)

    cve_table: list = []
    if args.demo:
        console.print("[yellow]DEMO[/yellow] Enrichissement NVD passe en mode demo")
    elif not args.skip_cve:
        def _do_cve():
            mapper = CVEMapper(config)
            return mapper.enrich_report(vulns), mapper.map_component_table()

        vulns, cve_table = _run_with_progress("Enrichissement CVE via l'API NVD...", _do_cve)
        confirmed = sum(1 for v in vulns if v.get("nvd_confirmed"))
        console.print(f"[green]OK[/green] {confirmed}/{len(vulns)} CVE confirmes par NVD")

    scenarios: dict = {"scenarios": []}
    if args.demo:
        from vuln_ai.demo_data import DEMO_SCENARIOS
        scenarios = DEMO_SCENARIOS
        console.print("[yellow]DEMO[/yellow] Scenarios MITRE ATT&CK pre-remplis")
    elif not args.skip_scenarios:
        scenarios = _run_with_progress(
            "Generation des scenarios d'attaque (MITRE ATT&CK)...",
            lambda: AttackScenarioGenerator(config).generate(vulns, arch),
        )
        console.print(f"[green]OK[/green] {len(scenarios.get('scenarios', []))} scenarios generes")

    if args.demo:
        from vuln_ai.demo_data import DEMO_MITIGATIONS
        mitigations = DEMO_MITIGATIONS
        console.print("[yellow]DEMO[/yellow] Mitigations pre-remplies")
    else:
        mitigations = _run_with_progress(
            "Generation des mitigations...",
            lambda: MitigationGenerator(config).generate(vulns),
        )
        console.print(f"[green]OK[/green] {len(mitigations.get('mitigations', []))} mitigations generees")

    report_paths = ReportBuilder(config).build(
        arch_name=arch.name,
        vulnerabilities=vulns,
        scenarios=scenarios,
        mitigations=mitigations,
        risk_score=risk_score,
        summary=summary,
        cve_table=cve_table,
    )

    console.print()
    console.print(Panel(
        "\n".join(f"[green]{fmt.upper()}[/green]  {path}" for fmt, path in report_paths.items()),
        title="[bold]Rapports generes[/bold]",
        expand=False,
    ))


def _print_vuln_table(vulns: list) -> None:
    table = Table(show_header=True, header_style="bold cyan", box=None, pad_edge=False)
    table.add_column("ID", style="dim", width=10)
    table.add_column("Severite", width=10)
    table.add_column("Composant", width=30)
    table.add_column("Type", width=16)
    table.add_column("CVE", width=18)
    table.add_column("CVSS", width=6)

    _sev_style = {"CRITICAL": "red bold", "HIGH": "yellow bold", "MEDIUM": "yellow", "LOW": "green"}

    for v in vulns:
        sev = v.get("severity", "?")
        table.add_row(
            v.get("id", ""),
            f"[{_sev_style.get(sev, 'white')}]{sev}[/{_sev_style.get(sev, 'white')}]",
            v.get("component", "")[:30],
            v.get("type", ""),
            v.get("cve_id") or "-",
            str(v.get("cvss_score") or "-"),
        )

    console.print(table)


if __name__ == "__main__":
    main()
