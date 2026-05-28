"""
vuln_ai — Entry point.

Usage:
    python -m vuln_ai.main [--arch PATH] [--config PATH] [--skip-cve] [--skip-scenarios] [--demo]
"""
from __future__ import annotations

import argparse
import json
import sys
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
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as p:
        t = p.add_task(label, total=None)
        result = fn()
        p.remove_task(t)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="VulnAI -- LLM-driven vulnerability analysis pipeline")
    parser.add_argument("--arch", default=str(_DEFAULT_ARCH), help="Path to architecture description file")
    parser.add_argument("--config", default=str(_DEFAULT_CONFIG), help="Path to config.yaml")
    parser.add_argument("--skip-cve", action="store_true", help="Skip NVD CVE enrichment (faster)")
    parser.add_argument("--skip-scenarios", action="store_true", help="Skip attack scenario generation")
    parser.add_argument("--demo", action="store_true", help="Use pre-crafted demo data (no LLM / API key required)")
    args = parser.parse_args()

    config = load_config(Path(args.config))
    arch_text = Path(args.arch).read_text(encoding="utf-8")

    console.print(Panel(
        "[bold cyan]VulnAI -- Automated Security Analysis[/bold cyan]\n"
        f"[dim]Architecture: {args.arch}[/dim]"
        + (" [yellow](DEMO MODE)[/yellow]" if args.demo else ""),
        expand=False,
    ))

    # ── Step 1: Parse architecture ──────────────────────────────────────
    arch = _run_with_progress("Parsing architecture...", lambda: ArchitectureParser().parse(arch_text))
    console.print(f"[green]OK[/green] Architecture: [bold]{arch.name}[/bold] "
                  f"-- {len(arch.components)} components -- topology: {arch.network_topology}")

    # ── Step 2: LLM vulnerability analysis ─────────────────────────────
    if args.demo:
        from vuln_ai.demo_data import DEMO_LLM_REPORT
        llm_report = DEMO_LLM_REPORT
        console.print("[yellow]DEMO[/yellow] Using pre-crafted vulnerability data (no LLM call)")
    else:
        llm_report = _run_with_progress(
            "Analysing vulnerabilities via LLM...",
            lambda: LLMAnalyzer(config).analyze(arch),
        )

    vulns = llm_report.get("vulnerabilities", [])
    risk_score = llm_report.get("risk_score", 0)
    summary = llm_report.get("summary", "")
    filtered = llm_report.get("filtered_count", 0)

    console.print(f"[green]OK[/green] {len(vulns)} vulnerabilities identified "
                  f"(risk score [bold red]{risk_score}[/bold red]/100, {filtered} filtered as low-confidence)")
    _print_vuln_table(vulns)

    # ── Step 3: CVE enrichment ──────────────────────────────────────────
    cve_table: list = []
    if args.skip_cve or args.demo:
        if args.demo:
            console.print("[yellow]DEMO[/yellow] Skipping NVD enrichment in demo mode")
    else:
        def _do_cve():
            mapper = CVEMapper(config)
            enriched = mapper.enrich_report(vulns)
            table = mapper.map_component_table()
            return enriched, table

        vulns_enriched, cve_table = _run_with_progress("Enriching vulnerabilities via NVD API...", _do_cve)
        vulns = vulns_enriched
        confirmed = sum(1 for v in vulns if v.get("nvd_confirmed"))
        console.print(f"[green]OK[/green] CVE enrichment done -- {confirmed}/{len(vulns)} confirmed by NVD")

    # ── Step 4: Attack scenarios ────────────────────────────────────────
    scenarios: dict = {"scenarios": []}
    if args.demo:
        from vuln_ai.demo_data import DEMO_SCENARIOS
        scenarios = DEMO_SCENARIOS
        console.print("[yellow]DEMO[/yellow] Using pre-crafted MITRE ATT&CK scenarios")
    elif not args.skip_scenarios:
        scenarios = _run_with_progress(
            "Generating attack scenarios (MITRE ATT&CK)...",
            lambda: AttackScenarioGenerator(config).generate(vulns, arch),
        )
        console.print(f"[green]OK[/green] Generated {len(scenarios.get('scenarios', []))} attack scenarios")

    # ── Step 5: Mitigations ─────────────────────────────────────────────
    if args.demo:
        from vuln_ai.demo_data import DEMO_MITIGATIONS
        mitigations = DEMO_MITIGATIONS
        console.print("[yellow]DEMO[/yellow] Using pre-crafted mitigations")
    else:
        mitigations = _run_with_progress(
            "Generating mitigations...",
            lambda: MitigationGenerator(config).generate(vulns),
        )
        console.print(f"[green]OK[/green] Generated {len(mitigations.get('mitigations', []))} mitigations")

    # ── Step 6: Build reports ───────────────────────────────────────────
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
        title="[bold]Reports saved[/bold]",
        expand=False,
    ))


def _print_vuln_table(vulns: list) -> None:
    table = Table(show_header=True, header_style="bold cyan", box=None, pad_edge=False)
    table.add_column("ID", style="dim", width=10)
    table.add_column("Severity", width=10)
    table.add_column("Component", width=30)
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
