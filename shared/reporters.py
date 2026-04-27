"""Reporters for shared findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from shared.findings import Finding, Severity
from shared.scoring import RiskScorer


class JSONReporter:
    """Write findings and risk score to JSON."""

    def write(self, findings: list[Finding], output_path: str | Path) -> None:
        scorer = RiskScorer(findings)
        payload: dict[str, Any] = {
            "risk_score": scorer.score(),
            "summary": scorer.score_breakdown(),
            "findings": [finding.to_dict() for finding in findings],
        }
        Path(output_path).write_text(json.dumps(payload, indent=2), encoding="utf-8")


class HTMLReporter:
    """Render findings and risk score to a dark-themed HTML report."""

    def __init__(self, template_dir: str | Path | None = None) -> None:
        default_dir = Path(__file__).parent / "templates"
        self.template_dir = Path(template_dir) if template_dir else default_dir
        self.environment = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )

    def write(self, findings: list[Finding], output_path: str | Path) -> None:
        scorer = RiskScorer(findings)
        template = self.environment.get_template("report.html.j2")
        html = template.render(
            findings=findings,
            risk_score=scorer.score(),
            summary=scorer.score_breakdown(),
            total_findings=len(findings),
        )
        Path(output_path).write_text(html, encoding="utf-8")


class CLIReporter:
    """Print findings and risk score to the terminal."""

    _SEVERITY_STYLES: dict[Severity, str] = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "orange1",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "blue",
        Severity.INFO: "dim",
    }

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def print(self, findings: list[Finding]) -> None:
        scorer = RiskScorer(findings)
        summary = scorer.score_breakdown()
        summary_text = "\n".join(f"{severity}: {count}" for severity, count in summary.items())
        self.console.print(
            Panel(
                f"Risk score: {scorer.score()}\nTotal findings: {len(findings)}\n{summary_text}",
                title="Cloud Security Suite Summary",
            )
        )

        table = Table(title="Findings")
        table.add_column("Severity")
        table.add_column("Tool")
        table.add_column("Check")
        table.add_column("Resource")
        table.add_column("Region")
        table.add_column("Title")

        for finding in findings:
            table.add_row(
                f"[{self._SEVERITY_STYLES[finding.severity]}]{finding.severity.name}[/]",
                finding.tool,
                finding.check_id,
                finding.resource,
                finding.region or "-",
                finding.title,
            )

        self.console.print(table)
