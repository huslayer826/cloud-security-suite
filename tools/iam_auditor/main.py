"""CLI entry point for the IAM Auditor."""

from __future__ import annotations

import argparse
import logging
import time
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from botocore.exceptions import BotoCoreError, ClientError
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from shared.aws_client import get_account_id, get_client
from shared.findings import Finding, Severity
from shared.reporters import CLIReporter, HTMLReporter, JSONReporter
from shared.scoring import RiskScorer
from tools.iam_auditor.base import BaseCheck
from tools.iam_auditor.checks import CHECK_REGISTRY

LOGGER = logging.getLogger(__name__)
VERSION = "0.5.0"
CONSOLE = Console()

SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the Cloud Security Suite IAM Auditor.")
    parser.add_argument("--profile", help="AWS profile name to use.")
    parser.add_argument(
        "--region",
        default="us-east-1",
        help="AWS region for client configuration.",
    )
    parser.add_argument(
        "--output",
        choices=["json", "html", "cli", "all"],
        default="cli",
        help="Report output format.",
    )
    parser.add_argument(
        "--output-dir",
        default="./reports",
        help="Directory for JSON and HTML reports.",
    )
    parser.add_argument(
        "--severity-threshold",
        choices=[severity.name for severity in Severity],
        help="Filter out findings below this severity.",
    )
    parser.add_argument(
        "--list-checks",
        action="store_true",
        help="List available IAM Auditor checks and exit.",
    )
    parser.add_argument(
        "--check",
        action="append",
        dest="check_ids",
        help="Run only the specified check ID. Can be provided multiple times.",
    )
    return parser.parse_args(argv)


def filter_by_threshold(findings: list[Finding], threshold: str | None) -> list[Finding]:
    if threshold is None:
        return findings

    threshold_severity = Severity[threshold]
    threshold_rank = SEVERITY_ORDER[threshold_severity]
    return [finding for finding in findings if SEVERITY_ORDER[finding.severity] >= threshold_rank]


def selected_checks(check_ids: list[str] | None) -> list[BaseCheck]:
    if not check_ids:
        return CHECK_REGISTRY

    requested = {check_id.upper() for check_id in check_ids}
    checks = [check for check in CHECK_REGISTRY if check.check_id in requested]
    missing = requested - {check.check_id for check in checks}
    if missing:
        raise ValueError(f"Unknown check ID(s): {', '.join(sorted(missing))}")
    return checks


def list_checks() -> None:
    table = Table(title="IAM Auditor Checks")
    table.add_column("Check ID", style="bold cyan")
    table.add_column("Severity")
    table.add_column("Title")
    table.add_column("Description")

    for check in CHECK_REGISTRY:
        table.add_row(
            check.check_id,
            check.severity.name,
            check.title,
            check.description,
        )

    CONSOLE.print(table)


def print_startup_banner(account_id: str, region: str) -> None:
    CONSOLE.print(
        Panel(
            f"[bold]Cloud Security Suite IAM Auditor[/bold]\n"
            f"Version: {VERSION}\n"
            f"Account: {account_id}\n"
            f"Region: {region}",
            title="Starting Scan",
            border_style="blue",
        )
    )


def run_audit(
    profile: str | None,
    region: str,
    check_ids: list[str] | None = None,
) -> tuple[list[Finding], str, float]:
    iam_client = get_client("iam", region=region, profile=profile)
    account_id = get_account_id(profile=profile)
    findings: list[Finding] = []
    checks = selected_checks(check_ids)
    started_at = time.perf_counter()

    print_startup_banner(account_id, region)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=CONSOLE,
    ) as progress:
        task_id = progress.add_task("Running IAM checks", total=len(checks))
        for check in checks:
            progress.update(task_id, description=f"Running {check.check_id} {check.title}")
            try:
                findings.extend(check.run(iam_client, account_id))
            except Exception:
                LOGGER.exception("Check %s failed; continuing", check.check_id)
            progress.advance(task_id)

    return findings, account_id, round(time.perf_counter() - started_at, 2)


def write_reports(
    findings: list[Finding],
    output: str,
    output_dir: str,
    metadata: dict[str, object] | None = None,
) -> None:
    output_path = Path(output_dir)

    if output in {"json", "html", "all"}:
        output_path.mkdir(parents=True, exist_ok=True)

    if output in {"json", "all"}:
        JSONReporter().write(findings, output_path / "iam-auditor-report.json", metadata=metadata)

    if output in {"html", "all"}:
        HTMLReporter().write(findings, output_path / "iam-auditor-report.html", metadata=metadata)

    if output in {"cli", "all"}:
        CLIReporter().print(findings)


def has_high_or_critical(findings: list[Finding]) -> bool:
    return any(finding.severity in {Severity.HIGH, Severity.CRITICAL} for finding in findings)


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    args = parse_args(argv)

    if args.list_checks:
        list_checks()
        return 0

    try:
        selected_checks(args.check_ids)
        findings, account_id, scan_duration = run_audit(
            profile=args.profile,
            region=args.region,
            check_ids=args.check_ids,
        )
    except ValueError as error:
        CONSOLE.print(f"[bold red]{error}[/bold red]")
        return 2
    except (BotoCoreError, ClientError) as error:
        CONSOLE.print(
            Panel(
                f"Unable to start IAM audit: {error}\n\n"
                "Check AWS credentials, profile, and IAM read permissions, then retry.",
                title="AWS Connection Error",
                border_style="red",
            )
        )
        return 2

    filtered_findings = filter_by_threshold(findings, args.severity_threshold)
    risk_score = RiskScorer(filtered_findings).score()
    LOGGER.info("Collected %s findings with risk score %s", len(filtered_findings), risk_score)

    scan_timestamp = datetime.now(UTC).isoformat()
    metadata = {
        "report_title": "Cloud Security Suite IAM Auditor Report",
        "account_id": account_id,
        "region": args.region,
        "scan_timestamp": scan_timestamp,
        "generated_at": scan_timestamp,
        "scan_duration_seconds": scan_duration,
        "version": VERSION,
    }

    write_reports(filtered_findings, args.output, args.output_dir, metadata=metadata)
    return 1 if has_high_or_critical(filtered_findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
