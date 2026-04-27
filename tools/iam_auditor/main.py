"""CLI entry point for the IAM Auditor."""

from __future__ import annotations

import argparse
import logging
from collections.abc import Sequence
from pathlib import Path

from shared.aws_client import get_account_id, get_client
from shared.findings import Finding, Severity
from shared.reporters import CLIReporter, HTMLReporter, JSONReporter
from shared.scoring import RiskScorer
from tools.iam_auditor.checks import CHECK_REGISTRY

LOGGER = logging.getLogger(__name__)

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
    return parser.parse_args(argv)


def filter_by_threshold(findings: list[Finding], threshold: str | None) -> list[Finding]:
    if threshold is None:
        return findings

    threshold_severity = Severity[threshold]
    threshold_rank = SEVERITY_ORDER[threshold_severity]
    return [
        finding
        for finding in findings
        if SEVERITY_ORDER[finding.severity] >= threshold_rank
    ]


def run_audit(profile: str | None, region: str) -> list[Finding]:
    iam_client = get_client("iam", region=region, profile=profile)
    account_id = get_account_id(profile=profile)
    findings: list[Finding] = []

    for check in CHECK_REGISTRY:
        try:
            findings.extend(check.run(iam_client, account_id))
        except Exception:
            LOGGER.exception("Check %s failed; continuing", check.check_id)

    return findings


def write_reports(findings: list[Finding], output: str, output_dir: str) -> None:
    output_path = Path(output_dir)

    if output in {"json", "html", "all"}:
        output_path.mkdir(parents=True, exist_ok=True)

    if output in {"json", "all"}:
        JSONReporter().write(findings, output_path / "iam-auditor-report.json")

    if output in {"html", "all"}:
        HTMLReporter().write(findings, output_path / "iam-auditor-report.html")

    if output in {"cli", "all"}:
        CLIReporter().print(findings)


def has_high_or_critical(findings: list[Finding]) -> bool:
    return any(finding.severity in {Severity.HIGH, Severity.CRITICAL} for finding in findings)


def main(argv: Sequence[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
    args = parse_args(argv)

    findings = run_audit(profile=args.profile, region=args.region)
    filtered_findings = filter_by_threshold(findings, args.severity_threshold)
    risk_score = RiskScorer(filtered_findings).score()
    LOGGER.info("Collected %s findings with risk score %s", len(filtered_findings), risk_score)

    write_reports(filtered_findings, args.output, args.output_dir)
    return 1 if has_high_or_critical(filtered_findings) else 0


if __name__ == "__main__":
    raise SystemExit(main())
