"""CLI entry point for CloudTrail Analyzer."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

from shared.reporters import CLIReporter, HTMLReporter, JSONReporter
from shared.scoring import RiskScorer
from tools.cloudtrail_analyzer.detections import detection_registry
from tools.cloudtrail_analyzer.event_loader import load_from_athena, load_from_files
from tools.cloudtrail_analyzer.utils import parse_event_time


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Analyze CloudTrail events for suspicious activity."
    )
    parser.add_argument("--mode", choices=["local", "athena"], default="local")
    parser.add_argument(
        "--input-dir", help="Directory containing CloudTrail .json or .json.gz files."
    )
    parser.add_argument("--athena-database", help="Athena database for CloudTrail query mode.")
    parser.add_argument("--athena-workgroup", default="primary", help="Athena workgroup.")
    parser.add_argument("--athena-output-location", help="S3 output location for Athena results.")
    parser.add_argument("--start-time", help="Inclusive ISO timestamp filter.")
    parser.add_argument("--end-time", help="Exclusive ISO timestamp filter.")
    parser.add_argument(
        "--known-countries-file", help="State file for known console login countries."
    )
    parser.add_argument("--profile", help="Reserved for future AWS profile selection.")
    parser.add_argument("--region", default="us-east-1", help="AWS region metadata for reports.")
    parser.add_argument(
        "--output",
        choices=["json", "html", "cli", "all"],
        default="cli",
        help="Report output format.",
    )
    parser.add_argument(
        "--output-dir", default="./reports", help="Directory for JSON and HTML reports."
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    events = list(filter_events(load_events(args), args.start_time, args.end_time))
    findings = []
    for detection in detection_registry(args.known_countries_file):
        findings.extend(detection.analyze(events))

    metadata = {
        "report_title": "Cloud Security Suite CloudTrail Analyzer Report",
        "account_id": "from-events",
        "region": args.region,
        "scan_timestamp": datetime.now(UTC).isoformat(),
        "generated_at": datetime.now(UTC).isoformat(),
        "scan_duration_seconds": 0,
        "event_count": len(events),
    }
    write_reports(findings, args.output, args.output_dir, metadata)
    return 1 if findings else 0


def load_events(args: argparse.Namespace):
    if args.mode == "local":
        if not args.input_dir:
            raise SystemExit("--input-dir is required for local mode")
        return load_from_files(args.input_dir)

    missing = [
        name for name in ["athena_database", "athena_output_location"] if not getattr(args, name)
    ]
    if missing:
        raise SystemExit(f"Missing Athena arguments: {', '.join(missing)}")
    query = build_athena_query(args.start_time, args.end_time)
    return load_from_athena(
        query=query,
        workgroup=args.athena_workgroup,
        database=args.athena_database,
        output_location=args.athena_output_location,
    )


def filter_events(events, start_time: str | None, end_time: str | None):
    start = datetime.fromisoformat(start_time.replace("Z", "+00:00")) if start_time else None
    end = datetime.fromisoformat(end_time.replace("Z", "+00:00")) if end_time else None
    for event in events:
        event_time = parse_event_time(event)
        if start and event_time < start:
            continue
        if end and event_time >= end:
            continue
        yield event


def build_athena_query(start_time: str | None, end_time: str | None) -> str:
    filters = []
    if start_time:
        filters.append(f"eventtime >= '{start_time}'")
    if end_time:
        filters.append(f"eventtime < '{end_time}'")
    where = f"WHERE {' AND '.join(filters)}" if filters else ""
    return f"SELECT * FROM cloudtrail_logs {where}"  # nosec B608


def write_reports(findings, output: str, output_dir: str, metadata: dict[str, object]) -> None:
    output_path = Path(output_dir)
    if output in {"json", "html", "all"}:
        output_path.mkdir(parents=True, exist_ok=True)
    if output in {"json", "all"}:
        JSONReporter().write(findings, output_path / "cloudtrail-analyzer-report.json", metadata)
    if output in {"html", "all"}:
        HTMLReporter().write(findings, output_path / "cloudtrail-analyzer-report.html", metadata)
    if output in {"cli", "all"}:
        CLIReporter().print(findings)
    RiskScorer(findings).score()


if __name__ == "__main__":
    raise SystemExit(main())
