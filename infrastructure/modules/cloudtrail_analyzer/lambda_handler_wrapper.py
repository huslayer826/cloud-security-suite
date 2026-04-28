"""Lambda wrapper for the scheduled CloudTrail Analyzer."""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import boto3

from shared.findings import Severity
from shared.scoring import RiskScorer
from tools.cloudtrail_analyzer.detections import detection_registry
from tools.cloudtrail_analyzer.event_loader import load_from_athena
from tools.cloudtrail_analyzer.main import write_reports

s3_client = boto3.client("s3")
sns_client = boto3.client("sns")


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    end_time = datetime.now(UTC)
    start_time = end_time - timedelta(days=int(os.getenv("LOOKBACK_DAYS", "1")))
    database = os.environ["ATHENA_DATABASE"]
    workgroup = os.environ["ATHENA_WORKGROUP"]
    output_location = os.environ["ATHENA_OUTPUT_LOCATION"]
    report_bucket = os.environ["REPORT_BUCKET"]
    topic_arn = os.environ["SNS_TOPIC_ARN"]
    region = os.environ.get("AWS_REGION", "us-east-1")

    query = (
        "SELECT * FROM cloudtrail_logs "
        f"WHERE eventtime >= '{start_time.isoformat().replace('+00:00', 'Z')}' "
        f"AND eventtime < '{end_time.isoformat().replace('+00:00', 'Z')}'"
    )
    events = list(load_from_athena(query, workgroup, database, output_location))
    findings = []
    for detection in detection_registry():
        findings.extend(detection.analyze(events))

    scan_timestamp = datetime.now(UTC).isoformat()
    metadata = {
        "report_title": "Cloud Security Suite CloudTrail Analyzer Report",
        "account_id": "from-cloudtrail",
        "region": region,
        "scan_timestamp": scan_timestamp,
        "generated_at": scan_timestamp,
        "scan_duration_seconds": 0,
        "event_count": len(events),
        "trigger": event.get("source", "manual"),
    }

    output_dir = Path("/tmp/cloudtrail-analyzer")
    output_dir.mkdir(parents=True, exist_ok=True)
    write_reports(findings, "all", str(output_dir), metadata)

    key_prefix = f"reports/cloudtrail-analyzer/{end_time:%Y/%m/%d/%H%M%S}"
    json_key = f"{key_prefix}/cloudtrail-analyzer-report.json"
    html_key = f"{key_prefix}/cloudtrail-analyzer-report.html"
    _upload_report(
        report_bucket,
        json_key,
        output_dir / "cloudtrail-analyzer-report.json",
        "application/json",
    )
    _upload_report(
        report_bucket,
        html_key,
        output_dir / "cloudtrail-analyzer-report.html",
        "text/html",
    )

    scorer = RiskScorer(findings)
    high_findings = [
        item for item in findings if item.severity in {Severity.HIGH, Severity.CRITICAL}
    ]
    if high_findings:
        sns_client.publish(
            TopicArn=topic_arn,
            Subject="Cloud Security Suite CloudTrail Analyzer alert",
            Message=(
                f"CloudTrail Analyzer found {len(high_findings)} HIGH/CRITICAL findings.\n"
                f"Risk score: {scorer.score()}\n"
                f"HTML report: s3://{report_bucket}/{html_key}"
            ),
        )

    return {
        "event_count": len(events),
        "finding_count": len(findings),
        "risk_score": scorer.score(),
        "high_or_critical_count": len(high_findings),
        "reports": {
            "json": f"s3://{report_bucket}/{json_key}",
            "html": f"s3://{report_bucket}/{html_key}",
        },
    }


def _upload_report(bucket: str, key: str, path: Path, content_type: str) -> None:
    s3_client.upload_file(
        str(path),
        bucket,
        key,
        ExtraArgs={"ContentType": content_type, "ServerSideEncryption": "AES256"},
    )
