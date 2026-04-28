"""AWS Lambda wrapper for the Cloud Security Suite IAM Auditor."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import boto3

from shared.findings import Severity
from shared.scoring import RiskScorer
from tools.iam_auditor.main import has_high_or_critical, run_audit, write_reports

s3_client = boto3.client("s3")
sns_client = boto3.client("sns")


def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    """Run the IAM Auditor, store reports in S3, and alert on high severity findings."""
    region = os.environ.get("AWS_REGION", "us-east-1")
    bucket = os.environ["REPORT_BUCKET"]
    topic_arn = os.environ["SNS_TOPIC_ARN"]

    scan_started = datetime.now(UTC)
    findings, account_id, scan_duration = run_audit(profile=None, region=region)
    scan_timestamp = scan_started.isoformat()

    metadata = {
        "report_title": "Cloud Security Suite IAM Auditor Report",
        "account_id": account_id,
        "region": region,
        "scan_timestamp": scan_timestamp,
        "generated_at": datetime.now(UTC).isoformat(),
        "scan_duration_seconds": scan_duration,
        "trigger": event.get("source", "manual"),
    }

    output_dir = Path("/tmp/iam-auditor")
    output_dir.mkdir(parents=True, exist_ok=True)
    write_reports(findings, "all", str(output_dir), metadata=metadata)

    key_prefix = f"reports/iam-auditor/{account_id}/{scan_started:%Y/%m/%d/%H%M%S}"
    json_key = f"{key_prefix}/iam-auditor-report.json"
    html_key = f"{key_prefix}/iam-auditor-report.html"

    _upload_report(bucket, json_key, output_dir / "iam-auditor-report.json", "application/json")
    _upload_report(bucket, html_key, output_dir / "iam-auditor-report.html", "text/html")

    scorer = RiskScorer(findings)
    summary = scorer.score_breakdown()
    high_or_critical = has_high_or_critical(findings)

    if high_or_critical:
        sns_client.publish(
            TopicArn=topic_arn,
            Subject="Cloud Security Suite IAM Auditor alert",
            Message=_alert_message(account_id, region, scorer.score(), summary, bucket, html_key),
        )

    return {
        "account_id": account_id,
        "region": region,
        "risk_score": scorer.score(),
        "summary": summary,
        "finding_count": len(findings),
        "high_or_critical": high_or_critical,
        "reports": {
            "json": f"s3://{bucket}/{json_key}",
            "html": f"s3://{bucket}/{html_key}",
        },
    }


def _upload_report(bucket: str, key: str, path: Path, content_type: str) -> None:
    s3_client.upload_file(
        str(path),
        bucket,
        key,
        ExtraArgs={
            "ContentType": content_type,
            "ServerSideEncryption": "AES256",
        },
    )


def _alert_message(
    account_id: str,
    region: str,
    risk_score: float,
    summary: dict[str, int],
    bucket: str,
    html_key: str,
) -> str:
    alert_summary = {}
    for severity in [
        Severity.CRITICAL,
        Severity.HIGH,
        Severity.MEDIUM,
        Severity.LOW,
        Severity.INFO,
    ]:
        alert_summary[severity.name] = summary.get(severity.name, 0)
    return json.dumps(
        {
            "message": "IAM Auditor found HIGH or CRITICAL findings.",
            "account_id": account_id,
            "region": region,
            "risk_score": risk_score,
            "summary": alert_summary,
            "html_report": f"s3://{bucket}/{html_key}",
        },
        indent=2,
    )
