"""AWS Lambda entry point for GuardDuty finding processing."""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any

from shared.findings import Finding, Severity
from tools.guardduty_processor.enrichment import enrich_finding
from tools.guardduty_processor.notifier import notify
from tools.guardduty_processor.remediation import remediate

LOGGER = logging.getLogger(__name__)
LOGGER.setLevel(logging.INFO)


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Process a GuardDuty EventBridge event."""
    detail = event["detail"]
    finding = build_finding(detail)
    enriched_finding = enrich_finding(finding, detail)
    remediation_findings = remediate(detail, enriched_finding)
    notification_result = notify(enriched_finding, detail, remediation_findings)

    response = {
        "status": "processed",
        "aws_request_id": getattr(context, "aws_request_id", None),
        "finding_id": detail.get("id"),
        "finding_type": detail.get("type"),
        "severity": enriched_finding.severity.name,
        "resource": enriched_finding.resource,
        "enriched": bool(enriched_finding.metadata.get("enrichment")),
        "remediation_actions": [item.to_dict() for item in remediation_findings],
        "notification": notification_result,
    }
    LOGGER.info("GuardDuty finding processed: %s", response)
    return response


def build_finding(detail: dict[str, Any]) -> Finding:
    """Convert GuardDuty finding detail into a shared Finding."""
    severity = map_guardduty_severity(float(detail.get("severity", 0)))
    account_id = detail.get("accountId")
    region = detail.get("region")
    finding_type = detail.get("type", "Unknown")
    resource = resource_identifier(detail)

    return Finding(
        tool="guardduty-processor",
        check_id=finding_type,
        severity=severity,
        resource=resource,
        region=region,
        account_id=account_id,
        title=detail.get("title", finding_type),
        description=detail.get("description", "GuardDuty finding received."),
        remediation="Review the finding, validate impact, and follow the mapped response playbook.",
        references=[
            "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html"
        ],
        metadata={
            "guardduty_id": detail.get("id"),
            "guardduty_severity": detail.get("severity"),
            "finding_type": finding_type,
            "service": detail.get("service", {}),
            "raw_resource": detail.get("resource", {}),
            "received_at": datetime.now(UTC).isoformat(),
            "auto_remediate": os.getenv("AUTO_REMEDIATE", "false").lower() == "true",
            "dry_run": os.getenv("DRY_RUN", "true").lower() == "true",
        },
    )


def map_guardduty_severity(severity: float) -> Severity:
    """Map GuardDuty numeric severity to Cloud Security Suite severity."""
    if severity >= 8.5:
        return Severity.CRITICAL
    if severity >= 7.0:
        return Severity.HIGH
    if severity >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def resource_identifier(detail: dict[str, Any]) -> str:
    """Extract a useful resource identifier from GuardDuty detail."""
    resource = detail.get("resource", {})
    resource_type = resource.get("resourceType", "unknown")

    if "instanceDetails" in resource:
        instance_id = resource["instanceDetails"].get("instanceId", "unknown-instance")
        return f"ec2:{instance_id}"
    if "accessKeyDetails" in resource:
        access_key = resource["accessKeyDetails"].get("accessKeyId", "unknown-key")
        user_name = resource["accessKeyDetails"].get("userName", "unknown-user")
        return f"iam-user:{user_name}/access-key-****{access_key[-4:]}"
    if "s3BucketDetails" in resource:
        buckets = resource.get("s3BucketDetails", [])
        if buckets:
            return f"s3:{buckets[0].get('name', 'unknown-bucket')}"
    return str(resource.get("resourceType", resource_type))
