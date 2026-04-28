"""Notification helpers for GuardDuty Processor."""

from __future__ import annotations

import json
import logging
import os
from typing import Any
from urllib import request
from urllib.parse import urlparse

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from shared.findings import Finding

LOGGER = logging.getLogger(__name__)


def notify(
    finding: Finding,
    detail: dict[str, Any],
    remediation_findings: list[Finding],
) -> dict[str, Any]:
    """Publish a formatted notification to SNS and optional Slack webhook."""
    message = format_message(finding, detail, remediation_findings)
    result = {"sns": "skipped", "slack": "skipped"}

    topic_arn = os.getenv("SNS_TOPIC_ARN")
    if topic_arn:
        try:
            boto3.client("sns", region_name=finding.region).publish(
                TopicArn=topic_arn,
                Subject=f"GuardDuty {finding.severity.name}: {finding.check_id}",
                Message=message,
            )
            result["sns"] = "published"
        except (BotoCoreError, ClientError) as error:
            LOGGER.warning("Unable to publish SNS notification: %s", error)
            result["sns"] = "failed"

    webhook_url = os.getenv("SLACK_WEBHOOK_URL")
    if webhook_url:
        try:
            post_slack(webhook_url, finding, detail, remediation_findings)
            result["slack"] = "published"
        except (OSError, ValueError) as error:
            LOGGER.warning("Unable to publish Slack notification: %s", error)
            result["slack"] = "failed"

    return result


def format_message(
    finding: Finding,
    detail: dict[str, Any],
    remediation_findings: list[Finding],
) -> str:
    console_link = guardduty_console_link(detail)
    remediation_summary = "None"
    if remediation_findings:
        remediation_summary = "; ".join(item.description for item in remediation_findings)

    return "\n".join(
        [
            f"Severity: {finding.severity.name}",
            f"Finding type: {finding.check_id}",
            f"Resource: {finding.resource}",
            f"Description: {finding.description}",
            f"AWS console: {console_link}",
            f"Remediation action: {remediation_summary}",
        ]
    )


def post_slack(
    webhook_url: str,
    finding: Finding,
    detail: dict[str, Any],
    remediation_findings: list[Finding],
) -> None:
    parsed_url = urlparse(webhook_url)
    if parsed_url.scheme != "https":
        raise ValueError("Slack webhook URL must use HTTPS")

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"GuardDuty {finding.severity.name}: {finding.check_id}",
                },
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Resource:*\n{finding.resource}"},
                    {"type": "mrkdwn", "text": f"*Region:*\n{finding.region or 'unknown'}"},
                    {"type": "mrkdwn", "text": f"*Account:*\n{finding.account_id or 'unknown'}"},
                    {
                        "type": "mrkdwn",
                        "text": f"*Remediation:*\n{_slack_remediation(remediation_findings)}",
                    },
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": finding.description},
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "Open in AWS"},
                        "url": guardduty_console_link(detail),
                    }
                ],
            },
        ]
    }
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with request.urlopen(req, timeout=5) as response:  # nosec B310
        response.read()


def guardduty_console_link(detail: dict[str, Any]) -> str:
    region = detail.get("region", "us-east-1")
    finding_id = detail.get("id", "")
    return f"https://{region}.console.aws.amazon.com/guardduty/home?region={region}#/findings?search=id%3D{finding_id}"


def _slack_remediation(remediation_findings: list[Finding]) -> str:
    if not remediation_findings:
        return "No automated action"
    return "; ".join(item.metadata.get("status", "recorded") for item in remediation_findings)
