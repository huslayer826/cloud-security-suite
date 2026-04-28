from __future__ import annotations

from collections.abc import Iterable

from shared.findings import Finding, Severity
from tools.cloudtrail_analyzer.base import BaseDetection
from tools.cloudtrail_analyzer.utils import account_id, event_uid, principal, region


class RootAccountUsageDetection(BaseDetection):
    detection_id = "CT-001"
    title = "Root account usage"
    severity = Severity.CRITICAL
    description = "Detects CloudTrail events performed by the AWS account root user."

    def analyze(self, events: Iterable[dict]) -> list[Finding]:
        findings = []
        for event in events:
            if event.get("userIdentity", {}).get("type") != "Root":
                continue
            findings.append(
                Finding(
                    tool="cloudtrail-analyzer",
                    check_id=self.detection_id,
                    severity=self.severity,
                    resource=principal(event),
                    region=region(event),
                    account_id=account_id(event),
                    title=self.title,
                    description="The AWS root account was used for a CloudTrail-recorded action.",
                    remediation=(
                        "Avoid root account use except for tasks that require it. Review "
                        "the event and rotate root credentials if unexpected."
                    ),
                    metadata={"event_id": event_uid(event), "event_name": event.get("eventName")},
                )
            )
        return findings
