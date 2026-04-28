from __future__ import annotations

from collections.abc import Iterable

from shared.findings import Finding, Severity
from tools.cloudtrail_analyzer.base import BaseDetection
from tools.cloudtrail_analyzer.utils import account_id, principal, region


class DisabledLoggingDetection(BaseDetection):
    detection_id = "CT-006"
    title = "Security logging disabled"
    severity = Severity.CRITICAL
    description = "Detects API calls that disable CloudTrail, S3 logging, or GuardDuty."

    def analyze(self, events: Iterable[dict]) -> list[Finding]:
        findings = []
        for event in events:
            name = event.get("eventName")
            source = event.get("eventSource")
            if not self._is_logging_disable_event(event):
                continue
            actor = principal(event)
            findings.append(
                Finding(
                    tool="cloudtrail-analyzer",
                    check_id=self.detection_id,
                    severity=self.severity,
                    resource=actor,
                    region=region(event),
                    account_id=account_id(event),
                    title=self.title,
                    description=(
                        f"{actor} called {source}:{name}, which can disable security "
                        "visibility."
                    ),
                    remediation=(
                        "Immediately verify logging status, restore disabled services, "
                        "and investigate the actor."
                    ),
                    metadata={"event_source": source, "event_name": name},
                )
            )
        return findings

    def _is_logging_disable_event(self, event: dict) -> bool:
        name = event.get("eventName")
        source = event.get("eventSource")
        if source == "cloudtrail.amazonaws.com" and name in {"StopLogging", "DeleteTrail"}:
            return True
        if source == "guardduty.amazonaws.com" and name == "DeleteDetector":
            return True
        if source == "s3.amazonaws.com" and name == "PutBucketLogging":
            logging_status = event.get("requestParameters", {}).get("BucketLoggingStatus")
            return logging_status in (None, {}, "")
        return False
