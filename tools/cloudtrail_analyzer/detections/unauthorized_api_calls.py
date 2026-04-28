from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import timedelta

from shared.findings import Finding, Severity
from tools.cloudtrail_analyzer.base import BaseDetection
from tools.cloudtrail_analyzer.utils import account_id, parse_event_time, principal, region


class UnauthorizedApiCallsDetection(BaseDetection):
    detection_id = "CT-007"
    title = "AccessDenied API call burst"
    severity = Severity.MEDIUM
    description = "Detects high AccessDenied volume from one principal in a short window."

    def analyze(self, events: Iterable[dict]) -> list[Finding]:
        grouped = defaultdict(list)
        for event in events:
            if event.get("errorCode") == "AccessDenied":
                grouped[principal(event)].append(event)
        findings = []
        for actor, actor_events in grouped.items():
            ordered = sorted(actor_events, key=parse_event_time)
            for index, event in enumerate(ordered):
                window = [
                    item
                    for item in ordered[index:]
                    if parse_event_time(item) - parse_event_time(event) <= timedelta(minutes=10)
                ]
                if len(window) >= 10:
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
                                f"{actor} produced {len(window)} AccessDenied errors "
                                "within 10 minutes."
                            ),
                            remediation=(
                                "Review whether the principal is probing permissions or "
                                "has a broken application role."
                            ),
                            metadata={"principal": actor, "access_denied_count": len(window)},
                        )
                    )
                    break
        return findings
