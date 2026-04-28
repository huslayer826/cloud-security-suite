from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import timedelta

from shared.findings import Finding, Severity
from tools.cloudtrail_analyzer.base import BaseDetection
from tools.cloudtrail_analyzer.utils import account_id, parse_event_time, principal, region


class MassResourceDeletionDetection(BaseDetection):
    detection_id = "CT-005"
    title = "Mass resource deletion"
    severity = Severity.HIGH
    description = "Detects more than 20 delete-style API calls by one principal within 5 minutes."

    def analyze(self, events: Iterable[dict]) -> list[Finding]:
        grouped = defaultdict(list)
        for event in events:
            name = event.get("eventName", "")
            if name.startswith(("Delete", "Terminate")) or name in {"StopLogging", "DeleteTrail"}:
                grouped[principal(event)].append(event)
        findings = []
        for actor, actor_events in grouped.items():
            ordered = sorted(actor_events, key=parse_event_time)
            for index, event in enumerate(ordered):
                window = [
                    item
                    for item in ordered[index:]
                    if parse_event_time(item) - parse_event_time(event) <= timedelta(minutes=5)
                ]
                if len(window) > 20:
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
                                f"{actor} made {len(window)} delete-style API calls "
                                "within 5 minutes."
                            ),
                            remediation=(
                                "Pause destructive automation if possible, verify intent, "
                                "and review affected resources from CloudTrail."
                            ),
                            metadata={"principal": actor, "delete_count": len(window)},
                        )
                    )
                    break
        return findings
