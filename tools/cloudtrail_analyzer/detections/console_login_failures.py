from __future__ import annotations

from collections import defaultdict
from collections.abc import Iterable
from datetime import timedelta

from shared.findings import Finding, Severity
from tools.cloudtrail_analyzer.base import BaseDetection
from tools.cloudtrail_analyzer.utils import account_id, parse_event_time, region, source_ip


class ConsoleLoginFailuresDetection(BaseDetection):
    detection_id = "CT-002"
    title = "Console login failure burst"
    severity = Severity.MEDIUM
    description = (
        "Detects more than five failed ConsoleLogin events from one source IP in 10 minutes."
    )

    def analyze(self, events: Iterable[dict]) -> list[Finding]:
        failures = defaultdict(list)
        for event in events:
            if event.get("eventName") != "ConsoleLogin":
                continue
            if event.get("responseElements", {}).get("ConsoleLogin") != "Failure":
                continue
            failures[source_ip(event)].append(event)

        findings = []
        for ip, ip_events in failures.items():
            ordered = sorted(ip_events, key=parse_event_time)
            for index, event in enumerate(ordered):
                window = [
                    item
                    for item in ordered[index:]
                    if parse_event_time(item) - parse_event_time(event) <= timedelta(minutes=10)
                ]
                if len(window) > 5:
                    findings.append(
                        Finding(
                            tool="cloudtrail-analyzer",
                            check_id=self.detection_id,
                            severity=self.severity,
                            resource=f"source-ip:{ip}",
                            region=region(event),
                            account_id=account_id(event),
                            title=self.title,
                            description=(
                                f"{len(window)} failed ConsoleLogin events from {ip} "
                                "within 10 minutes."
                            ),
                            remediation=(
                                "Investigate the source IP, verify targeted users, and "
                                "consider blocking or alerting on repeated failures."
                            ),
                            metadata={"source_ip": ip, "failure_count": len(window)},
                        )
                    )
                    break
        return findings
