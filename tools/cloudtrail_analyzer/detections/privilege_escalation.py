from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta

from shared.findings import Finding, Severity
from tools.cloudtrail_analyzer.base import BaseDetection
from tools.cloudtrail_analyzer.utils import account_id, parse_event_time, principal, region


class PrivilegeEscalationDetection(BaseDetection):
    detection_id = "CT-004"
    title = "Possible privilege escalation sequence"
    severity = Severity.HIGH
    description = (
        "Detects CreateUser followed by AdministratorAccess attachment by a non-admin actor."
    )

    def analyze(self, events: Iterable[dict]) -> list[Finding]:
        ordered = sorted(events, key=parse_event_time)
        findings = []
        create_events = [event for event in ordered if event.get("eventName") == "CreateUser"]
        for create_event in create_events:
            actor = principal(create_event)
            if "admin" in actor.lower():
                continue
            created_user = create_event.get("requestParameters", {}).get("userName")
            for event in ordered:
                if parse_event_time(event) < parse_event_time(create_event):
                    continue
                if parse_event_time(event) - parse_event_time(create_event) > timedelta(hours=1):
                    continue
                if event.get("eventName") != "AttachUserPolicy":
                    continue
                params = event.get("requestParameters", {})
                if params.get("userName") != created_user:
                    continue
                if "AdministratorAccess" not in params.get("policyArn", ""):
                    continue
                findings.append(
                    Finding(
                        tool="cloudtrail-analyzer",
                        check_id=self.detection_id,
                        severity=self.severity,
                        resource=f"iam-user:{created_user}",
                        region=region(event),
                        account_id=account_id(event),
                        title=self.title,
                        description=(
                            f"{actor} created {created_user} and attached "
                            "AdministratorAccess within 1 hour."
                        ),
                        remediation=(
                            "Review the actor, remove unexpected admin access, and inspect "
                            "surrounding IAM activity."
                        ),
                        metadata={"actor": actor, "created_user": created_user},
                    )
                )
                break
        return findings
