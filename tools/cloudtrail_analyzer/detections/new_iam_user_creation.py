from __future__ import annotations

from collections.abc import Iterable

from shared.findings import Finding, Severity
from tools.cloudtrail_analyzer.base import BaseDetection
from tools.cloudtrail_analyzer.utils import account_id, principal, region


class NewIamUserCreationDetection(BaseDetection):
    detection_id = "CT-008"
    title = "New IAM user created"
    severity = Severity.MEDIUM
    description = "Tracks IAM user creation events with creator and resulting user."

    def analyze(self, events: Iterable[dict]) -> list[Finding]:
        findings = []
        for event in events:
            if event.get("eventName") != "CreateUser":
                continue
            creator = principal(event)
            created_user = event.get("requestParameters", {}).get("userName", "unknown")
            findings.append(
                Finding(
                    tool="cloudtrail-analyzer",
                    check_id=self.detection_id,
                    severity=self.severity,
                    resource=f"iam-user:{created_user}",
                    region=region(event),
                    account_id=account_id(event),
                    title=self.title,
                    description=f"{creator} created IAM user {created_user}.",
                    remediation=(
                        "Verify the user has an owner, ticket, least-privilege permissions, "
                        "and MFA if console access is added."
                    ),
                    metadata={"creator": creator, "created_user": created_user},
                )
            )
        return findings
