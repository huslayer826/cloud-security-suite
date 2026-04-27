"""Unused IAM role checks."""

from __future__ import annotations

from datetime import UTC, datetime

from botocore.client import BaseClient

from shared.findings import Finding, Severity
from tools.iam_auditor.base import BaseCheck


class UnusedRolesCheck(BaseCheck):
    check_id = "IAM-010"
    title = "IAM roles are used or removed"
    severity = Severity.MEDIUM
    description = "Detects IAM roles that were never used or unused for more than 90 days."
    remediation = (
        "Review unused roles with application owners, detach permissions, and delete roles that "
        "are "
        "no longer needed."
    )

    def run(self, iam_client: BaseClient, account_id: str) -> list[Finding]:
        findings: list[Finding] = []
        for page in iam_client.get_paginator("list_roles").paginate():
            for role in page.get("Roles", []):
                role_last_used = role.get("RoleLastUsed", {}).get("LastUsedDate")
                if isinstance(role_last_used, datetime) and self._age_days(role_last_used) <= 90:
                    continue
                reason = "never_used" if not role_last_used else "unused_over_90_days"
                findings.append(
                    Finding(
                        tool="iam-auditor",
                        check_id=self.check_id,
                        severity=self.severity,
                        resource=role["Arn"],
                        region=None,
                        account_id=account_id,
                        title="IAM role appears unused",
                        description=f"IAM role {role['RoleName']} is {reason}.",
                        remediation=self.remediation,
                        references=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_manage_delete.html"
                        ],
                        metadata={"role_name": role["RoleName"], "reason": reason},
                    )
                )
        return findings

    def _age_days(self, value: datetime) -> int:
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return (datetime.now(UTC) - value).days
