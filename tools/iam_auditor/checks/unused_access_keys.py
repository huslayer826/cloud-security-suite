"""Unused IAM access key checks."""

from __future__ import annotations

from datetime import UTC, datetime

from botocore.client import BaseClient

from shared.findings import Finding, Severity
from tools.iam_auditor.base import BaseCheck


class UnusedAccessKeysCheck(BaseCheck):
    check_id = "IAM-005"
    title = "IAM access keys are used or removed"
    severity = Severity.MEDIUM
    description = "Detects access keys that were never used or unused for 90 days or more."
    remediation = (
        "Deactivate and delete unused access keys after confirming they are not needed. Prefer "
        "temporary credentials through roles for workloads."
    )

    def run(self, iam_client: BaseClient, account_id: str) -> list[Finding]:
        findings: list[Finding] = []
        for page in iam_client.get_paginator("list_users").paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                for key in iam_client.list_access_keys(UserName=username).get(
                    "AccessKeyMetadata", []
                ):
                    key_id = key["AccessKeyId"]
                    last_used = iam_client.get_access_key_last_used(AccessKeyId=key_id).get(
                        "AccessKeyLastUsed", {}
                    )
                    last_used_date = last_used.get("LastUsedDate")
                    if isinstance(last_used_date, datetime) and self._age_days(last_used_date) < 90:
                        continue
                    reason = "never_used" if not last_used_date else "unused_90_days_or_more"
                    findings.append(
                        Finding(
                            tool="iam-auditor",
                            check_id=self.check_id,
                            severity=self.severity,
                            resource=f"{username}/access-key-****{key_id[-4:]}",
                            region=None,
                            account_id=account_id,
                            title="IAM access key is unused",
                            description=f"IAM access key for user {username} is {reason}.",
                            remediation=self.remediation,
                            references=[
                                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
                            ],
                            metadata={
                                "username": username,
                                "key_id_suffix": key_id[-4:],
                                "reason": reason,
                            },
                        )
                    )
        return findings

    def _age_days(self, value: datetime) -> int:
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return (datetime.now(UTC) - value).days
