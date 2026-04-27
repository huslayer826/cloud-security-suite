"""IAM access key age checks."""

from __future__ import annotations

from datetime import UTC, datetime

from botocore.client import BaseClient

from shared.findings import Finding, Severity
from tools.iam_auditor.base import BaseCheck


class AccessKeyAgeCheck(BaseCheck):
    """Detect IAM user access keys that should be reviewed or rotated."""

    check_id = "IAM-003"
    title = "IAM access keys are rotated regularly"
    severity = Severity.HIGH
    description = "Checks IAM user access keys for age-based rotation findings."
    remediation = (
        "Rotate old IAM user access keys, update dependent workloads, and deactivate then delete "
        "the old keys after validation."
    )

    def run(self, iam_client: BaseClient, account_id: str) -> list[Finding]:
        findings: list[Finding] = []
        paginator = iam_client.get_paginator("list_users")

        for page in paginator.paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                keys = iam_client.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
                for key in keys:
                    severity = self._severity_for_age(key["CreateDate"])
                    if severity is None:
                        continue
                    age_days = self._age_days(key["CreateDate"])
                    key_id = key["AccessKeyId"]
                    findings.append(
                        Finding(
                            tool="iam-auditor",
                            check_id=self.check_id,
                            severity=severity,
                            resource=f"{username}/access-key-****{key_id[-4:]}",
                            region=None,
                            account_id=account_id,
                            title="IAM access key should be reviewed for rotation",
                            description=(
                                f"IAM access key for user {username} is {age_days} days old."
                            ),
                            remediation=self.remediation,
                            references=[
                                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"
                            ],
                            metadata={
                                "username": username,
                                "key_id_suffix": key_id[-4:],
                                "age_days": age_days,
                                "status": key.get("Status"),
                            },
                        )
                    )

        return findings

    def _severity_for_age(self, created_at: datetime) -> Severity | None:
        age_days = self._age_days(created_at)
        if age_days > 90:
            return Severity.HIGH
        if age_days >= 60:
            return Severity.MEDIUM
        if age_days >= 30:
            return Severity.INFO
        return None

    def _age_days(self, created_at: datetime) -> int:
        now = datetime.now(UTC)
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=UTC)
        return (now - created_at).days
