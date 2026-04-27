"""Inactive IAM user checks."""

from __future__ import annotations

from datetime import UTC, datetime

from botocore.client import BaseClient

from shared.findings import Finding, Severity
from tools.iam_auditor.base import BaseCheck
from tools.iam_auditor.checks.policy_utils import allows_full_admin


class InactiveUsersCheck(BaseCheck):
    check_id = "IAM-004"
    title = "IAM users are active and reviewed"
    severity = Severity.MEDIUM
    description = "Detects IAM users with stale console or access key activity."
    remediation = (
        "Disable or remove unused IAM users after ownership review. Prefer federation or IAM "
        "Identity "
        "Center for human access, and remove direct administrative policies from inactive users."
    )

    def run(self, iam_client: BaseClient, account_id: str) -> list[Finding]:
        findings: list[Finding] = []
        for page in iam_client.get_paginator("list_users").paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                reasons = self._inactive_reasons(iam_client, username, user)
                if not reasons:
                    continue
                has_admin = self._has_admin_privileges(iam_client, username)
                findings.append(
                    Finding(
                        tool="iam-auditor",
                        check_id=self.check_id,
                        severity=Severity.HIGH if has_admin else self.severity,
                        resource=f"arn:aws:iam::{account_id}:user/{username}",
                        region=None,
                        account_id=account_id,
                        title="IAM user appears inactive",
                        description=(
                            f"IAM user {username} has stale activity: {', '.join(reasons)}."
                        ),
                        remediation=self.remediation,
                        references=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_manage.html"
                        ],
                        metadata={"username": username, "reasons": reasons, "has_admin": has_admin},
                    )
                )
        return findings

    def _inactive_reasons(
        self, iam_client: BaseClient, username: str, user: dict[str, object]
    ) -> list[str]:
        reasons: list[str] = []
        password_last_used = user.get("PasswordLastUsed")
        if isinstance(password_last_used, datetime) and self._age_days(password_last_used) > 90:
            reasons.append("password_last_used_over_90_days")

        for key in iam_client.list_access_keys(UserName=username).get("AccessKeyMetadata", []):
            key_id = key["AccessKeyId"]
            last_used = iam_client.get_access_key_last_used(AccessKeyId=key_id).get(
                "AccessKeyLastUsed", {}
            )
            last_used_date = last_used.get("LastUsedDate")
            if not isinstance(last_used_date, datetime) or self._age_days(last_used_date) > 90:
                reasons.append(f"access_key_****{key_id[-4:]}_unused_over_90_days")
        return reasons

    def _has_admin_privileges(self, iam_client: BaseClient, username: str) -> bool:
        for policy in iam_client.list_attached_user_policies(UserName=username).get(
            "AttachedPolicies", []
        ):
            if policy.get("PolicyName") == "AdministratorAccess":
                return True
            policy_document = self._managed_policy_document(iam_client, policy["PolicyArn"])
            if allows_full_admin(policy_document):
                return True
        for policy_name in iam_client.list_user_policies(UserName=username).get("PolicyNames", []):
            document = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)[
                "PolicyDocument"
            ]
            if allows_full_admin(document):
                return True
        return False

    def _managed_policy_document(
        self, iam_client: BaseClient, policy_arn: str
    ) -> dict[str, object]:
        policy = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]
        version = iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=policy["DefaultVersionId"],
        )
        return version["PolicyVersion"]["Document"]

    def _age_days(self, value: datetime) -> int:
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return (datetime.now(UTC) - value).days
