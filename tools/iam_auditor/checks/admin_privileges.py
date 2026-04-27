"""Direct administrator privilege checks."""

from __future__ import annotations

from botocore.client import BaseClient

from shared.findings import Finding, Severity
from tools.iam_auditor.base import BaseCheck
from tools.iam_auditor.checks.policy_utils import allows_full_admin


class AdminPrivilegesCheck(BaseCheck):
    check_id = "IAM-007"
    title = "Users do not have direct administrator policies"
    severity = Severity.HIGH
    description = "Detects users directly attached to AdministratorAccess or equivalent policies."
    remediation = (
        "Remove direct administrator policies from IAM users. Grant administrative access through "
        "reviewed group membership, IAM Identity Center, or assumed roles with approval controls."
    )

    def run(self, iam_client: BaseClient, account_id: str) -> list[Finding]:
        findings: list[Finding] = []
        for page in iam_client.get_paginator("list_users").paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                policies = self._direct_admin_policies(iam_client, username)
                if not policies:
                    continue
                findings.append(
                    Finding(
                        tool="iam-auditor",
                        check_id=self.check_id,
                        severity=self.severity,
                        resource=f"arn:aws:iam::{account_id}:user/{username}",
                        region=None,
                        account_id=account_id,
                        title="IAM user has direct administrator privileges",
                        description=(
                            f"IAM user {username} has direct admin policies: {', '.join(policies)}."
                        ),
                        remediation=self.remediation,
                        references=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#use-groups-for-permissions"
                        ],
                        metadata={"username": username, "admin_policies": policies},
                    )
                )
        return findings

    def _direct_admin_policies(self, iam_client: BaseClient, username: str) -> list[str]:
        policies: list[str] = []
        for policy in iam_client.list_attached_user_policies(UserName=username).get(
            "AttachedPolicies", []
        ):
            if policy["PolicyName"] == "AdministratorAccess":
                policies.append(policy["PolicyName"])
                continue
            document = self._managed_policy_document(iam_client, policy["PolicyArn"])
            if allows_full_admin(document):
                policies.append(policy["PolicyName"])
        for policy_name in iam_client.list_user_policies(UserName=username).get("PolicyNames", []):
            document = iam_client.get_user_policy(UserName=username, PolicyName=policy_name)[
                "PolicyDocument"
            ]
            if allows_full_admin(document):
                policies.append(policy_name)
        return policies

    def _managed_policy_document(
        self, iam_client: BaseClient, policy_arn: str
    ) -> dict[str, object]:
        policy = iam_client.get_policy(PolicyArn=policy_arn)["Policy"]
        return iam_client.get_policy_version(
            PolicyArn=policy_arn,
            VersionId=policy["DefaultVersionId"],
        )["PolicyVersion"]["Document"]
