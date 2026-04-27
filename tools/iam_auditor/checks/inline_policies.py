"""Inline policy checks."""

from __future__ import annotations

from botocore.client import BaseClient

from shared.findings import Finding, Severity
from tools.iam_auditor.base import BaseCheck


class InlinePoliciesCheck(BaseCheck):
    check_id = "IAM-008"
    title = "Inline policies are avoided"
    severity = Severity.LOW
    description = "Detects IAM users and roles with inline policies."
    remediation = (
        "Move inline permissions into named customer-managed policies so they can be reviewed, "
        "versioned, reused, and monitored consistently."
    )

    def run(self, iam_client: BaseClient, account_id: str) -> list[Finding]:
        findings: list[Finding] = []
        for page in iam_client.get_paginator("list_users").paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                findings.extend(
                    self._find_inline_policies(
                        iam_client.list_user_policies(UserName=username).get("PolicyNames", []),
                        f"arn:aws:iam::{account_id}:user/{username}",
                        "user",
                        username,
                        account_id,
                    )
                )
        for page in iam_client.get_paginator("list_roles").paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                findings.extend(
                    self._find_inline_policies(
                        iam_client.list_role_policies(RoleName=role_name).get("PolicyNames", []),
                        role["Arn"],
                        "role",
                        role_name,
                        account_id,
                    )
                )
        return findings

    def _find_inline_policies(
        self,
        policy_names: list[str],
        resource: str,
        entity_type: str,
        entity_name: str,
        account_id: str,
    ) -> list[Finding]:
        return [
            Finding(
                tool="iam-auditor",
                check_id=self.check_id,
                severity=self.severity,
                resource=resource,
                region=None,
                account_id=account_id,
                title="IAM entity has inline policies",
                description=f"IAM {entity_type} {entity_name} has inline policy {policy_name}.",
                remediation=self.remediation,
                references=[
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-vs-inline.html"
                ],
                metadata={
                    "entity_type": entity_type,
                    "entity_name": entity_name,
                    "policy_name": policy_name,
                },
            )
            for policy_name in policy_names
        ]
