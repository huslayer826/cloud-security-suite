"""IAM role trust relationship checks."""

from __future__ import annotations

import re

from botocore.client import BaseClient

from shared.findings import Finding, Severity
from tools.iam_auditor.base import BaseCheck
from tools.iam_auditor.checks.policy_utils import (
    has_external_id_condition,
    principal_values,
    statements,
)

ACCOUNT_ID_PATTERN = re.compile(r"arn:aws:iam::(\d{12}):root|^(\d{12})$")


class RoleTrustRelationshipsCheck(BaseCheck):
    check_id = "IAM-009"
    title = "Role trust policies restrict principals"
    severity = Severity.CRITICAL
    description = "Detects public or external role trust without compensating conditions."
    remediation = (
        "Restrict role trust policies to known principals and require sts:ExternalId for "
        "third-party "
        "or external-account access. Avoid wildcard principals without strong conditions."
    )

    def run(self, iam_client: BaseClient, account_id: str) -> list[Finding]:
        findings: list[Finding] = []
        for page in iam_client.get_paginator("list_roles").paginate():
            for role in page.get("Roles", []):
                findings.extend(self._find_role_issues(role, account_id))
        return findings

    def _find_role_issues(self, role: dict[str, object], account_id: str) -> list[Finding]:
        findings: list[Finding] = []
        trust_policy = role.get("AssumeRolePolicyDocument", {})
        for statement in statements(trust_policy):
            if statement.get("Effect") != "Allow":
                continue
            principals = list(principal_values(statement.get("Principal")))
            has_condition = "Condition" in statement
            if "*" in principals and not has_condition:
                findings.append(
                    self._finding(
                        role,
                        account_id,
                        Severity.CRITICAL,
                        "IAM role trust policy allows wildcard principals",
                        (
                            "The role trust policy allows any principal to assume the role without "
                            "conditions."
                        ),
                        {"principals": principals},
                    )
                )
                continue

            external_accounts = [
                external_account
                for principal in principals
                if (external_account := self._external_account_id(principal, account_id))
                is not None
            ]
            if external_accounts and not has_external_id_condition(statement):
                findings.append(
                    self._finding(
                        role,
                        account_id,
                        Severity.HIGH,
                        "IAM role trusts external accounts without ExternalId",
                        (
                            "The role trust policy allows an external AWS account without "
                            "sts:ExternalId."
                        ),
                        {"external_accounts": external_accounts},
                    )
                )
        return findings

    def _external_account_id(self, principal: str, account_id: str) -> str | None:
        match = ACCOUNT_ID_PATTERN.match(principal)
        if not match:
            return None
        trusted_account = match.group(1) or match.group(2)
        return trusted_account if trusted_account != account_id else None

    def _finding(
        self,
        role: dict[str, object],
        account_id: str,
        severity: Severity,
        title: str,
        description: str,
        metadata: dict[str, object],
    ) -> Finding:
        return Finding(
            tool="iam-auditor",
            check_id=self.check_id,
            severity=severity,
            resource=str(role["Arn"]),
            region=None,
            account_id=account_id,
            title=title,
            description=description,
            remediation=self.remediation,
            references=[
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_update-role-trust-policy.html"
            ],
            metadata={"role_name": role["RoleName"], **metadata},
        )
