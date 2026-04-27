"""Customer-managed wildcard policy checks."""

from __future__ import annotations

from botocore.client import BaseClient

from shared.findings import Finding, Severity
from tools.iam_auditor.base import BaseCheck
from tools.iam_auditor.checks.policy_utils import allows_full_admin


class WildcardPoliciesCheck(BaseCheck):
    check_id = "IAM-006"
    title = "Customer-managed policies avoid full wildcard access"
    severity = Severity.CRITICAL
    description = "Detects customer-managed policies allowing all actions on all resources."
    remediation = (
        "Replace wildcard customer-managed policies with least-privilege statements scoped to "
        "required services, actions, resources, and conditions."
    )

    def run(self, iam_client: BaseClient, account_id: str) -> list[Finding]:
        findings: list[Finding] = []
        for page in iam_client.get_paginator("list_policies").paginate(Scope="Local"):
            for policy in page.get("Policies", []):
                document = self._policy_document(
                    iam_client, policy["Arn"], policy["DefaultVersionId"]
                )
                if not allows_full_admin(document):
                    continue
                entities = iam_client.list_entities_for_policy(PolicyArn=policy["Arn"])
                findings.append(
                    Finding(
                        tool="iam-auditor",
                        check_id=self.check_id,
                        severity=self.severity,
                        resource=policy["Arn"],
                        region=None,
                        account_id=account_id,
                        title="Customer-managed policy allows wildcard administrator access",
                        description=(
                            f"Policy {policy['PolicyName']} allows all actions on all resources."
                        ),
                        remediation=self.remediation,
                        references=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
                        ],
                        metadata={
                            "policy_name": policy["PolicyName"],
                            "attached_users": [
                                item["UserName"] for item in entities.get("PolicyUsers", [])
                            ],
                            "attached_groups": [
                                item["GroupName"] for item in entities.get("PolicyGroups", [])
                            ],
                            "attached_roles": [
                                item["RoleName"] for item in entities.get("PolicyRoles", [])
                            ],
                        },
                    )
                )
        return findings

    def _policy_document(
        self,
        iam_client: BaseClient,
        policy_arn: str,
        version_id: str,
    ) -> dict[str, object]:
        return iam_client.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)[
            "PolicyVersion"
        ]["Document"]
