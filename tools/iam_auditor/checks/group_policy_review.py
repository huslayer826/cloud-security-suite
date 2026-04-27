"""IAM group policy review checks."""

from __future__ import annotations

from botocore.client import BaseClient

from shared.findings import Finding, Severity
from tools.iam_auditor.base import BaseCheck


class GroupPolicyReviewCheck(BaseCheck):
    check_id = "IAM-012"
    title = "Policy-bearing groups have members"
    severity = Severity.LOW
    description = "Detects empty IAM groups that still have attached permissions."
    remediation = (
        "Remove policies from empty groups or delete groups that are no longer part of the access "
        "model. Review group membership before reusing dormant groups."
    )

    def run(self, iam_client: BaseClient, account_id: str) -> list[Finding]:
        findings: list[Finding] = []
        for page in iam_client.get_paginator("list_groups").paginate():
            for group in page.get("Groups", []):
                group_name = group["GroupName"]
                users = iam_client.get_group(GroupName=group_name).get("Users", [])
                attached = iam_client.list_attached_group_policies(GroupName=group_name).get(
                    "AttachedPolicies", []
                )
                inline = iam_client.list_group_policies(GroupName=group_name).get("PolicyNames", [])
                if users or not (attached or inline):
                    continue
                findings.append(
                    Finding(
                        tool="iam-auditor",
                        check_id=self.check_id,
                        severity=self.severity,
                        resource=group["Arn"],
                        region=None,
                        account_id=account_id,
                        title="Empty IAM group has attached permissions",
                        description=f"IAM group {group_name} has policies but no members.",
                        remediation=self.remediation,
                        references=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_groups_manage.html"
                        ],
                        metadata={
                            "group_name": group_name,
                            "attached_policies": [item["PolicyName"] for item in attached],
                            "inline_policies": inline,
                        },
                    )
                )
        return findings
