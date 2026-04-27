"""IAM access key rotation hygiene checks."""

from __future__ import annotations

from botocore.client import BaseClient

from shared.findings import Finding, Severity
from tools.iam_auditor.base import BaseCheck


class AccessKeyRotationPolicyCheck(BaseCheck):
    check_id = "IAM-013"
    title = "IAM users have at most one active access key"
    severity = Severity.MEDIUM
    description = "Detects IAM users with two active access keys."
    remediation = (
        "Complete key rotation by updating workloads to the new key, deactivating the old key, and "
        "deleting it after validation. Keep only one active key per IAM user."
    )

    def run(self, iam_client: BaseClient, account_id: str) -> list[Finding]:
        findings: list[Finding] = []
        for page in iam_client.get_paginator("list_users").paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                keys = iam_client.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
                active_keys = [key for key in keys if key.get("Status") == "Active"]
                if len(active_keys) < 2:
                    continue
                findings.append(
                    Finding(
                        tool="iam-auditor",
                        check_id=self.check_id,
                        severity=self.severity,
                        resource=f"arn:aws:iam::{account_id}:user/{username}",
                        region=None,
                        account_id=account_id,
                        title="IAM user has two active access keys",
                        description=(
                            f"IAM user {username} has {len(active_keys)} active access keys."
                        ),
                        remediation=self.remediation,
                        references=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html#Using_RotateAccessKey"
                        ],
                        metadata={
                            "username": username,
                            "active_key_suffixes": [key["AccessKeyId"][-4:] for key in active_keys],
                        },
                    )
                )
        return findings
