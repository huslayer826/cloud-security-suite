"""Console user MFA checks."""

from __future__ import annotations

from botocore.client import BaseClient

from shared.findings import Finding, Severity
from tools.iam_auditor.base import BaseCheck


class MFAForConsoleUsersCheck(BaseCheck):
    check_id = "IAM-011"
    title = "Console users have MFA"
    severity = Severity.HIGH
    description = "Detects IAM users with console passwords but no MFA device."
    remediation = (
        "Require MFA for every IAM user with console access. Assign a virtual or hardware MFA "
        "device, "
        "or remove the login profile if console access is not required."
    )

    def run(self, iam_client: BaseClient, account_id: str) -> list[Finding]:
        findings: list[Finding] = []
        for page in iam_client.get_paginator("list_users").paginate():
            for user in page.get("Users", []):
                username = user["UserName"]
                if not self._has_login_profile(iam_client, username):
                    continue
                devices = iam_client.list_mfa_devices(UserName=username).get("MFADevices", [])
                if devices:
                    continue
                findings.append(
                    Finding(
                        tool="iam-auditor",
                        check_id=self.check_id,
                        severity=self.severity,
                        resource=f"arn:aws:iam::{account_id}:user/{username}",
                        region=None,
                        account_id=account_id,
                        title="Console user does not have MFA",
                        description=f"IAM user {username} has console access but no MFA device.",
                        remediation=self.remediation,
                        references=[
                            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable.html"
                        ],
                        metadata={"username": username},
                    )
                )
        return findings

    def _has_login_profile(self, iam_client: BaseClient, username: str) -> bool:
        try:
            iam_client.get_login_profile(UserName=username)
        except iam_client.exceptions.NoSuchEntityException:
            return False
        return True
