"""Root account MFA check."""

from __future__ import annotations

from botocore.client import BaseClient

from shared.findings import Finding, Severity
from tools.iam_auditor.base import BaseCheck


class RootMFACheck(BaseCheck):
    """Detect whether root account MFA is disabled."""

    check_id = "IAM-001"
    title = "Root account MFA is enabled"
    severity = Severity.CRITICAL
    description = "Checks whether MFA is enabled for the AWS account root user."
    remediation = (
        "Enable a hardware MFA device for the AWS account root user. Follow the AWS docs: "
        "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html"
    )

    def run(self, iam_client: BaseClient, account_id: str) -> list[Finding]:
        summary = iam_client.get_account_summary()
        mfa_enabled = summary.get("SummaryMap", {}).get("AccountMFAEnabled", 0)

        if mfa_enabled:
            return []

        return [
            Finding(
                tool="iam-auditor",
                check_id=self.check_id,
                severity=self.severity,
                resource=f"arn:aws:iam::{account_id}:root",
                region=None,
                account_id=account_id,
                title="Root account MFA is disabled",
                description="The AWS account root user does not have MFA enabled.",
                remediation=self.remediation,
                references=[
                    "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa_enable_physical.html"
                ],
                metadata={"account_mfa_enabled": mfa_enabled},
            )
        ]
