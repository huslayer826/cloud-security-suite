"""IAM account password policy checks."""

from __future__ import annotations

from botocore.client import BaseClient

from shared.findings import Finding, Severity
from tools.iam_auditor.base import BaseCheck


class PasswordPolicyCheck(BaseCheck):
    """Detect weak or missing IAM password policy settings."""

    check_id = "IAM-002"
    title = "IAM password policy meets baseline"
    severity = Severity.HIGH
    description = "Checks account password policy strength and rotation controls."
    remediation = (
        "Configure an IAM account password policy with at least 14 characters, uppercase and "
        "symbol requirements, maximum age of 90 days or less, and reuse prevention of at least 5."
    )

    def run(self, iam_client: BaseClient, account_id: str) -> list[Finding]:
        try:
            policy = iam_client.get_account_password_policy()["PasswordPolicy"]
        except iam_client.exceptions.NoSuchEntityException:
            return [
                self._finding(
                    severity=Severity.HIGH,
                    account_id=account_id,
                    title="No IAM password policy is configured",
                    description="The AWS account does not have an IAM password policy.",
                    metadata={"policy_exists": False},
                )
            ]

        findings: list[Finding] = []
        minimum_length = int(policy.get("MinimumPasswordLength", 0))
        max_age = policy.get("MaxPasswordAge")
        reuse_prevention = int(policy.get("PasswordReusePrevention", 0))

        if minimum_length < 14:
            findings.append(
                self._finding(
                    severity=Severity.MEDIUM,
                    account_id=account_id,
                    title="IAM password minimum length is below 14 characters",
                    description=f"The configured minimum password length is {minimum_length}.",
                    metadata={"minimum_password_length": minimum_length},
                )
            )

        if not policy.get("RequireUppercaseCharacters", False):
            findings.append(
                self._finding(
                    severity=Severity.LOW,
                    account_id=account_id,
                    title="IAM password policy does not require uppercase characters",
                    description=(
                        "The IAM password policy allows passwords without uppercase letters."
                    ),
                    metadata={"require_uppercase_characters": False},
                )
            )

        if not policy.get("RequireSymbols", False):
            findings.append(
                self._finding(
                    severity=Severity.LOW,
                    account_id=account_id,
                    title="IAM password policy does not require symbols",
                    description="The IAM password policy allows passwords without symbols.",
                    metadata={"require_symbols": False},
                )
            )

        if max_age is None or int(max_age) > 90:
            findings.append(
                self._finding(
                    severity=Severity.MEDIUM,
                    account_id=account_id,
                    title="IAM password maximum age is not set to 90 days or less",
                    description=(
                        "The IAM password policy has no maximum age or allows passwords older "
                        "than 90 days."
                    ),
                    metadata={"max_password_age": max_age},
                )
            )

        if reuse_prevention < 5:
            findings.append(
                self._finding(
                    severity=Severity.LOW,
                    account_id=account_id,
                    title="IAM password reuse prevention is below 5",
                    description=(
                        f"The configured password reuse prevention value is {reuse_prevention}."
                    ),
                    metadata={"password_reuse_prevention": reuse_prevention},
                )
            )

        return findings

    def _finding(
        self,
        *,
        severity: Severity,
        account_id: str,
        title: str,
        description: str,
        metadata: dict[str, object],
    ) -> Finding:
        return Finding(
            tool="iam-auditor",
            check_id=self.check_id,
            severity=severity,
            resource=f"arn:aws:iam::{account_id}:account-password-policy",
            region=None,
            account_id=account_id,
            title=title,
            description=description,
            remediation=self.remediation,
            references=[
                "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html"
            ],
            metadata=metadata,
        )
