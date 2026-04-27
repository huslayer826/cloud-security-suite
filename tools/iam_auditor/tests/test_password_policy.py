from moto import mock_aws

from shared.aws_client import get_client
from shared.findings import Severity
from tools.iam_auditor.checks.password_policy import PasswordPolicyCheck


@mock_aws
def test_password_policy_check_returns_no_findings_for_strong_policy() -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireSymbols=True,
        RequireNumbers=True,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        AllowUsersToChangePassword=True,
        MaxPasswordAge=90,
        PasswordReusePrevention=5,
    )

    assert PasswordPolicyCheck().run(iam_client, "123456789012") == []


@mock_aws
def test_password_policy_check_reports_missing_policy() -> None:
    iam_client = get_client("iam", region="us-east-1")

    findings = PasswordPolicyCheck().run(iam_client, "123456789012")

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].title == "No IAM password policy is configured"


@mock_aws
def test_password_policy_check_reports_weak_policy_settings() -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.update_account_password_policy(
        MinimumPasswordLength=8,
        RequireSymbols=False,
        RequireNumbers=True,
        RequireUppercaseCharacters=False,
        RequireLowercaseCharacters=True,
        AllowUsersToChangePassword=True,
        MaxPasswordAge=120,
        PasswordReusePrevention=2,
    )

    findings = PasswordPolicyCheck().run(iam_client, "123456789012")

    assert [finding.severity for finding in findings] == [
        Severity.MEDIUM,
        Severity.LOW,
        Severity.LOW,
        Severity.MEDIUM,
        Severity.LOW,
    ]
    assert {finding.metadata.popitem()[0] for finding in findings} == {
        "minimum_password_length",
        "require_uppercase_characters",
        "require_symbols",
        "max_password_age",
        "password_reuse_prevention",
    }
