from moto import mock_aws

from shared.aws_client import get_client
from shared.findings import Severity
from tools.iam_auditor.checks.root_mfa import RootMFACheck


@mock_aws
def test_root_mfa_check_returns_no_findings_when_enabled(monkeypatch) -> None:
    iam_client = get_client("iam", region="us-east-1")
    monkeypatch.setattr(
        iam_client,
        "get_account_summary",
        lambda: {"SummaryMap": {"AccountMFAEnabled": 1}},
    )

    assert RootMFACheck().run(iam_client, "123456789012") == []


@mock_aws
def test_root_mfa_check_reports_disabled_root_mfa() -> None:
    iam_client = get_client("iam", region="us-east-1")

    findings = RootMFACheck().run(iam_client, "123456789012")

    assert len(findings) == 1
    assert findings[0].check_id == "IAM-001"
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].resource == "arn:aws:iam::123456789012:root"
