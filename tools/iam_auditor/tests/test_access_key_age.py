from datetime import UTC, datetime, timedelta

from moto import mock_aws

from shared.aws_client import get_client
from shared.findings import Severity
from tools.iam_auditor.checks.access_key_age import AccessKeyAgeCheck


@mock_aws
def test_access_key_age_check_ignores_recent_keys() -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_user(UserName="alice")
    iam_client.create_access_key(UserName="alice")

    assert AccessKeyAgeCheck().run(iam_client, "123456789012") == []


@mock_aws
def test_access_key_age_check_reports_old_keys(monkeypatch) -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_user(UserName="alice")
    access_key = iam_client.create_access_key(UserName="alice")["AccessKey"]
    old_date = datetime.now(UTC) - timedelta(days=91)

    def list_access_keys(UserName: str) -> dict[str, list[dict[str, object]]]:  # noqa: N803
        return {
            "AccessKeyMetadata": [
                {
                    "UserName": UserName,
                    "AccessKeyId": access_key["AccessKeyId"],
                    "Status": "Active",
                    "CreateDate": old_date,
                }
            ]
        }

    monkeypatch.setattr(iam_client, "list_access_keys", list_access_keys)

    findings = AccessKeyAgeCheck().run(iam_client, "123456789012")

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].resource == f"alice/access-key-****{access_key['AccessKeyId'][-4:]}"
    assert access_key["AccessKeyId"] not in findings[0].resource


def test_access_key_age_severity_bands() -> None:
    check = AccessKeyAgeCheck()

    assert check._severity_for_age(datetime.now(UTC) - timedelta(days=91)) == Severity.HIGH
    assert check._severity_for_age(datetime.now(UTC) - timedelta(days=60)) == Severity.MEDIUM
    assert check._severity_for_age(datetime.now(UTC) - timedelta(days=30)) == Severity.INFO
    assert check._severity_for_age(datetime.now(UTC) - timedelta(days=29)) is None
