from tools.guardduty_processor.lambda_handler import build_finding
from tools.guardduty_processor.notifier import format_message, notify
from tools.guardduty_processor.tests.conftest import load_fixture


def test_format_message_is_scannable() -> None:
    event = load_fixture("iam_exfiltration.json")
    finding = build_finding(event["detail"])

    message = format_message(finding, event["detail"], [])

    assert "Severity: HIGH" in message
    assert "Finding type:" in message
    assert "AWS console:" in message
    assert "Remediation action: None" in message


def test_notify_skips_when_no_destinations(monkeypatch) -> None:
    monkeypatch.delenv("SNS_TOPIC_ARN", raising=False)
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    event = load_fixture("low_finding.json")
    finding = build_finding(event["detail"])

    assert notify(finding, event["detail"], []) == {"sns": "skipped", "slack": "skipped"}
