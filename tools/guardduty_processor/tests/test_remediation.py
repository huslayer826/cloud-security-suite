from shared.findings import Severity
from tools.guardduty_processor.lambda_handler import build_finding
from tools.guardduty_processor.remediation import remediate
from tools.guardduty_processor.tests.conftest import load_fixture


def test_remediation_respects_dry_run(monkeypatch) -> None:
    event = load_fixture("iam_exfiltration.json")
    finding = build_finding(event["detail"])
    monkeypatch.setenv("AUTO_REMEDIATE", "true")
    monkeypatch.setenv("DRY_RUN", "true")

    actions = remediate(event["detail"], finding)

    assert len(actions) == 1
    assert actions[0].severity == Severity.INFO
    assert actions[0].metadata["status"] == "dry_run"


def test_remediation_skips_unknown_type(monkeypatch) -> None:
    event = load_fixture("s3_anomaly.json")
    finding = build_finding(event["detail"])
    monkeypatch.setenv("AUTO_REMEDIATE", "true")
    monkeypatch.setenv("DRY_RUN", "true")

    assert remediate(event["detail"], finding) == []


def test_port_probe_dry_run_records_quarantine_action(monkeypatch) -> None:
    event = load_fixture("ec2_port_probe.json")
    finding = build_finding(event["detail"])
    monkeypatch.setenv("AUTO_REMEDIATE", "true")
    monkeypatch.setenv("DRY_RUN", "true")

    actions = remediate(event["detail"], finding)

    assert actions[0].metadata["status"] == "dry_run"
    assert "quarantine" in actions[0].title.lower()
