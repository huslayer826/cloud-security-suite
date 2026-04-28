from shared.findings import Severity
from tools.guardduty_processor.lambda_handler import (
    build_finding,
    lambda_handler,
    map_guardduty_severity,
)
from tools.guardduty_processor.tests.conftest import load_fixture


def test_severity_mapping() -> None:
    assert map_guardduty_severity(2.0) == Severity.LOW
    assert map_guardduty_severity(4.0) == Severity.MEDIUM
    assert map_guardduty_severity(7.0) == Severity.HIGH
    assert map_guardduty_severity(8.7) == Severity.CRITICAL


def test_build_finding_from_guardduty_event() -> None:
    event = load_fixture("iam_exfiltration.json")

    finding = build_finding(event["detail"])

    assert finding.tool == "guardduty-processor"
    assert (
        finding.check_id
        == "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS"
    )
    assert finding.severity == Severity.HIGH
    assert finding.resource == "iam-user:alice/access-key-****MPLE"


def test_full_handler_end_to_end_for_each_fixture(monkeypatch) -> None:
    monkeypatch.setattr(
        "tools.guardduty_processor.lambda_handler.enrich_finding",
        lambda finding, detail: finding,
    )
    monkeypatch.setattr(
        "tools.guardduty_processor.lambda_handler.remediate",
        lambda detail, finding: [],
    )
    monkeypatch.setattr(
        "tools.guardduty_processor.lambda_handler.notify",
        lambda finding, detail, remediation_findings: {"sns": "skipped", "slack": "skipped"},
    )

    for fixture_name in [
        "ec2_port_probe.json",
        "iam_exfiltration.json",
        "s3_anomaly.json",
        "critical_finding.json",
        "low_finding.json",
    ]:
        response = lambda_handler(load_fixture(fixture_name), None)
        assert response["status"] == "processed"
        assert response["finding_id"]
        assert response["resource"]


def test_critical_and_low_fixture_severities() -> None:
    critical = build_finding(load_fixture("critical_finding.json")["detail"])
    assert critical.severity == Severity.CRITICAL
    assert build_finding(load_fixture("low_finding.json")["detail"]).severity == Severity.LOW
