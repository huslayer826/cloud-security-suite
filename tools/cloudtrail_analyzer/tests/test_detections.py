from shared.findings import Severity
from tools.cloudtrail_analyzer.detections import detection_registry
from tools.cloudtrail_analyzer.event_loader import load_from_files
from tools.cloudtrail_analyzer.tests.conftest import SAMPLE_DIR


def sample_events() -> list[dict]:
    return list(load_from_files(str(SAMPLE_DIR)))


def finding_by_id(check_id: str):
    findings = []
    for detection in detection_registry():
        findings.extend(detection.analyze(sample_events()))
    return [finding for finding in findings if finding.check_id == check_id]


def test_root_account_usage_detection() -> None:
    findings = finding_by_id("CT-001")
    assert findings
    assert findings[0].severity == Severity.CRITICAL


def test_console_login_failures_detection() -> None:
    findings = finding_by_id("CT-002")
    assert findings[0].metadata["failure_count"] == 6


def test_console_login_new_country_detection(tmp_path) -> None:
    state_file = tmp_path / "known_countries.json"
    detection = detection_registry(str(state_file))[2]

    first_run = detection.analyze(sample_events())
    second_run = detection.analyze(sample_events())

    assert [finding for finding in first_run if finding.check_id == "CT-003"]
    assert not [finding for finding in second_run if finding.check_id == "CT-003"]


def test_privilege_escalation_detection() -> None:
    findings = finding_by_id("CT-004")
    assert findings[0].metadata["created_user"] == "temp-admin"


def test_mass_resource_deletion_detection() -> None:
    findings = finding_by_id("CT-005")
    assert findings[0].metadata["delete_count"] == 21


def test_disabled_logging_detection() -> None:
    findings = finding_by_id("CT-006")
    assert len(findings) == 2


def test_unauthorized_api_calls_detection() -> None:
    findings = finding_by_id("CT-007")
    assert findings[0].metadata["access_denied_count"] == 10


def test_new_iam_user_creation_detection() -> None:
    findings = finding_by_id("CT-008")
    assert {finding.metadata["created_user"] for finding in findings} >= {
        "temp-admin",
        "new-analyst",
    }
