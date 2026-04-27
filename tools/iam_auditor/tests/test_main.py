import json

from moto import mock_aws

from tools.iam_auditor import main as iam_main


@mock_aws
def test_main_writes_json_and_returns_failure_for_high_findings(tmp_path) -> None:
    output_dir = tmp_path / "reports"

    exit_code = iam_main.main(
        [
            "--region",
            "us-east-1",
            "--output",
            "json",
            "--output-dir",
            str(output_dir),
        ]
    )

    report_path = output_dir / "iam-auditor-report.json"
    payload = json.loads(report_path.read_text(encoding="utf-8"))

    assert exit_code == 1
    assert report_path.exists()
    assert payload["summary"]["CRITICAL"] == 1
    assert payload["summary"]["HIGH"] == 1


def test_filter_by_threshold_removes_lower_severities() -> None:
    findings = [
        check_finding
        for check in iam_main.CHECK_REGISTRY
        for check_finding in [
            iam_main.Finding(
                tool="iam-auditor",
                check_id=check.check_id,
                severity=iam_main.Severity.LOW,
                resource="resource",
                region=None,
                account_id="123456789012",
                title="Title",
                description="Description",
                remediation="Remediate",
            )
        ]
    ]

    assert iam_main.filter_by_threshold(findings, "HIGH") == []
