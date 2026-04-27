import json

from rich.console import Console

from shared.findings import Finding, Severity
from shared.reporters import CLIReporter, HTMLReporter, JSONReporter


def make_finding(severity: Severity = Severity.MEDIUM) -> Finding:
    return Finding(
        tool="iam-auditor",
        check_id="IAM001",
        severity=severity,
        resource="arn:aws:iam::123456789012:user/alice",
        region="us-east-1",
        account_id="123456789012",
        title="User has administrator access",
        description="A user has broad permissions.",
        remediation="Remove administrator access.",
    )


def test_json_reporter_writes_findings_and_summary(tmp_path) -> None:
    output_path = tmp_path / "report.json"

    JSONReporter().write([make_finding(Severity.HIGH)], output_path)

    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert payload["risk_score"] > 0
    assert payload["summary"]["HIGH"] == 1
    assert payload["findings"][0]["severity"] == "HIGH"


def test_html_reporter_renders_dark_report(tmp_path) -> None:
    output_path = tmp_path / "report.html"

    HTMLReporter().write([make_finding(Severity.CRITICAL)], output_path)

    html = output_path.read_text(encoding="utf-8")
    assert "Cloud Security Suite Report" in html
    assert "CRITICAL" in html
    assert "Breakdown chart placeholder" in html
    assert "querySelectorAll" in html


def test_cli_reporter_prints_summary_and_table() -> None:
    console = Console(record=True, width=120)

    CLIReporter(console=console).print([make_finding(Severity.LOW)])

    output = console.export_text()
    assert "Cloud Security Suite Summary" in output
    assert "Risk score:" in output
    assert "LOW" in output
    assert "iam-auditor" in output
