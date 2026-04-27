from shared.findings import Finding, Severity
from shared.scoring import RiskScorer


def make_finding(severity: Severity) -> Finding:
    return Finding(
        tool="test-tool",
        check_id=f"CHECK-{severity.name}",
        severity=severity,
        resource="resource",
        region="us-east-1",
        account_id="123456789012",
        title="Title",
        description="Description",
        remediation="Remediate",
    )


def test_empty_findings_score_zero() -> None:
    scorer = RiskScorer([])

    assert scorer.score() == 0.0
    assert scorer.score_breakdown() == {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "INFO": 0,
    }


def test_score_breakdown_counts_each_severity() -> None:
    findings = [
        make_finding(Severity.CRITICAL),
        make_finding(Severity.HIGH),
        make_finding(Severity.HIGH),
        make_finding(Severity.LOW),
    ]

    assert RiskScorer(findings).score_breakdown() == {
        "CRITICAL": 1,
        "HIGH": 2,
        "MEDIUM": 0,
        "LOW": 1,
        "INFO": 0,
    }


def test_score_caps_at_100() -> None:
    findings = [make_finding(Severity.CRITICAL) for _ in range(100)]

    assert RiskScorer(findings).score() == 100.0


def test_logarithmic_dampener_limits_low_finding_volume() -> None:
    low_score = RiskScorer([make_finding(Severity.LOW) for _ in range(1000)]).score()
    critical_score = RiskScorer([make_finding(Severity.CRITICAL) for _ in range(5)]).score()

    assert low_score <= 100.0
    assert critical_score <= 100.0
