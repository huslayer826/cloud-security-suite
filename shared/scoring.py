"""Risk scoring for shared findings."""

from __future__ import annotations

import math
from collections import Counter

from shared.findings import Finding, Severity


class RiskScorer:
    """Calculate a capped 0-100 risk score from findings."""

    _WEIGHTS: dict[Severity, float] = {
        Severity.CRITICAL: 5.0,
        Severity.HIGH: 3.0,
        Severity.MEDIUM: 2.0,
        Severity.LOW: 1.0,
        Severity.INFO: 0.5,
    }

    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings

    def score(self) -> float:
        """Return a capped risk score with logarithmic count dampening."""
        if not self.findings:
            return 0.0

        weighted_total = sum(
            finding.severity.value * self._WEIGHTS[finding.severity] for finding in self.findings
        )
        dampened_score = math.log1p(weighted_total) * 12
        return min(round(dampened_score, 2), 100.0)

    def score_breakdown(self) -> dict[str, int]:
        """Return finding counts grouped by severity name."""
        counts = Counter(finding.severity for finding in self.findings)
        return {severity.name: counts.get(severity, 0) for severity in Severity}
