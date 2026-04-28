"""Base abstractions for CloudTrail Analyzer detections."""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterable

from shared.findings import Finding, Severity


class BaseDetection(ABC):
    """Base class for CloudTrail detections."""

    detection_id: str
    title: str
    severity: Severity
    description: str

    @abstractmethod
    def analyze(self, events: Iterable[dict]) -> list[Finding]:
        """Analyze CloudTrail events and return findings."""
