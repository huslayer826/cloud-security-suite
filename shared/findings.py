"""Finding model shared by all Cloud Security Suite tools."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(Enum):
    """Severity levels with numeric impact values."""

    CRITICAL = 100
    HIGH = 75
    MEDIUM = 50
    LOW = 25
    INFO = 10


@dataclass(frozen=True)
class Finding:
    """A security finding emitted by a Cloud Security Suite tool."""

    tool: str
    check_id: str
    severity: Severity
    resource: str
    region: str | None
    account_id: str | None
    title: str
    description: str
    remediation: str
    references: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly representation of the finding."""
        return {
            "tool": self.tool,
            "check_id": self.check_id,
            "severity": self.severity.name,
            "severity_score": self.severity.value,
            "resource": self.resource,
            "region": self.region,
            "account_id": self.account_id,
            "title": self.title,
            "description": self.description,
            "remediation": self.remediation,
            "references": self.references,
            "metadata": self.metadata,
            "timestamp": self.timestamp.isoformat(),
        }
