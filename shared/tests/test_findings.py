from dataclasses import FrozenInstanceError
from datetime import datetime

import pytest

from shared.findings import Finding, Severity


def test_finding_to_dict_is_json_friendly() -> None:
    timestamp = datetime(2026, 1, 2, 3, 4, 5)
    finding = Finding(
        tool="iam-auditor",
        check_id="IAM001",
        severity=Severity.HIGH,
        resource="arn:aws:iam::123456789012:user/alice",
        region=None,
        account_id="123456789012",
        title="User has administrator access",
        description="A user has broad permissions.",
        remediation="Remove administrator access.",
        references=["https://example.com"],
        metadata={"policy": "AdministratorAccess"},
        timestamp=timestamp,
    )

    assert finding.to_dict() == {
        "tool": "iam-auditor",
        "check_id": "IAM001",
        "severity": "HIGH",
        "severity_score": 75,
        "resource": "arn:aws:iam::123456789012:user/alice",
        "region": None,
        "account_id": "123456789012",
        "title": "User has administrator access",
        "description": "A user has broad permissions.",
        "remediation": "Remove administrator access.",
        "references": ["https://example.com"],
        "metadata": {"policy": "AdministratorAccess"},
        "timestamp": "2026-01-02T03:04:05",
    }


def test_default_collections_are_not_shared() -> None:
    first = Finding(
        tool="iam-auditor",
        check_id="IAM001",
        severity=Severity.LOW,
        resource="resource-1",
        region="us-east-1",
        account_id=None,
        title="First",
        description="Description",
        remediation="Remediate",
    )
    second = Finding(
        tool="iam-auditor",
        check_id="IAM002",
        severity=Severity.INFO,
        resource="resource-2",
        region="us-east-1",
        account_id=None,
        title="Second",
        description="Description",
        remediation="Remediate",
    )

    first.references.append("https://example.com")
    first.metadata["key"] = "value"

    assert second.references == []
    assert second.metadata == {}


def test_finding_is_frozen() -> None:
    finding = Finding(
        tool="iam-auditor",
        check_id="IAM001",
        severity=Severity.LOW,
        resource="resource",
        region=None,
        account_id=None,
        title="Title",
        description="Description",
        remediation="Remediate",
    )

    with pytest.raises(FrozenInstanceError):
        finding.title = "Changed"  # type: ignore[misc]
