"""Base abstractions for IAM Auditor checks."""

from __future__ import annotations

from abc import ABC, abstractmethod

from botocore.client import BaseClient

from shared.findings import Finding, Severity


class BaseCheck(ABC):
    """Base class for IAM Auditor checks."""

    check_id: str
    title: str
    severity: Severity = Severity.INFO
    description: str

    @abstractmethod
    def run(self, iam_client: BaseClient, account_id: str) -> list[Finding]:
        """Run the check and return any findings."""
