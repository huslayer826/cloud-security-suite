from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from shared.findings import Finding, Severity
from tools.cloudtrail_analyzer.base import BaseDetection
from tools.cloudtrail_analyzer.utils import account_id, country, principal, region


class ConsoleLoginNewCountryDetection(BaseDetection):
    detection_id = "CT-003"
    title = "Console login from new country"
    severity = Severity.HIGH
    description = (
        "Detects successful ConsoleLogin events from a country not previously seen for a user."
    )

    def __init__(self, known_countries_file: str | None = None) -> None:
        self.known_countries_file = known_countries_file
        self.known = self._load_known()

    def analyze(self, events: Iterable[dict]) -> list[Finding]:
        findings = []
        changed = False
        for event in events:
            if event.get("eventName") != "ConsoleLogin":
                continue
            if event.get("responseElements", {}).get("ConsoleLogin") != "Success":
                continue
            user = principal(event)
            event_country = country(event)
            if not event_country:
                continue
            known_for_user = self.known.setdefault(user, [])
            if event_country not in known_for_user:
                findings.append(
                    Finding(
                        tool="cloudtrail-analyzer",
                        check_id=self.detection_id,
                        severity=self.severity,
                        resource=user,
                        region=region(event),
                        account_id=account_id(event),
                        title=self.title,
                        description=(
                            f"Successful console login for {user} from new country "
                            f"{event_country}."
                        ),
                        remediation=(
                            "Verify the login with the user and review MFA, session history, "
                            "and identity provider logs."
                        ),
                        metadata={"user": user, "country": event_country},
                    )
                )
                known_for_user.append(event_country)
                changed = True
        if changed:
            self._save_known()
        return findings

    def _load_known(self) -> dict[str, list[str]]:
        if not self.known_countries_file:
            return {}
        path = Path(self.known_countries_file)
        if not path.exists():
            return {}
        return json.loads(path.read_text(encoding="utf-8"))

    def _save_known(self) -> None:
        if not self.known_countries_file:
            return
        path = Path(self.known_countries_file)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.known, indent=2), encoding="utf-8")
