"""Utility helpers for CloudTrail Analyzer detections."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any


def parse_event_time(event: dict[str, Any]) -> datetime:
    raw = event.get("eventTime")
    if isinstance(raw, datetime):
        return raw if raw.tzinfo else raw.replace(tzinfo=UTC)
    if not raw:
        return datetime.min.replace(tzinfo=UTC)
    return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))


def principal(event: dict[str, Any]) -> str:
    identity = event.get("userIdentity", {})
    return (
        identity.get("arn")
        or identity.get("userName")
        or identity.get("principalId")
        or identity.get("type")
        or "unknown"
    )


def region(event: dict[str, Any]) -> str | None:
    return event.get("awsRegion")


def account_id(event: dict[str, Any]) -> str | None:
    identity = event.get("userIdentity", {})
    return event.get("recipientAccountId") or identity.get("accountId")


def source_ip(event: dict[str, Any]) -> str:
    return event.get("sourceIPAddress", "unknown")


def country(event: dict[str, Any]) -> str | None:
    return (
        event.get("awsRegion")
        if event.get("sourceIPAddress") in {"AWS Internal", "cloudtrail.amazonaws.com"}
        else event.get("additionalEventData", {}).get("Country")
    )


def event_uid(event: dict[str, Any]) -> str:
    return event.get("eventID") or f"{event.get('eventName', 'event')}:{parse_event_time(event)}"
