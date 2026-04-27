"""Helpers for parsing IAM policy documents."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def statements(document: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        statement for statement in as_list(document.get("Statement")) if isinstance(statement, dict)
    ]


def includes_wildcard(value: Any) -> bool:
    values = as_list(value)
    return "*" in values or any(item == "*" for item in values)


def allows_full_admin(document: dict[str, Any]) -> bool:
    """Return true when a policy allows all actions on all resources."""
    for statement in statements(document):
        if statement.get("Effect") != "Allow":
            continue

        action_wildcard = includes_wildcard(statement.get("Action")) or "NotAction" in statement
        resource_wildcard = (
            includes_wildcard(statement.get("Resource")) or "NotResource" in statement
        )
        if action_wildcard and resource_wildcard:
            return True

    return False


def principal_values(principal: Any) -> Iterable[str]:
    if principal == "*":
        yield "*"
        return
    if not isinstance(principal, dict):
        return

    for value in principal.values():
        for item in as_list(value):
            if isinstance(item, str):
                yield item


def has_external_id_condition(statement: dict[str, Any]) -> bool:
    condition = statement.get("Condition", {})
    if not isinstance(condition, dict):
        return False

    for operator_values in condition.values():
        if isinstance(operator_values, dict) and "sts:ExternalId" in operator_values:
            return True

    return False
