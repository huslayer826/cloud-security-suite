"""CloudTrail event loading helpers."""

from __future__ import annotations

import gzip
import json
import time
from collections.abc import Iterable
from contextlib import suppress
from pathlib import Path
from typing import Any

import boto3


def load_from_files(directory: str) -> Iterable[dict]:
    """Recursively yield CloudTrail records from .json and .json.gz files."""
    for path in sorted(Path(directory).rglob("*")):
        if path.suffix == ".json" or path.name.endswith(".json.gz"):
            opener = gzip.open if path.name.endswith(".gz") else open
            with opener(path, "rt", encoding="utf-8") as handle:
                payload = json.load(handle)
            yield from payload.get("Records", [])


def load_from_athena(
    query: str,
    workgroup: str,
    database: str,
    output_location: str,
) -> Iterable[dict]:
    """Run an Athena query and yield each result row as a CloudTrail-like dict."""
    client = boto3.client("athena")
    execution = client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={"Database": database},
        ResultConfiguration={"OutputLocation": output_location},
        WorkGroup=workgroup,
    )
    execution_id = execution["QueryExecutionId"]
    _wait_for_query(client, execution_id)

    paginator = client.get_paginator("get_query_results")
    header: list[str] | None = None
    for page in paginator.paginate(QueryExecutionId=execution_id):
        for row in page["ResultSet"]["Rows"]:
            values = [item.get("VarCharValue") for item in row.get("Data", [])]
            if header is None:
                header = [value or "" for value in values]
                continue
            yield _athena_row_to_event(header, values)


def _wait_for_query(client: Any, execution_id: str) -> None:
    while True:
        response = client.get_query_execution(QueryExecutionId=execution_id)
        state = response["QueryExecution"]["Status"]["State"]
        if state == "SUCCEEDED":
            return
        if state in {"FAILED", "CANCELLED"}:
            reason = response["QueryExecution"]["Status"].get("StateChangeReason", state)
            raise RuntimeError(f"Athena query {execution_id} ended with {state}: {reason}")
        time.sleep(2)


def _athena_row_to_event(header: list[str], values: list[str | None]) -> dict:
    event = {key: value for key, value in zip(header, values, strict=False)}
    for json_field in [
        "userIdentity",
        "requestParameters",
        "responseElements",
        "additionalEventData",
    ]:
        if isinstance(event.get(json_field), str):
            with suppress(json.JSONDecodeError):
                event[json_field] = json.loads(event[json_field])
    return event
