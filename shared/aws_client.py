"""AWS client helpers shared by suite tools."""

from __future__ import annotations

import boto3
from botocore.client import BaseClient


def _session(profile: str | None = None) -> boto3.Session:
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()


def get_client(
    service: str,
    region: str | None = None,
    profile: str | None = None,
) -> BaseClient:
    """Return a boto3 client using default credentials or a named profile."""
    return _session(profile).client(service, region_name=region)


def get_account_id(profile: str | None = None) -> str:
    """Return the AWS account ID for the active credentials."""
    sts_client = get_client("sts", profile=profile)
    identity = sts_client.get_caller_identity()
    return str(identity["Account"])
