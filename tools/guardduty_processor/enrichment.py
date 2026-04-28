"""Context enrichment for GuardDuty findings."""

from __future__ import annotations

import logging
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from shared.findings import Finding

LOGGER = logging.getLogger(__name__)


def enrich_finding(finding: Finding, detail: dict[str, Any]) -> Finding:
    """Return a finding with best-effort AWS resource context."""
    metadata = dict(finding.metadata)
    metadata["enrichment"] = {}
    finding_type = detail.get("type", "")
    resource = detail.get("resource", {})
    region = detail.get("region") or finding.region or "us-east-1"

    if finding_type.startswith(("UnauthorizedAccess:EC2/", "Recon:EC2/")):
        metadata["enrichment"]["ec2"] = enrich_ec2(resource, region)
    elif finding_type.startswith(("UnauthorizedAccess:IAMUser/", "Stealth:IAMUser/")):
        metadata["enrichment"]["iam_user"] = enrich_iam_user(resource, region)
    elif "S3" in finding_type or resource.get("resourceType") == "S3Bucket":
        metadata["enrichment"]["s3"] = enrich_s3(resource, region)

    return replace(finding, metadata=metadata)


def enrich_ec2(resource: dict[str, Any], region: str) -> dict[str, Any]:
    context: dict[str, Any] = {}
    instance = resource.get("instanceDetails", {})
    instance_id = instance.get("instanceId")
    if not instance_id:
        return context

    ec2_client = boto3.client("ec2", region_name=region)
    cloudtrail_client = boto3.client("cloudtrail", region_name=region)

    try:
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance_data = response["Reservations"][0]["Instances"][0]
        context.update(
            {
                "instance_id": instance_id,
                "tags": {tag["Key"]: tag["Value"] for tag in instance_data.get("Tags", [])},
                "vpc_id": instance_data.get("VpcId"),
                "subnet_id": instance_data.get("SubnetId"),
                "iam_instance_profile": instance_data.get("IamInstanceProfile", {}).get("Arn"),
            }
        )
    except (BotoCoreError, ClientError, KeyError, IndexError) as error:
        LOGGER.warning("Unable to enrich EC2 instance %s: %s", instance_id, error)

    try:
        context["recent_cloudtrail_events"] = _recent_cloudtrail_events(
            cloudtrail_client,
            "ResourceName",
            instance_id,
        )
    except (BotoCoreError, ClientError) as error:
        LOGGER.warning("Unable to fetch CloudTrail events for %s: %s", instance_id, error)

    return context


def enrich_iam_user(resource: dict[str, Any], region: str) -> dict[str, Any]:
    context: dict[str, Any] = {}
    access_key = resource.get("accessKeyDetails", {})
    user_name = access_key.get("userName")
    if not user_name:
        return context

    iam_client = boto3.client("iam", region_name=region)
    cloudtrail_client = boto3.client("cloudtrail", region_name=region)

    try:
        groups = iam_client.list_groups_for_user(UserName=user_name)["Groups"]
        context["groups"] = [group["GroupName"] for group in groups]
    except (BotoCoreError, ClientError) as error:
        LOGGER.warning("Unable to fetch IAM groups for %s: %s", user_name, error)

    try:
        context["attached_policies"] = [
            policy["PolicyName"]
            for policy in iam_client.list_attached_user_policies(UserName=user_name)[
                "AttachedPolicies"
            ]
        ]
    except (BotoCoreError, ClientError) as error:
        LOGGER.warning("Unable to fetch IAM policies for %s: %s", user_name, error)

    try:
        context["mfa_enabled"] = bool(iam_client.list_mfa_devices(UserName=user_name)["MFADevices"])
    except (BotoCoreError, ClientError) as error:
        LOGGER.warning("Unable to fetch MFA devices for %s: %s", user_name, error)

    try:
        context["recent_cloudtrail_events"] = _recent_cloudtrail_events(
            cloudtrail_client,
            "Username",
            user_name,
        )
    except (BotoCoreError, ClientError) as error:
        LOGGER.warning("Unable to fetch CloudTrail events for %s: %s", user_name, error)

    return context


def enrich_s3(resource: dict[str, Any], region: str) -> dict[str, Any]:
    context: dict[str, Any] = {}
    buckets = resource.get("s3BucketDetails", [])
    if not buckets:
        return context

    bucket_name = buckets[0].get("name")
    if not bucket_name:
        return context

    s3_client = boto3.client("s3", region_name=region)
    cloudtrail_client = boto3.client("cloudtrail", region_name=region)

    context["bucket_name"] = bucket_name
    for key, operation in {
        "public_access_block": s3_client.get_public_access_block,
        "encryption": s3_client.get_bucket_encryption,
        "logging": s3_client.get_bucket_logging,
    }.items():
        try:
            context[key] = operation(Bucket=bucket_name)
        except (BotoCoreError, ClientError) as error:
            LOGGER.warning("Unable to enrich S3 bucket %s %s: %s", bucket_name, key, error)

    try:
        context["recent_cloudtrail_events"] = _recent_cloudtrail_events(
            cloudtrail_client,
            "ResourceName",
            bucket_name,
        )
    except (BotoCoreError, ClientError) as error:
        LOGGER.warning("Unable to fetch CloudTrail events for bucket %s: %s", bucket_name, error)

    return context


def _recent_cloudtrail_events(
    client: Any,
    lookup_key: str,
    lookup_value: str,
) -> list[dict[str, Any]]:
    response = client.lookup_events(
        LookupAttributes=[{"AttributeKey": lookup_key, "AttributeValue": lookup_value}],
        StartTime=datetime.now(UTC) - timedelta(days=7),
        EndTime=datetime.now(UTC),
        MaxResults=5,
    )
    return [
        {
            "event_name": event.get("EventName"),
            "event_time": event.get("EventTime").isoformat()
            if event.get("EventTime")
            else None,
            "username": event.get("Username"),
        }
        for event in response.get("Events", [])
    ]
