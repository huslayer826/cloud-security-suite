"""GuardDuty auto-remediation playbooks."""

from __future__ import annotations

import logging
import os
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import boto3

from shared.findings import Finding, Severity

LOGGER = logging.getLogger(__name__)
RemediationHandler = Callable[[dict[str, Any], Finding, bool, bool], list[Finding]]


def remediate(detail: dict[str, Any], finding: Finding) -> list[Finding]:
    """Run a registered remediation playbook if enabled."""
    auto_remediate = _env_bool("AUTO_REMEDIATE", default=False)
    dry_run = _env_bool("DRY_RUN", default=True)
    finding_type = detail.get("type", "")
    handler = PLAYBOOK_REGISTRY.get(finding_type)

    if handler is None:
        LOGGER.info("No remediation playbook registered for %s", finding_type)
        return []

    return handler(detail, finding, auto_remediate, dry_run)


def revoke_exfiltrated_access_key(
    detail: dict[str, Any],
    finding: Finding,
    auto_remediate: bool,
    dry_run: bool,
) -> list[Finding]:
    access_key = detail.get("resource", {}).get("accessKeyDetails", {})
    access_key_id = access_key.get("accessKeyId")
    user_name = access_key.get("userName")
    action = (
        f"Deactivate access key ****{access_key_id[-4:]}" if access_key_id else "Deactivate key"
    )

    if auto_remediate and not dry_run and user_name and access_key_id:
        boto3.client("iam", region_name=finding.region).update_access_key(
            UserName=user_name,
            AccessKeyId=access_key_id,
            Status="Inactive",
        )
        LOGGER.info("Revoked access key %s for user %s", access_key_id, user_name)
        status = "executed"
    else:
        LOGGER.info("DRY_RUN or auto-remediation disabled: would %s for %s", action, user_name)
        status = "dry_run" if dry_run else "skipped"

    return [
        _remediation_finding(
            finding,
            title="GuardDuty remediation: access key deactivation",
            description=f"{status}: {action} for IAM user {user_name}.",
            action=action,
            status=status,
        )
    ]


def quarantine_port_probe_instance(
    detail: dict[str, Any],
    finding: Finding,
    auto_remediate: bool,
    dry_run: bool,
) -> list[Finding]:
    instance = detail.get("resource", {}).get("instanceDetails", {})
    instance_id = instance.get("instanceId")
    region = finding.region or detail.get("region") or "us-east-1"
    action = f"Attach quarantine security group and snapshot volumes for {instance_id}"

    if auto_remediate and not dry_run and instance_id:
        ec2_client = boto3.client("ec2", region_name=region)
        quarantine_group_id = _ensure_quarantine_security_group(ec2_client, instance)
        ec2_client.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[quarantine_group_id],
        )
        for volume in _instance_volume_ids(ec2_client, instance_id):
            ec2_client.create_snapshot(
                VolumeId=volume,
                Description=f"Cloud Security Suite quarantine snapshot for {instance_id}",
            )
        LOGGER.info("Quarantined instance %s", instance_id)
        status = "executed"
    else:
        LOGGER.info("DRY_RUN or auto-remediation disabled: would %s", action)
        status = "dry_run" if dry_run else "skipped"

    return [
        _remediation_finding(
            finding,
            title="GuardDuty remediation: EC2 quarantine",
            description=f"{status}: {action}.",
            action=action,
            status=status,
        )
    ]


def _ensure_quarantine_security_group(ec2_client: Any, instance: dict[str, Any]) -> str:
    vpc_id = instance.get("networkInterfaces", [{}])[0].get("vpcId") or instance.get("vpcId")
    group_name = "cloud-security-suite-quarantine"
    response = ec2_client.describe_security_groups(
        Filters=[
            {"Name": "group-name", "Values": [group_name]},
            {"Name": "vpc-id", "Values": [vpc_id]},
        ]
    )
    if response.get("SecurityGroups"):
        return response["SecurityGroups"][0]["GroupId"]

    created = ec2_client.create_security_group(
        GroupName=group_name,
        Description="Cloud Security Suite quarantine group",
        VpcId=vpc_id,
    )
    group_id = created["GroupId"]
    try:
        ec2_client.revoke_security_group_egress(
            GroupId=group_id,
            IpPermissions=[
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
    except Exception:
        LOGGER.warning("Unable to remove default egress from quarantine group", exc_info=True)
    return group_id


def _instance_volume_ids(ec2_client: Any, instance_id: str) -> list[str]:
    response = ec2_client.describe_instances(InstanceIds=[instance_id])
    instances = response.get("Reservations", [{}])[0].get("Instances", [])
    if not instances:
        return []
    return [
        mapping["Ebs"]["VolumeId"]
        for mapping in instances[0].get("BlockDeviceMappings", [])
        if "Ebs" in mapping
    ]


def _remediation_finding(
    source: Finding,
    title: str,
    description: str,
    action: str,
    status: str,
) -> Finding:
    return Finding(
        tool="guardduty-processor",
        check_id=f"{source.check_id}:remediation",
        severity=Severity.INFO,
        resource=source.resource,
        region=source.region,
        account_id=source.account_id,
        title=title,
        description=description,
        remediation="Recorded remediation action for audit trail.",
        metadata={
            "source_check_id": source.check_id,
            "action": action,
            "status": status,
            "timestamp": datetime.now(UTC).isoformat(),
        },
    )


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.lower() in {"1", "true", "yes", "y"}


PLAYBOOK_REGISTRY: dict[str, RemediationHandler] = {
    "UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS": (
        revoke_exfiltrated_access_key
    ),
    "Recon:EC2/PortProbeUnprotectedPort": quarantine_port_probe_instance,
}
