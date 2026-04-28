# GuardDuty Processor

## Overview

The GuardDuty Processor is an event-driven Lambda handler for Amazon GuardDuty findings delivered through EventBridge. It converts each finding into the shared Cloud Security Suite `Finding` model, enriches it with resource context, optionally runs guarded remediation playbooks, and publishes a scannable notification to SNS and optionally Slack.

## Supported Finding Types

The processor accepts any GuardDuty finding type and always sends a notification. Enrichment currently supports:

| Category | Examples | Enrichment |
| --- | --- | --- |
| EC2 | `UnauthorizedAccess:EC2/...`, `Recon:EC2/...` | Instance tags, VPC, subnet, attached IAM role, recent CloudTrail events |
| IAM user | `UnauthorizedAccess:IAMUser/...`, `Stealth:IAMUser/...` | Groups, attached policies, MFA status, recent CloudTrail events |
| S3 | S3 finding types or `resourceType = S3Bucket` | Public access block, encryption, bucket logging, recent CloudTrail events |

GuardDuty numeric severity maps to Cloud Security Suite severity as:

| GuardDuty severity | Suite severity |
| --- | --- |
| `< 4.0` | LOW |
| `4.0 - 6.9` | MEDIUM |
| `7.0 - 8.4` | HIGH |
| `8.5+` | CRITICAL |

## Remediation Playbooks

All remediation is disabled unless `AUTO_REMEDIATE=true`. `DRY_RUN=true` is the default kill switch and prevents writes even when auto-remediation is enabled.

| Finding type | Severity | Side effects |
| --- | --- | --- |
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | HIGH | In non-dry-run mode, calls `iam:UpdateAccessKey` to set the leaked key to `Inactive`. |
| `Recon:EC2/PortProbeUnprotectedPort` | MEDIUM | In non-dry-run mode, creates or reuses a quarantine security group, attaches it to the instance, removes outbound access from the quarantine group, and snapshots attached EBS volumes. |
| All other types | Any | No automated remediation; notification only. |

Every playbook emits an INFO remediation finding describing the action or dry-run intent for audit trails.

## Required IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents",
        "ec2:CreateSecurityGroup",
        "ec2:CreateSnapshot",
        "ec2:DescribeInstances",
        "ec2:DescribeSecurityGroups",
        "ec2:ModifyInstanceAttribute",
        "ec2:RevokeSecurityGroupEgress",
        "iam:ListAttachedUserPolicies",
        "iam:ListGroupsForUser",
        "iam:ListMFADevices",
        "iam:UpdateAccessKey",
        "s3:GetBucketEncryption",
        "s3:GetBucketLogging",
        "s3:GetBucketPublicAccessBlock",
        "sns:Publish"
      ],
      "Resource": "*"
    }
  ]
}
```

In production, scope EC2, SNS, and S3 permissions further where possible.

## Environment Variables

| Variable | Default | Purpose |
| --- | --- | --- |
| `AUTO_REMEDIATE` | `false` | Enables registered remediation playbooks when `true`. |
| `DRY_RUN` | `true` | Hard kill switch. When `true`, intended actions are logged but not executed. |
| `SNS_TOPIC_ARN` | unset | SNS topic for notifications. If unset, SNS publishing is skipped. |
| `SLACK_WEBHOOK_URL` | unset | Optional Slack incoming webhook URL. If unset, Slack publishing is skipped. |

To disable auto-remediation entirely, leave `AUTO_REMEDIATE=false` or unset it. To test alerting safely, set `AUTO_REMEDIATE=true` and keep `DRY_RUN=true`.

## SNS Message Format

```text
Severity: HIGH
Finding type: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
Resource: iam-user:alice/access-key-****MPLE
Description: IAM user credentials were used from an external network.
AWS console: https://us-east-1.console.aws.amazon.com/guardduty/home?region=us-east-1#/findings?search=id%3Dgd-iam-001
Remediation action: dry_run: Deactivate access key ****MPLE for IAM user alice.
```

## Slack Message Format

Slack notifications use Block Kit:

- Header: `GuardDuty <SEVERITY>: <finding type>`
- Fields: resource, region, account, remediation status
- Section: finding description
- Button: direct link to the GuardDuty console finding
