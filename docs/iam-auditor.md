# IAM Auditor

## Overview

The IAM Auditor checks AWS account identity controls and emits normalized Cloud Security Suite findings that can be scored and reported through the shared reporters.

## Checks

| Check ID | Title | Severity | What it detects |
| --- | --- | --- | --- |
| IAM-001 | Root account MFA is enabled | CRITICAL | Reports when the AWS account root user does not have MFA enabled. |
| IAM-002 | IAM password policy meets baseline | HIGH | Reports missing or weak password policy settings, including short passwords, missing uppercase or symbol requirements, weak age limits, and weak reuse prevention. |
| IAM-003 | IAM access keys are rotated regularly | HIGH | Reports IAM user access keys older than 30 days, with severity increasing at 60 and 90 days. |
| IAM-004 | IAM users are active and reviewed | MEDIUM/HIGH | Reports users with stale console or key activity, elevated to HIGH when the user also has administrator privileges. |
| IAM-005 | IAM access keys are used or removed | MEDIUM | Reports access keys that were never used or unused for 90 days or more. |
| IAM-006 | Customer-managed policies avoid full wildcard access | CRITICAL | Reports customer-managed policies that allow all actions on all resources. |
| IAM-007 | Users do not have direct administrator policies | HIGH | Reports IAM users directly attached to AdministratorAccess or equivalent wildcard permissions. |
| IAM-008 | Inline policies are avoided | LOW | Reports users and roles with inline policies that are harder to audit and reuse. |
| IAM-009 | Role trust policies restrict principals | CRITICAL/HIGH | Reports wildcard role trust without conditions and external account trust without sts:ExternalId. |
| IAM-010 | IAM roles are used or removed | MEDIUM | Reports roles that were never used or unused for more than 90 days. |
| IAM-011 | Console users have MFA | HIGH | Reports IAM users with console access but no assigned MFA device. |
| IAM-012 | Policy-bearing groups have members | LOW | Reports empty IAM groups that still have attached or inline permissions. |
| IAM-013 | IAM users have at most one active access key | MEDIUM | Reports users with two active access keys, suggesting an unfinished rotation. |

## Required IAM Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:GetAccountSummary",
        "iam:GetAccountPasswordPolicy",
        "iam:GetAccessKeyLastUsed",
        "iam:GetGroup",
        "iam:GetLoginProfile",
        "iam:GetPolicy",
        "iam:GetPolicyVersion",
        "iam:GetRolePolicy",
        "iam:GetUserPolicy",
        "iam:ListAccessKeys",
        "iam:ListAttachedGroupPolicies",
        "iam:ListAttachedUserPolicies",
        "iam:ListEntitiesForPolicy",
        "iam:ListGroupPolicies",
        "iam:ListGroups",
        "iam:ListMFADevices",
        "iam:ListPolicies",
        "iam:ListRolePolicies",
        "iam:ListRoles",
        "iam:ListUserPolicies",
        "iam:ListUsers",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

## Example CLI Usage

```bash
python -m tools.iam_auditor.main --profile audit --output all --output-dir ./reports
python -m tools.iam_auditor.main --severity-threshold HIGH --output cli
```

## Example Output

```text
Cloud Security Suite Summary
Risk score: 82.3
Total findings: 3
CRITICAL: 1
HIGH: 1
MEDIUM: 1
LOW: 0
INFO: 0
```
