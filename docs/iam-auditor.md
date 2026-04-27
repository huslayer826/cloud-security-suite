# IAM Auditor

## Overview

The IAM Auditor checks AWS account identity controls and emits normalized Cloud Security Suite findings that can be scored and reported through the shared reporters.

## Checks

| Check ID | Title | Severity | What it detects |
| --- | --- | --- | --- |
| IAM-001 | Root account MFA is enabled | CRITICAL | Reports when the AWS account root user does not have MFA enabled. |
| IAM-002 | IAM password policy meets baseline | HIGH | Reports missing or weak password policy settings, including short passwords, missing uppercase or symbol requirements, weak age limits, and weak reuse prevention. |
| IAM-003 | IAM access keys are rotated regularly | HIGH | Reports IAM user access keys older than 30 days, with severity increasing at 60 and 90 days. |

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
        "iam:ListAccessKeys",
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
