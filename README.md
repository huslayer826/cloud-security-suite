# Cloud Security Suite

A Python and Terraform suite for automated AWS security auditing, threat detection, and incident response.

[![test](https://img.shields.io/github/actions/workflow/status/huslayer826/cloud-security-suite/test.yml?branch=main&label=tests)](https://github.com/huslayer826/cloud-security-suite/actions/workflows/test.yml)
[![lint](https://img.shields.io/github/actions/workflow/status/huslayer826/cloud-security-suite/lint.yml?branch=main&label=lint)](https://github.com/huslayer826/cloud-security-suite/actions/workflows/lint.yml)
[![coverage](https://img.shields.io/codecov/c/github/huslayer826/cloud-security-suite?label=coverage)](https://codecov.io/gh/huslayer826/cloud-security-suite)
![Python](https://img.shields.io/badge/python-3.11-blue)
![Terraform](https://img.shields.io/badge/terraform-%3E%3D1.6-844FBA)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Hero Screenshot

![IAM Auditor HTML report](assets/iam-auditor-screenshot.png)

## What This Is

Cloud Security Suite is a hands-on AWS security engineering portfolio project that combines Python analysis tools with Terraform-managed serverless deployment. It includes an IAM Auditor, GuardDuty Processor, and CloudTrail Analyzer that share a common finding model, severity system, scoring engine, and report format.

I built it to practice the work an AWS security engineer actually does: reading AWS event shapes, translating risky configurations into actionable findings, deploying small automation safely, and making the output useful for humans. It is intended for internship reviewers, hiring managers, and cloud security learners who want to see practical AWS detection and response code rather than a toy script.

## Architecture

![Cloud Security Suite architecture](assets/architecture.png)

Terraform deploys the suite as three serverless workflows. The IAM Auditor runs on an EventBridge schedule, audits account posture through IAM APIs, writes JSON/HTML reports to S3, and sends high-severity summaries through SNS. The GuardDuty Processor receives GuardDuty findings from EventBridge, enriches them with AWS context, optionally runs guarded remediation playbooks, and notifies humans by email or Slack. The CloudTrail Analyzer runs scheduled Athena queries over an existing CloudTrail S3 bucket, applies detection rules, and publishes reports and alerts.

## Tools

### IAM Auditor

The IAM Auditor performs AWS IAM posture checks and produces CLI, JSON, and polished HTML reports with severity-weighted risk scoring.

![IAM Auditor demo](assets/demo.gif)

Run locally:

```bash
python -m tools.iam_auditor --profile audit --region us-east-1 --output all
```

Checks include root MFA, password policy strength, access key age, unused keys, direct administrator access, wildcard policies, unsafe role trust relationships, console users without MFA, inactive identities, and orphaned groups. See [docs/iam-auditor.md](docs/iam-auditor.md) for the full list.

### GuardDuty Processor

The GuardDuty Processor is an event-driven Lambda that handles GuardDuty findings as they arrive, maps them into the shared finding format, enriches the event with EC2/IAM/S3 context, and sends a clear notification.

Example notification fields:

```text
Severity: HIGH
Finding type: UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS
Resource: arn:aws:iam::123456789012:user/demo-user
Remediation action: DRY_RUN recorded intended access key disablement
```

Playbooks include leaked IAM access key disablement and EC2 quarantine/snapshot handling, both gated behind `AUTO_REMEDIATE` and `DRY_RUN`. See [docs/guardduty-processor.md](docs/guardduty-processor.md) for supported finding types, environment variables, and IAM permissions.

### CloudTrail Analyzer

The CloudTrail Analyzer reviews CloudTrail events from local files or Athena and applies detection rules for suspicious account activity.

Example detection output:

```text
CT-001 CRITICAL Root account usage
CT-004 HIGH     Privilege escalation sequence
CT-006 CRITICAL Security logging disabled
```

Detections include root account usage, console login bursts, new-country console logins, privilege escalation sequences, mass deletion, disabled logging, unauthorized API reconnaissance, and new IAM user creation. See [docs/cloudtrail-analyzer.md](docs/cloudtrail-analyzer.md) for Athena setup and extension guidance.

## Quick Start

```bash
git clone https://github.com/huslayer826/cloud-security-suite.git
cd cloud-security-suite
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Configure AWS credentials with a profile that has read-only security audit permissions:

```bash
aws configure --profile audit
aws sts get-caller-identity --profile audit
```

Run the IAM Auditor locally:

```bash
python -m tools.iam_auditor --profile audit --region us-east-1 --output cli
python -m tools.iam_auditor --profile audit --region us-east-1 --output html --output-dir ./reports
```

Deployment instructions live in [infrastructure/README.md](infrastructure/README.md).

## Deploying to AWS

See [infrastructure/README.md](infrastructure/README.md) for Terraform prerequisites, Lambda packaging, `terraform.tfvars` setup, scheduled deployment, manual Lambda invocation, remote state, and teardown.

## Tech Stack

- Python 3.11
- Boto3 and Botocore
- Jinja2
- Rich
- Pytest and pytest-cov
- Moto
- Ruff and mypy
- Terraform
- AWS Lambda
- Amazon EventBridge
- Amazon S3
- Amazon SNS
- Amazon Athena and AWS Glue
- Amazon GuardDuty
- AWS CloudTrail

## What I Learned

- IAM policy parsing has a lot of edge cases: `Action` and `Resource` can be strings or lists, wildcard risk can hide behind policy versions, and `NotAction` / `NotResource` need separate handling instead of being treated like normal allow statements.
- EventBridge GuardDuty findings and CloudTrail events look similar at a high level but have very different shapes, so each processor needs its own normalization layer before shared reporting can work cleanly.
- Athena partition projection is useful for CloudTrail because it avoids crawling every date partition, but the S3 location template has to match the exact `AWSLogs/account/CloudTrail/region/year/month/day` layout.
- Auto-remediation needs boring safety defaults. `DRY_RUN=true` and explicit `AUTO_REMEDIATE=false` make the GuardDuty Processor useful for demos and testing without accidentally changing a real account.
- Terraform Lambda packaging is easy to underestimate: local source layout, runtime dependencies, ignored zip artifacts, and source hashes all affect whether infrastructure plans are repeatable.
- Recruiter-friendly output still needs engineering discipline underneath it. The HTML report is polished, but it is only useful because every finding carries structured severity, resource, remediation, metadata, and references.

## Roadmap

- Multi-account Security Hub aggregation across AWS Organizations.
- Slack approval workflow before high-risk remediation actions run.
- Sigma rule support for CloudTrail detections.
- Optional KMS keys and stronger security hardening controls for all Terraform-managed storage, logs, and notifications.
- Additional sample datasets and demo scenarios for GuardDuty and CloudTrail.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for branch naming, commit style, local test commands, Terraform validation, and pull request expectations.

## License

MIT. See [LICENSE](LICENSE).
