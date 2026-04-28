# Cloud Security Suite

[![test](https://img.shields.io/github/actions/workflow/status/huslayer826/cloud-security-suite/test.yml?branch=main&label=tests)](https://github.com/huslayer826/cloud-security-suite/actions/workflows/test.yml)
[![lint](https://img.shields.io/github/actions/workflow/status/huslayer826/cloud-security-suite/lint.yml?branch=main&label=lint)](https://github.com/huslayer826/cloud-security-suite/actions/workflows/lint.yml)
[![coverage](https://img.shields.io/codecov/c/github/huslayer826/cloud-security-suite?label=coverage)](https://codecov.io/gh/huslayer826/cloud-security-suite)
![Python](https://img.shields.io/badge/python-3.11-blue)
![Terraform](https://img.shields.io/badge/terraform-%3E%3D1.6-844FBA)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

## Project Pitch

A Python and Terraform suite for automated AWS security auditing, threat detection, and incident response.

## Badges

CI badges track tests, linting, coverage, supported runtime versions, and license.

## Architecture Diagram

Placeholder for the architecture diagram.

## Tools

### IAM Auditor

The IAM Auditor reviews AWS IAM posture across root MFA, password policy, access keys, direct admin access, risky customer-managed policies, role trust relationships, inline policies, inactive identities, console MFA, orphaned groups, and key rotation hygiene.

Full check details live in [docs/iam-auditor.md](docs/iam-auditor.md).

![IAM Auditor sample report](assets/iam-auditor-screenshot.png)

Quick start:

```bash
python -m tools.iam_auditor --profile audit --region us-east-1 --output all
```

### GuardDuty Processor

Coming soon.

### CloudTrail Analyzer

Coming soon.

## Quick Start

```bash
git clone https://github.com/oyousef25/cloud-security-suite.git
cd cloud-security-suite
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Configure AWS credentials with a read-only audit profile before running the tools. The IAM Auditor needs IAM read permissions and `sts:GetCallerIdentity`; see [docs/iam-auditor.md](docs/iam-auditor.md) for the minimal policy.

```bash
python -m tools.iam_auditor --profile audit --output cli
python -m tools.iam_auditor --profile audit --output html --output-dir ./reports
```

CLI output preview:

```text
Cloud Security Suite IAM Auditor
Version: 0.5.0
Account: 123456789012
Region: us-east-1

Cloud Security Suite Summary
Risk score: 96.4
Total findings: 9
CRITICAL: 2
HIGH: 2
MEDIUM: 2
LOW: 2
INFO: 1
```

Sample HTML and JSON outputs are committed under `tools/iam_auditor/sample_output/`.

## Deployment

The first Terraform deployment target is the IAM Auditor as a scheduled AWS Lambda with S3 report storage and SNS alerts.

See [infrastructure/README.md](infrastructure/README.md) for packaging, planning, applying, manual invocation, remote state, and destroy instructions.

## What I Learned

Placeholder for project learnings.

## License

MIT License.
