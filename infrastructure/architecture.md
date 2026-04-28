# Deployed AWS Architecture

## IAM Auditor

- Scheduled EventBridge rule runs the IAM Auditor Lambda every 24 hours by default.
- The Lambda reads IAM account posture, writes JSON and HTML reports to an encrypted S3 reports bucket, and publishes HIGH/CRITICAL summaries to SNS.
- CloudWatch Logs stores Lambda execution logs with 30-day retention.

## GuardDuty Processor

- EventBridge routes all GuardDuty Finding events to the GuardDuty Processor Lambda.
- The Lambda enriches findings with EC2, IAM, S3, and CloudTrail context.
- SNS sends human-review notifications. Slack can be enabled with a webhook environment variable.
- Optional remediation playbooks are gated by `AUTO_REMEDIATE` and `DRY_RUN`.

## CloudTrail Analyzer

- A scheduled EventBridge rule runs the CloudTrail Analyzer Lambda daily by default.
- The Lambda queries existing CloudTrail logs in S3 through Athena.
- Glue stores the CloudTrail external table with date and region partition projection.
- A dedicated S3 bucket stores Athena query results and generated JSON/HTML analyzer reports.
- SNS receives HIGH/CRITICAL analyzer summaries.

## Shared Services

- All Lambda functions write logs to CloudWatch Logs.
- Terraform applies default tags for project, environment, manager, and component.
- Existing CloudTrail log buckets are referenced as inputs rather than created by this project.
