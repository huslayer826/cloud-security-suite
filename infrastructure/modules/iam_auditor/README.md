# IAM Auditor Terraform Module

This module deploys the Cloud Security Suite IAM Auditor as a scheduled AWS Lambda.

## Resources

- S3 bucket for JSON and HTML reports
- S3 versioning, AES-256 server-side encryption, public access blocking, and report lifecycle transition to Glacier after 90 days
- SNS topic and email subscription for HIGH/CRITICAL findings
- Lambda execution role with least-privilege IAM read permissions, S3 report write access, and SNS publish access
- Python 3.11 Lambda function
- CloudWatch log group with 30-day retention
- EventBridge schedule rule and Lambda target

## Required Variables

- `project_name`
- `environment`
- `aws_region`
- `notification_email`
- `schedule_expression`
- `lambda_package_path`

## Package

From `infrastructure/`:

```bash
./modules/iam_auditor/package.sh
```

The script creates `modules/iam_auditor/iam_auditor_lambda.zip`, which Terraform uploads to Lambda.

## Manual Invocation

After deployment:

```bash
aws lambda invoke \
  --function-name "$(terraform output -raw iam_auditor_lambda_name)" \
  --payload '{}' \
  response.json
cat response.json
```

If the function finds HIGH or CRITICAL findings, it publishes a JSON summary to the SNS topic. Reports are always written to S3 under `reports/iam-auditor/<account-id>/`.
