# Cloud Security Suite Infrastructure

This Terraform configuration deploys the Cloud Security Suite serverless components: the IAM Auditor, GuardDuty Processor, and CloudTrail Analyzer.

## Prerequisites

- Terraform >= 1.6
- AWS CLI configured with credentials for the target account
- Python 3.11

## Deploy

```bash
cd infrastructure
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` and set `notification_email` and any environment-specific values.

Package the IAM Auditor Lambda code:

```bash
./modules/iam_auditor/package.sh
```

Initialize and deploy:

```bash
terraform init
terraform plan
terraform apply
```

Confirm the SNS subscription email after apply, or alerts will not be delivered.

## Manual Test Run

After deployment, invoke the Lambda immediately:

```bash
aws lambda invoke \
  --function-name "$(terraform output -raw iam_auditor_lambda_name)" \
  --payload '{}' \
  response.json
cat response.json
```

Reports are written to the S3 bucket from `terraform output -raw iam_auditor_reports_bucket_name`.

## Deploy GuardDuty Processor

The GuardDuty Processor receives GuardDuty findings from EventBridge, enriches them, optionally performs guarded remediation, and sends notifications to SNS and optional Slack.

Prerequisites:

- GuardDuty is already enabled in the target region, or set `enable_guardduty = true`.
- Confirm the SNS subscription email after `terraform apply`.
- Keep `guardduty_dry_run = true` until you are ready to test remediation safely.

Package the Lambda code:

```bash
./modules/guardduty_processor/package.sh
```

Plan and apply as usual:

```bash
terraform plan
terraform apply
```

To trigger a sample finding:

```bash
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
aws guardduty create-sample-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-types Recon:EC2/PortProbeUnprotectedPort
```

Verify the Lambda fired by checking CloudWatch logs:

```bash
aws logs tail "/aws/lambda/$(terraform output -raw guardduty_processor_lambda_name)" --follow
```

You should also receive an SNS email notification after the subscription is confirmed.

## Deploy CloudTrail Analyzer

The CloudTrail Analyzer uses Athena and Glue to query an existing CloudTrail S3 bucket. It does not create a new CloudTrail trail.

Prerequisites:

- An existing S3 bucket containing CloudTrail logs.
- The Lambda package created before `terraform plan`.
- Athena can write query results to the module-managed results bucket.

Configure the source bucket in `terraform.tfvars`:

```hcl
cloudtrail_bucket_name = "my-existing-cloudtrail-bucket"
cloudtrail_prefix      = ""
```

Package the Lambda:

```bash
./modules/cloudtrail_analyzer/package.sh
```

Deploy:

```bash
terraform plan
terraform apply
```

Manually invoke the analyzer:

```bash
aws lambda invoke \
  --function-name "$(terraform output -raw cloudtrail_analyzer_lambda_name)" \
  --payload '{}' \
  response.json
cat response.json
```

Generated reports and Athena results are stored in:

```bash
terraform output -raw cloudtrail_analyzer_results_bucket_name
```

## Enable S3 Backend

The `backend "s3"` block in `main.tf` is commented out intentionally. To enable remote state:

1. Create an S3 bucket for Terraform state.
2. Create a DynamoDB table for state locking with a string partition key named `LockID`.
3. Uncomment the backend block in `main.tf` and set the bucket, key, region, and table name.
4. Run `terraform init -migrate-state`.

## Destroy

```bash
terraform destroy
```

The reports bucket has `force_destroy = false`, so Terraform will not delete it while reports remain. Empty or archive the bucket before destroying if needed.
