# CloudTrail Analyzer Terraform Module

Deploys the CloudTrail Analyzer as a scheduled Lambda backed by Athena and Glue.

## Resources

- Athena workgroup for analyzer queries
- Glue database and CloudTrail table with partition projection by region and date
- S3 bucket for Athena query results and generated analyzer reports
- Scheduled Python 3.11 Lambda function
- SNS topic and email subscription for HIGH/CRITICAL findings
- CloudWatch log group
- IAM role with Athena, Glue, S3, SNS, and logging permissions

## Inputs

The module expects an existing CloudTrail S3 bucket via `cloudtrail_bucket_name`. It does not create a new trail.

## Package

From `infrastructure/`:

```bash
./modules/cloudtrail_analyzer/package.sh
```

## Manual Invocation

```bash
aws lambda invoke \
  --function-name "$(terraform output -raw cloudtrail_analyzer_lambda_name)" \
  --payload '{}' \
  response.json
cat response.json
```
