# CloudTrail Analyzer

## Overview

The CloudTrail Analyzer reviews CloudTrail events from local log files or Athena query results and emits normalized Cloud Security Suite findings. It is designed for investigation workflows, detection engineering demos, and batch analysis of account activity.

## Detection Library

| ID | Detection | Severity |
| --- | --- | --- |
| CT-001 | Root account usage | CRITICAL |
| CT-002 | Console login failure burst | MEDIUM |
| CT-003 | Console login from a new country | HIGH |
| CT-004 | Possible privilege escalation sequence | HIGH |
| CT-005 | Mass resource deletion | HIGH |
| CT-006 | Security logging disabled | CRITICAL |
| CT-007 | AccessDenied API call burst | MEDIUM |
| CT-008 | New IAM user created | MEDIUM |

## Local Usage

```bash
python -m tools.cloudtrail_analyzer \
  --mode local \
  --input-dir tools/cloudtrail_analyzer/sample_data \
  --output all \
  --output-dir ./reports
```

## Athena Setup

Example external table for CloudTrail logs in S3:

```sql
CREATE EXTERNAL TABLE cloudtrail_logs (
  eventVersion string,
  userIdentity string,
  eventTime string,
  eventSource string,
  eventName string,
  awsRegion string,
  sourceIPAddress string,
  userAgent string,
  errorCode string,
  errorMessage string,
  requestParameters string,
  responseElements string,
  additionalEventData string,
  requestID string,
  eventID string,
  readOnly string,
  resources array<struct<ARN:string,accountId:string,type:string>>,
  eventType string,
  recipientAccountId string
)
PARTITIONED BY (`region` string, `year` string, `month` string, `day` string)
ROW FORMAT SERDE 'org.openx.data.jsonserde.JsonSerDe'
LOCATION 's3://YOUR-CLOUDTRAIL-BUCKET/AWSLogs/YOUR-ACCOUNT-ID/CloudTrail/';
```

Partition by region and date to keep queries inexpensive. Repair or add partitions after new logs arrive:

```sql
MSCK REPAIR TABLE cloudtrail_logs;
```

Example query:

```sql
SELECT *
FROM cloudtrail_logs
WHERE eventtime >= '2026-04-27T00:00:00Z'
  AND eventtime < '2026-04-28T00:00:00Z';
```

CLI Athena mode:

```bash
python -m tools.cloudtrail_analyzer \
  --mode athena \
  --athena-database security_logs \
  --athena-workgroup primary \
  --athena-output-location s3://my-athena-results/cloudtrail-analyzer/ \
  --start-time 2026-04-27T00:00:00Z \
  --end-time 2026-04-28T00:00:00Z \
  --output html
```

## Required Permissions

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "athena:GetQueryExecution",
        "athena:GetQueryResults",
        "athena:StartQueryExecution",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutObject",
        "glue:GetDatabase",
        "glue:GetTable",
        "glue:GetPartitions"
      ],
      "Resource": "*"
    }
  ]
}
```

For local mode, no AWS permissions are required.

## Extending Detections

1. Create a module under `tools/cloudtrail_analyzer/detections/`.
2. Subclass `BaseDetection`.
3. Set `detection_id`, `title`, `severity`, and `description`.
4. Implement `analyze(events)` and return shared `Finding` objects.
5. Register the detection in `detections/__init__.py`.
6. Add sample events and tests.
