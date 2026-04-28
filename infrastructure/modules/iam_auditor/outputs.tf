output "reports_bucket_name" {
  description = "S3 bucket that stores IAM Auditor reports."
  value       = aws_s3_bucket.reports.bucket
}

output "lambda_function_name" {
  description = "IAM Auditor Lambda function name."
  value       = aws_lambda_function.iam_auditor.function_name
}

output "alert_topic_arn" {
  description = "SNS topic ARN for high-severity IAM Auditor alerts."
  value       = aws_sns_topic.alerts.arn
}
