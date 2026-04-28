output "iam_auditor_reports_bucket_name" {
  description = "S3 bucket that stores IAM Auditor JSON and HTML reports."
  value       = module.iam_auditor.reports_bucket_name
}

output "iam_auditor_lambda_name" {
  description = "IAM Auditor Lambda function name."
  value       = module.iam_auditor.lambda_function_name
}

output "iam_auditor_alert_topic_arn" {
  description = "SNS topic ARN for high-severity IAM Auditor alerts."
  value       = module.iam_auditor.alert_topic_arn
}
