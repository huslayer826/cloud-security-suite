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

output "guardduty_processor_lambda_name" {
  description = "GuardDuty Processor Lambda function name."
  value       = module.guardduty_processor.lambda_function_name
}

output "guardduty_processor_notification_topic_arn" {
  description = "SNS topic ARN for GuardDuty Processor notifications."
  value       = module.guardduty_processor.notification_topic_arn
}

output "guardduty_processor_event_rule_name" {
  description = "EventBridge rule that routes GuardDuty findings."
  value       = module.guardduty_processor.event_rule_name
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID when Terraform creates one."
  value       = module.guardduty_processor.guardduty_detector_id
}

output "cloudtrail_analyzer_lambda_name" {
  description = "CloudTrail Analyzer Lambda function name."
  value       = module.cloudtrail_analyzer.lambda_function_name
}

output "cloudtrail_analyzer_athena_workgroup_name" {
  description = "Athena workgroup used by the CloudTrail Analyzer."
  value       = module.cloudtrail_analyzer.athena_workgroup_name
}

output "cloudtrail_analyzer_glue_database_name" {
  description = "Glue database containing the CloudTrail table."
  value       = module.cloudtrail_analyzer.glue_database_name
}

output "cloudtrail_analyzer_results_bucket_name" {
  description = "S3 bucket for Athena query results and analyzer reports."
  value       = module.cloudtrail_analyzer.athena_results_bucket_name
}

output "cloudtrail_analyzer_alert_topic_arn" {
  description = "SNS topic ARN for CloudTrail Analyzer alerts."
  value       = module.cloudtrail_analyzer.alert_topic_arn
}
