output "lambda_function_name" {
  description = "GuardDuty Processor Lambda function name."
  value       = aws_lambda_function.guardduty_processor.function_name
}

output "notification_topic_arn" {
  description = "SNS topic ARN for GuardDuty Processor human-review notifications."
  value       = aws_sns_topic.notifications.arn
}

output "event_rule_name" {
  description = "EventBridge rule name that routes GuardDuty findings."
  value       = aws_cloudwatch_event_rule.guardduty_findings.name
}

output "guardduty_detector_id" {
  description = "GuardDuty detector ID when this module creates one."
  value       = var.enable_guardduty ? aws_guardduty_detector.this[0].id : null
}
