variable "aws_region" {
  description = "AWS region for regional resources such as Lambda, EventBridge, SNS, and S3."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming and tags."
  type        = string
  default     = "cloud-security-suite"
}

variable "environment" {
  description = "Deployment environment name."
  type        = string
  default     = "prod"
}

variable "notification_email" {
  description = "Email address subscribed to high-severity IAM Auditor SNS alerts."
  type        = string
}

variable "schedule_expression" {
  description = "EventBridge schedule expression for the IAM Auditor Lambda."
  type        = string
  default     = "rate(24 hours)"
}

variable "permissions_boundary" {
  description = "Optional IAM permissions boundary ARN for the Lambda execution role."
  type        = string
  default     = null
}

variable "enable_guardduty" {
  description = "Whether to create and enable a GuardDuty detector in this region."
  type        = bool
  default     = false
}

variable "guardduty_auto_remediate" {
  description = "Whether the GuardDuty Processor may execute remediation playbooks."
  type        = bool
  default     = false
}

variable "guardduty_dry_run" {
  description = "Hard kill switch for GuardDuty remediation. Keep true unless ready to execute actions."
  type        = bool
  default     = true
}

variable "slack_webhook_url" {
  description = "Optional Slack incoming webhook URL for GuardDuty notifications."
  type        = string
  default     = ""
  sensitive   = true
}
