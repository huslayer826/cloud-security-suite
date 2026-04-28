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
