variable "project_name" {
  type = string
}

variable "environment" {
  type = string
}

variable "aws_region" {
  type = string
}

variable "notification_email" {
  type = string
}

variable "cloudtrail_bucket_name" {
  type = string
}

variable "cloudtrail_prefix" {
  type    = string
  default = ""
}

variable "lambda_package_path" {
  type = string
}

variable "lambda_source_hash" {
  type    = string
  default = null
}

variable "schedule_expression" {
  type    = string
  default = "rate(24 hours)"
}

variable "lookback_days" {
  type    = number
  default = 1
}

variable "lambda_timeout_seconds" {
  type    = number
  default = 900
}

variable "lambda_memory_size" {
  type    = number
  default = 1024
}

variable "permissions_boundary" {
  type    = string
  default = null
}
