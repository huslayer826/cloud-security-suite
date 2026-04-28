data "aws_caller_identity" "current" {}

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

locals {
  name_prefix         = "${var.project_name}-${var.environment}-iam-auditor"
  reports_bucket_name = lower("${var.project_name}-${var.environment}-${data.aws_caller_identity.current.account_id}-iam-auditor-reports")
}

resource "aws_s3_bucket" "reports" {
  bucket        = local.reports_bucket_name
  force_destroy = false

  tags = {
    Component = "iam-auditor"
  }
}

resource "aws_s3_bucket_public_access_block" "reports" {
  bucket = aws_s3_bucket.reports.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    id     = "transition-reports-to-glacier"
    status = "Enabled"

    filter {
      prefix = "reports/"
    }

    transition {
      days          = 90
      storage_class = "GLACIER"
    }
  }
}

resource "aws_sns_topic" "alerts" {
  name = "${local.name_prefix}-alerts"

  tags = {
    Component = "iam-auditor"
  }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.name_prefix}"
  retention_in_days = 30

  tags = {
    Component = "iam-auditor"
  }
}

resource "aws_iam_role" "lambda" {
  name                 = "${local.name_prefix}-lambda-role"
  assume_role_policy   = data.aws_iam_policy_document.lambda_assume_role.json
  permissions_boundary = var.permissions_boundary

  tags = {
    Component = "iam-auditor"
  }
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid    = "WriteCloudWatchLogs"
    effect = "Allow"

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]

    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    sid    = "ReadIamPosture"
    effect = "Allow"

    actions = [
      "iam:GetAccountPasswordPolicy",
      "iam:GetAccountSummary",
      "iam:GetAccessKeyLastUsed",
      "iam:GetGroup",
      "iam:GetLoginProfile",
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:GetUserPolicy",
      "iam:ListAccessKeys",
      "iam:ListAttachedGroupPolicies",
      "iam:ListAttachedUserPolicies",
      "iam:ListEntitiesForPolicy",
      "iam:ListGroupPolicies",
      "iam:ListGroups",
      "iam:ListMFADevices",
      "iam:ListPolicies",
      "iam:ListRolePolicies",
      "iam:ListRoles",
      "iam:ListUserPolicies",
      "iam:ListUsers",
      "sts:GetCallerIdentity",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "WriteReports"
    effect = "Allow"

    actions = ["s3:PutObject"]

    resources = ["${aws_s3_bucket.reports.arn}/reports/*"]
  }

  statement {
    sid    = "PublishHighSeverityAlerts"
    effect = "Allow"

    actions = ["sns:Publish"]

    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${local.name_prefix}-lambda-policy"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

resource "aws_lambda_function" "iam_auditor" {
  function_name    = local.name_prefix
  description      = "Scheduled IAM Auditor for Cloud Security Suite"
  role             = aws_iam_role.lambda.arn
  handler          = "lambda_handler.lambda_handler"
  runtime          = "python3.11"
  filename         = var.lambda_package_path
  source_code_hash = var.lambda_source_hash
  timeout          = var.lambda_timeout_seconds
  memory_size      = var.lambda_memory_size

  environment {
    variables = {
      REPORT_BUCKET = aws_s3_bucket.reports.bucket
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
      AWS_REGION    = var.aws_region
      PROJECT_NAME  = var.project_name
      ENVIRONMENT   = var.environment
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.lambda,
  ]

  tags = {
    Component = "iam-auditor"
  }
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${local.name_prefix}-schedule"
  description         = "Scheduled execution for the Cloud Security Suite IAM Auditor"
  schedule_expression = var.schedule_expression

  tags = {
    Component = "iam-auditor"
  }
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "iam-auditor-lambda"
  arn       = aws_lambda_function.iam_auditor.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.iam_auditor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
