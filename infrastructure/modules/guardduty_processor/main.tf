resource "aws_guardduty_detector" "this" {
  count  = var.enable_guardduty ? 1 : 0
  enable = true

  tags = {
    Component = "guardduty-processor"
  }
}

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
  name_prefix = "${var.project_name}-${var.environment}-guardduty-processor"
}

resource "aws_sns_topic" "notifications" {
  name = "${local.name_prefix}-notifications"

  tags = {
    Component = "guardduty-processor"
  }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.notifications.arn
  protocol  = "email"
  endpoint  = var.notification_email
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${local.name_prefix}"
  retention_in_days = var.log_retention_days

  tags = {
    Component = "guardduty-processor"
  }
}

resource "aws_iam_role" "lambda" {
  name                 = "${local.name_prefix}-lambda-role"
  assume_role_policy   = data.aws_iam_policy_document.lambda_assume_role.json
  permissions_boundary = var.permissions_boundary

  tags = {
    Component = "guardduty-processor"
  }
}

resource "aws_iam_policy" "remediation" {
  name        = "${local.name_prefix}-remediation"
  description = "Least-privilege remediation permissions for GuardDuty Processor playbooks"
  policy      = file("${path.module}/../../iam_policies/guardduty_remediation.json")

  tags = {
    Component = "guardduty-processor"
  }
}

resource "aws_iam_role_policy_attachment" "remediation" {
  role       = aws_iam_role.lambda.name
  policy_arn = aws_iam_policy.remediation.arn
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
    sid    = "ReadEnrichmentContext"
    effect = "Allow"

    actions = [
      "cloudtrail:LookupEvents",
      "ec2:DescribeInstances",
      "iam:ListAttachedUserPolicies",
      "iam:ListGroupsForUser",
      "iam:ListMFADevices",
      "s3:GetBucketEncryption",
      "s3:GetBucketLogging",
      "s3:GetBucketPublicAccessBlock",
    ]

    resources = ["*"]
  }

  statement {
    sid    = "PublishNotifications"
    effect = "Allow"

    actions = ["sns:Publish"]

    resources = [aws_sns_topic.notifications.arn]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${local.name_prefix}-lambda-policy"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

resource "aws_lambda_function" "guardduty_processor" {
  function_name    = local.name_prefix
  description      = "Event-driven GuardDuty finding processor for Cloud Security Suite"
  role             = aws_iam_role.lambda.arn
  handler          = "lambda_handler_wrapper.lambda_handler"
  runtime          = "python3.11"
  filename         = var.lambda_package_path
  source_code_hash = var.lambda_source_hash
  timeout          = var.lambda_timeout_seconds
  memory_size      = var.lambda_memory_size

  environment {
    variables = {
      AUTO_REMEDIATE    = tostring(var.auto_remediate)
      DRY_RUN           = tostring(var.dry_run)
      SNS_TOPIC_ARN     = aws_sns_topic.notifications.arn
      SLACK_WEBHOOK_URL = var.slack_webhook_url
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.lambda,
    aws_iam_role_policy.lambda,
    aws_iam_role_policy_attachment.remediation,
  ]

  tags = {
    Component = "guardduty-processor"
  }
}

resource "aws_cloudwatch_event_rule" "guardduty_findings" {
  name        = "${local.name_prefix}-findings"
  description = "Route all GuardDuty findings to the Cloud Security Suite GuardDuty Processor"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })

  tags = {
    Component = "guardduty-processor"
  }
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.guardduty_findings.name
  target_id = "guardduty-processor-lambda"
  arn       = aws_lambda_function.guardduty_processor.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromGuardDutyEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.guardduty_processor.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_findings.arn
}
