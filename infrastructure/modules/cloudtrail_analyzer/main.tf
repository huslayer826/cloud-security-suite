data "aws_caller_identity" "current" {}

locals {
  name_prefix                  = "${var.project_name}-${var.environment}-cloudtrail-analyzer"
  database_name                = replace("${var.project_name}_${var.environment}_cloudtrail", "-", "_")
  athena_results_bucket        = lower("${var.project_name}-${var.environment}-${data.aws_caller_identity.current.account_id}-athena-results")
  normalized_cloudtrail_prefix = trim(var.cloudtrail_prefix, "/")
  cloudtrail_location          = local.normalized_cloudtrail_prefix == "" ? "s3://${var.cloudtrail_bucket_name}" : "s3://${var.cloudtrail_bucket_name}/${local.normalized_cloudtrail_prefix}"
}

resource "aws_s3_bucket" "athena_results" {
  bucket        = local.athena_results_bucket
  force_destroy = false

  tags = {
    Component = "cloudtrail-analyzer"
  }
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_athena_workgroup" "cloudtrail" {
  name          = local.name_prefix
  force_destroy = true

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.bucket}/athena-results/"

      encryption_configuration {
        encryption_option = "SSE_S3"
      }
    }
  }

  tags = {
    Component = "cloudtrail-analyzer"
  }
}

resource "aws_glue_catalog_database" "cloudtrail" {
  name = local.database_name
}

resource "aws_glue_catalog_table" "cloudtrail_logs" {
  name          = "cloudtrail_logs"
  database_name = aws_glue_catalog_database.cloudtrail.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    EXTERNAL                    = "TRUE"
    "projection.enabled"        = "true"
    "projection.region.type"    = "enum"
    "projection.region.values"  = var.aws_region
    "projection.year.type"      = "integer"
    "projection.year.range"     = "2020,2035"
    "projection.month.type"     = "integer"
    "projection.month.range"    = "1,12"
    "projection.month.digits"   = "2"
    "projection.day.type"       = "integer"
    "projection.day.range"      = "1,31"
    "projection.day.digits"     = "2"
    "storage.location.template" = "${local.cloudtrail_location}/AWSLogs/${data.aws_caller_identity.current.account_id}/CloudTrail/$${region}/$${year}/$${month}/$${day}/"
    "classification"            = "json"
    "compressionType"           = "gzip"
    "typeOfData"                = "file"
  }

  partition_keys {
    name = "region"
    type = "string"
  }

  partition_keys {
    name = "year"
    type = "string"
  }

  partition_keys {
    name = "month"
    type = "string"
  }

  partition_keys {
    name = "day"
    type = "string"
  }

  storage_descriptor {
    location      = local.cloudtrail_location
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      name                  = "cloudtrail-json-serde"
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
    }

    columns {
      name = "eventversion"
      type = "string"
    }

    columns {
      name = "useridentity"
      type = "string"
    }

    columns {
      name = "eventtime"
      type = "string"
    }

    columns {
      name = "eventsource"
      type = "string"
    }

    columns {
      name = "eventname"
      type = "string"
    }

    columns {
      name = "awsregion"
      type = "string"
    }

    columns {
      name = "sourceipaddress"
      type = "string"
    }

    columns {
      name = "useragent"
      type = "string"
    }

    columns {
      name = "errorcode"
      type = "string"
    }

    columns {
      name = "errormessage"
      type = "string"
    }

    columns {
      name = "requestparameters"
      type = "string"
    }

    columns {
      name = "responseelements"
      type = "string"
    }

    columns {
      name = "additionaleventdata"
      type = "string"
    }

    columns {
      name = "requestid"
      type = "string"
    }

    columns {
      name = "eventid"
      type = "string"
    }

    columns {
      name = "readonly"
      type = "string"
    }

    columns {
      name = "resources"
      type = "array<struct<ARN:string,accountId:string,type:string>>"
    }

    columns {
      name = "eventtype"
      type = "string"
    }

    columns {
      name = "recipientaccountid"
      type = "string"
    }
  }
}

resource "aws_sns_topic" "alerts" {
  name = "${local.name_prefix}-alerts"

  tags = {
    Component = "cloudtrail-analyzer"
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
    Component = "cloudtrail-analyzer"
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

resource "aws_iam_role" "lambda" {
  name                 = "${local.name_prefix}-lambda-role"
  assume_role_policy   = data.aws_iam_policy_document.lambda_assume_role.json
  permissions_boundary = var.permissions_boundary

  tags = {
    Component = "cloudtrail-analyzer"
  }
}

data "aws_iam_policy_document" "lambda" {
  statement {
    sid       = "WriteLogs"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }

  statement {
    sid    = "RunAthenaQueries"
    effect = "Allow"
    actions = [
      "athena:GetQueryExecution",
      "athena:GetQueryResults",
      "athena:StartQueryExecution",
    ]
    resources = [aws_athena_workgroup.cloudtrail.arn]
  }

  statement {
    sid       = "ReadGlueTable"
    effect    = "Allow"
    actions   = ["glue:GetDatabase", "glue:GetTable", "glue:GetPartitions"]
    resources = ["*"]
  }

  statement {
    sid       = "ReadCloudTrailLogs"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.cloudtrail_bucket_name}", "arn:aws:s3:::${var.cloudtrail_bucket_name}/*"]
  }

  statement {
    sid       = "WriteAthenaResultsAndReports"
    effect    = "Allow"
    actions   = ["s3:GetObject", "s3:ListBucket", "s3:PutObject"]
    resources = [aws_s3_bucket.athena_results.arn, "${aws_s3_bucket.athena_results.arn}/*"]
  }

  statement {
    sid       = "PublishAlerts"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "${local.name_prefix}-lambda-policy"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

resource "aws_lambda_function" "cloudtrail_analyzer" {
  function_name    = local.name_prefix
  description      = "Scheduled CloudTrail Analyzer for Cloud Security Suite"
  role             = aws_iam_role.lambda.arn
  handler          = "lambda_handler_wrapper.lambda_handler"
  runtime          = "python3.11"
  filename         = var.lambda_package_path
  source_code_hash = var.lambda_source_hash
  timeout          = var.lambda_timeout_seconds
  memory_size      = var.lambda_memory_size

  environment {
    variables = {
      ATHENA_DATABASE        = aws_glue_catalog_database.cloudtrail.name
      ATHENA_WORKGROUP       = aws_athena_workgroup.cloudtrail.name
      ATHENA_OUTPUT_LOCATION = "s3://${aws_s3_bucket.athena_results.bucket}/athena-results/"
      REPORT_BUCKET          = aws_s3_bucket.athena_results.bucket
      SNS_TOPIC_ARN          = aws_sns_topic.alerts.arn
      LOOKBACK_DAYS          = tostring(var.lookback_days)
    }
  }

  depends_on = [aws_cloudwatch_log_group.lambda, aws_iam_role_policy.lambda]

  tags = {
    Component = "cloudtrail-analyzer"
  }
}

resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${local.name_prefix}-schedule"
  description         = "Daily CloudTrail Analyzer execution"
  schedule_expression = var.schedule_expression

  tags = {
    Component = "cloudtrail-analyzer"
  }
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "cloudtrail-analyzer-lambda"
  arn       = aws_lambda_function.cloudtrail_analyzer.arn
}

resource "aws_lambda_permission" "allow_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.cloudtrail_analyzer.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}
