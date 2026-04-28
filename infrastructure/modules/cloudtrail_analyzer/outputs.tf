output "lambda_function_name" {
  value = aws_lambda_function.cloudtrail_analyzer.function_name
}

output "athena_workgroup_name" {
  value = aws_athena_workgroup.cloudtrail.name
}

output "glue_database_name" {
  value = aws_glue_catalog_database.cloudtrail.name
}

output "athena_results_bucket_name" {
  value = aws_s3_bucket.athena_results.bucket
}

output "alert_topic_arn" {
  value = aws_sns_topic.alerts.arn
}
