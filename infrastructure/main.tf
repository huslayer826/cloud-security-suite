terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }

  # Uncomment and configure after creating the state bucket and lock table.
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "cloud-security-suite/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "your-terraform-lock-table"
  #   encrypt        = true
  # }
}

module "iam_auditor" {
  source = "./modules/iam_auditor"

  project_name          = var.project_name
  environment           = var.environment
  aws_region            = var.aws_region
  notification_email    = var.notification_email
  schedule_expression   = var.schedule_expression
  lambda_package_path   = "${path.module}/modules/iam_auditor/iam_auditor_lambda.zip"
  lambda_source_hash    = try(filebase64sha256("${path.module}/modules/iam_auditor/iam_auditor_lambda.zip"), null)
  permissions_boundary  = var.permissions_boundary
}
