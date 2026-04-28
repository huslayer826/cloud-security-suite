"""Lambda handler wrapper for Terraform packaging."""

from tools.guardduty_processor.lambda_handler import lambda_handler

__all__ = ["lambda_handler"]
