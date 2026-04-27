"""IAM Auditor check registry."""

from tools.iam_auditor.base import BaseCheck
from tools.iam_auditor.checks.access_key_age import AccessKeyAgeCheck
from tools.iam_auditor.checks.password_policy import PasswordPolicyCheck
from tools.iam_auditor.checks.root_mfa import RootMFACheck

CHECK_REGISTRY: list[BaseCheck] = [
    RootMFACheck(),
    PasswordPolicyCheck(),
    AccessKeyAgeCheck(),
]
