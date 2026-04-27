"""IAM Auditor check registry."""

from tools.iam_auditor.base import BaseCheck
from tools.iam_auditor.checks.access_key_age import AccessKeyAgeCheck
from tools.iam_auditor.checks.access_key_rotation_policy import AccessKeyRotationPolicyCheck
from tools.iam_auditor.checks.admin_privileges import AdminPrivilegesCheck
from tools.iam_auditor.checks.group_policy_review import GroupPolicyReviewCheck
from tools.iam_auditor.checks.inactive_users import InactiveUsersCheck
from tools.iam_auditor.checks.inline_policies import InlinePoliciesCheck
from tools.iam_auditor.checks.mfa_for_console_users import MFAForConsoleUsersCheck
from tools.iam_auditor.checks.password_policy import PasswordPolicyCheck
from tools.iam_auditor.checks.role_trust_relationships import RoleTrustRelationshipsCheck
from tools.iam_auditor.checks.root_mfa import RootMFACheck
from tools.iam_auditor.checks.unused_access_keys import UnusedAccessKeysCheck
from tools.iam_auditor.checks.unused_roles import UnusedRolesCheck
from tools.iam_auditor.checks.wildcard_policies import WildcardPoliciesCheck

CHECK_REGISTRY: list[BaseCheck] = [
    RootMFACheck(),
    PasswordPolicyCheck(),
    AccessKeyAgeCheck(),
    InactiveUsersCheck(),
    UnusedAccessKeysCheck(),
    WildcardPoliciesCheck(),
    AdminPrivilegesCheck(),
    InlinePoliciesCheck(),
    RoleTrustRelationshipsCheck(),
    UnusedRolesCheck(),
    MFAForConsoleUsersCheck(),
    GroupPolicyReviewCheck(),
    AccessKeyRotationPolicyCheck(),
]
