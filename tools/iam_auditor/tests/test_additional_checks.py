import json
from datetime import UTC, datetime, timedelta
from typing import Any

from moto import mock_aws

from shared.aws_client import get_client
from shared.findings import Severity
from tools.iam_auditor.checks.access_key_rotation_policy import AccessKeyRotationPolicyCheck
from tools.iam_auditor.checks.admin_privileges import AdminPrivilegesCheck
from tools.iam_auditor.checks.group_policy_review import GroupPolicyReviewCheck
from tools.iam_auditor.checks.inactive_users import InactiveUsersCheck
from tools.iam_auditor.checks.inline_policies import InlinePoliciesCheck
from tools.iam_auditor.checks.mfa_for_console_users import MFAForConsoleUsersCheck
from tools.iam_auditor.checks.role_trust_relationships import RoleTrustRelationshipsCheck
from tools.iam_auditor.checks.unused_access_keys import UnusedAccessKeysCheck
from tools.iam_auditor.checks.unused_roles import UnusedRolesCheck
from tools.iam_auditor.checks.wildcard_policies import WildcardPoliciesCheck

ACCOUNT_ID = "123456789012"
ADMIN_POLICY = json.dumps(
    {"Version": "2012-10-17", "Statement": {"Effect": "Allow", "Action": "*", "Resource": "*"}}
)
READ_ONLY_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": ["*"]},
    }
)
TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        },
    }
)


class StaticPaginator:
    def __init__(self, pages: list[dict[str, Any]]) -> None:
        self.pages = pages

    def paginate(self, **_kwargs: Any) -> list[dict[str, Any]]:
        return self.pages


def create_policy(iam_client, name: str, document: str) -> str:
    return iam_client.create_policy(PolicyName=name, PolicyDocument=document)["Policy"]["Arn"]


def patch_access_key_last_used(iam_client, value: datetime | None) -> None:
    iam_client.get_access_key_last_used = lambda AccessKeyId: {  # noqa: N803
        "AccessKeyLastUsed": {"LastUsedDate": value} if value else {}
    }


@mock_aws
def test_inactive_users_reports_stale_admin_user(monkeypatch) -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_user(UserName="alice")
    policy_arn = create_policy(iam_client, "AdminEquivalent", ADMIN_POLICY)
    iam_client.attach_user_policy(UserName="alice", PolicyArn=policy_arn)
    old_date = datetime.now(UTC) - timedelta(days=91)
    original_get_paginator = iam_client.get_paginator

    def get_paginator(name: str):
        if name == "list_users":
            return StaticPaginator(
                [{"Users": [{"UserName": "alice", "PasswordLastUsed": old_date}]}]
            )
        return original_get_paginator(name)

    monkeypatch.setattr(iam_client, "get_paginator", get_paginator)

    findings = InactiveUsersCheck().run(iam_client, ACCOUNT_ID)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].metadata["has_admin"] is True


@mock_aws
def test_inactive_users_returns_clean_for_recent_activity(monkeypatch) -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_user(UserName="alice")
    recent_date = datetime.now(UTC) - timedelta(days=10)
    monkeypatch.setattr(
        iam_client,
        "get_paginator",
        lambda name: StaticPaginator(
            [{"Users": [{"UserName": "alice", "PasswordLastUsed": recent_date}]}]
        ),
    )

    assert InactiveUsersCheck().run(iam_client, ACCOUNT_ID) == []


@mock_aws
def test_unused_access_keys_reports_never_used_key() -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_user(UserName="alice")
    iam_client.create_access_key(UserName="alice")
    patch_access_key_last_used(iam_client, None)

    findings = UnusedAccessKeysCheck().run(iam_client, ACCOUNT_ID)

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].metadata["reason"] == "never_used"


@mock_aws
def test_unused_access_keys_returns_clean_for_recently_used_key() -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_user(UserName="alice")
    iam_client.create_access_key(UserName="alice")
    patch_access_key_last_used(iam_client, datetime.now(UTC) - timedelta(days=5))

    assert UnusedAccessKeysCheck().run(iam_client, ACCOUNT_ID) == []


@mock_aws
def test_wildcard_policies_reports_customer_managed_admin_policy() -> None:
    iam_client = get_client("iam", region="us-east-1")
    policy_arn = create_policy(iam_client, "DangerousWildcard", ADMIN_POLICY)

    findings = WildcardPoliciesCheck().run(iam_client, ACCOUNT_ID)

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].resource == policy_arn


@mock_aws
def test_wildcard_policies_returns_clean_for_scoped_policy() -> None:
    iam_client = get_client("iam", region="us-east-1")
    create_policy(iam_client, "ReadOnly", READ_ONLY_POLICY)

    assert WildcardPoliciesCheck().run(iam_client, ACCOUNT_ID) == []


@mock_aws
def test_admin_privileges_reports_direct_admin_policy() -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_user(UserName="alice")
    policy_arn = create_policy(iam_client, "AdminEquivalent", ADMIN_POLICY)
    iam_client.attach_user_policy(UserName="alice", PolicyArn=policy_arn)

    findings = AdminPrivilegesCheck().run(iam_client, ACCOUNT_ID)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH
    assert findings[0].metadata["admin_policies"] == ["AdminEquivalent"]


@mock_aws
def test_admin_privileges_returns_clean_for_group_based_policy() -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_user(UserName="alice")
    iam_client.create_group(GroupName="admins")
    policy_arn = create_policy(iam_client, "AdminEquivalent", ADMIN_POLICY)
    iam_client.attach_group_policy(GroupName="admins", PolicyArn=policy_arn)
    iam_client.add_user_to_group(GroupName="admins", UserName="alice")

    assert AdminPrivilegesCheck().run(iam_client, ACCOUNT_ID) == []


@mock_aws
def test_inline_policies_reports_user_and_role_inline_policies() -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_user(UserName="alice")
    iam_client.put_user_policy(
        UserName="alice", PolicyName="InlineUser", PolicyDocument=READ_ONLY_POLICY
    )
    iam_client.create_role(RoleName="app-role", AssumeRolePolicyDocument=TRUST_POLICY)
    iam_client.put_role_policy(
        RoleName="app-role", PolicyName="InlineRole", PolicyDocument=READ_ONLY_POLICY
    )

    findings = InlinePoliciesCheck().run(iam_client, ACCOUNT_ID)

    assert len(findings) == 2
    assert {finding.metadata["entity_type"] for finding in findings} == {"user", "role"}


@mock_aws
def test_inline_policies_returns_clean_without_inline_policies() -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_user(UserName="alice")
    iam_client.create_role(RoleName="app-role", AssumeRolePolicyDocument=TRUST_POLICY)

    assert InlinePoliciesCheck().run(iam_client, ACCOUNT_ID) == []


@mock_aws
def test_role_trust_relationships_reports_wildcard_principal() -> None:
    iam_client = get_client("iam", region="us-east-1")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"},
        }
    )
    iam_client.create_role(RoleName="public-role", AssumeRolePolicyDocument=trust)

    findings = RoleTrustRelationshipsCheck().run(iam_client, ACCOUNT_ID)

    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


@mock_aws
def test_role_trust_relationships_returns_clean_with_external_id() -> None:
    iam_client = get_client("iam", region="us-east-1")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::210987654321:root"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"sts:ExternalId": "vendor-123"}},
            },
        }
    )
    iam_client.create_role(RoleName="vendor-role", AssumeRolePolicyDocument=trust)

    assert RoleTrustRelationshipsCheck().run(iam_client, ACCOUNT_ID) == []


@mock_aws
def test_unused_roles_reports_never_used_role() -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_role(RoleName="unused-role", AssumeRolePolicyDocument=TRUST_POLICY)

    findings = UnusedRolesCheck().run(iam_client, ACCOUNT_ID)

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert findings[0].metadata["reason"] == "never_used"


@mock_aws
def test_unused_roles_returns_clean_for_recently_used_role(monkeypatch) -> None:
    iam_client = get_client("iam", region="us-east-1")
    recent_date = datetime.now(UTC) - timedelta(days=5)
    role: dict[str, Any] = {
        "RoleName": "used-role",
        "Arn": f"arn:aws:iam::{ACCOUNT_ID}:role/used-role",
        "RoleLastUsed": {"LastUsedDate": recent_date},
    }
    monkeypatch.setattr(
        iam_client,
        "get_paginator",
        lambda name: StaticPaginator([{"Roles": [role]}]),
    )

    assert UnusedRolesCheck().run(iam_client, ACCOUNT_ID) == []


@mock_aws
def test_mfa_for_console_users_reports_login_profile_without_mfa() -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_user(UserName="alice")
    iam_client.create_login_profile(UserName="alice", Password="Password123!@#")

    findings = MFAForConsoleUsersCheck().run(iam_client, ACCOUNT_ID)

    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


@mock_aws
def test_mfa_for_console_users_returns_clean_without_console_access() -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_user(UserName="alice")

    assert MFAForConsoleUsersCheck().run(iam_client, ACCOUNT_ID) == []


@mock_aws
def test_group_policy_review_reports_empty_group_with_policy() -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_group(GroupName="future-admins")
    policy_arn = create_policy(iam_client, "ReadOnly", READ_ONLY_POLICY)
    iam_client.attach_group_policy(GroupName="future-admins", PolicyArn=policy_arn)

    findings = GroupPolicyReviewCheck().run(iam_client, ACCOUNT_ID)

    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW
    assert findings[0].metadata["attached_policies"] == ["ReadOnly"]


@mock_aws
def test_group_policy_review_returns_clean_for_group_with_member() -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_user(UserName="alice")
    iam_client.create_group(GroupName="admins")
    policy_arn = create_policy(iam_client, "ReadOnly", READ_ONLY_POLICY)
    iam_client.attach_group_policy(GroupName="admins", PolicyArn=policy_arn)
    iam_client.add_user_to_group(GroupName="admins", UserName="alice")

    assert GroupPolicyReviewCheck().run(iam_client, ACCOUNT_ID) == []


@mock_aws
def test_access_key_rotation_policy_reports_two_active_keys() -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_user(UserName="alice")
    iam_client.create_access_key(UserName="alice")
    iam_client.create_access_key(UserName="alice")

    findings = AccessKeyRotationPolicyCheck().run(iam_client, ACCOUNT_ID)

    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM
    assert len(findings[0].metadata["active_key_suffixes"]) == 2


@mock_aws
def test_access_key_rotation_policy_returns_clean_for_one_active_key() -> None:
    iam_client = get_client("iam", region="us-east-1")
    iam_client.create_user(UserName="alice")
    iam_client.create_access_key(UserName="alice")

    assert AccessKeyRotationPolicyCheck().run(iam_client, ACCOUNT_ID) == []
