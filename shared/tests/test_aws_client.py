import os

from moto import mock_aws

from shared.aws_client import get_account_id, get_client


@mock_aws
def test_get_client_returns_configured_client() -> None:
    client = get_client("s3", region="us-west-2")

    assert client.meta.service_model.service_name == "s3"
    assert client.meta.region_name == "us-west-2"


@mock_aws
def test_get_account_id_returns_sts_identity_account() -> None:
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

    assert get_account_id() == "123456789012"
