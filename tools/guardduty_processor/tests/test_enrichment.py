from datetime import UTC, datetime

from shared.findings import Severity
from tools.guardduty_processor.enrichment import enrich_ec2, enrich_iam_user, enrich_s3
from tools.guardduty_processor.lambda_handler import build_finding
from tools.guardduty_processor.tests.conftest import load_fixture


class FakeEC2Client:
    def describe_instances(self, InstanceIds):  # noqa: N802, N803
        return {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": InstanceIds[0],
                            "VpcId": "vpc-12345678",
                            "SubnetId": "subnet-12345678",
                            "Tags": [{"Key": "Name", "Value": "demo-instance"}],
                            "IamInstanceProfile": {
                                "Arn": "arn:aws:iam::123456789012:instance-profile/app"
                            },
                        }
                    ]
                }
            ]
        }


class FakeCloudTrailClient:
    def lookup_events(self, **_kwargs):
        return {
            "Events": [
                {
                    "EventName": "RunInstances",
                    "EventTime": datetime.now(UTC),
                    "Username": "alice",
                }
            ]
        }


class FakeIAMClient:
    def list_groups_for_user(self, UserName):  # noqa: N802, N803
        return {"Groups": [{"GroupName": "developers"}]}

    def list_attached_user_policies(self, UserName):  # noqa: N802, N803
        return {"AttachedPolicies": [{"PolicyName": "ReadOnlyAccess"}]}

    def list_mfa_devices(self, UserName):  # noqa: N802, N803
        return {"MFADevices": [{"SerialNumber": "arn:aws:iam::123456789012:mfa/alice"}]}


class FakeS3Client:
    def get_public_access_block(self, Bucket):  # noqa: N802, N803
        return {"PublicAccessBlockConfiguration": {"BlockPublicAcls": True}}

    def get_bucket_encryption(self, Bucket):  # noqa: N802, N803
        return {"ServerSideEncryptionConfiguration": {"Rules": []}}

    def get_bucket_logging(self, Bucket):  # noqa: N802, N803
        return {"LoggingEnabled": {"TargetBucket": "logs"}}


def test_ec2_enrichment_adds_instance_context(monkeypatch) -> None:
    monkeypatch.setattr(
        "tools.guardduty_processor.enrichment.boto3.client",
        lambda service, region_name=None: FakeEC2Client()
        if service == "ec2"
        else FakeCloudTrailClient(),
    )
    detail = load_fixture("ec2_port_probe.json")["detail"]

    context = enrich_ec2(detail["resource"], "us-east-1")

    assert context["instance_id"] == "i-0123456789abcdef0"
    assert context["tags"]["Name"] == "demo-instance"
    assert context["recent_cloudtrail_events"][0]["event_name"] == "RunInstances"


def test_iam_enrichment_adds_user_context(monkeypatch) -> None:
    monkeypatch.setattr(
        "tools.guardduty_processor.enrichment.boto3.client",
        lambda service, region_name=None: FakeIAMClient()
        if service == "iam"
        else FakeCloudTrailClient(),
    )
    detail = load_fixture("iam_exfiltration.json")["detail"]

    context = enrich_iam_user(detail["resource"], "us-east-1")

    assert context["groups"] == ["developers"]
    assert context["attached_policies"] == ["ReadOnlyAccess"]
    assert context["mfa_enabled"] is True


def test_s3_enrichment_adds_bucket_context(monkeypatch) -> None:
    monkeypatch.setattr(
        "tools.guardduty_processor.enrichment.boto3.client",
        lambda service, region_name=None: FakeS3Client()
        if service == "s3"
        else FakeCloudTrailClient(),
    )
    detail = load_fixture("s3_anomaly.json")["detail"]

    context = enrich_s3(detail["resource"], "us-east-1")

    assert context["bucket_name"] == "demo-public-bucket"
    public_access = context["public_access_block"]["PublicAccessBlockConfiguration"]
    assert public_access["BlockPublicAcls"] is True


def test_enrich_finding_adds_expected_branch(monkeypatch) -> None:
    monkeypatch.setattr(
        "tools.guardduty_processor.enrichment.enrich_iam_user",
        lambda resource, region: {"groups": ["security"]},
    )
    detail = load_fixture("iam_exfiltration.json")["detail"]
    finding = build_finding(detail)

    enriched = __import__(
        "tools.guardduty_processor.enrichment",
        fromlist=["enrich_finding"],
    ).enrich_finding(finding, detail)

    assert enriched.metadata["enrichment"]["iam_user"]["groups"] == ["security"]
    assert enriched.severity == Severity.HIGH
