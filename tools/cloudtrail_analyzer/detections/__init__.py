"""CloudTrail Analyzer detection registry."""

from tools.cloudtrail_analyzer.base import BaseDetection
from tools.cloudtrail_analyzer.detections.console_login_failures import (
    ConsoleLoginFailuresDetection,
)
from tools.cloudtrail_analyzer.detections.console_login_new_country import (
    ConsoleLoginNewCountryDetection,
)
from tools.cloudtrail_analyzer.detections.disabled_logging import DisabledLoggingDetection
from tools.cloudtrail_analyzer.detections.mass_resource_deletion import (
    MassResourceDeletionDetection,
)
from tools.cloudtrail_analyzer.detections.new_iam_user_creation import NewIamUserCreationDetection
from tools.cloudtrail_analyzer.detections.privilege_escalation import PrivilegeEscalationDetection
from tools.cloudtrail_analyzer.detections.root_account_usage import RootAccountUsageDetection
from tools.cloudtrail_analyzer.detections.unauthorized_api_calls import (
    UnauthorizedApiCallsDetection,
)


def detection_registry(known_countries_file: str | None = None) -> list[BaseDetection]:
    return [
        RootAccountUsageDetection(),
        ConsoleLoginFailuresDetection(),
        ConsoleLoginNewCountryDetection(known_countries_file=known_countries_file),
        PrivilegeEscalationDetection(),
        MassResourceDeletionDetection(),
        DisabledLoggingDetection(),
        UnauthorizedApiCallsDetection(),
        NewIamUserCreationDetection(),
    ]
