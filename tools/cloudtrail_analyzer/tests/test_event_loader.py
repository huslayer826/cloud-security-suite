from tools.cloudtrail_analyzer.event_loader import load_from_files
from tools.cloudtrail_analyzer.tests.conftest import SAMPLE_DIR


def test_load_from_files_yields_records() -> None:
    events = list(load_from_files(str(SAMPLE_DIR)))

    assert len(events) >= 40
    assert any(event["eventName"] == "ConsoleLogin" for event in events)
