from tools.cloudtrail_analyzer.main import main
from tools.cloudtrail_analyzer.tests.conftest import SAMPLE_DIR


def test_main_local_html_report(tmp_path) -> None:
    exit_code = main(
        [
            "--mode",
            "local",
            "--input-dir",
            str(SAMPLE_DIR),
            "--output",
            "html",
            "--output-dir",
            str(tmp_path),
            "--known-countries-file",
            str(tmp_path / "countries.json"),
        ]
    )

    report = tmp_path / "cloudtrail-analyzer-report.html"
    assert exit_code == 1
    assert report.exists()
    assert "CloudTrail Analyzer" in report.read_text(encoding="utf-8")
