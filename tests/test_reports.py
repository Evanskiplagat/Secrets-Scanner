import json
from pathlib import Path

from scanner.core.baseline import write_baseline_file
from scanner.core.models import Detection, Severity
from scanner.reports.renderers import write_csv_report, write_html_report, write_json_report


def sample_detection(tmp_path: Path) -> Detection:
    file_path = tmp_path / "config.py"
    file_path.write_text("placeholder", encoding="utf-8")
    return Detection(
        file_path=file_path,
        line_number=25,
        secret_type="AWS Access Key",
        severity=Severity.CRITICAL,
        preview="AKIA****9KLM",
        rule_id="aws_access_key",
        matched_text="AKIA1234567890ABCD9KLM",
    )


def test_json_report_masks_values(tmp_path: Path) -> None:
    detection = sample_detection(tmp_path)
    destination = tmp_path / "report.json"

    write_json_report(destination, [detection], tmp_path, scanned_files=1)
    payload = json.loads(destination.read_text(encoding="utf-8"))

    assert payload["findings"][0]["preview"] == "AKIA****9KLM"
    assert "matched_text" not in payload["findings"][0]


def test_csv_and_html_reports_are_written(tmp_path: Path) -> None:
    detection = sample_detection(tmp_path)
    csv_destination = tmp_path / "report.csv"
    html_destination = tmp_path / "report.html"

    write_csv_report(csv_destination, [detection], tmp_path)
    write_html_report(html_destination, [detection], tmp_path, scanned_files=1)

    assert "AWS Access Key" in csv_destination.read_text(encoding="utf-8")
    assert "Secret Scanner Report" in html_destination.read_text(encoding="utf-8")


def test_baseline_file_uses_hashes_not_raw_values(tmp_path: Path) -> None:
    detection = sample_detection(tmp_path)
    destination = tmp_path / "baseline.json"

    write_baseline_file(destination, [detection], tmp_path, scanned_files=1)
    payload = json.loads(destination.read_text(encoding="utf-8"))

    finding = payload["findings"][0]
    assert finding["preview"] == "AKIA****9KLM"
    assert "AKIA1234567890ABCD9KLM" not in destination.read_text(encoding="utf-8")
    assert len(finding["secret_hash"]) == 64
