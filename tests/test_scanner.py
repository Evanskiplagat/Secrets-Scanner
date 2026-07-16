import json
from pathlib import Path

from scanner.core.baseline import filter_suppressed_detections, load_suppressed_fingerprints
from rich.console import Console

from scanner.core.config import ScanConfig
from scanner.core.models import Severity
from scanner.core.scanner import scan_repository


def test_scan_repository_applies_severity_filter(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "config.py").write_text('password = "shorter-but-valid"\n', encoding="utf-8")
    (project / "token.env").write_text('API_KEY="1234567890ABCDEFGHIJ"\n', encoding="utf-8")

    config = ScanConfig(target_path=project, min_severity=Severity.HIGH)
    findings, scanned_files = scan_repository(config, Console(file=None, width=120))

    assert scanned_files == 2
    assert findings
    assert all(finding.severity >= Severity.HIGH for finding in findings)


def test_scan_repository_respects_exclusions(tmp_path: Path) -> None:
    project = tmp_path / "project"
    ignored = project / "node_modules"
    kept = project / "src"
    ignored.mkdir(parents=True)
    kept.mkdir(parents=True)
    (ignored / "ignored.js").write_text('const apiKey = "1234567890ABCDEFGHIJ";\n', encoding="utf-8")
    (kept / "main.py").write_text('password = "VisiblePassword123"\n', encoding="utf-8")

    config = ScanConfig(target_path=project)
    findings, scanned_files = scan_repository(config, Console(file=None, width=120))

    assert scanned_files == 1
    assert findings
    assert all(finding.file_path.name == "main.py" for finding in findings)


def test_baseline_suppresses_matching_findings(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "config.py").write_text('password = "VisiblePassword123"\n', encoding="utf-8")

    config = ScanConfig(target_path=project)
    findings, scanned_files = scan_repository(config, Console(file=None, width=120))
    assert scanned_files == 1
    assert findings

    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "findings": [
                    {"fingerprint": finding.fingerprint(project)}
                    for finding in findings
                ]
            }
        ),
        encoding="utf-8",
    )

    suppressed = load_suppressed_fingerprints(baseline_path, None)
    filtered = filter_suppressed_detections(findings, project, suppressed)

    assert filtered == []


def test_ignore_file_suppresses_matching_findings(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "config.py").write_text('password = "VisiblePassword123"\n', encoding="utf-8")

    config = ScanConfig(target_path=project)
    findings, _ = scan_repository(config, Console(file=None, width=120))
    assert findings

    ignore_path = tmp_path / ".secret-scanner-ignore"
    ignore_path.write_text(
        "# accepted findings\n"
        + "\n".join(finding.fingerprint(project) for finding in findings)
        + "\n",
        encoding="utf-8",
    )

    suppressed = load_suppressed_fingerprints(None, ignore_path)
    filtered = filter_suppressed_detections(findings, project, suppressed)

    assert filtered == []


def test_scan_repository_continues_when_a_file_scan_fails(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    broken_file = project / "broken.py"
    valid_file = project / "valid.py"
    broken_file.write_text('password = "BrokenPassword123"\n', encoding="utf-8")
    valid_file.write_text('password = "VisiblePassword123"\n', encoding="utf-8")

    from scanner.core import scanner as scanner_module

    original_scan_file = scanner_module._scan_file

    def flaky_scan(file_path: Path):
        if file_path == broken_file:
            raise RuntimeError("boom")
        return original_scan_file(file_path)

    monkeypatch.setattr(scanner_module, "_scan_file", flaky_scan)

    findings, scanned_files = scan_repository(ScanConfig(target_path=project), Console(file=None, width=120))

    assert scanned_files == 2
    assert findings
    assert all(finding.file_path == valid_file for finding in findings)
