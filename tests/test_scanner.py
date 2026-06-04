from pathlib import Path

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
