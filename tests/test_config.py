from pathlib import Path

from scanner.core.cli import main
from scanner.core.config import discover_config_path, load_project_config
from scanner.core.models import Severity


def test_load_project_config_from_yaml(tmp_path: Path) -> None:
    config_path = tmp_path / ".secret-scanner.yml"
    config_path.write_text(
        "\n".join(
            [
                "severity: high",
                "workers: 6",
                "log_level: info",
                "baseline: baselines/current.json",
                "ignore_file: .secret-scanner-ignore",
                "exclude:",
                "  - vendor",
                "  - coverage",
            ]
        ),
        encoding="utf-8",
    )

    config = load_project_config(config_path)

    assert config.min_severity == Severity.HIGH
    assert config.max_workers == 6
    assert config.log_level == "INFO"
    assert config.baseline_path == (tmp_path / "baselines" / "current.json").resolve()
    assert config.ignore_file_path == (tmp_path / ".secret-scanner-ignore").resolve()
    assert config.exclusions == ["vendor", "coverage"]


def test_discover_config_path_finds_project_file(tmp_path: Path) -> None:
    config_path = tmp_path / ".secret-scanner.yaml"
    config_path.write_text("severity: medium\n", encoding="utf-8")

    assert discover_config_path(tmp_path) == config_path


def test_main_uses_project_config_defaults(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / ".secret-scanner.yml").write_text(
        "\n".join(
            [
                "severity: high",
                "workers: 3",
                "log_level: debug",
                "exclude:",
                "  - vendor",
            ]
        ),
        encoding="utf-8",
    )
    (project / "main.py").write_text('password = "VisiblePassword123"\n', encoding="utf-8")

    captured: dict[str, object] = {}

    def fake_scan_repository(config, console):
        captured["config"] = config
        return [], 1

    monkeypatch.setattr("scanner.core.cli.scan_repository", fake_scan_repository)
    monkeypatch.setattr("scanner.core.cli.render_terminal", lambda *args, **kwargs: None)

    exit_code = main(["scan", str(project)])
    config = captured["config"]

    assert exit_code == 0
    assert config.min_severity == Severity.HIGH
    assert config.max_workers == 3
    assert config.log_level == "DEBUG"
    assert "vendor" in config.exclusions


def test_main_cli_flags_override_project_config(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / ".secret-scanner.yml").write_text(
        "\n".join(
            [
                "severity: critical",
                "workers: 8",
                "log_level: info",
                "exclude:",
                "  - vendor",
            ]
        ),
        encoding="utf-8",
    )
    (project / "main.py").write_text('password = "VisiblePassword123"\n', encoding="utf-8")

    captured: dict[str, object] = {}

    def fake_scan_repository(config, console):
        captured["config"] = config
        return [], 1

    monkeypatch.setattr("scanner.core.cli.scan_repository", fake_scan_repository)
    monkeypatch.setattr("scanner.core.cli.render_terminal", lambda *args, **kwargs: None)

    exit_code = main(
        [
            "scan",
            str(project),
            "--severity",
            "low",
            "--workers",
            "2",
            "--log-level",
            "ERROR",
            "--exclude",
            "build-output",
        ]
    )
    config = captured["config"]

    assert exit_code == 0
    assert config.min_severity == Severity.LOW
    assert config.max_workers == 2
    assert config.log_level == "ERROR"
    assert "vendor" in config.exclusions
    assert "build-output" in config.exclusions
