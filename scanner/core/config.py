from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from scanner.core.models import Severity


DEFAULT_EXCLUSIONS = {
    ".git",
    "node_modules",
    ".venv",
    "dist",
    "build",
    "__pycache__",
}

SUPPORTED_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".java",
    ".yaml",
    ".yml",
    ".json",
    ".env",
    ".tf",
    ".tfvars",
}

CONFIG_FILENAMES = (
    ".secret-scanner.yml",
    ".secret-scanner.yaml",
    ".secret-scanner.json",
)


@dataclass(slots=True)
class ScanConfig:
    target_path: Path
    exclusions: set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUSIONS))
    min_severity: Severity = Severity.LOW
    max_workers: int | None = None
    log_level: str = "WARNING"
    baseline_path: Path | None = None
    ignore_file_path: Path | None = None


@dataclass(slots=True)
class ProjectConfig:
    min_severity: Severity | None = None
    max_workers: int | None = None
    log_level: str | None = None
    exclusions: list[str] = field(default_factory=list)
    baseline_path: Path | None = None
    ignore_file_path: Path | None = None


def discover_config_path(scan_root: Path) -> Path | None:
    for filename in CONFIG_FILENAMES:
        candidate = scan_root / filename
        if candidate.is_file():
            return candidate
    return None


def load_project_config(config_path: Path) -> ProjectConfig:
    payload = _load_config_payload(config_path)
    if not isinstance(payload, dict):
        raise ValueError("Config file must contain a top-level object.")

    base_dir = config_path.parent
    severity_value = payload.get("severity")
    workers_value = payload.get("workers")
    log_level_value = payload.get("log_level")
    exclude_value = payload.get("exclude", [])
    baseline_value = payload.get("baseline")
    ignore_file_value = payload.get("ignore_file")

    if severity_value is not None and not isinstance(severity_value, str):
        raise ValueError("'severity' must be a string.")
    if workers_value is not None and not isinstance(workers_value, int):
        raise ValueError("'workers' must be an integer.")
    if log_level_value is not None and not isinstance(log_level_value, str):
        raise ValueError("'log_level' must be a string.")

    exclusions = _normalize_exclusions(exclude_value)
    baseline_path = _resolve_optional_path(base_dir, baseline_value, "baseline")
    ignore_file_path = _resolve_optional_path(base_dir, ignore_file_value, "ignore_file")

    return ProjectConfig(
        min_severity=Severity.from_string(severity_value) if severity_value else None,
        max_workers=workers_value,
        log_level=log_level_value.upper() if log_level_value else None,
        exclusions=exclusions,
        baseline_path=baseline_path,
        ignore_file_path=ignore_file_path,
    )


def _load_config_payload(config_path: Path) -> dict[str, object]:
    suffix = config_path.suffix.lower()
    if suffix == ".json":
        return json.loads(config_path.read_text(encoding="utf-8"))
    if suffix in {".yml", ".yaml"}:
        return _parse_simple_yaml(config_path.read_text(encoding="utf-8"))
    raise ValueError(f"Unsupported config format: {config_path.suffix}")


def _normalize_exclusions(value: object) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(entry, str) for entry in value):
        raise ValueError("'exclude' must be a list of strings.")
    return value


def _resolve_optional_path(base_dir: Path, value: object, field_name: str) -> Path | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"'{field_name}' must be a string.")
    return (base_dir / value).resolve()


def _parse_simple_yaml(text: str) -> dict[str, object]:
    result: dict[str, object] = {}
    current_list_key: str | None = None

    for raw_line in text.splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if stripped.startswith("- "):
            if current_list_key is None:
                raise ValueError("List item found before a list key.")
            list_value = result.setdefault(current_list_key, [])
            if not isinstance(list_value, list):
                raise ValueError(f"'{current_list_key}' must be a list.")
            list_value.append(_parse_scalar(stripped[2:].strip()))
            continue

        current_list_key = None
        if ":" not in stripped:
            raise ValueError(f"Invalid config line: {raw_line}")

        key, raw_value = stripped.split(":", 1)
        key = key.strip()
        value = raw_value.strip()
        if not key:
            raise ValueError(f"Invalid config line: {raw_line}")

        if value == "":
            result[key] = []
            current_list_key = key
            continue

        result[key] = _parse_scalar(value)

    return result


def _parse_scalar(value: str) -> object:
    if not value:
        return ""
    if value[0] == value[-1] and value[0] in {'"', "'"}:
        return value[1:-1]
    if value.isdigit():
        return int(value)
    return value
