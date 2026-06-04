from __future__ import annotations

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


@dataclass(slots=True)
class ScanConfig:
    target_path: Path
    exclusions: set[str] = field(default_factory=lambda: set(DEFAULT_EXCLUSIONS))
    min_severity: Severity = Severity.LOW
    max_workers: int | None = None
    log_level: str = "WARNING"

