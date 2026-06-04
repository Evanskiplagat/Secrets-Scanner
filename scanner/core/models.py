from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import IntEnum
from pathlib import Path


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_string(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]

    def label(self) -> str:
        return self.name.title()


@dataclass(frozen=True, slots=True)
class Detection:
    file_path: Path
    line_number: int
    secret_type: str
    severity: Severity
    preview: str
    rule_id: str
    matched_text: str

    def to_report_dict(self, base_path: Path) -> dict[str, str | int]:
        return {
            "file": str(self.file_path.relative_to(base_path)),
            "line": self.line_number,
            "type": self.secret_type,
            "severity": self.severity.label(),
            "preview": self.preview,
            "rule_id": self.rule_id,
        }


@dataclass(frozen=True, slots=True)
class ScanSummary:
    scanned_files: int
    findings: int
    by_severity: dict[str, int]

    def to_dict(self) -> dict[str, int | dict[str, int]]:
        return asdict(self)

