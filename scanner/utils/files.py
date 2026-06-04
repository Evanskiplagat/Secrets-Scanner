from __future__ import annotations

import logging
from pathlib import Path

from scanner.core.config import SUPPORTED_SUFFIXES

LOGGER = logging.getLogger(__name__)


def should_scan_file(path: Path) -> bool:
    if path.name.startswith(".env"):
        return True
    return path.suffix.lower() in SUPPORTED_SUFFIXES


def iter_candidate_files(root: Path, exclusions: set[str]) -> list[Path]:
    if root.is_file():
        if any(part in exclusions for part in root.parts):
            return []
        return [root] if should_scan_file(root) else []

    files: list[Path] = []
    for path in root.rglob("*"):
        if any(part in exclusions for part in path.parts):
            continue
        if path.is_file() and should_scan_file(path):
            files.append(path)
    LOGGER.debug("Discovered %s candidate files under %s", len(files), root)
    return files


def read_text_safely(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        LOGGER.warning("Failed reading %s: %s", path, exc)
        return ""
