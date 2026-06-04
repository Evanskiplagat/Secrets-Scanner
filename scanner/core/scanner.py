from __future__ import annotations

import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from scanner.core.config import ScanConfig
from scanner.core.models import Detection
from scanner.detectors.engine import detect_secrets
from scanner.utils.files import iter_candidate_files, read_text_safely

LOGGER = logging.getLogger(__name__)


def _scan_file(file_path: Path) -> list[Detection]:
    content = read_text_safely(file_path)
    if not content:
        return []
    return detect_secrets(file_path, content)


def scan_repository(config: ScanConfig, console: Console) -> tuple[list[Detection], int]:
    candidate_files = iter_candidate_files(config.target_path, config.exclusions)
    max_workers = config.max_workers or min(32, (os.cpu_count() or 4) * 2)
    filtered_findings: list[Detection] = []

    LOGGER.info("Scanning %s files with %s workers", len(candidate_files), max_workers)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total} files"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task_id = progress.add_task("Scanning repository", total=len(candidate_files) or 1)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {executor.submit(_scan_file, file_path): file_path for file_path in candidate_files}
            for future in as_completed(future_map):
                findings = future.result()
                filtered_findings.extend(
                    detection for detection in findings if detection.severity >= config.min_severity
                )
                progress.advance(task_id)

    return filtered_findings, len(candidate_files)

