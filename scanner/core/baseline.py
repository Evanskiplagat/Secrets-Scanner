from __future__ import annotations

import json
from pathlib import Path

from scanner.core.models import Detection
from scanner.reports.renderers import build_summary


def load_suppressed_fingerprints(
    baseline_path: Path | None,
    ignore_file_path: Path | None,
) -> set[str]:
    suppressed: set[str] = set()

    if baseline_path is not None and baseline_path.exists():
        payload = json.loads(baseline_path.read_text(encoding="utf-8"))
        for finding in payload.get("findings", []):
            fingerprint = finding.get("fingerprint")
            if isinstance(fingerprint, str) and fingerprint:
                suppressed.add(fingerprint)

    if ignore_file_path is not None and ignore_file_path.exists():
        for line in ignore_file_path.read_text(encoding="utf-8").splitlines():
            entry = line.strip()
            if entry and not entry.startswith("#"):
                suppressed.add(entry)

    return suppressed


def filter_suppressed_detections(
    detections: list[Detection],
    base_path: Path,
    suppressed_fingerprints: set[str],
) -> list[Detection]:
    if not suppressed_fingerprints:
        return detections
    return [
        detection
        for detection in detections
        if detection.fingerprint(base_path) not in suppressed_fingerprints
    ]


def write_baseline_file(
    destination: Path,
    detections: list[Detection],
    base_path: Path,
    scanned_files: int,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "summary": build_summary(detections, scanned_files).to_dict(),
        "findings": [detection.to_baseline_record(base_path) for detection in detections],
    }
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
