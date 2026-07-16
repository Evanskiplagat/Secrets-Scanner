from __future__ import annotations

import csv
from html import escape
import json
from collections import Counter
from pathlib import Path

from rich.console import Console
from rich.table import Table

from scanner.core.models import Detection, ScanSummary, Severity


def _ensure_parent_directory(destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)


def build_summary(detections: list[Detection], scanned_files: int) -> ScanSummary:
    counts = Counter(detection.severity.label() for detection in detections)
    for severity in Severity:
        counts.setdefault(severity.label(), 0)
    return ScanSummary(
        scanned_files=scanned_files,
        findings=len(detections),
        by_severity=dict(counts),
    )


def render_terminal(console: Console, detections: list[Detection], base_path: Path, scanned_files: int) -> None:
    summary = build_summary(detections, scanned_files)
    console.print()
    console.print(f"[bold]Scanned files:[/bold] {summary.scanned_files}")
    console.print(f"[bold]Findings:[/bold] {summary.findings}")
    console.print(
        "[bold]Severity counts:[/bold] "
        + ", ".join(f"{name}={count}" for name, count in summary.by_severity.items())
    )

    if not detections:
        console.print("[green]No secrets detected.[/green]")
        return

    table = Table(title="Secret Scanner Findings", show_lines=False)
    table.add_column("File", overflow="fold")
    table.add_column("Line", justify="right")
    table.add_column("Type")
    table.add_column("Severity")
    table.add_column("Preview", overflow="fold")

    for detection in sorted(
        detections, key=lambda item: (-int(item.severity), str(item.file_path), item.line_number)
    ):
        table.add_row(
            str(detection.file_path.relative_to(base_path)),
            str(detection.line_number),
            detection.secret_type,
            detection.severity.label(),
            detection.preview,
        )
    console.print(table)


def write_json_report(destination: Path, detections: list[Detection], base_path: Path, scanned_files: int) -> None:
    _ensure_parent_directory(destination)
    payload = {
        "summary": build_summary(detections, scanned_files).to_dict(),
        "findings": [detection.to_report_dict(base_path) for detection in detections],
    }
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_csv_report(destination: Path, detections: list[Detection], base_path: Path) -> None:
    _ensure_parent_directory(destination)
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["file", "line", "type", "severity", "preview", "rule_id"])
        writer.writeheader()
        for detection in detections:
            writer.writerow(detection.to_report_dict(base_path))


def write_html_report(destination: Path, detections: list[Detection], base_path: Path, scanned_files: int) -> None:
    _ensure_parent_directory(destination)
    summary = build_summary(detections, scanned_files)
    rows = "\n".join(
        (
            "<tr>"
            f"<td>{escape(str(detection.file_path.relative_to(base_path)))}</td>"
            f"<td>{detection.line_number}</td>"
            f"<td>{escape(detection.secret_type)}</td>"
            f"<td>{escape(detection.severity.label())}</td>"
            f"<td>{escape(detection.preview)}</td>"
            "</tr>"
        )
        for detection in detections
    )
    report_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Secret Scanner Report</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 2rem; color: #111827; }}
    .summary {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; }}
    .card {{ padding: 1rem; border: 1px solid #d1d5db; border-radius: 8px; min-width: 140px; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border: 1px solid #e5e7eb; padding: 0.75rem; text-align: left; vertical-align: top; }}
    th {{ background: #f3f4f6; }}
  </style>
</head>
<body>
  <h1>Secret Scanner Report</h1>
  <div class="summary">
    <div class="card"><strong>Scanned files</strong><br>{summary.scanned_files}</div>
    <div class="card"><strong>Findings</strong><br>{summary.findings}</div>
    <div class="card"><strong>Critical</strong><br>{summary.by_severity["Critical"]}</div>
    <div class="card"><strong>High</strong><br>{summary.by_severity["High"]}</div>
    <div class="card"><strong>Medium</strong><br>{summary.by_severity["Medium"]}</div>
    <div class="card"><strong>Low</strong><br>{summary.by_severity["Low"]}</div>
  </div>
  <table>
    <thead>
      <tr><th>File</th><th>Line</th><th>Type</th><th>Severity</th><th>Preview</th></tr>
    </thead>
    <tbody>
      {rows}
    </tbody>
  </table>
</body>
</html>
"""
    destination.write_text(report_html, encoding="utf-8")


def write_sarif_report(destination: Path, detections: list[Detection], base_path: Path, scanned_files: int) -> None:
    _ensure_parent_directory(destination)
    summary = build_summary(detections, scanned_files)
    rules = {
        detection.rule_id: {
            "id": detection.rule_id,
            "name": detection.secret_type,
            "shortDescription": {"text": detection.secret_type},
            "properties": {
                "security-severity": str(int(detection.severity) * 2.5),
                "precision": "medium",
                "tags": ["security", "secrets", detection.severity.label().lower()],
            },
            "help": {
                "text": (
                    f"Potential {detection.secret_type} detected. "
                    "Review the finding and rotate or remove the secret if it is valid."
                )
            },
        }
        for detection in detections
    }
    results = [
        {
            "ruleId": detection.rule_id,
            "level": _sarif_level(detection.severity),
            "message": {
                "text": (
                    f"{detection.secret_type} detected with masked preview "
                    f"'{detection.preview}' at line {detection.line_number}."
                )
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": detection.file_path.relative_to(base_path).as_posix(),
                        },
                        "region": {
                            "startLine": detection.line_number,
                        },
                    }
                }
            ],
            "partialFingerprints": {
                "secretScannerFingerprint": detection.fingerprint(base_path),
            },
            "properties": {
                "secret_type": detection.secret_type,
                "severity": detection.severity.label(),
                "preview": detection.preview,
            },
        }
        for detection in detections
    ]
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Secret Scanner",
                        "informationUri": "https://sarifweb.azurewebsites.net/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {
                        "executionSuccessful": True,
                    }
                ],
                "properties": {
                    "summary": summary.to_dict(),
                },
            }
        ],
    }
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _sarif_level(severity: Severity) -> str:
    if severity >= Severity.HIGH:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"
