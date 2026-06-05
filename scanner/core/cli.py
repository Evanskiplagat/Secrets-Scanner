from __future__ import annotations

import argparse
import logging
from pathlib import Path

from rich.console import Console

from scanner import __version__
from scanner.core.baseline import (
    filter_suppressed_detections,
    load_suppressed_fingerprints,
    write_baseline_file,
)
from scanner.core.config import DEFAULT_EXCLUSIONS, ScanConfig
from scanner.core.models import Severity
from scanner.core.scanner import scan_repository
from scanner.reports.renderers import (
    render_terminal,
    write_csv_report,
    write_html_report,
    write_json_report,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secret-scanner",
        description="Scan repositories and files for accidentally exposed secrets.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Scan a directory recursively.")
    scan_parser.add_argument("target", type=Path, help="Directory or file to scan.")
    scan_parser.add_argument(
        "--json",
        nargs="?",
        const="secret-scan-report.json",
        metavar="PATH",
        help="Write a JSON report. Uses secret-scan-report.json when no path is supplied.",
    )
    scan_parser.add_argument(
        "--csv",
        nargs="?",
        const="secret-scan-report.csv",
        metavar="PATH",
        help="Write a CSV report. Uses secret-scan-report.csv when no path is supplied.",
    )
    scan_parser.add_argument(
        "--html",
        nargs="?",
        const="secret-scan-report.html",
        metavar="PATH",
        help="Write an HTML report. Uses secret-scan-report.html when no path is supplied.",
    )
    scan_parser.add_argument(
        "--baseline",
        metavar="PATH",
        help="Suppress findings present in a baseline JSON file.",
    )
    scan_parser.add_argument(
        "--write-baseline",
        nargs="?",
        const="secret-scan-baseline.json",
        metavar="PATH",
        help="Write a baseline JSON file. Uses secret-scan-baseline.json when no path is supplied.",
    )
    scan_parser.add_argument(
        "--ignore-file",
        metavar="PATH",
        help="Load newline-delimited finding fingerprints to suppress.",
    )
    scan_parser.add_argument(
        "--severity",
        choices=[severity.name.lower() for severity in Severity],
        default="low",
        help="Minimum severity to include in output.",
    )
    scan_parser.add_argument(
        "--exclude",
        action="append",
        default=[],
        metavar="NAME",
        help="Add a directory or file segment to exclude. Can be passed multiple times.",
    )
    scan_parser.add_argument(
        "--workers",
        type=int,
        default=None,
        help="Maximum worker threads for file scanning.",
    )
    scan_parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="WARNING",
        help="Logging verbosity.",
    )
    return parser


def configure_logging(level: str) -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _resolve_scan_root(target: Path) -> Path:
    resolved = target.resolve()
    return resolved.parent if resolved.is_file() else resolved


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    configure_logging(args.log_level)
    console = Console()

    if args.command != "scan":
        parser.error("Unsupported command")

    target = args.target.resolve()
    if not target.exists():
        console.print(f"[red]Target not found:[/red] {target}")
        return 2

    exclusions = set(DEFAULT_EXCLUSIONS)
    exclusions.update(args.exclude)
    scan_root = _resolve_scan_root(target)
    config = ScanConfig(
        target_path=target,
        exclusions=exclusions,
        min_severity=Severity.from_string(args.severity),
        max_workers=args.workers,
        log_level=args.log_level,
        baseline_path=Path(args.baseline).resolve() if args.baseline else None,
        ignore_file_path=Path(args.ignore_file).resolve() if args.ignore_file else None,
    )

    detections, scanned_files = scan_repository(config, console)
    suppressed_fingerprints = load_suppressed_fingerprints(config.baseline_path, config.ignore_file_path)
    detections = filter_suppressed_detections(detections, scan_root, suppressed_fingerprints)
    render_terminal(console, detections, scan_root, scanned_files)

    if args.json:
        write_json_report(Path(args.json), detections, scan_root, scanned_files)
        console.print(f"[cyan]JSON report written:[/cyan] {args.json}")
    if args.csv:
        write_csv_report(Path(args.csv), detections, scan_root)
        console.print(f"[cyan]CSV report written:[/cyan] {args.csv}")
    if args.html:
        write_html_report(Path(args.html), detections, scan_root, scanned_files)
        console.print(f"[cyan]HTML report written:[/cyan] {args.html}")
    if args.write_baseline:
        write_baseline_file(Path(args.write_baseline), detections, scan_root, scanned_files)
        console.print(f"[cyan]Baseline file written:[/cyan] {args.write_baseline}")

    highest_severity = max((detection.severity for detection in detections), default=Severity.LOW)
    return 1 if highest_severity >= Severity.HIGH and detections else 0
