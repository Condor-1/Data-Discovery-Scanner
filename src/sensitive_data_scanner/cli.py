"""Command-line interface for sensitive-data-scanner."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from sensitive_data_scanner import __version__
from sensitive_data_scanner.reporting.console import print_findings
from sensitive_data_scanner.reporting.json import print_json_findings
from sensitive_data_scanner.scanner import scan_path


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""

    parser = argparse.ArgumentParser(
        prog="sdscan",
        description="Scan files and folders for exposed sensitive data.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"sdscan {__version__}",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="scan a file or folder")
    scan_parser.add_argument("target", help="file or folder path to scan")
    scan_parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable colored terminal output",
    )
    scan_parser.add_argument(
        "--format",
        choices=("text", "json"),
        default="text",
        help="output format",
    )
    scan_parser.add_argument(
        "--quiet",
        action="store_true",
        help="only show a compact result",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI."""

    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "scan":
        target = Path(args.target)
        if not target.exists():
            print(f"Error: target path does not exist: {target}", file=sys.stderr)
            return 2

        findings = scan_path(target)
        findings_list = list(findings)
        if args.format == "json":
            print_json_findings(findings_list, quiet=args.quiet)
        else:
            print_findings(findings_list, use_color=not args.no_color, quiet=args.quiet)

        return 1 if findings_list else 0

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
