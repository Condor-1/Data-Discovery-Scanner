"""Main scanning engine for sensitive data discovery."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

from sensitive_data_scanner.detection.patterns import find_sensitive_patterns
from sensitive_data_scanner.detection.script_warnings import find_script_warnings
from sensitive_data_scanner.findings import Finding
from sensitive_data_scanner.io.file_type import is_script_file, is_supported_file
from sensitive_data_scanner.io.file_walker import walk_files
from sensitive_data_scanner.io.text_reader import read_text_lines


def scan_path(target: str | Path) -> Iterator[Finding]:
    """Scan a file or directory and yield findings as they are discovered."""

    for file_path in walk_files(target):
        if not is_supported_file(file_path):
            continue

        yield from scan_file(file_path)


def scan_file(file_path: str | Path) -> Iterator[Finding]:
    """Scan one text file line by line."""

    path = Path(file_path)
    should_check_script_warnings = is_script_file(path)

    for line_number, line in read_text_lines(path):
        for match in find_sensitive_patterns(line):
            yield Finding(
                file_path=path,
                line_number=line_number,
                finding_type=match.rule_name,
                matched_value=match.value,
                severity=match.severity,
            )

        if should_check_script_warnings:
            for warning in find_script_warnings(line):
                yield Finding(
                    file_path=path,
                    line_number=line_number,
                    finding_type=warning.warning_type,
                    matched_value=warning.value,
                    severity="WARNING",
                )


def collect_findings(target: str | Path) -> list[Finding]:
    """Scan a target and return all findings as a list."""

    return list(scan_path(target))
