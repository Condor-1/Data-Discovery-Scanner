"""Console reporting for scanner findings."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from typing import TextIO
import sys

from sensitive_data_scanner.detection.masking import mask_sensitive_value
from sensitive_data_scanner.findings import Finding


SEVERITY_COLORS = {
    "HIGH": "\033[31m",
    "MEDIUM": "\033[33m",
    "LOW": "\033[36m",
    "WARNING": "\033[35m",
}
RESET_COLOR = "\033[0m"


def print_findings(
    findings: Iterable[Finding],
    output: TextIO = sys.stdout,
    use_color: bool = True,
    quiet: bool = False,
) -> None:
    """Print scanner findings and a summary to the terminal."""

    finding_list = list(findings)

    if quiet:
        message = (
            f"Findings detected: {len(finding_list)}"
            if finding_list
            else "No findings detected."
        )
        print(message, file=output)
        return

    if not finding_list:
        print("No findings detected.", file=output)
        return

    for finding in finding_list:
        print(format_finding(finding, use_color=use_color), file=output)
        print(file=output)

    print_summary(finding_list, output=output, use_color=use_color)


def format_finding(finding: Finding, use_color: bool = True) -> str:
    """Return a human-readable terminal block for one finding."""

    severity = _format_severity(finding.severity, use_color=use_color)
    matched_value = _format_matched_value(finding)

    return "\n".join(
        (
            f"[{severity}] {finding.finding_type}",
            f"File: {finding.file_path}",
            f"Line: {finding.line_number}",
            f"Match: {matched_value}",
        )
    )


def print_summary(
    findings: Iterable[Finding],
    output: TextIO = sys.stdout,
    use_color: bool = True,
) -> None:
    """Print total counts grouped by severity and finding type."""

    finding_list = list(findings)
    severity_counts = Counter(finding.severity for finding in finding_list)
    type_counts = Counter(finding.finding_type for finding in finding_list)

    print("Summary", file=output)
    print(f"Total findings: {len(finding_list)}", file=output)

    for severity, count in severity_counts.most_common():
        label = _format_severity(severity, use_color=use_color)
        print(f"{label}: {count}", file=output)

    print("By type:", file=output)
    for finding_type, count in type_counts.most_common():
        print(f"- {finding_type}: {count}", file=output)


def _format_severity(severity: str, use_color: bool = True) -> str:
    """Return a severity label with optional ANSI color."""

    normalized = severity.upper()

    if not use_color:
        return normalized

    color = SEVERITY_COLORS.get(normalized)
    if color is None:
        return normalized

    return f"{color}{normalized}{RESET_COLOR}"


def _format_matched_value(finding: Finding) -> str:
    """Mask sensitive values while leaving non-secret warnings readable."""

    if finding.severity == "WARNING" and finding.finding_type != "Hardcoded Credential In Script":
        return finding.matched_value

    return mask_sensitive_value(finding.matched_value)
