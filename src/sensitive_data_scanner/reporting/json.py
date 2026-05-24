"""JSON reporting for scanner findings."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
import json
from typing import Any, TextIO
import sys

from sensitive_data_scanner.detection.masking import mask_sensitive_value
from sensitive_data_scanner.findings import Finding


def build_summary(findings: Iterable[Finding]) -> dict[str, Any]:
    """Build summary counts for a set of findings."""

    finding_list = list(findings)
    severity_counts = Counter(finding.severity for finding in finding_list)
    type_counts = Counter(finding.finding_type for finding in finding_list)

    return {
        "total_findings": len(finding_list),
        "by_severity": dict(severity_counts),
        "by_type": dict(type_counts),
    }


def finding_to_dict(finding: Finding) -> dict[str, Any]:
    """Convert one finding to a JSON-serializable dictionary."""

    return {
        "severity": finding.severity,
        "file_path": str(finding.file_path),
        "line_number": finding.line_number,
        "finding_type": finding.finding_type,
        "matched_value": _format_matched_value(finding),
    }


def findings_to_json_payload(findings: Iterable[Finding], quiet: bool = False) -> dict[str, Any]:
    """Build the JSON payload for scan results."""

    finding_list = list(findings)
    summary = build_summary(finding_list)

    if quiet:
        return {"summary": summary}

    return {
        "findings": [finding_to_dict(finding) for finding in finding_list],
        "summary": summary,
    }


def print_json_findings(
    findings: Iterable[Finding],
    output: TextIO = sys.stdout,
    quiet: bool = False,
) -> None:
    """Print scan results as JSON."""

    payload = findings_to_json_payload(findings, quiet=quiet)
    print(json.dumps(payload, indent=2), file=output)


def _format_matched_value(finding: Finding) -> str:
    """Mask sensitive values while leaving non-secret warnings readable."""

    if finding.severity == "WARNING" and finding.finding_type != "Hardcoded Credential In Script":
        return finding.matched_value

    return mask_sensitive_value(finding.matched_value)
