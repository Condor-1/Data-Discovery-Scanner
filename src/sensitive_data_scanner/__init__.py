"""Sensitive Data Discovery Scanner package."""

from __future__ import annotations

from sensitive_data_scanner.findings import Finding
from sensitive_data_scanner.scanner import collect_findings, scan_file, scan_path

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "__version__",
    "collect_findings",
    "scan_file",
    "scan_path",
]
