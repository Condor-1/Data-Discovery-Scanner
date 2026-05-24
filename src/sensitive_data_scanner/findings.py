"""Data models for scanner findings."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Finding:
    """A single scanner finding."""

    file_path: Path
    line_number: int
    finding_type: str
    matched_value: str
    severity: str
