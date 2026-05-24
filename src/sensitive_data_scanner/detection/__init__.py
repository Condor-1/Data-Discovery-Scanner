"""Detection rules for sensitive data and script warnings."""

from __future__ import annotations

from sensitive_data_scanner.detection.masking import mask_sensitive_value
from sensitive_data_scanner.detection.patterns import find_sensitive_patterns
from sensitive_data_scanner.detection.script_warnings import find_script_warnings

__all__ = [
    "find_script_warnings",
    "find_sensitive_patterns",
    "mask_sensitive_value",
]
