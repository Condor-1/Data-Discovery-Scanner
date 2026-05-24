"""Input helpers for walking and reading files."""

from __future__ import annotations

from sensitive_data_scanner.io.file_type import (
    get_extension,
    is_config_or_text_file,
    is_programming_file,
    is_script_file,
    is_supported_file,
)
from sensitive_data_scanner.io.file_walker import walk_files
from sensitive_data_scanner.io.text_reader import read_text_lines

__all__ = [
    "get_extension",
    "is_config_or_text_file",
    "is_programming_file",
    "is_script_file",
    "is_supported_file",
    "read_text_lines",
    "walk_files",
]
