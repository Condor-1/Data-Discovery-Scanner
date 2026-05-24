"""File type helpers for scanner-supported files."""

from __future__ import annotations

from pathlib import Path

from sensitive_data_scanner.config import (
    CONFIG_TEXT_EXTENSIONS,
    PROGRAMMING_EXTENSIONS,
    SCRIPT_EXTENSIONS,
    SUPPORTED_EXTENSIONS,
)


def get_extension(file_path: str | Path) -> str:
    """Return a lowercase file extension for a path."""

    path = Path(file_path)
    suffix = path.suffix.lower()

    if suffix:
        return suffix

    name = path.name.lower()
    if name in SUPPORTED_EXTENSIONS:
        return name

    return ""


def is_supported_file(file_path: str | Path) -> bool:
    """Return True when a file extension is supported by the scanner."""

    return get_extension(file_path) in SUPPORTED_EXTENSIONS


def is_programming_file(file_path: str | Path) -> bool:
    """Return True when a path looks like a supported programming file."""

    return get_extension(file_path) in PROGRAMMING_EXTENSIONS


def is_config_or_text_file(file_path: str | Path) -> bool:
    """Return True when a path looks like a supported config or text file."""

    return get_extension(file_path) in CONFIG_TEXT_EXTENSIONS


def is_script_file(file_path: str | Path) -> bool:
    """Return True when a path looks like a supported shell script file."""

    return get_extension(file_path) in SCRIPT_EXTENSIONS
