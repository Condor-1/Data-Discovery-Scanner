"""Recursive file discovery for scanner targets."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
from pathlib import Path

from sensitive_data_scanner.config import DEFAULT_IGNORED_DIRECTORIES


def walk_files(
    target: str | Path,
    ignored_directories: Iterable[str] = DEFAULT_IGNORED_DIRECTORIES,
) -> Iterator[Path]:
    """Yield file paths under a target file or directory.

    Ignored directory names are skipped at every depth.
    """

    target_path = Path(target)
    ignored_names = set(ignored_directories)

    if target_path.is_file():
        yield target_path
        return

    if not target_path.is_dir():
        return

    for path in target_path.rglob("*"):
        if _has_ignored_parent(path, target_path, ignored_names):
            continue

        if path.is_file():
            yield path


def _has_ignored_parent(path: Path, root: Path, ignored_names: set[str]) -> bool:
    """Return True when a path sits inside an ignored directory."""

    try:
        relative_parts = path.relative_to(root).parts
    except ValueError:
        relative_parts = path.parts

    return any(part in ignored_names for part in relative_parts[:-1])
