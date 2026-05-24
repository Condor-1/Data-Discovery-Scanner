"""Safe text file reading helpers."""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path


def read_text_lines(path: str | Path) -> Iterator[tuple[int, str]]:
    """Yield a text file line by line with line numbers.

    Files are decoded as UTF-8 with replacement characters for invalid bytes so
    a scan can continue even when a file contains mixed or imperfect encoding.
    """

    try:
        with Path(path).open("r", encoding="utf-8", errors="replace") as file:
            for line_number, line in enumerate(file, start=1):
                yield line_number, line.rstrip("\r\n")
    except OSError:
        return
