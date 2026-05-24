from pathlib import Path

from sensitive_data_scanner.io.text_reader import read_text_lines


def test_read_text_lines_streams_line_numbers(tmp_path: Path) -> None:
    file_path = tmp_path / "sample.txt"
    file_path.write_text("one\ntwo\n", encoding="utf-8")

    assert list(read_text_lines(file_path)) == [(1, "one"), (2, "two")]


def test_read_text_lines_replaces_invalid_encoding(tmp_path: Path) -> None:
    file_path = tmp_path / "mixed.txt"
    file_path.write_bytes(b"good\nbad:\xff\n")

    assert list(read_text_lines(file_path)) == [(1, "good"), (2, "bad:\ufffd")]


def test_read_text_lines_skips_missing_files(tmp_path: Path) -> None:
    assert list(read_text_lines(tmp_path / "missing.txt")) == []
