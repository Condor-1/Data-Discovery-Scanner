from pathlib import Path

from sensitive_data_scanner.io.file_walker import walk_files


def test_walk_files_returns_files_recursively(tmp_path: Path) -> None:
    nested = tmp_path / "src"
    nested.mkdir()
    file_path = nested / "app.py"
    file_path.write_text("print('hello')", encoding="utf-8")

    assert list(walk_files(tmp_path)) == [file_path]


def test_walk_files_skips_ignored_directories(tmp_path: Path) -> None:
    kept = tmp_path / "app.py"
    kept.write_text("print('hello')", encoding="utf-8")

    ignored_dir = tmp_path / "node_modules"
    ignored_dir.mkdir()
    ignored_file = ignored_dir / "package.json"
    ignored_file.write_text("{}", encoding="utf-8")

    assert list(walk_files(tmp_path)) == [kept]


def test_walk_files_accepts_single_file(tmp_path: Path) -> None:
    file_path = tmp_path / "config.txt"
    file_path.write_text("value", encoding="utf-8")

    assert list(walk_files(file_path)) == [file_path]
