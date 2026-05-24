from sensitive_data_scanner.io.file_type import (
    get_extension,
    is_config_or_text_file,
    is_programming_file,
    is_script_file,
    is_supported_file,
)


def test_get_extension_handles_normal_extensions() -> None:
    assert get_extension("app.PY") == ".py"
    assert get_extension("notes.txt") == ".txt"


def test_get_extension_handles_dotenv_files() -> None:
    assert get_extension(".env") == ".env"


def test_supported_file_types() -> None:
    assert is_supported_file("app.py")
    assert is_supported_file("settings.json")
    assert is_supported_file(".env")
    assert not is_supported_file("image.png")


def test_file_type_categories() -> None:
    assert is_programming_file("main.go")
    assert is_config_or_text_file("config.yaml")
    assert is_script_file("cleanup.bat")
