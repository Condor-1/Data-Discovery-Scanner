from pathlib import Path

from sensitive_data_scanner.scanner import collect_findings


def test_collect_findings_scans_supported_files(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("API_KEY=abcd1234abcd1234abcd\n", encoding="utf-8")

    ignored_file = tmp_path / "image.png"
    ignored_file.write_text("password = ShouldNotBeScanned123", encoding="utf-8")

    findings = collect_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file_path == env_file
    assert findings[0].finding_type == "Possible API Key"


def test_collect_findings_includes_script_warnings(tmp_path: Path) -> None:
    script_file = tmp_path / "cleanup.bat"
    script_file.write_text("del /s /q C:\\Windows\\System32\\*\n", encoding="utf-8")

    findings = collect_findings(tmp_path)

    assert len(findings) == 1
    assert findings[0].file_path == script_file
    assert findings[0].finding_type == "Dangerous System Deletion Command"
    assert findings[0].severity == "WARNING"
