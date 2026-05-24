from pathlib import Path

import pytest

from sensitive_data_scanner import cli
from sensitive_data_scanner.findings import Finding


def test_build_parser_accepts_scan_command() -> None:
    parser = cli.build_parser()

    args = parser.parse_args(["scan", "./folder", "--no-color", "--format", "json", "--quiet"])

    assert args.command == "scan"
    assert args.target == "./folder"
    assert args.no_color is True
    assert args.format == "json"
    assert args.quiet is True


def test_build_parser_supports_version() -> None:
    parser = cli.build_parser()

    with pytest.raises(SystemExit) as error:
        parser.parse_args(["--version"])

    assert error.value.code == 0


def test_main_scans_target_and_prints_findings(monkeypatch, tmp_path: Path) -> None:
    calls = {}
    fake_findings = [
        Finding(Path("config.py"), 1, "Possible API Key", "abcd1234abcd1234abcd", "HIGH")
    ]

    def fake_scan_path(target: Path):
        calls["target"] = target
        return fake_findings

    def fake_print_findings(findings, use_color: bool = True, quiet: bool = False):
        calls["findings"] = findings
        calls["use_color"] = use_color
        calls["quiet"] = quiet

    monkeypatch.setattr(cli, "scan_path", fake_scan_path)
    monkeypatch.setattr(cli, "print_findings", fake_print_findings)

    exit_code = cli.main(["scan", str(tmp_path), "--no-color"])

    assert exit_code == 1
    assert calls["target"] == tmp_path
    assert calls["findings"] == fake_findings
    assert calls["use_color"] is False
    assert calls["quiet"] is False


def test_main_returns_zero_when_no_findings(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "scan_path", lambda target: [])
    monkeypatch.setattr(cli, "print_findings", lambda findings, use_color=True, quiet=False: None)

    assert cli.main(["scan", str(tmp_path)]) == 0


def test_main_routes_json_output(monkeypatch, tmp_path: Path) -> None:
    calls = {}
    fake_findings = [
        Finding(Path("config.py"), 1, "Possible API Key", "abcd1234abcd1234abcd", "HIGH")
    ]

    monkeypatch.setattr(cli, "scan_path", lambda target: fake_findings)

    def fake_print_json_findings(findings, quiet: bool = False):
        calls["findings"] = findings
        calls["quiet"] = quiet

    monkeypatch.setattr(cli, "print_json_findings", fake_print_json_findings)

    exit_code = cli.main(["scan", str(tmp_path), "--format", "json", "--quiet"])

    assert exit_code == 1
    assert calls["findings"] == fake_findings
    assert calls["quiet"] is True


def test_main_returns_error_for_missing_target(capsys) -> None:
    exit_code = cli.main(["scan", "missing-folder"])

    assert exit_code == 2
    assert "target path does not exist" in capsys.readouterr().err
