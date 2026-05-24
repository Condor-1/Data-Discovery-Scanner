from io import StringIO
from pathlib import Path

from sensitive_data_scanner.findings import Finding
from sensitive_data_scanner.reporting.console import format_finding, print_findings


def test_format_finding_masks_sensitive_values() -> None:
    finding = Finding(
        file_path=Path("config.py"),
        line_number=12,
        finding_type="Possible API Key",
        matched_value="sk_live_abcdefghijklmnop",
        severity="HIGH",
    )

    output = format_finding(finding, use_color=False)

    assert "sk_live_****************" in output
    assert "abcdefghijklmnop" not in output


def test_format_finding_leaves_non_secret_warning_readable() -> None:
    finding = Finding(
        file_path=Path("cleanup.bat"),
        line_number=2,
        finding_type="Dangerous System Deletion Command",
        matched_value="del /s /q C:\\Windows\\*",
        severity="WARNING",
    )

    output = format_finding(finding, use_color=False)

    assert "del /s /q C:\\Windows\\*" in output


def test_print_findings_outputs_summary_counts() -> None:
    findings = [
        Finding(Path("a.py"), 1, "Possible API Key", "abcd1234abcd1234abcd", "HIGH"),
        Finding(Path("b.txt"), 2, "Email Address", "admin@example.com", "MEDIUM"),
    ]
    output = StringIO()

    print_findings(findings, output=output, use_color=False)

    text = output.getvalue()
    assert "Total findings: 2" in text
    assert "HIGH: 1" in text
    assert "MEDIUM: 1" in text
    assert "- Possible API Key: 1" in text


def test_print_findings_handles_empty_results() -> None:
    output = StringIO()

    print_findings([], output=output, use_color=False)

    assert output.getvalue().strip() == "No findings detected."


def test_print_findings_quiet_outputs_compact_count() -> None:
    findings = [
        Finding(Path("a.py"), 1, "Possible API Key", "abcd1234abcd1234abcd", "HIGH"),
    ]
    output = StringIO()

    print_findings(findings, output=output, use_color=False, quiet=True)

    assert output.getvalue().strip() == "Findings detected: 1"
