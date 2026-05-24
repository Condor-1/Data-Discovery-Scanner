import json
from io import StringIO
from pathlib import Path

from sensitive_data_scanner.findings import Finding
from sensitive_data_scanner.reporting.json import (
    finding_to_dict,
    findings_to_json_payload,
    print_json_findings,
)


def test_finding_to_dict_masks_sensitive_values() -> None:
    finding = Finding(
        file_path=Path("config.py"),
        line_number=12,
        finding_type="Possible API Key",
        matched_value="sk_live_abcdefghijklmnop",
        severity="HIGH",
    )

    data = finding_to_dict(finding)

    assert data["matched_value"] == "sk_live_****************"
    assert data["file_path"] == "config.py"


def test_findings_to_json_payload_includes_summary_and_findings() -> None:
    findings = [
        Finding(Path("a.py"), 1, "Possible API Key", "abcd1234abcd1234abcd", "HIGH"),
        Finding(Path("b.txt"), 2, "Email Address", "admin@example.com", "MEDIUM"),
    ]

    payload = findings_to_json_payload(findings)

    assert len(payload["findings"]) == 2
    assert payload["summary"]["total_findings"] == 2
    assert payload["summary"]["by_severity"] == {"HIGH": 1, "MEDIUM": 1}


def test_findings_to_json_payload_quiet_only_includes_summary() -> None:
    findings = [
        Finding(Path("a.py"), 1, "Possible API Key", "abcd1234abcd1234abcd", "HIGH"),
    ]

    payload = findings_to_json_payload(findings, quiet=True)

    assert payload == {
        "summary": {
            "total_findings": 1,
            "by_severity": {"HIGH": 1},
            "by_type": {"Possible API Key": 1},
        }
    }


def test_print_json_findings_outputs_valid_json() -> None:
    output = StringIO()
    findings = [
        Finding(Path("a.py"), 1, "Possible API Key", "abcd1234abcd1234abcd", "HIGH"),
    ]

    print_json_findings(findings, output=output)

    payload = json.loads(output.getvalue())
    assert payload["summary"]["total_findings"] == 1
