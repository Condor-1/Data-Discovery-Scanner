import sensitive_data_scanner
from sensitive_data_scanner import Finding


def test_package_exposes_version() -> None:
    assert sensitive_data_scanner.__version__ == "0.1.0"


def test_package_exports_finding_model() -> None:
    assert Finding.__name__ == "Finding"
