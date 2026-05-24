from sensitive_data_scanner.detection.patterns import find_sensitive_patterns


def _types_for(line: str) -> list[str]:
    return [match.rule_name for match in find_sensitive_patterns(line)]


def test_detects_api_key() -> None:
    matches = list(find_sensitive_patterns("api_key = 'abcd1234abcd1234abcd'"))

    assert len(matches) == 1
    assert matches[0].rule_name == "Possible API Key"
    assert matches[0].value == "abcd1234abcd1234abcd"
    assert matches[0].severity == "HIGH"


def test_detects_password_token_email_and_secret() -> None:
    assert "Possible Password" in _types_for('password = "CorrectHorse123"')
    assert "Possible Token" in _types_for("token = abcdefghijklmnopqrstuvwxyz123456")
    assert "Email Address" in _types_for("Contact admin@example.com for help")
    assert "Possible Secret" in _types_for("client_secret = supersecretvalue123")


def test_ignores_short_password_values() -> None:
    assert "Possible Password" not in _types_for("password = short")


def test_returns_multiple_matches_from_one_line() -> None:
    matches = list(
        find_sensitive_patterns(
            "email=admin@example.com token=abcdefghijklmnopqrstuvwxyz123456"
        )
    )

    assert [match.rule_name for match in matches] == ["Possible Token", "Email Address"]
