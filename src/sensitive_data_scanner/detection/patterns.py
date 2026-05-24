"""Regex rules for detecting likely sensitive data."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterator


@dataclass(frozen=True)
class PatternRule:
    """A compiled sensitive-data detection rule."""

    name: str
    severity: str
    regex: re.Pattern[str]


@dataclass(frozen=True)
class PatternMatch:
    """A sensitive-data match found in a single line."""

    rule_name: str
    severity: str
    value: str
    start: int
    end: int


SENSITIVE_PATTERNS: tuple[PatternRule, ...] = (
    PatternRule(
        name="Possible API Key",
        severity="HIGH",
        regex=re.compile(
            r"""
            \b
            (?:api[_-]?key|apikey|access[_-]?key|client[_-]?key)
            \b
            \s*[:=]\s*
            ['"]?
            (?P<value>[A-Za-z0-9][A-Za-z0-9_\-]{15,})
            ['"]?
            """,
            flags=re.IGNORECASE | re.VERBOSE,
        ),
    ),
    PatternRule(
        name="Possible Password",
        severity="HIGH",
        regex=re.compile(
            r"""
            \b
            (?:password|passwd|pwd)
            \b
            \s*[:=]\s*
            ['"]?
            (?P<value>[^'"\s]{8,})
            ['"]?
            """,
            flags=re.IGNORECASE | re.VERBOSE,
        ),
    ),
    PatternRule(
        name="Possible Token",
        severity="HIGH",
        regex=re.compile(
            r"""
            \b
            (?:token|auth[_-]?token|access[_-]?token|refresh[_-]?token|bearer)
            \b
            \s*[:=]\s*
            ['"]?
            (?P<value>[A-Za-z0-9._\-]{20,})
            ['"]?
            """,
            flags=re.IGNORECASE | re.VERBOSE,
        ),
    ),
    PatternRule(
        name="Email Address",
        severity="MEDIUM",
        regex=re.compile(
            r"""
            \b
            (?P<value>[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})
            \b
            """,
            flags=re.IGNORECASE | re.VERBOSE,
        ),
    ),
    PatternRule(
        name="Possible Secret",
        severity="HIGH",
        regex=re.compile(
            r"""
            \b
            (?:secret|client[_-]?secret|app[_-]?secret|private[_-]?key|credential)
            \b
            \s*[:=]\s*
            ['"]?
            (?P<value>[^'"\s]{12,})
            ['"]?
            """,
            flags=re.IGNORECASE | re.VERBOSE,
        ),
    ),
)


def find_sensitive_patterns(line: str) -> Iterator[PatternMatch]:
    """Yield all sensitive-data pattern matches found in a line of text."""

    for rule in SENSITIVE_PATTERNS:
        for match in rule.regex.finditer(line):
            value = match.group("value")
            yield PatternMatch(
                rule_name=rule.name,
                severity=rule.severity,
                value=value,
                start=match.start("value"),
                end=match.end("value"),
            )
