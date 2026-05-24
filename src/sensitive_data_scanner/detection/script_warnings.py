"""Suspicious script behavior warning rules."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Iterator


@dataclass(frozen=True)
class ScriptWarningRule:
    """A compiled warning rule for script files."""

    name: str
    regex: re.Pattern[str]


@dataclass(frozen=True)
class ScriptWarningMatch:
    """A suspicious script pattern found in a single line."""

    warning_type: str
    value: str
    start: int
    end: int


SCRIPT_WARNING_PATTERNS: tuple[ScriptWarningRule, ...] = (
    ScriptWarningRule(
        name="Suspicious Eval Execution",
        regex=re.compile(
            r"""
            \b
            (?:eval|exec|invoke-expression|iex)
            \s*\(
            """,
            flags=re.IGNORECASE | re.VERBOSE,
        ),
    ),
    ScriptWarningRule(
        name="Suspicious Download Command",
        regex=re.compile(
            r"""
            \b
            (?:
                curl|wget|invoke-webrequest|iwr|invoke-restmethod|
                start-bitstransfer|downloadfile|downloadstring
            )
            \b
            """,
            flags=re.IGNORECASE | re.VERBOSE,
        ),
    ),
    ScriptWarningRule(
        name="Suspicious Encoded PowerShell",
        regex=re.compile(
            r"""
            \b
            powershell(?:\.exe)?
            \b
            .*
            \s
            (?:-enc|-encodedcommand)
            \b
            """,
            flags=re.IGNORECASE | re.VERBOSE,
        ),
    ),
    ScriptWarningRule(
        name="Suspicious Hidden PowerShell",
        regex=re.compile(
            r"""
            \b
            powershell(?:\.exe)?
            \b
            .*
            (?:-w|-windowstyle)
            \s+
            hidden
            \b
            """,
            flags=re.IGNORECASE | re.VERBOSE,
        ),
    ),
    ScriptWarningRule(
        name="Dangerous System Deletion Command",
        regex=re.compile(
            r"""
            (?:
                (?:
                    \b(?:del|erase)\b
                    (?=[^\r\n]*(?:/s|/q|\*|c:\\\s*$))
                    |
                    \b(?:rd|rmdir)\b
                )
                .*
                (?:
                    c:\\(?:$|\s|[\\*])
                    |c:\\windows(?:\\system32)?(?:\b|[\\*])
                    |c:\\users(?:\b|[\\*])
                    |%systemroot%(?:\b|[\\*])
                    |%windir%(?:\b|[\\*])
                    |%userprofile%(?:\b|[\\*])
                    |%homepath%(?:\b|[\\*])
                    |system32(?:\b|[\\*])
                    |(?:desktop|documents|downloads)(?:\\\*|\s*$)
                )
                |
                \brm\s+-[rf]+\s+
                (?:
                    /|/etc|/bin|/usr|/var|/home
                )\b
            )
            """,
            flags=re.IGNORECASE | re.VERBOSE,
        ),
    ),
    ScriptWarningRule(
        name="Hardcoded Credential In Script",
        regex=re.compile(
            r"""
            \b
            (?:password|passwd|pwd|token|secret|credential)
            \b
            \s*[:=]\s*
            ['"]?
            [^'"\s]{8,}
            ['"]?
            """,
            flags=re.IGNORECASE | re.VERBOSE,
        ),
    ),
)


def find_script_warnings(line: str) -> Iterator[ScriptWarningMatch]:
    """Yield suspicious script warning matches found in a line of text."""

    for rule in SCRIPT_WARNING_PATTERNS:
        for match in rule.regex.finditer(line):
            yield ScriptWarningMatch(
                warning_type=rule.name,
                value=match.group(0).strip(),
                start=match.start(),
                end=match.end(),
            )
