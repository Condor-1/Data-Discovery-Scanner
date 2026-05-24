"""Project-wide scanner configuration."""

from __future__ import annotations

PROGRAMMING_EXTENSIONS = {
    ".py",
    ".java",
    ".c",
    ".cpp",
    ".js",
    ".ts",
    ".go",
    ".rs",
    ".php",
    ".sh",
}

CONFIG_TEXT_EXTENSIONS = {
    ".env",
    ".json",
    ".yaml",
    ".yml",
    ".ini",
    ".cfg",
    ".xml",
    ".toml",
    ".txt",
    ".md",
    ".log",
}

SCRIPT_EXTENSIONS = {
    ".bat",
    ".cmd",
    ".ps1",
}

SUPPORTED_EXTENSIONS = PROGRAMMING_EXTENSIONS | CONFIG_TEXT_EXTENSIONS | SCRIPT_EXTENSIONS

DEFAULT_IGNORED_DIRECTORIES = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    "target",
    ".idea",
    ".vscode",
}

