"""Helpers for masking sensitive values before display."""

from __future__ import annotations


def mask_sensitive_value(value: str, visible_prefix: int = 8, visible_suffix: int = 0) -> str:
    """Return a masked version of a sensitive value.

    The default keeps enough leading context to identify common key families
    such as ``sk_live_`` while hiding the actual secret material.
    """

    if not value:
        return ""

    if len(value) <= visible_prefix + visible_suffix:
        return "*" * len(value)

    prefix = value[:visible_prefix]
    suffix = value[-visible_suffix:] if visible_suffix else ""
    hidden_length = len(value) - len(prefix) - len(suffix)

    return f"{prefix}{'*' * hidden_length}{suffix}"
