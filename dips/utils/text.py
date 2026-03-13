"""Text helpers."""

from __future__ import annotations

from collections.abc import Iterable


def clip_text(value: str, limit: int = 180) -> str:
    if len(value) <= limit:
        return value
    return f"{value[: limit - 3]}..."


def normalize_whitespace(value: str) -> str:
    return " ".join(value.split())


def unique_preserve_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        key = value.strip()
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(key)
    return result
