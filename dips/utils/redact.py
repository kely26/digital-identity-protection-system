"""Evidence redaction helpers."""

from __future__ import annotations

import os
from dataclasses import asdict, is_dataclass
from pathlib import Path
import re
from typing import Any

from dips.utils.patterns import AWS_ACCESS_KEY_RE, EMAIL_RE, GITHUB_TOKEN_RE, JWT_RE, PRIVATE_KEY_RE
from dips.utils.text import clip_text

WINDOWS_USER_RE = re.compile(r"([A-Za-z]:[\\/](?:Users|Documents and Settings)[\\/])([^\\/]+)")
POSIX_HOME_RE = re.compile(r"/(?:home|Users)/([^/]+)")
SENSITIVE_KEYS = {
    "password",
    "passwords",
    "secret",
    "secrets",
    "token",
    "tokens",
    "api_key",
    "apikey",
    "private_key",
    "hash_salt",
    "authorization",
}


def _mask_email(value: str) -> str:
    if "@" not in value:
        return value
    local, domain = value.split("@", 1)
    if len(local) <= 2:
        return f"{local[0]}***@{domain}" if local else f"***@{domain}"
    return f"{local[:2]}***@{domain}"


def _mask_identifier(value: str) -> str:
    normalized = value.strip()
    if "@" in normalized:
        return _mask_email(normalized)
    if len(normalized) <= 3:
        return normalized[:1] + "***" if normalized else "***"
    return normalized[:3] + "***"


def redact_path(value: str) -> str:
    normalized = value.replace("\\", "/")
    try:
        home = Path.home().as_posix()
    except OSError:
        home = ""
    if home and normalized == home:
        return "~"
    if home and normalized.startswith(f"{home}/"):
        return "~/" + normalized[len(home) + 1 :]
    normalized = WINDOWS_USER_RE.sub(r"\1[user]", normalized)
    normalized = POSIX_HOME_RE.sub("~", normalized)
    if os.sep == "\\":
        normalized = normalized.replace("/", "\\")
    return normalized


def _already_redacted(value: Any) -> bool:
    if isinstance(value, str):
        return value.startswith("[REDACTED_") and value.endswith("]")
    if isinstance(value, list):
        return all(_already_redacted(item) for item in value)
    if isinstance(value, dict):
        return all(_already_redacted(item) for item in value.values())
    return False


def redact_string(value: str) -> str:
    redacted = redact_path(value)
    redacted = GITHUB_TOKEN_RE.sub("[REDACTED_GITHUB_TOKEN]", redacted)
    redacted = AWS_ACCESS_KEY_RE.sub("[REDACTED_AWS_KEY]", redacted)
    redacted = JWT_RE.sub("[REDACTED_JWT]", redacted)
    redacted = PRIVATE_KEY_RE.sub("[REDACTED_PRIVATE_KEY_HEADER]", redacted)
    redacted = EMAIL_RE.sub(lambda match: _mask_email(match.group(0)), redacted)
    return clip_text(redacted, 240)


def redact_value(value: Any) -> Any:
    if isinstance(value, str):
        return redact_string(value)
    if isinstance(value, Path):
        return redact_path(str(value))
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and key.lower() in SENSITIVE_KEYS:
                if _already_redacted(item):
                    redacted[key] = item
                    continue
                if isinstance(item, list):
                    redacted[key] = ["[REDACTED_SECRET]" for _ in item]
                elif isinstance(item, dict):
                    redacted[key] = {nested_key: "[REDACTED_SECRET]" for nested_key in item}
                else:
                    redacted[key] = "[REDACTED_SECRET]"
                continue
            redacted[key] = redact_value(item)
        return redacted
    if is_dataclass(value):
        return redact_value(asdict(value))
    return value
