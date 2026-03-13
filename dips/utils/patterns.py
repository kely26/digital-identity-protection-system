"""Reusable detection patterns."""

from __future__ import annotations

import re

EMAIL_RE = re.compile(r"\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", re.IGNORECASE)
PLAINTEXT_PASSWORD_RE = re.compile(
    r"(?im)\b(password|passwd|pwd|secret|token|api[_-]?key)\b\s*[:=]\s*[\"']?([^\s\"'`;]{4,})"
)
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
GITHUB_TOKEN_RE = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b")
AWS_ACCESS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |OPENSSH |DSA |EC |PGP )?PRIVATE KEY-----")
URL_RE = re.compile(r"https?://[^\s<>'\"]+")
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:[A-Z0-9](?:[A-Z0-9\-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,63}\b", re.IGNORECASE)
SUSPICIOUS_URL_RE = re.compile(r"https?://(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:/|$)", re.IGNORECASE)
SENSITIVE_FILENAME_RE = re.compile(
    r"(?i)(passwords?|creds?|credentials?|tokens?|secrets?|backup|browser[-_ ]export|vault).*"
)
URGENT_WORDS_RE = re.compile(
    r"(?i)\b(?:urgent|immediately|verify now|action required|suspended|final warning|click now|limited time)\b"
)
RISKY_ATTACHMENT_RE = re.compile(r"(?i)\.(?:exe|scr|js|jse|vbs|cmd|bat|ps1|lnk|iso|html?)$")

COMMON_PASSWORDS = {
    "123456",
    "123456789",
    "admin",
    "changeme",
    "dragon",
    "football",
    "iloveyou",
    "letmein",
    "monkey",
    "passw0rd",
    "password",
    "password1",
    "password123",
    "qwerty",
    "welcome",
}

CHROMIUM_SAFE_BROWSING_KEYS = (
    ("safebrowsing", "enabled"),
    ("safebrowsing", "enhanced"),
)
