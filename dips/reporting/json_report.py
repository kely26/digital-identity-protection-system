"""JSON report writer."""

from __future__ import annotations
from pathlib import Path

from dips.core.models import ScanReport, to_primitive
from dips.utils.redact import redact_value
from dips.utils.secure_io import atomic_write_json


def _sanitize_report_payload(payload: dict) -> dict:
    sanitized = dict(payload)
    if sanitized.get("username"):
        sanitized["username"] = "[REDACTED_USER]"
    if sanitized.get("hostname"):
        sanitized["hostname"] = "[REDACTED_HOST]"
    config = sanitized.get("config")
    if isinstance(config, dict):
        config = dict(config)
        credential = config.get("credential")
        if isinstance(credential, dict):
            credential = dict(credential)
            passwords = credential.get("passwords")
            if isinstance(passwords, list) and passwords:
                credential["passwords"] = ["[REDACTED_PASSWORD_INPUT]"] * len(passwords)
            config["credential"] = credential
        breach = config.get("breach_intelligence")
        if isinstance(breach, dict):
            breach = dict(breach)
            identifiers = breach.get("identifiers")
            if isinstance(identifiers, list):
                breach["identifiers"] = ["[REDACTED_IDENTIFIER]" for _ in identifiers]
            if breach.get("hash_salt"):
                breach["hash_salt"] = "[REDACTED_HASH_SALT]"
            config["breach_intelligence"] = breach
        plugin_system = config.get("plugin_system")
        if isinstance(plugin_system, dict) and isinstance(plugin_system.get("plugin_configs"), dict):
            plugin_system = dict(plugin_system)
            plugin_system["plugin_configs"] = {
                key: redact_value(value) for key, value in plugin_system["plugin_configs"].items()
            }
            config["plugin_system"] = plugin_system
        sanitized["config"] = config
    return sanitized


def render_json_payload(report: ScanReport, *, redact: bool = True) -> dict:
    payload = to_primitive(report)
    if redact:
        payload = _sanitize_report_payload(payload)
        return redact_value(payload)
    return payload


def write_json_payload(payload: dict, output_path: Path) -> Path:
    atomic_write_json(output_path, payload, private=True)
    return output_path


def write_json_report(
    report: ScanReport,
    output_path: Path,
    *,
    redact: bool = True,
    payload: dict | None = None,
) -> Path:
    report_payload = payload if payload is not None else render_json_payload(report, redact=redact)
    return write_json_payload(report_payload, output_path)
