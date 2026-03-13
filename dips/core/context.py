"""Scan context creation."""

from __future__ import annotations

import getpass
import os
import platform
import socket
import uuid
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter

from dips.core.config import AppConfig
from dips.core.models import ScanContext
from dips.utils.files import iter_candidate_files
from dips.utils.paths import current_user_profile, discover_browser_profiles, expand_scan_paths, path_from_input
from dips.utils.text import unique_preserve_order


def _load_passwords(values: list[str], password_file: str | None, notes: list[str]) -> list[str]:
    passwords = [value.strip() for value in values if value.strip()]
    if password_file:
        path = path_from_input(password_file)
        if not path.exists():
            notes.append(f"Password file was not found and was skipped: {path}")
        elif not path.is_file():
            notes.append(f"Password file path is not a regular file and was skipped: {path}")
        else:
            try:
                passwords.extend(
                    line.strip()
                    for line in path.read_text(encoding="utf-8", errors="replace").splitlines()
                    if line.strip()
                )
            except OSError as exc:
                notes.append(f"Password file could not be read and was skipped: {path} ({exc})")
    return unique_preserve_order(passwords)


def _load_email_inputs(values: list[str], notes: list[str]) -> list[Path]:
    result: list[Path] = []
    for value in values:
        candidate = path_from_input(value)
        if not candidate.exists():
            notes.append(f"Email input was not found and was skipped: {candidate}")
            continue
        if not candidate.is_file():
            notes.append(f"Email input is not a regular file and was skipped: {candidate}")
            continue
        try:
            result.append(candidate.resolve())
        except OSError as exc:
            notes.append(f"Email input could not be resolved and was skipped: {candidate} ({exc})")
    return result


def build_scan_context(
    config: AppConfig,
) -> ScanContext:
    user_profile = current_user_profile().resolve()
    configured_paths = list(config.scan.paths)
    target_paths = expand_scan_paths(configured_paths, fallback=user_profile)

    notes: list[str] = []
    if not any(path_from_input(path).exists() for path in configured_paths if path):
        notes.append("No explicit scan paths were usable; defaulted to the current user profile.")

    username = getpass.getuser()
    email_identifier = os.environ.get("EMAIL", "")
    user_identifiers = unique_preserve_order(
        [
            username,
            email_identifier,
            email_identifier.split("@", 1)[0] if "@" in email_identifier else "",
            *config.breach_intelligence.identifiers,
        ]
    )

    discovery_started = perf_counter()
    candidate_files = iter_candidate_files(
        target_paths,
        allowed_extensions={item.lower() for item in config.scan.extensions},
        exclude_dirs=set(config.scan.exclude_dirs),
        max_file_size_bytes=int(config.scan.max_file_size_mb * 1024 * 1024),
        max_files=int(config.scan.max_files),
    )
    notes.append(f"Discovered {len(candidate_files)} candidate files in scan scope.")
    notes.append(f"Candidate discovery completed in {int((perf_counter() - discovery_started) * 1000)} ms.")

    return ScanContext(
        scan_id=uuid.uuid4().hex[:12],
        started_at=datetime.now(timezone.utc).isoformat(),
        platform_name=platform.system().lower(),
        hostname=socket.gethostname(),
        username=username,
        user_profile=user_profile,
        working_directory=Path.cwd(),
        config=config,
        target_paths=target_paths,
        candidate_files=candidate_files,
        browser_profiles=discover_browser_profiles(user_profile=user_profile),
        email_inputs=_load_email_inputs(config.email.inputs, notes),
        password_inputs=_load_passwords(config.credential.passwords, config.credential.password_file, notes),
        user_identifiers=user_identifiers,
        notes=notes,
    )
