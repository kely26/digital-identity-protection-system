"""Filesystem helpers."""

from __future__ import annotations

import os
from pathlib import Path

SPECIAL_SCAN_NAMES = {
    ".bash_history",
    ".zsh_history",
    ".env",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    "prefs.js",
    "preferences",
}


def _matches_candidate_name(file_name: str, allowed_extensions: set[str]) -> bool:
    lowered = file_name.lower()
    if lowered in SPECIAL_SCAN_NAMES:
        return True
    return Path(lowered).suffix in allowed_extensions


def is_scan_candidate(path: Path, allowed_extensions: set[str]) -> bool:
    if not path.is_file():
        return False
    return _matches_candidate_name(path.name, allowed_extensions)


def iter_candidate_files(
    roots: list[Path],
    *,
    allowed_extensions: set[str],
    exclude_dirs: set[str],
    max_file_size_bytes: int,
    max_files: int,
) -> list[Path]:
    files: list[Path] = []
    seen: set[Path] = set()

    for root in roots:
        if not root.exists():
            continue
        if root.is_file():
            if not _matches_candidate_name(root.name, allowed_extensions):
                continue
            try:
                size = root.stat().st_size
                candidate = root.resolve()
            except OSError:
                continue
            if candidate not in seen and size <= max_file_size_bytes:
                seen.add(candidate)
                files.append(candidate)
            continue

        for current_root, dir_names, file_names in os.walk(root):
            dir_names[:] = [name for name in dir_names if name not in exclude_dirs]
            current_dir = Path(current_root)
            for file_name in file_names:
                if not _matches_candidate_name(file_name, allowed_extensions):
                    continue
                candidate = current_dir / file_name
                try:
                    size = candidate.stat().st_size
                    resolved = candidate.resolve()
                except OSError:
                    continue
                if resolved in seen or size > max_file_size_bytes:
                    continue
                seen.add(resolved)
                files.append(resolved)
                if len(files) >= max_files:
                    return files
    return files


def safe_read_text(path: Path, max_chars: int = 200_000) -> str:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    if len(content) > max_chars:
        return content[:max_chars]
    return content
