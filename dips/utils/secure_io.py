"""Safer file IO helpers for sensitive local artifacts."""

from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
from typing import Any


def read_bytes_limited(path: Path, *, max_bytes: int | None = None) -> bytes:
    if path.exists() and path.is_dir():
        raise IsADirectoryError(str(path))
    if max_bytes is not None and path.stat().st_size > max_bytes:
        raise ValueError(f"File exceeds the maximum supported size of {max_bytes} bytes: {path}")
    return path.read_bytes()


def read_json_file(path: Path, *, max_bytes: int | None = None) -> Any:
    raw = read_bytes_limited(path, max_bytes=max_bytes)
    return json.loads(raw.decode("utf-8"))


def set_private_file_permissions(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        os.chmod(path, 0o600)
    except OSError:
        return


def atomic_write_text(
    path: Path,
    content: str,
    *,
    encoding: str = "utf-8",
    private: bool = False,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        if private and os.name != "nt":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding=encoding) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        if private:
            set_private_file_permissions(path)
    except Exception:
        try:
            tmp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def atomic_write_json(path: Path, payload: Any, *, private: bool = False) -> None:
    atomic_write_text(
        path,
        json.dumps(payload, indent=2, sort_keys=True),
        encoding="utf-8",
        private=private,
    )
