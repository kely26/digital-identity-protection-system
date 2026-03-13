from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

import pytest

from dips.core.config import load_config
from dips.core.models import ScanContext
from dips.utils.files import iter_candidate_files


@pytest.fixture()
def default_config():
    return deepcopy(load_config())


@pytest.fixture()
def make_context(tmp_path):
    def _make_context(
        *,
        config,
        target_paths: list[Path] | None = None,
        browser_profiles=None,
        email_inputs=None,
        password_inputs=None,
        user_identifiers=None,
        platform_name: str = "linux",
        user_profile: Path | None = None,
        candidate_files=None,
        notes=None,
    ) -> ScanContext:
        profile = user_profile or (tmp_path / "home")
        profile.mkdir(parents=True, exist_ok=True)
        paths = target_paths or [profile]
        files = candidate_files
        if files is None:
            files = iter_candidate_files(
                paths,
                allowed_extensions=set(config.scan.extensions),
                exclude_dirs=set(config.scan.exclude_dirs),
                max_file_size_bytes=config.scan.max_file_size_mb * 1024 * 1024,
                max_files=config.scan.max_files,
            )
        return ScanContext(
            scan_id="testscan001",
            started_at=datetime.now(timezone.utc).isoformat(),
            platform_name=platform_name,
            hostname="test-host",
            username="alice",
            user_profile=profile,
            working_directory=tmp_path,
            config=config,
            target_paths=paths,
            candidate_files=files,
            browser_profiles=browser_profiles or [],
            email_inputs=email_inputs or [],
            password_inputs=password_inputs or [],
            user_identifiers=user_identifiers or ["alice"],
            notes=notes or [],
        )

    return _make_context
