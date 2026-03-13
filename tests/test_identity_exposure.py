from __future__ import annotations

import shutil
from pathlib import Path

from dips.scanners.identity_exposure import IdentityExposureScanner


def test_identity_exposure_detects_sensitive_patterns(default_config, make_context, tmp_path):
    fixture = Path(__file__).parent / "fixtures" / "exposure" / "leaky.env"
    target = tmp_path / "passwords_backup.env"
    shutil.copy(fixture, target)

    context = make_context(config=default_config, target_paths=[tmp_path])
    result = IdentityExposureScanner().run(context)
    titles = {finding.title for finding in result.findings}

    assert result.status == "completed"
    assert "Exposed email addresses detected" in titles
    assert "Plaintext credential material detected" in titles
    assert "GitHub token pattern detected" in titles
    assert "AWS access key pattern detected" in titles
    assert "Private key material detected" in titles
    assert "Sensitive file naming pattern detected" in titles
