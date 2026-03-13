from __future__ import annotations

import shutil
from pathlib import Path

from dips.core.models import BrowserProfile
from dips.scanners.browser_audit import BrowserAuditScanner


def test_browser_audit_flags_risky_profiles(default_config, make_context, tmp_path):
    fixture_root = Path(__file__).parent / "fixtures" / "browser"
    runtime_root = tmp_path / "browser"
    shutil.copytree(fixture_root, runtime_root)

    chromium_profile = BrowserProfile(
        browser="chrome",
        display_name="Google Chrome",
        family="chromium",
        profile_name="Default",
        profile_path=str(runtime_root / "chromium" / "Default"),
        root_path=str(runtime_root / "chromium"),
        artifacts={
            "preferences": str(runtime_root / "chromium" / "Default" / "Preferences"),
            "login_data": str(runtime_root / "chromium" / "Default" / "Login Data"),
            "cookies": str(runtime_root / "chromium" / "Default" / "Cookies"),
            "extensions_root": str(runtime_root / "chromium" / "Default" / "Extensions"),
        },
    )
    firefox_profile = BrowserProfile(
        browser="firefox",
        display_name="Mozilla Firefox",
        family="firefox",
        profile_name="profile",
        profile_path=str(runtime_root / "firefox" / "profile"),
        root_path=str(runtime_root / "firefox"),
        artifacts={
            "prefs": str(runtime_root / "firefox" / "profile" / "prefs.js"),
            "logins": str(runtime_root / "firefox" / "profile" / "logins.json"),
            "extensions": str(runtime_root / "firefox" / "profile" / "extensions.json"),
        },
    )

    context = make_context(config=default_config, browser_profiles=[chromium_profile, firefox_profile])
    result = BrowserAuditScanner().run(context)
    titles = {finding.title for finding in result.findings}

    assert "Browser profile stores credential or session artifacts" in titles
    assert "Safe browsing protection disabled" in titles
    assert "Password leak detection disabled" in titles
    assert "High browser extension count detected" in titles
    assert "Firefox saved logins detected" in titles
    assert "Firefox phishing protection disabled" in titles
    assert "Firefox breach alerts disabled" in titles
    assert "High Firefox extension count detected" in titles
