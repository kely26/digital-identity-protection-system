from __future__ import annotations

from dips.utils.paths import current_user_profile, discover_browser_profiles, expand_scan_paths


def test_discover_browser_profiles_windows_layout(tmp_path):
    profile = tmp_path / "user"
    chrome_default = profile / "AppData" / "Local" / "Google" / "Chrome" / "User Data" / "Default"
    chrome_default.mkdir(parents=True)
    (chrome_default / "Preferences").write_text("{}", encoding="utf-8")

    profiles = discover_browser_profiles(user_profile=profile, system_name="Windows")

    assert profiles
    assert profiles[0].browser == "chrome"
    assert profiles[0].family == "chromium"


def test_expand_scan_paths_accepts_windows_env_style_on_posix(tmp_path, monkeypatch):
    profile = tmp_path / "profile"
    docs = profile / "Documents"
    docs.mkdir(parents=True)
    monkeypatch.setenv("USERPROFILE", str(profile))

    paths = expand_scan_paths([r"%USERPROFILE%\Documents"], fallback=tmp_path)

    assert paths == [docs.resolve()]


def test_current_user_profile_uses_home_drive_and_home_path_fallback(tmp_path):
    env = {
        "USERPROFILE": "",
        "HOME": "",
        "HOMEDRIVE": str(tmp_path),
        "HOMEPATH": "/windows-user",
    }

    profile = current_user_profile(env=env, system_name="Windows")

    assert profile == (tmp_path / "windows-user")
