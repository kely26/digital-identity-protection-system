"""Cross-platform path helpers."""

from __future__ import annotations

import os
import platform
from pathlib import Path
import re
from typing import Mapping

from dips.core.models import BrowserProfile


WINDOWS_ENV_RE = re.compile(r"%([^%]+)%")


def expand_environment(value: str, *, env: Mapping[str, str] | None = None) -> str:
    env_map = os.environ if env is None else env
    expanded = os.path.expandvars(value)
    if "%" not in expanded:
        return expanded

    def _replace(match: re.Match[str]) -> str:
        name = match.group(1)
        return env_map.get(name, match.group(0))

    return WINDOWS_ENV_RE.sub(_replace, expanded)


def normalize_path_text(value: str, *, env: Mapping[str, str] | None = None) -> str:
    normalized = expand_environment(value, env=env)
    if os.sep == "/" and "\\" in normalized:
        normalized = normalized.replace("\\", "/")
    return normalized


def path_from_input(value: str | Path, *, env: Mapping[str, str] | None = None) -> Path:
    if isinstance(value, Path):
        return value.expanduser()
    return Path(normalize_path_text(value, env=env)).expanduser()


def current_user_profile(
    *,
    env: Mapping[str, str] | None = None,
    system_name: str | None = None,
) -> Path:
    env_map = os.environ if env is None else env
    resolved_system = (system_name or platform.system()).lower()
    home_drive = env_map.get("HOMEDRIVE", "")
    home_path = env_map.get("HOMEPATH", "")
    drive_home = f"{home_drive}{home_path}".strip()
    candidates = (
        [env_map.get("USERPROFILE", ""), drive_home, env_map.get("HOME", "")]
        if resolved_system.startswith("win")
        else [env_map.get("HOME", ""), env_map.get("USERPROFILE", ""), drive_home]
    )
    for candidate in candidates:
        if candidate:
            return path_from_input(candidate, env=env_map)
    return Path.home()


def expand_scan_paths(values: list[str], *, fallback: Path) -> list[Path]:
    expanded = [path_from_input(value) for value in values if value]
    existing: list[Path] = []
    seen: set[Path] = set()
    for path in expanded:
        if not path.exists():
            continue
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        existing.append(resolved)
    if existing:
        return existing
    return [fallback.resolve()]


def discover_browser_profiles(user_profile: Path | None = None, system_name: str | None = None) -> list[BrowserProfile]:
    base = user_profile or current_user_profile()
    system_name = (system_name or platform.system()).lower()
    profiles: list[BrowserProfile] = []

    def add_chromium(browser: str, display_name: str, root: Path) -> None:
        if not root.exists():
            return
        candidates = [root / "Default", *sorted(root.glob("Profile *"))]
        if root.name.lower().startswith("opera") or (root / "Preferences").exists():
            candidates.append(root)
        seen: set[Path] = set()
        for candidate in candidates:
            if candidate in seen or not candidate.exists() or not candidate.is_dir():
                continue
            preferences = candidate / "Preferences"
            if not preferences.exists() and candidate != root:
                continue
            seen.add(candidate)
            profiles.append(
                BrowserProfile(
                    browser=browser,
                    display_name=display_name,
                    family="chromium",
                    profile_name=candidate.name,
                    profile_path=str(candidate),
                    root_path=str(root),
                    artifacts={
                        "preferences": str(preferences),
                        "login_data": str(candidate / "Login Data"),
                        "cookies": str(candidate / "Cookies"),
                        "extensions_root": str(candidate / "Extensions"),
                    },
                )
            )

    def add_firefox(root: Path) -> None:
        if not root.exists():
            return
        for candidate in sorted(root.iterdir()):
            if not candidate.is_dir():
                continue
            prefs = candidate / "prefs.js"
            if not prefs.exists():
                continue
            profiles.append(
                BrowserProfile(
                    browser="firefox",
                    display_name="Mozilla Firefox",
                    family="firefox",
                    profile_name=candidate.name,
                    profile_path=str(candidate),
                    root_path=str(root),
                    artifacts={
                        "prefs": str(prefs),
                        "logins": str(candidate / "logins.json"),
                        "extensions": str(candidate / "extensions.json"),
                    },
                )
            )

    if system_name.startswith("win"):
        local = base / "AppData" / "Local"
        roaming = base / "AppData" / "Roaming"
        chromium_roots = {
            "chrome": ("Google Chrome", local / "Google" / "Chrome" / "User Data"),
            "chromium": ("Chromium", local / "Chromium" / "User Data"),
            "edge": ("Microsoft Edge", local / "Microsoft" / "Edge" / "User Data"),
            "brave": ("Brave", local / "BraveSoftware" / "Brave-Browser" / "User Data"),
            "vivaldi": ("Vivaldi", local / "Vivaldi" / "User Data"),
            "opera": ("Opera", roaming / "Opera Software" / "Opera Stable"),
        }
        firefox_root = roaming / "Mozilla" / "Firefox" / "Profiles"
    else:
        config_root = base / ".config"
        chromium_roots = {
            "chrome": ("Google Chrome", config_root / "google-chrome"),
            "chromium": ("Chromium", config_root / "chromium"),
            "edge": ("Microsoft Edge", config_root / "microsoft-edge"),
            "brave": ("Brave", config_root / "BraveSoftware" / "Brave-Browser"),
            "vivaldi": ("Vivaldi", config_root / "vivaldi"),
            "opera": ("Opera", config_root / "opera"),
        }
        firefox_root = base / ".mozilla" / "firefox"

    for browser, (display_name, root) in chromium_roots.items():
        add_chromium(browser, display_name, root)
    add_firefox(firefox_root)
    return profiles
