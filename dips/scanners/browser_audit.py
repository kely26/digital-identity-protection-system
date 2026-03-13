"""Browser security auditing."""

from __future__ import annotations

import json
from pathlib import Path

from dips.core.models import ModuleResult
from dips.modules.base import ScannerModule
from dips.utils.files import safe_read_text


def _read_json(path: Path) -> dict:
    try:
        raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def _nested_get(mapping: dict, *keys: str):
    current = mapping
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


class BrowserAuditScanner(ScannerModule):
    name = "browser_audit"
    description = "Audits common browser profile settings and local browser storage artifacts."

    def supports(self, context) -> bool:
        return bool(context.browser_profiles)

    def _audit_chromium(self, profile, max_extension_count: int) -> list:
        findings = []
        profile_path = Path(profile.profile_path)
        prefs = _read_json(Path(profile.artifacts.get("preferences", "")))
        login_data = Path(profile.artifacts.get("login_data", ""))
        cookies = Path(profile.artifacts.get("cookies", ""))

        if login_data.exists() or cookies.exists():
            findings.append(
                self.build_finding(
                    severity="medium",
                    confidence="high",
                    title="Browser profile stores credential or session artifacts",
                    summary="This browser profile contains local login or session databases.",
                    evidence={"profile": profile.profile_name, "browser": profile.display_name},
                    location=str(profile_path),
                    recommendation="Review whether saved passwords and long-lived sessions are necessary on this endpoint.",
                    tags=["browser", "credentials", "sessions"],
                )
            )

        safe_browsing_enabled = _nested_get(prefs, "safebrowsing", "enabled")
        if safe_browsing_enabled is False:
            findings.append(
                self.build_finding(
                    severity="high",
                    confidence="high",
                    title="Safe browsing protection disabled",
                    summary="The browser profile appears to have safe browsing protections disabled.",
                    evidence={"browser": profile.display_name, "profile": profile.profile_name},
                    location=str(profile_path),
                    recommendation="Enable safe browsing protections for phishing and malware detection.",
                    tags=["browser", "safebrowsing"],
                )
            )

        leak_detection = prefs.get("password_manager_leak_detection")
        if leak_detection is None:
            leak_detection = _nested_get(prefs, "profile", "password_manager_leak_detection")
        if leak_detection is False:
            findings.append(
                self.build_finding(
                    severity="medium",
                    confidence="medium",
                    title="Password leak detection disabled",
                    summary="The browser profile appears to have credential leak detection disabled.",
                    evidence={"browser": profile.display_name, "profile": profile.profile_name},
                    location=str(profile_path),
                    recommendation="Enable browser leak detection or use a password manager with breach notifications.",
                    tags=["browser", "password-manager"],
                )
            )

        extensions = _nested_get(prefs, "extensions", "settings") or {}
        if isinstance(extensions, dict) and len(extensions) > max_extension_count:
            findings.append(
                self.build_finding(
                    severity="medium",
                    confidence="high",
                    title="High browser extension count detected",
                    summary=f"The profile contains {len(extensions)} extensions, which increases attack surface.",
                    evidence={"extension_count": len(extensions), "browser": profile.display_name},
                    location=str(profile_path),
                    recommendation="Remove unused extensions and review extension permissions regularly.",
                    tags=["browser", "extensions"],
                )
            )

        return findings

    def _audit_firefox(self, profile, max_extension_count: int) -> list:
        findings = []
        profile_path = Path(profile.profile_path)
        prefs_path = Path(profile.artifacts.get("prefs", ""))
        prefs_text = safe_read_text(prefs_path) if prefs_path.exists() else ""
        logins = Path(profile.artifacts.get("logins", ""))
        extensions_json = _read_json(Path(profile.artifacts.get("extensions", "")))

        if logins.exists():
            findings.append(
                self.build_finding(
                    severity="medium",
                    confidence="high",
                    title="Firefox saved logins detected",
                    summary="Firefox login storage artifacts were found in the profile.",
                    evidence={"browser": profile.display_name, "profile": profile.profile_name},
                    location=str(profile_path),
                    recommendation="Review whether browser-saved passwords are necessary on this endpoint.",
                    tags=["browser", "credentials"],
                )
            )

        if 'user_pref("browser.safebrowsing.phishing.enabled", false);' in prefs_text.lower():
            findings.append(
                self.build_finding(
                    severity="high",
                    confidence="high",
                    title="Firefox phishing protection disabled",
                    summary="Firefox phishing protection is disabled in prefs.js.",
                    evidence={"preference": "browser.safebrowsing.phishing.enabled"},
                    location=str(profile_path),
                    recommendation="Enable Firefox phishing protection.",
                    tags=["browser", "phishing-protection"],
                )
            )

        if 'user_pref("signon.management.page.breach-alerts.enabled", false);' in prefs_text.lower():
            findings.append(
                self.build_finding(
                    severity="medium",
                    confidence="high",
                    title="Firefox breach alerts disabled",
                    summary="Firefox breach alerting appears disabled for this profile.",
                    evidence={"preference": "signon.management.page.breach-alerts.enabled"},
                    location=str(profile_path),
                    recommendation="Enable Firefox breach alerts or use another breach-notification workflow.",
                    tags=["browser", "breach-alerts"],
                )
            )

        addons = extensions_json.get("addons")
        if isinstance(addons, list) and len(addons) > max_extension_count:
            findings.append(
                self.build_finding(
                    severity="medium",
                    confidence="medium",
                    title="High Firefox extension count detected",
                    summary=f"The Firefox profile contains {len(addons)} extensions.",
                    evidence={"extension_count": len(addons)},
                    location=str(profile_path),
                    recommendation="Reduce installed extensions to the minimum needed set.",
                    tags=["browser", "extensions"],
                )
            )

        return findings

    def run(self, context) -> ModuleResult:
        findings = []
        max_extension_count = context.config.browser.max_extension_count
        for profile in context.browser_profiles:
            if profile.family == "chromium":
                findings.extend(self._audit_chromium(profile, max_extension_count))
            elif profile.family == "firefox":
                findings.extend(self._audit_firefox(profile, max_extension_count))

        return ModuleResult(
            module=self.name,
            description=self.description,
            status="completed",
            findings=findings,
            metadata={"profiles": len(context.browser_profiles)},
        )
