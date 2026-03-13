"""Built-in and external module registry helpers."""

from __future__ import annotations

from dips.modules.base import ScannerModule
from dips.modules.ai_security_analysis import AiSecurityAnalysisScanner
from dips.modules.breach_intelligence import BreachIntelligenceScanner
from dips.modules.threat_intelligence import ThreatIntelligenceScanner
from dips.scanners.browser_audit import BrowserAuditScanner
from dips.scanners.credential_hygiene import CredentialHygieneScanner
from dips.scanners.email_phishing import EmailPhishingScanner
from dips.scanners.identity_exposure import IdentityExposureScanner
from dips.scanners.privacy_risk import PrivacyRiskScanner


BUILTIN_MODULES: dict[str, type[ScannerModule]] = {
    "identity_exposure": IdentityExposureScanner,
    "breach_intelligence": BreachIntelligenceScanner,
    "credential_hygiene": CredentialHygieneScanner,
    "privacy_risk": PrivacyRiskScanner,
    "browser_audit": BrowserAuditScanner,
    "email_phishing": EmailPhishingScanner,
    "threat_intelligence": ThreatIntelligenceScanner,
    "ai_security_analysis": AiSecurityAnalysisScanner,
}


def load_enabled_modules(enabled_names: list[str]) -> list[ScannerModule]:
    modules: list[ScannerModule] = []
    for name in enabled_names:
        module_cls = BUILTIN_MODULES.get(name)
        if module_cls is not None:
            modules.append(module_cls())
    return modules


def load_enabled_modules_with_plugins(
    enabled_names: list[str],
    plugin_modules: dict[str, ScannerModule] | None = None,
) -> list[ScannerModule]:
    modules: list[ScannerModule] = []
    plugin_modules = plugin_modules or {}
    for name in enabled_names:
        module_cls = BUILTIN_MODULES.get(name)
        if module_cls is not None:
            modules.append(module_cls())
            continue
        plugin_module = plugin_modules.get(name)
        if plugin_module is not None:
            modules.append(plugin_module)
    return modules
