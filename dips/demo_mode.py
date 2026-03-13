"""Synthetic demo data for DIPS screenshots and product walkthroughs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

from dips.core.config import load_config
from dips.core.models import (
    EventPattern,
    EventTimeline,
    Finding,
    ModuleResult,
    ScanReport,
    SecurityEvent,
    stable_finding_id,
)
from dips.reporting.html_report import render_html_payload
from dips.reporting.json_report import render_json_payload, write_json_payload
from dips.scoring.engine import summarize_results
from dips.utils.secure_io import atomic_write_text

DEFAULT_DEMO_OUTPUT_DIR = Path("reports/demo")


@dataclass(slots=True)
class DemoArtifacts:
    output_dir: Path
    reports: list[ScanReport]
    outputs_by_scan: dict[str, dict[str, Path]]

    @property
    def latest_report(self) -> ScanReport:
        return self.reports[-1]

    @property
    def latest_outputs(self) -> dict[str, Path]:
        return self.outputs_by_scan[self.latest_report.scan_id]


def _finding(
    module: str,
    severity: str,
    title: str,
    summary: str,
    location: str,
    recommendation: str,
    tags: list[str],
    evidence: dict[str, Any] | None = None,
    *,
    confidence: str = "high",
) -> Finding:
    return Finding(
        id=stable_finding_id(module, title, location, summary),
        module=module,
        severity=severity,
        confidence=confidence,
        title=title,
        summary=summary,
        evidence=evidence or {},
        location=location,
        recommendation=recommendation,
        tags=tags,
    )


def _module(
    module: str,
    description: str,
    findings: list[Finding],
    metadata: dict[str, Any],
    *,
    duration_ms: int,
    warnings: list[str] | None = None,
) -> ModuleResult:
    return ModuleResult(
        module=module,
        description=description,
        status="completed",
        findings=findings,
        warnings=list(warnings or []),
        metadata=metadata,
        duration_ms=duration_ms,
    )


def _event(
    event_id: str,
    timestamp: str,
    module: str,
    severity: str,
    event_type: str,
    title: str,
    summary: str,
    location: str,
    *,
    scan_id: str,
    tags: list[str] | None = None,
    related_findings: list[str] | None = None,
    correlations: list[str] | None = None,
) -> SecurityEvent:
    return SecurityEvent(
        id=event_id,
        timestamp=timestamp,
        module=module,
        severity=severity,
        event_type=event_type,
        title=title,
        summary=summary,
        location=location,
        scan_id=scan_id,
        tags=list(tags or []),
        related_findings=list(related_findings or []),
        correlations=list(correlations or []),
    )


@lru_cache(maxsize=1)
def _demo_config():
    return load_config()


def _timeline(
    scan_id: str,
    started_at: datetime,
    items: list[tuple[str, str, str, str, str, str, str, list[str], list[str], list[str]]],
    patterns: list[tuple[str, str, str, str, list[str], list[str]]],
) -> EventTimeline:
    events = [
        _event(
            event_id,
            (started_at + timedelta(minutes=index * 2 + 1)).isoformat(),
            module,
            severity,
            event_type,
            title,
            summary,
            location,
            scan_id=scan_id,
            tags=tags,
            related_findings=related_findings,
            correlations=correlations,
        )
        for index, (
            event_id,
            module,
            severity,
            event_type,
            title,
            summary,
            location,
            tags,
            related_findings,
            correlations,
        ) in enumerate(items)
    ]
    return EventTimeline(
        store_path="examples/demo-reports/demo-event-timeline.json",
        total_events=len(events),
        events=events,
        patterns=[
            EventPattern(
                id=pattern_id,
                name=name,
                severity=severity,
                summary=summary,
                event_ids=event_ids,
                modules=modules,
            )
            for pattern_id, name, severity, summary, event_ids, modules in patterns
        ],
    )


def _baseline_report() -> ScanReport:
    scan_id = "demo-baseline-001"
    started_at = datetime(2026, 3, 12, 12, 25, tzinfo=timezone.utc)
    identity_findings = [
        _finding(
            "identity_exposure",
            "medium",
            "Plaintext email address collection detected",
            "A local campaign planning export contains a plain business contact list.",
            "~/Workspace/exports/contact-rollup.csv",
            "Move the export into controlled storage and remove plaintext copies from the workstation.",
            ["identity", "email"],
            {"email_count": 34, "file_name": "contact-rollup.csv"},
        ),
        _finding(
            "identity_exposure",
            "medium",
            "Session token artifact detected in analyst notes",
            "A notes export contains a reusable session artifact that should not live in plaintext storage.",
            "~/Workspace/notes/session-notes.txt",
            "Rotate the affected session or API token and remove plaintext notes exports.",
            ["token", "secret"],
            {"file_name": "session-notes.txt", "sample": "demo_session_token_blue"},
        ),
    ]
    breach_findings = [
        _finding(
            "breach_intelligence",
            "low",
            "Identity exposure detected in breach intelligence",
            "finance.ops@example.com appears in one offline breach archive used for the demo scenario.",
            "finance.ops@example.com",
            "Rotate related credentials and add MFA to the identity set used in public-facing services.",
            ["breach", "identity", "email"],
            {
                "identifier": "finance.ops@example.com",
                "identifier_type": "email",
                "identifier_hash": "demo-baseline-a1b2",
                "breach_count": 1,
                "sources": ["breach_archive_2023"],
            },
        )
    ]
    credential_findings = [
        _finding(
            "credential_hygiene",
            "medium",
            "Common password detected",
            "A staged credential candidate matches a common-password blocklist entry.",
            "credential_inputs",
            "Replace the reused secret with a unique passphrase generated for this account set.",
            ["password", "common"],
            {"password_alias": "campaign-portal"},
        ),
        _finding(
            "credential_hygiene",
            "medium",
            "Password reuse detected",
            "Two demo service accounts share the same password candidate.",
            "credential_inputs",
            "Assign unique passwords to each service account and enforce MFA where supported.",
            ["password", "reuse"],
            {"count": 2, "accounts": ["campaign-portal", "vendor-portal"]},
        ),
    ]
    privacy_findings = [
        _finding(
            "privacy_risk",
            "low",
            "Credential store artifact detected",
            "A local browser export bundle includes remembered account details in an unprotected folder.",
            "~/Workspace/browser-export/browser-passwords.csv",
            "Delete the export and move any required secrets into a managed vault.",
            ["privacy", "credential-store"],
            {"file_name": "browser-passwords.csv"},
        )
    ]
    browser_findings = [
        _finding(
            "browser_audit",
            "low",
            "Saved logins present in browser profile",
            "The primary Chromium profile stores saved logins for multiple business services.",
            "Chrome/Profile 1",
            "Disable local password storage and move credentials into a managed password manager.",
            ["browser", "credential"],
            {"browser": "Chrome", "profile": "Profile 1"},
        ),
        _finding(
            "browser_audit",
            "low",
            "Leak detection protection disabled",
            "Password leak detection is disabled in the main browser profile.",
            "Chrome/Profile 1",
            "Enable password leak detection and monitor for reused credentials.",
            ["browser", "protection"],
            {"browser": "Chrome", "profile": "Profile 1"},
        ),
    ]
    email_findings = [
        _finding(
            "email_phishing",
            "low",
            "Suspicious URLs detected in email body",
            "A vendor-themed email references a deceptive login URL with account pressure wording.",
            "vendor-warning.eml",
            "Do not open the message, block the sender, and brief the affected user group.",
            ["email", "url", "phishing"],
            {"urls": ["https://vendor-security-check.example/login"], "sender": "billing@example-mail.example"},
        )
    ]
    threat_findings = [
        _finding(
            "threat_intelligence",
            "low",
            "Threat intelligence match for domain",
            "The domain in the staged email appears in a suspicious-domain feed used for the demo.",
            "vendor-warning.eml",
            "Review the destination domain before allowing it through mail or web controls.",
            ["threat-intel", "domain", "suspicious", "phishing"],
            {
                "indicator": "vendor-security-check.example",
                "indicator_type": "domain",
                "reputation": "suspicious",
                "confidence": 0.61,
                "sources": ["brand-monitor-feed"],
            },
            confidence="medium",
        )
    ]
    ai_patterns = [
        {
            "title": "Password reuse overlaps with early breach exposure",
            "severity": "medium",
            "summary": "A reused credential appears alongside a breach hit, increasing the chance of credential stuffing.",
            "related_findings": [credential_findings[1].id, breach_findings[0].id],
        }
    ]
    modules = [
        _module(
            "identity_exposure",
            "Demo exposure analysis for exported identities and tokens.",
            identity_findings,
            {"scanned_files": 18, "exposure_findings": len(identity_findings)},
            duration_ms=420,
        ),
        _module(
            "breach_intelligence",
            "Demo breach intelligence matching.",
            breach_findings,
            {"identifiers_scanned": 2, "identifiers_with_hits": 1, "offline_dataset_count": 1},
            duration_ms=180,
        ),
        _module(
            "credential_hygiene",
            "Demo credential hygiene assessment.",
            credential_findings,
            {"password_count": 6, "unique_passwords": 5},
            duration_ms=140,
        ),
        _module(
            "privacy_risk",
            "Demo local privacy artifact review.",
            privacy_findings,
            {"artifact_count": 3},
            duration_ms=220,
        ),
        _module(
            "browser_audit",
            "Demo browser posture audit.",
            browser_findings,
            {"profiles": 2, "extensions_seen": 11},
            duration_ms=310,
        ),
        _module(
            "email_phishing",
            "Demo phishing analysis.",
            email_findings,
            {"emails_scanned": 1},
            duration_ms=160,
        ),
        _module(
            "threat_intelligence",
            "Demo threat intelligence enrichment.",
            threat_findings,
            {"indicators_scanned": 4, "indicators_enriched": 1},
            duration_ms=110,
        ),
        _module(
            "ai_security_analysis",
            "Demo AI risk explanation layer.",
            [],
            {
                "analysis_mode": "demo-synthetic",
                "findings_reviewed": 9,
                "summary": "DIPS demo mode shows early identity leakage, weak credential hygiene, and emerging phishing pressure with limited but credible exposure.",
                "risk_explanation": "The exposure set is still containable, but password reuse and browser-stored credentials lower the effort required for account takeover.",
                "recommended_actions": [
                    "Replace reused credentials and enable MFA on exposed services.",
                    "Remove plaintext token notes and browser password exports from local storage.",
                    "Block the staged phishing domain and notify impacted users.",
                ],
                "suspicious_patterns": ai_patterns,
            },
            duration_ms=90,
        ),
    ]
    summary = summarize_results(modules, _demo_config())
    timeline = _timeline(
        scan_id,
        started_at,
        [
            ("demo-b1", "credential_hygiene", "high", "credential_reuse", "Password reuse detected", "Two service accounts share the same secret.", "credential_inputs", ["reuse"], [credential_findings[1].id], ["Password reuse overlaps with early breach exposure"]),
            ("demo-b2", "breach_intelligence", "low", "breach_exposure", "Identity exposure detected in breach intelligence", "An operational mailbox appears in one breach archive.", "finance.ops@example.com", ["breach"], [breach_findings[0].id], ["Password reuse overlaps with early breach exposure"]),
            ("demo-b3", "email_phishing", "low", "phishing_analysis", "Suspicious URLs detected in email body", "The staged vendor email contains a deceptive link.", "vendor-warning.eml", ["phishing"], [email_findings[0].id], []),
            ("demo-b4", "threat_intelligence", "low", "threat_intelligence", "Threat intelligence match for domain", "The linked domain is already tagged as suspicious.", "vendor-warning.eml", ["domain", "suspicious"], [threat_findings[0].id], []),
        ],
        [
            (
                "demo-pattern-b1",
                "Password reuse overlaps with early breach exposure",
                "medium",
                "Credential hygiene and breach history combine into a credible account-takeover path.",
                ["demo-b1", "demo-b2"],
                ["credential_hygiene", "breach_intelligence"],
            )
        ],
    )
    return ScanReport(
        scan_id=scan_id,
        started_at=started_at.isoformat(),
        finished_at=(started_at + timedelta(seconds=8)).isoformat(),
        duration_ms=8120,
        platform_name="linux",
        hostname="demo-workstation",
        username="demo-operator",
        user_profile="/home/demo-operator",
        target_paths=["/home/demo-operator/Workspace", "/home/demo-operator/Downloads"],
        notes=[
            "Demo mode generated synthetic findings. No live scan was executed.",
            "All domains, identities, and tokens in this report are staged examples.",
        ],
        modules=modules,
        summary=summary,
        config={
            "demo_mode": {"enabled": True, "scenario": "baseline", "safe_synthetic_data": True},
            "reporting": {"redact_evidence": False},
        },
        timeline=timeline,
    )


def _escalation_report() -> ScanReport:
    scan_id = "demo-escalation-002"
    started_at = datetime(2026, 3, 12, 14, 20, tzinfo=timezone.utc)
    identity_findings = [
        _finding(
            "identity_exposure",
            "high",
            "GitHub token pattern detected",
            "A staging token was exported into a note-taking workspace sync file.",
            "~/Workspace/notes/github-sync.txt",
            "Rotate the exposed token and remove plaintext sync exports from the workstation.",
            ["token", "secret"],
            {"sample": "demo_github_token_red", "file_name": "github-sync.txt"},
        ),
        _finding(
            "identity_exposure",
            "medium",
            "Plaintext email address collection detected",
            "A spreadsheet of partner identities is stored outside protected project storage.",
            "~/Workspace/exports/partner-identities.csv",
            "Move the file into approved storage and reduce local plaintext copies.",
            ["identity", "email"],
            {"email_count": 82, "file_name": "partner-identities.csv"},
        ),
    ]
    breach_findings = [
        _finding(
            "breach_intelligence",
            "medium",
            "Identity exposure detected in breach intelligence",
            "finance.ops@example.com appears in multiple synthetic credential leak collections used in the demo.",
            "finance.ops@example.com",
            "Force password rotation for the affected identity group and require MFA re-enrollment.",
            ["breach", "identity", "email"],
            {
                "identifier": "finance.ops@example.com",
                "identifier_type": "email",
                "identifier_hash": "demo-escalation-c3d4",
                "breach_count": 3,
                "sources": ["credential_leak", "forum_dump", "breach_archive_2024"],
            },
        )
    ]
    credential_findings = [
        _finding(
            "credential_hygiene",
            "high",
            "Password reuse detected",
            "Three staged business services share the same password candidate.",
            "credential_inputs",
            "Separate the password set immediately and enable MFA on all internet-facing services.",
            ["password", "reuse"],
            {"count": 3},
        ),
        _finding(
            "credential_hygiene",
            "medium",
            "Short password detected",
            "A demo account password is materially shorter than the team baseline.",
            "credential_inputs",
            "Replace the short password with a longer passphrase.",
            ["password", "length"],
            {"length": 8},
        ),
    ]
    privacy_findings = [
        _finding(
            "privacy_risk",
            "medium",
            "Sensitive file has broad permissions",
            "An SSH private key backup is accessible to a broad local group on the workstation.",
            "~/Workspace/ssh-backups/id_ed25519",
            "Restrict the file permissions and remove the backup from shared local storage.",
            ["private-key", "privacy"],
            {"file_name": "id_ed25519"},
        )
    ]
    browser_findings = [
        _finding(
            "browser_audit",
            "medium",
            "Disabled browser protection setting detected",
            "Safe browsing protections are disabled in the primary browser profile.",
            "Edge/Default",
            "Re-enable browser protection controls and review why they were disabled.",
            ["browser", "protection"],
            {"browser": "Edge", "profile": "Default"},
        ),
        _finding(
            "browser_audit",
            "medium",
            "Saved logins present in browser profile",
            "Saved business credentials remain available in the primary profile.",
            "Edge/Default",
            "Move credential storage to a managed password manager and clear local browser logins.",
            ["browser", "credential"],
            {"browser": "Edge", "profile": "Default"},
        ),
    ]
    email_findings = [
        _finding(
            "email_phishing",
            "medium",
            "Reply-To mismatch detected in email headers",
            "A staged invoice email uses a mismatched reply address designed to redirect the conversation.",
            "invoice-review.eml",
            "Report the sender, block the message, and warn the targeted finance group.",
            ["email", "phishing", "header"],
            {"from": "invoices@trusted-example.example", "reply_to": "settlement@outlook-gateway.example"},
        ),
        _finding(
            "email_phishing",
            "medium",
            "Suspicious URLs detected in email body",
            "The email links to a fake document portal with urgency language.",
            "invoice-review.eml",
            "Do not visit the URL and block the destination in mail or web controls.",
            ["email", "url", "phishing"],
            {"urls": ["https://docs-review-login.example/portal"]},
        ),
    ]
    threat_findings = [
        _finding(
            "threat_intelligence",
            "medium",
            "Threat intelligence match for url",
            "The invoice review URL is present in a malicious URL collection.",
            "invoice-review.eml",
            "Block the destination URL and investigate whether any users interacted with it.",
            ["threat-intel", "url", "malicious", "phishing"],
            {
                "indicator": "https://docs-review-login.example/portal",
                "indicator_type": "url",
                "reputation": "malicious",
                "confidence": 0.89,
                "sources": ["malicious_url_feed", "phish-tracker"],
            },
        )
    ]
    ai_patterns = [
        {
            "title": "Phishing pressure aligns with malicious infrastructure",
            "severity": "high",
            "summary": "The message design and the linked infrastructure point to a staged account-harvesting workflow.",
            "related_findings": [email_findings[0].id, email_findings[1].id, threat_findings[0].id],
        },
        {
            "title": "Exposed identity set has viable follow-on abuse paths",
            "severity": "high",
            "summary": "Breach hits and password reuse indicate that password spray or credential stuffing would likely succeed.",
            "related_findings": [breach_findings[0].id, credential_findings[0].id],
        },
    ]
    modules = [
        _module("identity_exposure", "Escalating exposure state.", identity_findings, {"scanned_files": 27}, duration_ms=460),
        _module("breach_intelligence", "Escalating breach intelligence state.", breach_findings, {"identifiers_scanned": 3, "identifiers_with_hits": 1, "offline_dataset_count": 2}, duration_ms=190),
        _module("credential_hygiene", "Escalating credential hygiene state.", credential_findings, {"password_count": 8, "unique_passwords": 6}, duration_ms=150),
        _module("privacy_risk", "Escalating privacy risk state.", privacy_findings, {"artifact_count": 4}, duration_ms=250),
        _module("browser_audit", "Escalating browser posture state.", browser_findings, {"profiles": 2, "extensions_seen": 14}, duration_ms=320),
        _module("email_phishing", "Escalating phishing state.", email_findings, {"emails_scanned": 1}, duration_ms=170),
        _module("threat_intelligence", "Escalating threat intelligence state.", threat_findings, {"indicators_scanned": 5, "indicators_enriched": 2}, duration_ms=130),
        _module(
            "ai_security_analysis",
            "Escalating AI analysis state.",
            [],
            {
                "analysis_mode": "demo-synthetic",
                "findings_reviewed": 11,
                "summary": "The demo posture has shifted from manageable hygiene gaps into an active identity-risk scenario with phishing, malicious infrastructure, and repeated credential weakness.",
                "risk_explanation": "The environment now shows both valid attack vectors and accessible identity material, increasing the likelihood of account takeover and business-email compromise.",
                "recommended_actions": [
                    "Block the malicious invoice URL and notify the finance team.",
                    "Force-reset reused or breached credentials and verify MFA coverage.",
                    "Re-enable disabled browser protections and remove stored business logins.",
                ],
                "suspicious_patterns": ai_patterns,
            },
            duration_ms=96,
        ),
    ]
    summary = summarize_results(modules, _demo_config())
    timeline = _timeline(
        scan_id,
        started_at,
        [
            ("demo-e1", "identity_exposure", "high", "token_exposure", "GitHub token pattern detected", "A token export was found in synced notes.", "~/Workspace/notes/github-sync.txt", ["token"], [identity_findings[0].id], ["Exposed identity set has viable follow-on abuse paths"]),
            ("demo-e2", "credential_hygiene", "high", "credential_reuse", "Password reuse detected", "Three services share a password.", "credential_inputs", ["reuse"], [credential_findings[0].id], ["Exposed identity set has viable follow-on abuse paths"]),
            ("demo-e3", "breach_intelligence", "medium", "breach_exposure", "Identity exposure detected in breach intelligence", "The finance mailbox appears across three breach sources.", "finance.ops@example.com", ["breach"], [breach_findings[0].id], ["Exposed identity set has viable follow-on abuse paths"]),
            ("demo-e4", "email_phishing", "medium", "phishing_analysis", "Reply-To mismatch detected in email headers", "The invoice lure redirects the reply channel.", "invoice-review.eml", ["phishing"], [email_findings[0].id], ["Phishing pressure aligns with malicious infrastructure"]),
            ("demo-e5", "threat_intelligence", "medium", "threat_intelligence", "Threat intelligence match for url", "The linked invoice portal is malicious.", "invoice-review.eml", ["malicious", "url"], [threat_findings[0].id], ["Phishing pressure aligns with malicious infrastructure"]),
        ],
        [
            (
                "demo-pattern-e1",
                "Phishing pressure aligns with malicious infrastructure",
                "high",
                "A business-email compromise lure now overlaps with a malicious destination URL.",
                ["demo-e4", "demo-e5"],
                ["email_phishing", "threat_intelligence"],
            ),
            (
                "demo-pattern-e2",
                "Exposed identity set has viable follow-on abuse paths",
                "high",
                "Breach exposure, token leakage, and password reuse create a credible takeover chain.",
                ["demo-e1", "demo-e2", "demo-e3"],
                ["identity_exposure", "credential_hygiene", "breach_intelligence"],
            ),
        ],
    )
    return ScanReport(
        scan_id=scan_id,
        started_at=started_at.isoformat(),
        finished_at=(started_at + timedelta(seconds=11)).isoformat(),
        duration_ms=11340,
        platform_name="linux",
        hostname="demo-workstation",
        username="demo-operator",
        user_profile="/home/demo-operator",
        target_paths=["/home/demo-operator/Workspace", "/home/demo-operator/InboxExports"],
        notes=[
            "Demo mode generated synthetic findings. No live scan was executed.",
            "This staged report is designed for dashboard screenshots and walkthroughs.",
        ],
        modules=modules,
        summary=summary,
        config={
            "demo_mode": {"enabled": True, "scenario": "escalation", "safe_synthetic_data": True},
            "reporting": {"redact_evidence": False},
        },
        timeline=timeline,
    )


def _incident_report() -> ScanReport:
    scan_id = "demo-incident-003"
    started_at = datetime(2026, 3, 12, 16, 41, tzinfo=timezone.utc)
    identity_findings = [
        _finding(
            "identity_exposure",
            "critical",
            "GitHub token pattern detected",
            "A staging integration token is present in a locally synced markdown notebook.",
            "~/Workspace/briefings/sprint-sync.md",
            "Rotate the exposed token immediately and remove all plaintext notebook copies from the device.",
            ["token", "secret"],
            {"sample": "demo_token_orange", "file_name": "sprint-sync.md"},
        ),
        _finding(
            "identity_exposure",
            "critical",
            "AWS access key pattern detected",
            "A cloud automation key is staged in a deployment runbook export.",
            "~/Workspace/runbooks/cloud-rollback.txt",
            "Revoke the key, replace it with a managed secret, and clean the runbook export.",
            ["token", "cloud", "secret"],
            {"sample": "demo_cloud_key_001", "file_name": "cloud-rollback.txt"},
        ),
        _finding(
            "identity_exposure",
            "high",
            "Private key material detected",
            "An SSH private key snippet is embedded in a troubleshooting paste.",
            "~/Workspace/support/escalation-snippet.txt",
            "Invalidate the key material and remove the paste artifact from local storage.",
            ["private-key", "secret"],
            {"file_name": "escalation-snippet.txt"},
        ),
        _finding(
            "identity_exposure",
            "medium",
            "Plaintext email address collection detected",
            "An incident export contains leadership and finance addresses in plaintext.",
            "~/Workspace/exports/executive-comms.csv",
            "Move the export into controlled storage and restrict local copies.",
            ["identity", "email"],
            {"email_count": 126, "file_name": "executive-comms.csv"},
        ),
    ]
    breach_findings = [
        _finding(
            "breach_intelligence",
            "high",
            "Identity exposure detected in breach intelligence",
            "finance.ops@example.com appears across four staged breach collections with credential reuse overlap.",
            "finance.ops@example.com",
            "Force password reset, require MFA re-validation, and review active sessions for the identity cluster.",
            ["breach", "identity", "email"],
            {
                "identifier": "finance.ops@example.com",
                "identifier_type": "email",
                "identifier_hash": "demo-incident-e5f6",
                "breach_count": 4,
                "sources": ["credential_leak", "forum_dump", "breach_archive_2024", "combo-list-sim"],
            },
        ),
        _finding(
            "breach_intelligence",
            "high",
            "Identity exposure detected in breach intelligence",
            "payments.portal@example.com appears in multiple credential leak aggregations.",
            "payments.portal@example.com",
            "Rotate the related service credentials and review access logs for replay activity.",
            ["breach", "identity", "email"],
            {
                "identifier": "payments.portal@example.com",
                "identifier_type": "email",
                "identifier_hash": "demo-incident-g7h8",
                "breach_count": 2,
                "sources": ["forum_dump", "stealer-log-sim"],
            },
        ),
    ]
    credential_findings = [
        _finding(
            "credential_hygiene",
            "high",
            "Password reuse detected",
            "Three staged critical services share the same password candidate.",
            "credential_inputs",
            "Break the reuse immediately and enforce a unique-password baseline across the service set.",
            ["password", "reuse"],
            {"count": 3, "accounts": ["payments-portal", "ops-console", "vendor-admin"]},
        ),
        _finding(
            "credential_hygiene",
            "medium",
            "Common password detected",
            "One demo credential candidate remains present in a common-password list.",
            "credential_inputs",
            "Replace the common password with a long unique passphrase.",
            ["password", "common"],
            {"password_alias": "vendor-admin"},
        ),
        _finding(
            "credential_hygiene",
            "medium",
            "Password contains user identifier",
            "A staged password includes the user alias, making it easier to guess.",
            "credential_inputs",
            "Remove names, aliases, or business terms from password construction.",
            ["password", "identifier"],
            {"password_alias": "finance.ops"},
        ),
    ]
    privacy_findings = [
        _finding(
            "privacy_risk",
            "high",
            "Sensitive file has broad permissions",
            "An SSH private key backup is readable by a broad local group.",
            "~/Workspace/keys/id_ed25519-demo",
            "Tighten file permissions and remove the backup from collaborative folders.",
            ["private-key", "privacy"],
            {"file_name": "id_ed25519-demo"},
        ),
        _finding(
            "privacy_risk",
            "medium",
            "Credential store artifact detected",
            "A browser export with session material remains in a downloads subfolder.",
            "~/Downloads/browser-session-export.csv",
            "Delete the export and use approved vault storage for any required credentials.",
            ["privacy", "credential-store"],
            {"file_name": "browser-session-export.csv"},
        ),
    ]
    browser_findings = [
        _finding(
            "browser_audit",
            "high",
            "Disabled browser protection setting detected",
            "Safe browsing protections are disabled in the analyst's default browser profile.",
            "Chrome/Default",
            "Re-enable the protection settings and review the profile for unauthorized changes.",
            ["browser", "protection"],
            {"browser": "Chrome", "profile": "Default"},
        ),
        _finding(
            "browser_audit",
            "medium",
            "Saved logins present in browser profile",
            "The default profile retains saved business credentials.",
            "Chrome/Default",
            "Remove stored logins from the browser and move them into a managed password manager.",
            ["browser", "credential"],
            {"browser": "Chrome", "profile": "Default"},
        ),
        _finding(
            "browser_audit",
            "medium",
            "High browser extension count detected",
            "The analyst profile contains more extensions than the defined hardening baseline.",
            "Chrome/Default",
            "Review and remove unnecessary extensions to reduce extension-supply-chain risk.",
            ["browser", "extensions"],
            {"browser": "Chrome", "profile": "Default", "extension_count": 19},
        ),
    ]
    email_findings = [
        _finding(
            "email_phishing",
            "high",
            "Reply-To mismatch detected in email headers",
            "A staged executive escalation email redirects replies to an external mailbox.",
            "wire-review.eml",
            "Quarantine the message, warn the target team, and validate recent reply activity.",
            ["email", "phishing", "header"],
            {"from": "leadership@trusted-announcements.example", "reply_to": "escalation@secure-mailhub.example"},
        ),
        _finding(
            "email_phishing",
            "high",
            "Email authentication failure detected",
            "The staged message includes failed authentication signals consistent with impersonation.",
            "wire-review.eml",
            "Block the sender infrastructure and review message delivery controls.",
            ["email", "phishing", "auth"],
            {"spf": "fail", "dkim": "fail", "dmarc": "fail"},
        ),
        _finding(
            "email_phishing",
            "high",
            "Suspicious URLs detected in email body",
            "The message links to a fake executive review portal with urgent payment language.",
            "wire-review.eml",
            "Block the URL and notify all users named in the targeted distribution.",
            ["email", "url", "phishing"],
            {"urls": ["https://executive-wire-review.example/approve"], "attachment_names": ["wire-review.html"]},
        ),
    ]
    threat_findings = [
        _finding(
            "threat_intelligence",
            "critical",
            "Threat intelligence match for url",
            "The staged executive review URL is tagged malicious by multiple threat feeds.",
            "wire-review.eml",
            "Block the URL immediately and investigate whether any user interacted with the destination.",
            ["threat-intel", "url", "malicious", "phishing"],
            {
                "indicator": "https://executive-wire-review.example/approve",
                "indicator_type": "url",
                "reputation": "malicious",
                "confidence": 0.96,
                "sources": ["ioc_database", "phish-tracker", "threat_feed_1"],
            },
        ),
        _finding(
            "threat_intelligence",
            "high",
            "Threat intelligence match for domain",
            "The impersonation domain is tied to prior business-email compromise campaigns.",
            "wire-review.eml",
            "Block the domain and add it to mail and web security controls.",
            ["threat-intel", "domain", "malicious", "phishing"],
            {
                "indicator": "executive-wire-review.example",
                "indicator_type": "domain",
                "reputation": "malicious",
                "confidence": 0.91,
                "sources": ["ioc_database", "brand-monitor-feed"],
            },
        ),
        _finding(
            "threat_intelligence",
            "medium",
            "Threat intelligence match for ip",
            "The staged phishing infrastructure resolves to an IP associated with prior credential-harvesting activity.",
            "wire-review.eml",
            "Block the resolved IP where practical and review historical network contact.",
            ["threat-intel", "ip", "suspicious"],
            {
                "indicator": "198.51.100.24",
                "indicator_type": "ip",
                "reputation": "suspicious",
                "confidence": 0.73,
                "sources": ["malicious-infra-lab"],
            },
            confidence="medium",
        ),
    ]
    ai_patterns = [
        {
            "title": "Credential reuse plus breach exposure",
            "severity": "high",
            "summary": "Multiple business identities appear in breach datasets while the service set still shows password reuse.",
            "related_findings": [breach_findings[0].id, breach_findings[1].id, credential_findings[0].id],
        },
        {
            "title": "Phishing with malicious infrastructure",
            "severity": "critical",
            "summary": "The executive impersonation email overlaps with malicious URL, domain, and infrastructure intelligence.",
            "related_findings": [email_findings[0].id, email_findings[1].id, email_findings[2].id, threat_findings[0].id, threat_findings[1].id],
        },
        {
            "title": "Exposed cloud and session material raises takeover risk",
            "severity": "critical",
            "summary": "Local token exposure, cloud key leakage, and browser-stored credentials create multiple paths to credential replay and session hijack.",
            "related_findings": [identity_findings[0].id, identity_findings[1].id, browser_findings[1].id],
        },
    ]
    modules = [
        _module("identity_exposure", "Critical exposure state.", identity_findings, {"scanned_files": 42, "exposure_findings": len(identity_findings)}, duration_ms=510),
        _module("breach_intelligence", "Critical breach exposure state.", breach_findings, {"identifiers_scanned": 4, "identifiers_with_hits": 2, "offline_dataset_count": 2}, duration_ms=215),
        _module("credential_hygiene", "Critical credential hygiene state.", credential_findings, {"password_count": 10, "unique_passwords": 7}, duration_ms=165),
        _module("privacy_risk", "Critical privacy exposure state.", privacy_findings, {"artifact_count": 6}, duration_ms=280),
        _module("browser_audit", "Critical browser posture state.", browser_findings, {"profiles": 3, "extensions_seen": 19}, duration_ms=340),
        _module("email_phishing", "Critical phishing state.", email_findings, {"emails_scanned": 2}, duration_ms=190),
        _module("threat_intelligence", "Critical threat intelligence state.", threat_findings, {"indicators_scanned": 8, "indicators_enriched": 4}, duration_ms=145),
        _module(
            "ai_security_analysis",
            "Critical AI analysis state.",
            [
                _finding(
                    "ai_security_analysis",
                    "high",
                    "Compounded identity takeover pattern detected",
                    "The staged environment shows multiple independent paths to account takeover and business-email compromise.",
                    "cross-module-analysis",
                    "Treat the correlated findings as one incident cluster and prioritize identity containment before broader cleanup.",
                    ["analysis", "correlation"],
                    {"scenario": "incident-demo"},
                    confidence="medium",
                )
            ],
            {
                "analysis_mode": "demo-synthetic",
                "findings_reviewed": 20,
                "summary": "The demo environment now reflects a clear identity-security incident with exposed tokens, breach hits, credential reuse, malicious phishing infrastructure, and browser hardening gaps.",
                "risk_explanation": "Any single control failure would be concerning, but the combination of breach overlap, reusable secrets, and malicious delivery infrastructure indicates a highly actionable account-takeover and business-email-compromise scenario.",
                "recommended_actions": [
                    "Rotate exposed tokens, cloud keys, and all reused credentials immediately.",
                    "Enable or verify MFA on impacted identities and review active sessions.",
                    "Quarantine the phishing campaign, block the malicious URL, domain, and IP, and alert affected users.",
                    "Re-enable browser protections and remove saved logins from analyst workstations.",
                ],
                "suspicious_patterns": ai_patterns,
            },
            duration_ms=102,
        ),
    ]
    summary = summarize_results(modules, _demo_config())
    timeline = _timeline(
        scan_id,
        started_at,
        [
            ("demo-i1", "credential_hygiene", "high", "credential_reuse", "Password reuse detected", "Shared passwords remain present across three critical services.", "credential_inputs", ["reuse"], [credential_findings[0].id], ["Credential reuse plus breach exposure"]),
            ("demo-i2", "breach_intelligence", "high", "breach_exposure", "Identity exposure detected in breach intelligence", "The primary finance mailbox appears in four breach collections.", "finance.ops@example.com", ["breach"], [breach_findings[0].id], ["Credential reuse plus breach exposure"]),
            ("demo-i3", "email_phishing", "high", "phishing_analysis", "Reply-To mismatch detected in email headers", "The staged executive lure redirects replies off-domain.", "wire-review.eml", ["phishing"], [email_findings[0].id], ["Phishing with malicious infrastructure"]),
            ("demo-i4", "email_phishing", "high", "phishing_analysis", "Email authentication failure detected", "SPF, DKIM, and DMARC all fail on the staged message.", "wire-review.eml", ["phishing"], [email_findings[1].id], ["Phishing with malicious infrastructure"]),
            ("demo-i5", "threat_intelligence", "critical", "threat_intelligence", "Threat intelligence match for url", "The executive review URL is already tagged malicious.", "wire-review.eml", ["malicious", "url"], [threat_findings[0].id], ["Phishing with malicious infrastructure"]),
            ("demo-i6", "browser_audit", "high", "browser_risk", "Disabled browser protection setting detected", "The primary browser profile is no longer enforcing safe browsing.", "Chrome/Default", ["browser"], [browser_findings[0].id], []),
            ("demo-i7", "identity_exposure", "critical", "token_exposure", "AWS access key pattern detected", "A cloud access key is present in a local rollback export.", "~/Workspace/runbooks/cloud-rollback.txt", ["token", "cloud"], [identity_findings[1].id], ["Exposed cloud and session material raises takeover risk"]),
            ("demo-i8", "identity_exposure", "critical", "token_exposure", "GitHub token pattern detected", "A token is stored in a synced notebook.", "~/Workspace/briefings/sprint-sync.md", ["token"], [identity_findings[0].id], ["Exposed cloud and session material raises takeover risk"]),
        ],
        [
            (
                "demo-pattern-i1",
                "Credential reuse plus breach exposure",
                "high",
                "The identity set is present in breach data while critical services still reuse passwords.",
                ["demo-i1", "demo-i2"],
                ["credential_hygiene", "breach_intelligence"],
            ),
            (
                "demo-pattern-i2",
                "Phishing with malicious infrastructure",
                "critical",
                "An executive-style phishing message overlaps with malicious URL and domain intelligence.",
                ["demo-i3", "demo-i4", "demo-i5"],
                ["email_phishing", "threat_intelligence"],
            ),
            (
                "demo-pattern-i3",
                "Exposed cloud and session material raises takeover risk",
                "critical",
                "Local token and cloud key exposure create multiple privileged session abuse paths.",
                ["demo-i7", "demo-i8"],
                ["identity_exposure"],
            ),
        ],
    )
    return ScanReport(
        scan_id=scan_id,
        started_at=started_at.isoformat(),
        finished_at=(started_at + timedelta(seconds=14)).isoformat(),
        duration_ms=14320,
        platform_name="linux",
        hostname="demo-workstation",
        username="demo-operator",
        user_profile="/home/demo-operator",
        target_paths=["/home/demo-operator/Workspace", "/home/demo-operator/InboxExports", "/home/demo-operator/Downloads"],
        notes=[
            "Demo mode generated synthetic findings. No live scan was executed.",
            "This staged incident profile is safe to publish and intended for screenshots, walkthroughs, and portfolio demos.",
        ],
        modules=modules,
        summary=summary,
        config={
            "demo_mode": {"enabled": True, "scenario": "incident", "safe_synthetic_data": True},
            "reporting": {"redact_evidence": False},
            "plugin_system": {"enabled_plugins": ["custom_scanner"]},
        },
        timeline=timeline,
        extensions={
            "plugins": {
                "custom_scanner": {
                    "version": "1.0.0",
                    "description": "Synthetic plugin extension used for demo-mode report completeness.",
                    "modules": ["custom_sensitive_file_scanner"],
                    "report": {
                        "title": "Custom Scanner Insights",
                        "summary": "The demo plugin flagged one additional secrets notebook and enriched two findings with analyst labels.",
                    },
                }
            }
        },
    )


def build_demo_reports() -> list[ScanReport]:
    return [_baseline_report(), _escalation_report(), _incident_report()]


def write_demo_reports(output_dir: Path | str = DEFAULT_DEMO_OUTPUT_DIR) -> DemoArtifacts:
    report_dir = Path(output_dir)
    report_dir.mkdir(parents=True, exist_ok=True)
    reports = build_demo_reports()
    outputs_by_scan: dict[str, dict[str, Path]] = {}
    for report in reports:
        payload = render_json_payload(report, redact=False)
        json_path = report_dir / f"{report.scan_id}.json"
        html_path = report_dir / f"{report.scan_id}.html"
        write_json_payload(payload, json_path)
        atomic_write_text(html_path, render_html_payload(payload), private=True)
        outputs_by_scan[report.scan_id] = {"json": json_path, "html": html_path}
    return DemoArtifacts(output_dir=report_dir, reports=reports, outputs_by_scan=outputs_by_scan)
