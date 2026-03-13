"""View-model helpers for the DIPS desktop dashboard."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path
from typing import Any

from dips.core.exceptions import ReportError
from dips.core.models import ScanReport, SEVERITY_ORDER
from dips.reporting.json_report import render_json_payload
from dips.utils.paths import path_from_input
from dips.utils.secure_io import read_json_file

MODULE_ORDER = [
    "identity_exposure",
    "breach_intelligence",
    "credential_hygiene",
    "privacy_risk",
    "browser_audit",
    "email_phishing",
    "threat_intelligence",
    "ai_security_analysis",
]

MODULE_META = {
    "identity_exposure": {
        "title": "Identity Exposure Monitor",
        "subtitle": "Plaintext identities, tokens, and sensitive local artifacts.",
        "empty": "No exposure findings were produced in the current scan scope.",
    },
    "breach_intelligence": {
        "title": "Breach Exposure Alerts",
        "subtitle": "Hashed identity checks against offline breach datasets and approved providers.",
        "empty": "No breach intelligence hits were generated for the configured identity targets.",
    },
    "credential_hygiene": {
        "title": "Credential Security",
        "subtitle": "Password hygiene, reuse patterns, and weak secret indicators.",
        "empty": "Credential hygiene needs password candidates before it can score local habits.",
    },
    "privacy_risk": {
        "title": "Local Privacy Risk Scanner",
        "subtitle": "Stored secrets, risky exports, and local permission gaps.",
        "empty": "No risky local privacy artifacts were found in the scanned profile scope.",
    },
    "browser_audit": {
        "title": "Browser Security Audit",
        "subtitle": "Risky browser settings, saved sessions, and extension sprawl.",
        "empty": "No browser findings were generated. This usually means no browser profiles were discovered.",
    },
    "email_phishing": {
        "title": "Phishing Analyzer",
        "subtitle": "Header anomalies, suspicious links, and attachment-driven lures.",
        "empty": "No email inputs were available for phishing analysis.",
    },
    "threat_intelligence": {
        "title": "Threat Intelligence",
        "subtitle": "IOC enrichment, malicious reputation matches, and indicator correlation.",
        "empty": "No threat intelligence matches were produced for the current scan inputs.",
    },
    "ai_security_analysis": {
        "title": "AI Security Analysis",
        "subtitle": "Plain-language risk explanations, suspicious pattern detection, and remediation guidance.",
        "empty": "No AI analysis is available until the scan completes and other modules produce findings.",
    },
}

SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}
SEVERITY_COLORS = {
    "info": "#4f87ff",
    "low": "#2fbf71",
    "medium": "#f5a524",
    "high": "#ff6b3d",
    "critical": "#ff4d6d",
}
MAX_REPORT_BYTES = 20 * 1024 * 1024
_RUNTIME_CACHE_KEY = "_runtime_cache"


def _runtime_cache(payload: dict[str, Any]) -> dict[Any, Any]:
    cache = payload.get(_RUNTIME_CACHE_KEY)
    if isinstance(cache, dict):
        return cache
    cache = {}
    payload[_RUNTIME_CACHE_KEY] = cache
    return cache


def _cached_payload_value(payload: dict[str, Any], key: Any, builder) -> Any:
    cache = _runtime_cache(payload)
    if key not in cache:
        cache[key] = builder()
    return cache[key]


def empty_payload() -> dict[str, Any]:
    modules = [
        {
            "module": module_name,
            "description": MODULE_META.get(module_name, {}).get("subtitle", ""),
            "status": "idle",
            "findings": [],
            "warnings": [],
            "metadata": {},
            "duration_ms": 0,
        }
        for module_name in MODULE_ORDER
    ]
    return {
        "scan_id": "pending",
        "started_at": "",
        "finished_at": "",
        "duration_ms": 0,
        "platform_name": "",
        "hostname": "",
        "username": "",
        "user_profile": "",
        "target_paths": [],
        "notes": ["Run a scan to populate the desktop dashboard."],
        "modules": modules,
        "summary": {
            "overall_score": 0,
            "overall_label": "minimal",
            "severity_counts": {severity: 0 for severity in SEVERITY_ORDER},
            "module_scores": {module_name: 0 for module_name in MODULE_ORDER},
            "top_recommendations": [],
            "category_scores": {},
            "contributing_findings": [],
            "risk_model": "digital_identity_weighted_sum",
        },
        "timeline": {
            "store_path": "",
            "total_events": 0,
            "events": [],
            "patterns": [],
        },
        "config": {},
    }


def build_payload(report: ScanReport, *, redact: bool = False) -> dict[str, Any]:
    payload = render_json_payload(report, redact=redact)
    for severity in SEVERITY_ORDER:
        payload.setdefault("summary", {}).setdefault("severity_counts", {}).setdefault(severity, 0)
    for module_name in MODULE_ORDER:
        payload.setdefault("summary", {}).setdefault("module_scores", {}).setdefault(module_name, 0)
    payload.setdefault("summary", {}).setdefault("category_scores", {})
    payload.setdefault("summary", {}).setdefault("contributing_findings", [])
    payload.setdefault("summary", {}).setdefault("risk_model", "digital_identity_weighted_sum")
    payload.setdefault("timeline", {})
    payload["timeline"].setdefault("store_path", "")
    payload["timeline"].setdefault("total_events", 0)
    payload["timeline"].setdefault("events", [])
    payload["timeline"].setdefault("patterns", [])
    return payload


def _safe_merge(base: Any, override: Any) -> Any:
    if isinstance(base, dict):
        if not isinstance(override, dict):
            return dict(base)
        merged = dict(base)
        for key, value in override.items():
            if key in merged:
                merged[key] = _safe_merge(merged[key], value)
            else:
                merged[key] = value
        return merged
    if isinstance(base, list):
        return list(override) if isinstance(override, list) else list(base)
    if override is None:
        return base
    return override


def normalize_report_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return _safe_merge(empty_payload(), payload)


def load_report_payload(path: str | Path) -> dict[str, Any]:
    report_path = path_from_input(path)
    if report_path.suffix.lower() != ".json":
        raise ReportError(f"Report file must be a JSON file: {report_path}")
    try:
        payload = read_json_file(report_path, max_bytes=MAX_REPORT_BYTES)
    except FileNotFoundError as exc:
        raise ReportError(f"Report file not found: {report_path}") from exc
    except UnicodeDecodeError as exc:
        raise ReportError(f"Report file must be UTF-8 text: {report_path}") from exc
    except json.JSONDecodeError as exc:
        raise ReportError(f"Report file is not valid JSON: {report_path}") from exc
    except ValueError as exc:
        raise ReportError(str(exc)) from exc
    except OSError as exc:
        raise ReportError(f"Failed to read report file {report_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ReportError(f"Expected a JSON object in the report payload: {report_path}")
    return normalize_report_payload(payload)


def load_latest_payload(output_dir: str | Path) -> tuple[dict[str, Any] | None, dict[str, str]]:
    report_dir = path_from_input(output_dir)
    if not report_dir.exists():
        return None, {}
    json_reports = sorted(report_dir.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)
    if not json_reports:
        return None, {}
    for latest in json_reports:
        try:
            payload = load_report_payload(latest)
        except ReportError:
            continue
        html_path = latest.with_suffix(".html")
        outputs = {"json": str(latest)}
        if html_path.exists():
            outputs["html"] = str(html_path)
        return payload, outputs
    return None, {}


def module_map(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return _cached_payload_value(
        payload,
        "module_map",
        lambda: {
            module.get("module", ""): module
            for module in payload.get("modules", [])
            if isinstance(module, dict)
        },
    )


def module_payload(payload: dict[str, Any], module_name: str) -> dict[str, Any]:
    module = module_map(payload).get(module_name)
    if module is not None:
        return module
    meta = MODULE_META.get(
        module_name,
        {
            "title": module_name.replace("_", " ").title(),
            "subtitle": "",
            "empty": "No findings are available for this module.",
        },
    )
    return {
        "module": module_name,
        "description": meta["subtitle"],
        "status": "idle",
        "findings": [],
        "warnings": [],
        "metadata": {},
        "duration_ms": 0,
    }


def protection_score(risk_score: int) -> int:
    return max(0, 100 - int(risk_score))


def overall_protection_score(payload: dict[str, Any]) -> int:
    summary = payload.get("summary", {})
    return protection_score(int(summary.get("overall_score", 0)))


def module_protection_score(payload: dict[str, Any], module_name: str) -> int:
    module_scores = payload.get("summary", {}).get("module_scores", {})
    return protection_score(int(module_scores.get(module_name, 0)))


def severity_counts(payload: dict[str, Any]) -> dict[str, int]:
    raw = payload.get("summary", {}).get("severity_counts", {})
    return {severity: int(raw.get(severity, 0)) for severity in SEVERITY_ORDER}


def flatten_findings(payload: dict[str, Any], module_name: str | None = None) -> list[dict[str, Any]]:
    cache_key = ("flatten_findings", module_name or "*")

    def _build() -> tuple[dict[str, Any], ...]:
        findings: list[dict[str, Any]] = []
        for module in payload.get("modules", []):
            if module_name and module.get("module") != module_name:
                continue
            module_title = MODULE_META.get(module.get("module", ""), {}).get("title", module.get("module", ""))
            for finding in module.get("findings", []):
                if not isinstance(finding, dict):
                    continue
                enriched = dict(finding)
                enriched["module_title"] = module_title
                enriched["module_status"] = module.get("status", "unknown")
                findings.append(enriched)
        findings.sort(
            key=lambda item: (-SEVERITY_RANK.get(item.get("severity", "info"), -1), item.get("title", ""))
        )
        return tuple(findings)

    return list(_cached_payload_value(payload, cache_key, _build))


def recent_alerts(payload: dict[str, Any], *, limit: int = 8) -> list[dict[str, Any]]:
    return flatten_findings(payload)[:limit]


def prioritized_alerts(payload: dict[str, Any], *, limit: int = 10) -> list[dict[str, Any]]:
    def _build() -> tuple[dict[str, Any], ...]:
        alerts = []
        for finding in flatten_findings(payload):
            priority_score = _priority_score(finding)
            enriched = dict(finding)
            enriched["priority_score"] = priority_score
            enriched["priority_label"] = _priority_label(priority_score)
            alerts.append(enriched)
        alerts.sort(
            key=lambda item: (
                -int(item.get("priority_score", 0)),
                -SEVERITY_RANK.get(str(item.get("severity", "info")), -1),
                str(item.get("title", "")),
            )
        )
        return tuple(alerts)

    return list(_cached_payload_value(payload, "prioritized_alerts", _build)[:limit])


def recommendation_list(payload: dict[str, Any], module_name: str | None = None) -> list[str]:
    if module_name is None:
        items = payload.get("summary", {}).get("top_recommendations", [])
        return [item for item in items if isinstance(item, str)]
    if module_name == "ai_security_analysis":
        metadata = module_payload(payload, module_name).get("metadata", {})
        items = metadata.get("recommended_actions", [])
        return [str(item) for item in items if str(item).strip()]
    recommendations: list[str] = []
    seen: set[str] = set()
    for finding in flatten_findings(payload, module_name):
        recommendation = finding.get("recommendation", "")
        if not recommendation or recommendation in seen:
            continue
        recommendations.append(recommendation)
        seen.add(recommendation)
    return recommendations[:6]


def module_score_rows(payload: dict[str, Any]) -> list[tuple[str, int]]:
    scores = payload.get("summary", {}).get("module_scores", {})
    rows = []
    for module_name in MODULE_ORDER:
        rows.append((MODULE_META.get(module_name, {}).get("title", module_name), int(scores.get(module_name, 0))))
    return rows


def category_score_rows(payload: dict[str, Any]) -> list[tuple[str, int]]:
    rows = []
    raw = payload.get("summary", {}).get("category_scores", {})
    for category, value in sorted(raw.items(), key=lambda item: (-int(item[1]), item[0])):
        label = category.replace("_", " ").title()
        rows.append((label, int(value)))
    return rows


def contributing_findings(payload: dict[str, Any], *, limit: int = 6) -> list[str]:
    findings = payload.get("summary", {}).get("contributing_findings", [])
    return [str(item) for item in findings[:limit] if isinstance(item, str)]


def threat_intel_rows(payload: dict[str, Any], *, limit: int = 8) -> list[dict[str, Any]]:
    def _build() -> tuple[dict[str, Any], ...]:
        findings = flatten_findings(payload, "threat_intelligence")
        rows: list[dict[str, Any]] = []
        for finding in findings:
            evidence = finding.get("evidence", {})
            indicator = str(evidence.get("indicator", finding.get("location", "")))
            sources = [str(item) for item in evidence.get("sources", []) if str(item).strip()]
            rows.append(
                {
                    "indicator": indicator,
                    "indicator_type": str(evidence.get("indicator_type", "unknown")).lower(),
                    "reputation": str(evidence.get("reputation", finding.get("severity", "unknown"))).lower(),
                    "confidence": float(evidence.get("confidence", 0.0)),
                    "sources": sources,
                    "severity": str(finding.get("severity", "info")).lower(),
                    "location": str(finding.get("location", "")),
                    "priority_label": _priority_label(_priority_score(finding)),
                }
            )
        rows.sort(
            key=lambda item: (
                -_reputation_rank(item["reputation"]),
                -int(round(item["confidence"] * 100)),
                item["indicator"],
            )
        )
        return tuple(rows)

    return list(_cached_payload_value(payload, "threat_intel_rows", _build)[:limit])


def threat_intel_summary(payload: dict[str, Any]) -> dict[str, int]:
    rows = threat_intel_rows(payload, limit=200)
    summary = {"total": 0, "malicious": 0, "suspicious": 0, "urls": 0, "domains": 0, "ips": 0}
    for row in rows:
        summary["total"] += 1
        reputation = str(row.get("reputation", "unknown"))
        indicator_type = str(row.get("indicator_type", "unknown"))
        if reputation == "malicious":
            summary["malicious"] += 1
        elif reputation == "suspicious":
            summary["suspicious"] += 1
        if indicator_type == "url":
            summary["urls"] += 1
        elif indicator_type == "domain":
            summary["domains"] += 1
        elif indicator_type == "ip":
            summary["ips"] += 1
    return summary


def severity_heatmap_rows(payload: dict[str, Any]) -> list[dict[str, Any]]:
    def _build() -> tuple[dict[str, Any], ...]:
        rows: list[dict[str, Any]] = []
        module_lookup = module_map(payload)
        ordered_names = [*MODULE_ORDER]
        for module_name in module_lookup:
            if module_name not in ordered_names:
                ordered_names.append(module_name)
        for module_name in ordered_names:
            module = module_lookup.get(module_name)
            if module is None:
                continue
            counts = {severity: 0 for severity in SEVERITY_ORDER}
            for finding in module.get("findings", []):
                severity = str(finding.get("severity", "info")).lower()
                if severity in counts:
                    counts[severity] += 1
            rows.append(
                {
                    "module": module_name,
                    "label": MODULE_META.get(module_name, {}).get("title", module_name.replace("_", " ").title()),
                    "values": [counts[severity] for severity in SEVERITY_ORDER],
                    "total": sum(counts.values()),
                }
            )
        return tuple(rows)

    return list(_cached_payload_value(payload, "severity_heatmap_rows", _build))


def identity_exposure_map_nodes(payload: dict[str, Any], *, limit: int = 12) -> list[dict[str, Any]]:
    supported_modules = {
        "identity_exposure",
        "breach_intelligence",
        "credential_hygiene",
        "privacy_risk",
        "browser_audit",
        "email_phishing",
        "threat_intelligence",
    }
    zone_map = {
        "identity_exposure": "storage",
        "breach_intelligence": "breach",
        "credential_hygiene": "credential",
        "privacy_risk": "storage",
        "browser_audit": "browser",
        "email_phishing": "messaging",
        "threat_intelligence": "network",
    }
    nodes: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for finding in prioritized_alerts(payload, limit=limit * 3):
        module_name = str(finding.get("module", ""))
        if module_name not in supported_modules:
            continue
        label = _node_label(finding)
        key = (zone_map.get(module_name, "identity"), label)
        if key in seen:
            continue
        seen.add(key)
        nodes.append(
            {
                "label": label,
                "zone": zone_map.get(module_name, "identity"),
                "module": module_name,
                "module_title": str(finding.get("module_title", module_name)),
                "severity": str(finding.get("severity", "info")).lower(),
                "weight": max(18, int(finding.get("priority_score", 40))),
                "summary": str(finding.get("summary", "")),
            }
        )
        if len(nodes) >= limit:
            break
    return nodes


def alert_correlation_clusters(payload: dict[str, Any], *, limit: int = 6) -> list[dict[str, Any]]:
    patterns = []
    for item in timeline_patterns(payload):
        modules = [str(module) for module in item.get("modules", []) if str(module).strip()]
        patterns.append(
            {
                "id": str(item.get("id", item.get("name", ""))),
                "label": str(item.get("name", "")),
                "severity": str(item.get("severity", "medium")).lower(),
                "summary": str(item.get("summary", "")),
                "modules": modules,
                "event_count": len(item.get("event_ids", [])),
                "source": "timeline",
            }
        )
    ai_metadata = module_payload(payload, "ai_security_analysis").get("metadata", {})
    for index, item in enumerate(ai_metadata.get("suspicious_patterns", []), start=1):
        if not isinstance(item, dict):
            continue
        patterns.append(
            {
                "id": f"ai-pattern-{index}",
                "label": str(item.get("title", "")),
                "severity": str(item.get("severity", "medium")).lower(),
                "summary": str(item.get("summary", "")),
                "modules": [],
                "event_count": len(item.get("related_findings", [])),
                "source": "ai",
            }
        )
    patterns.sort(
        key=lambda item: (-SEVERITY_RANK.get(item["severity"], -1), -int(item["event_count"]), item["label"])
    )
    return patterns[:limit]


def module_status_text(payload: dict[str, Any], module_name: str) -> str:
    module = module_payload(payload, module_name)
    warnings = module.get("warnings", [])
    status = str(module.get("status", "idle")).capitalize()
    if warnings:
        return f"{status} | {len(warnings)} warning(s)"
    return status


def _count_matching(findings: list[dict[str, Any]], *, title_contains: str = "", tag: str = "") -> int:
    count = 0
    for finding in findings:
        title = str(finding.get("title", "")).lower()
        tags = [str(item).lower() for item in finding.get("tags", [])]
        if title_contains and title_contains not in title:
            continue
        if tag and tag not in tags:
            continue
        count += 1
    return count


def module_metrics(payload: dict[str, Any], module_name: str) -> list[dict[str, str]]:
    module = module_payload(payload, module_name)
    findings = flatten_findings(payload, module_name)
    metadata = module.get("metadata", {})
    risk_score = int(payload.get("summary", {}).get("module_scores", {}).get(module_name, 0))
    protection = protection_score(risk_score)

    if module_name == "identity_exposure":
        return [
            {"title": "Protection Index", "value": str(protection), "subtitle": "100 means less exposure.", "tone": "primary"},
            {
                "title": "Exposure Findings",
                "value": str(len(findings)),
                "subtitle": "Local plaintext and token indicators.",
                "tone": "alert",
            },
            {
                "title": "Critical Signals",
                "value": str(sum(1 for item in findings if item.get("severity") in {"high", "critical"})),
                "subtitle": "High-priority identity issues.",
                "tone": "warning",
            },
            {
                "title": "Files Reviewed",
                "value": str(metadata.get("scanned_files", 0)),
                "subtitle": "Candidate files scanned this run.",
                "tone": "neutral",
            },
        ]

    if module_name == "breach_intelligence":
        total_hits = sum(int(item.get("evidence", {}).get("breach_count", 0)) for item in findings)
        return [
            {"title": "Breach Posture", "value": str(protection), "subtitle": "Higher is better for identity containment.", "tone": "primary"},
            {
                "title": "Targets Checked",
                "value": str(metadata.get("identifiers_scanned", 0)),
                "subtitle": "Emails and usernames evaluated locally.",
                "tone": "neutral",
            },
            {
                "title": "Exposed Identities",
                "value": str(metadata.get("identifiers_with_hits", len(findings))),
                "subtitle": "Identity targets matched in breach intelligence.",
                "tone": "alert",
            },
            {
                "title": "Exposure Records",
                "value": str(total_hits),
                "subtitle": "Total matched breach records across all sources.",
                "tone": "warning",
            },
        ]

    if module_name == "credential_hygiene":
        return [
            {"title": "Hygiene Score", "value": str(protection), "subtitle": "Lower risk means healthier credentials.", "tone": "primary"},
            {
                "title": "Weak Passwords",
                "value": str(
                    _count_matching(findings, title_contains="short password")
                    + _count_matching(findings, title_contains="low password complexity")
                    + _count_matching(findings, title_contains="common password")
                ),
                "subtitle": "Length, complexity, and common-password issues.",
                "tone": "warning",
            },
            {
                "title": "Reuse Detections",
                "value": str(_count_matching(findings, title_contains="password reuse")),
                "subtitle": "Repeated password candidates.",
                "tone": "alert",
            },
            {
                "title": "Candidates Reviewed",
                "value": str(metadata.get("password_count", 0)),
                "subtitle": "Passwords supplied for local hygiene analysis.",
                "tone": "neutral",
            },
        ]

    if module_name == "privacy_risk":
        return [
            {"title": "Privacy Score", "value": str(protection), "subtitle": "Lower score means more local exposure.", "tone": "primary"},
            {
                "title": "Risky Artifacts",
                "value": str(len(findings)),
                "subtitle": "Stored secrets, exports, and shell traces.",
                "tone": "alert",
            },
            {
                "title": "Permission Issues",
                "value": str(_count_matching(findings, title_contains="broad permissions")),
                "subtitle": "Sensitive files with overly broad access.",
                "tone": "warning",
            },
            {
                "title": "Credential Stores",
                "value": str(_count_matching(findings, title_contains="credential store")),
                "subtitle": "Local files likely storing authentication data.",
                "tone": "neutral",
            },
        ]

    if module_name == "browser_audit":
        return [
            {"title": "Browser Hardening", "value": str(protection), "subtitle": "Higher score means a tighter browser posture.", "tone": "primary"},
            {
                "title": "Profiles Audited",
                "value": str(metadata.get("profiles", 0)),
                "subtitle": "Discovered browser profiles.",
                "tone": "neutral",
            },
            {
                "title": "Risky Settings",
                "value": str(
                    _count_matching(findings, title_contains="disabled")
                    + _count_matching(findings, title_contains="protection")
                ),
                "subtitle": "Safe browsing, breach alerts, or leak detection gaps.",
                "tone": "warning",
            },
            {
                "title": "Stored Data Warnings",
                "value": str(
                    _count_matching(findings, title_contains="saved logins")
                    + _count_matching(findings, title_contains="stores credential")
                ),
                "subtitle": "Browser session and credential artifacts.",
                "tone": "alert",
            },
        ]

    if module_name == "email_phishing":
        return [
            {"title": "Phishing Defense", "value": str(protection), "subtitle": "Lower score means stronger phishing indicators were found.", "tone": "primary"},
            {
                "title": "Emails Analyzed",
                "value": str(metadata.get("emails_scanned", 0)),
                "subtitle": "User-supplied email samples scanned locally.",
                "tone": "neutral",
            },
            {
                "title": "Suspicious Links",
                "value": str(_count_matching(findings, title_contains="suspicious urls")),
                "subtitle": "Punycode, IP-literal, or otherwise risky URLs.",
                "tone": "warning",
            },
            {
                "title": "Header Anomalies",
                "value": str(
                    _count_matching(findings, title_contains="reply-to")
                    + _count_matching(findings, title_contains="authentication failure")
                ),
                "subtitle": "Sender and authentication mismatches.",
                "tone": "alert",
            },
        ]

    if module_name == "threat_intelligence":
        return [
            {"title": "Intel Coverage", "value": str(protection), "subtitle": "Higher is better when fewer malicious indicators are present.", "tone": "primary"},
            {
                "title": "Indicators Scanned",
                "value": str(metadata.get("indicators_scanned", 0)),
                "subtitle": "URLs, domains, and IPs evaluated against threat feeds.",
                "tone": "neutral",
            },
            {
                "title": "Malicious Matches",
                "value": str(
                    _count_matching(findings, tag="malicious")
                ),
                "subtitle": "Indicators marked malicious by threat intelligence.",
                "tone": "alert",
            },
            {
                "title": "Suspicious Matches",
                "value": str(
                    _count_matching(findings, tag="suspicious")
                ),
                "subtitle": "Indicators that need review but are not fully confirmed malicious.",
                "tone": "warning",
            },
        ]

    if module_name == "ai_security_analysis":
        recommended_actions = [
            str(item)
            for item in metadata.get("recommended_actions", [])
            if str(item).strip()
        ]
        suspicious_patterns = metadata.get("suspicious_patterns", [])
        return [
            {
                "title": "Analysis Coverage",
                "value": str(metadata.get("findings_reviewed", len(findings))),
                "subtitle": "Source findings reviewed by the AI analysis layer.",
                "tone": "primary",
            },
            {
                "title": "Compound Risks",
                "value": str(len(suspicious_patterns) if isinstance(suspicious_patterns, list) else 0),
                "subtitle": "Cross-module attack patterns detected from the report.",
                "tone": "alert",
            },
            {
                "title": "Action Queue",
                "value": str(len(recommended_actions)),
                "subtitle": "Plain-language remediation steps generated for the operator.",
                "tone": "warning",
            },
            {
                "title": "Analysis Mode",
                "value": str(metadata.get("analysis_mode", "local")).replace("-", " ").title(),
                "subtitle": "How the AI analysis module produced this assessment.",
                "tone": "neutral",
            },
        ]

    return [
        {"title": "Protection Index", "value": str(protection), "subtitle": "Module protection snapshot.", "tone": "primary"},
        {"title": "Findings", "value": str(len(findings)), "subtitle": "Alerts generated by this module.", "tone": "alert"},
    ]


def overview_cards(payload: dict[str, Any]) -> list[dict[str, str]]:
    alerts = prioritized_alerts(payload, limit=200)
    threat_summary = threat_intel_summary(payload)
    correlations = alert_correlation_clusters(payload, limit=20)
    return [
        {
            "title": "Identity Protection Score",
            "value": str(overall_protection_score(payload)),
            "subtitle": "Higher is better across all identity surfaces.",
            "tone": "primary",
        },
        {
            "title": "Priority 1 Alerts",
            "value": str(sum(1 for item in alerts if item.get("priority_label") == "P1")),
            "subtitle": "Highest urgency alerts requiring immediate containment.",
            "tone": "alert",
        },
        {
            "title": "Threat Intel Hits",
            "value": str(threat_summary["total"]),
            "subtitle": "Indicators enriched by local or provider-backed threat intelligence.",
            "tone": "warning",
        },
        {
            "title": "Correlated Signals",
            "value": str(len(correlations)),
            "subtitle": "Cross-module attack patterns currently linked in the timeline.",
            "tone": "neutral",
        },
    ]


def _history_label(value: str, fallback: str) -> str:
    if value:
        try:
            return datetime.fromisoformat(value).strftime("%m-%d")
        except ValueError:
            return value[:10]
    return fallback[:6]


def scan_history_points(payload: dict[str, Any], outputs: dict[str, str], *, limit: int = 8) -> list[dict[str, Any]]:
    json_output = outputs.get("json")
    if not json_output:
        return [
            {
                "scan_id": str(payload.get("scan_id", "pending")),
                "overall_score": int(payload.get("summary", {}).get("overall_score", 0)),
                "label": _history_label(str(payload.get("finished_at", "")), str(payload.get("scan_id", ""))),
                "overall_label": str(payload.get("summary", {}).get("overall_label", "minimal")),
            }
        ]

    report_dir = path_from_input(json_output).parent
    if not report_dir.exists():
        return []

    try:
        directory_mtime_ns = report_dir.stat().st_mtime_ns
    except OSError:
        return []

    def _build() -> tuple[dict[str, Any], ...]:
        rows: list[dict[str, Any]] = []
        for report_path in sorted(report_dir.glob("*.json"), key=lambda item: item.stat().st_mtime, reverse=True)[:limit]:
            try:
                report_payload = read_json_file(report_path, max_bytes=MAX_REPORT_BYTES)
            except (OSError, json.JSONDecodeError, UnicodeDecodeError, ValueError):
                continue
            if not isinstance(report_payload, dict):
                continue
            normalized = normalize_report_payload(report_payload)
            summary = normalized.get("summary", {})
            finished_at = str(normalized.get("finished_at", ""))
            scan_id = str(normalized.get("scan_id", report_path.stem))
            rows.append(
                {
                    "scan_id": scan_id,
                    "overall_score": int(summary.get("overall_score", 0)),
                    "overall_label": str(summary.get("overall_label", "minimal")),
                    "label": _history_label(finished_at, scan_id),
                }
            )
        if not rows:
            return tuple()
        rows.reverse()
        return tuple(rows)

    rows = list(
        _cached_payload_value(
            payload,
            ("scan_history_points", str(report_dir), directory_mtime_ns, limit),
            _build,
        )
    )

    if not rows:
        return []
    return rows


def risk_trend_summary(payload: dict[str, Any], outputs: dict[str, str]) -> dict[str, Any]:
    points = scan_history_points(payload, outputs, limit=8)
    if not points:
        return {"current": 0, "delta": 0, "direction": "stable", "label": "minimal"}

    current = int(points[-1].get("overall_score", 0))
    previous = int(points[-2].get("overall_score", current)) if len(points) > 1 else current
    delta = current - previous
    direction = "up" if delta > 0 else "down" if delta < 0 else "stable"
    return {
        "current": current,
        "delta": delta,
        "direction": direction,
        "label": str(points[-1].get("overall_label", "minimal")),
    }


def timeline_events(
    payload: dict[str, Any],
    *,
    severity: str = "all",
    module_name: str = "all",
    limit: int | None = None,
) -> list[dict[str, Any]]:
    events = list(
        _cached_payload_value(
            payload,
            "timeline_events_base",
            lambda: tuple(
                sorted(
                    (
                        item
                        for item in payload.get("timeline", {}).get("events", [])
                        if isinstance(item, dict)
                    ),
                    key=lambda item: (str(item.get("timestamp", "")), str(item.get("title", ""))),
                    reverse=True,
                )
            ),
        )
    )
    if severity != "all":
        events = [item for item in events if str(item.get("severity", "")).lower() == severity]
    if module_name != "all":
        events = [item for item in events if str(item.get("module", "")).lower() == module_name]
    if limit is not None:
        events = events[:limit]
    return events


def timeline_modules(payload: dict[str, Any]) -> list[str]:
    modules = {
        str(item.get("module", "")).lower()
        for item in payload.get("timeline", {}).get("events", [])
        if isinstance(item, dict) and item.get("module")
    }
    return sorted(module for module in modules if module)


def timeline_patterns(payload: dict[str, Any]) -> list[dict[str, Any]]:
    return list(
        _cached_payload_value(
            payload,
            "timeline_patterns",
            lambda: tuple(
                sorted(
                    (
                        item
                        for item in payload.get("timeline", {}).get("patterns", [])
                        if isinstance(item, dict)
                    ),
                    key=lambda item: (str(item.get("severity", "")), str(item.get("name", ""))),
                    reverse=True,
                )
            ),
        )
    )


def _priority_score(finding: dict[str, Any]) -> int:
    severity = str(finding.get("severity", "info")).lower()
    confidence = str(finding.get("confidence", "medium")).lower()
    tags = {str(item).lower() for item in finding.get("tags", [])}
    base = {
        "critical": 92,
        "high": 78,
        "medium": 58,
        "low": 34,
        "info": 18,
    }.get(severity, 18)
    confidence_bonus = {"high": 8, "medium": 4, "low": 1}.get(confidence, 2)
    tag_bonus = 0
    if "malicious" in tags:
        tag_bonus += 12
    if "phishing" in tags:
        tag_bonus += 10
    if "breach" in tags:
        tag_bonus += 9
    if {"token", "private-key", "secret"} & tags:
        tag_bonus += 11
    if "reuse" in tags:
        tag_bonus += 8
    return min(100, base + confidence_bonus + tag_bonus)


def _priority_label(score: int) -> str:
    if score >= 90:
        return "P1"
    if score >= 72:
        return "P2"
    if score >= 50:
        return "P3"
    return "P4"


def _node_label(finding: dict[str, Any]) -> str:
    evidence = finding.get("evidence", {})
    for key in ("identifier", "indicator", "file_name"):
        value = str(evidence.get(key, "")).strip()
        if value:
            return value if len(value) <= 24 else value[:21] + "..."
    location = str(finding.get("location", "")).strip()
    if location and location not in {"credential_inputs", "cross-module-analysis", "report_summary"}:
        return Path(location).name or location
    title = str(finding.get("title", "")).strip()
    return title if len(title) <= 24 else title[:21] + "..."


def _reputation_rank(reputation: str) -> int:
    return {"malicious": 3, "suspicious": 2, "unknown": 1}.get(reputation, 0)
