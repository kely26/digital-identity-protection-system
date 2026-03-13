"""Data models for DIPS."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from dips.core.config import AppConfig


SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


def stable_finding_id(*parts: str) -> str:
    joined = "||".join(parts)
    digest = hashlib.sha1(joined.encode("utf-8")).hexdigest()
    return digest[:12]


@dataclass(slots=True)
class BrowserProfile:
    browser: str
    display_name: str
    family: str
    profile_name: str
    profile_path: str
    root_path: str
    artifacts: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    id: str
    module: str
    severity: str
    confidence: str
    title: str
    summary: str
    evidence: dict[str, Any]
    location: str
    recommendation: str
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ModuleResult:
    module: str
    description: str
    status: str
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    duration_ms: int = 0


@dataclass(slots=True)
class RiskSummary:
    overall_score: int
    overall_label: str
    severity_counts: dict[str, int]
    module_scores: dict[str, int]
    top_recommendations: list[str]
    category_scores: dict[str, int] = field(default_factory=dict)
    contributing_findings: list[str] = field(default_factory=list)
    risk_model: str = "digital_identity_weighted_sum"


@dataclass(slots=True)
class SecurityEvent:
    id: str
    timestamp: str
    module: str
    severity: str
    event_type: str
    title: str
    summary: str
    location: str
    scan_id: str = ""
    tags: list[str] = field(default_factory=list)
    related_findings: list[str] = field(default_factory=list)
    correlations: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EventPattern:
    id: str
    name: str
    severity: str
    summary: str
    event_ids: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)


@dataclass(slots=True)
class EventTimeline:
    store_path: str = ""
    total_events: int = 0
    events: list[SecurityEvent] = field(default_factory=list)
    patterns: list[EventPattern] = field(default_factory=list)


@dataclass(slots=True)
class ScanContext:
    scan_id: str
    started_at: str
    platform_name: str
    hostname: str
    username: str
    user_profile: Path
    working_directory: Path
    config: AppConfig
    target_paths: list[Path]
    candidate_files: list[Path]
    browser_profiles: list[BrowserProfile]
    email_inputs: list[Path]
    password_inputs: list[str]
    user_identifiers: list[str]
    notes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanReport:
    scan_id: str
    started_at: str
    finished_at: str
    duration_ms: int
    platform_name: str
    hostname: str
    username: str
    user_profile: str
    target_paths: list[str]
    notes: list[str]
    modules: list[ModuleResult]
    summary: RiskSummary
    config: dict[str, Any]
    timeline: EventTimeline = field(default_factory=EventTimeline)
    extensions: dict[str, Any] = field(default_factory=dict)


def to_primitive(value: Any) -> Any:
    if is_dataclass(value):
        return {key: to_primitive(item) for key, item in asdict(value).items()}
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, list):
        return [to_primitive(item) for item in value]
    if isinstance(value, dict):
        return {key: to_primitive(item) for key, item in value.items()}
    return value
