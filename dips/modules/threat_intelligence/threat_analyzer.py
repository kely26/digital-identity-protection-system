"""Threat intelligence enrichment scanner module."""

from __future__ import annotations

from dips.core.models import ModuleResult
from dips.modules.base import ScannerModule
from dips.modules.threat_intelligence.intel_cache import ThreatIntelCache
from dips.modules.threat_intelligence.ioc_parser import extract_iocs_from_paths
from dips.modules.threat_intelligence.reputation_lookup import lookup_reputation
from dips.modules.threat_intelligence.threat_feed_manager import ThreatFeedManager
from dips.utils.paths import path_from_input


def _severity_for_result(reputation: str, indicator_type: str, confidence: float) -> str:
    if reputation == "malicious":
        if indicator_type == "url" and confidence >= 0.9:
            return "critical"
        return "high"
    if reputation == "suspicious":
        return "medium"
    return "low"


class ThreatIntelligenceScanner(ScannerModule):
    name = "threat_intelligence"
    description = "Enriches local indicators with threat intelligence feeds and optional providers."

    def supports(self, context) -> bool:
        settings = context.config.threat_intelligence
        return bool(settings.feed_paths or (settings.allow_online and settings.providers))

    def run(self, context) -> ModuleResult:
        settings = context.config.threat_intelligence
        cache_path = path_from_input(settings.cache_path)
        if not cache_path.is_absolute():
            cache_path = (context.working_directory / cache_path).resolve()

        manager = ThreatFeedManager(settings, working_directory=context.working_directory)
        cache = ThreatIntelCache(cache_path, ttl_seconds=settings.cache_ttl_seconds)

        candidate_paths = [*context.email_inputs, *context.candidate_files]
        observations = extract_iocs_from_paths(candidate_paths)
        unique_keys: set[tuple[str, str]] = set()
        findings = []
        enriched_count = 0

        for observation in observations:
            key = (observation.indicator, observation.indicator_type)
            if key in unique_keys:
                continue
            if len(unique_keys) >= settings.max_indicators:
                break
            unique_keys.add(key)

            intel = lookup_reputation(
                observation.indicator,
                observation.indicator_type,
                manager=manager,
                cache=cache,
            )
            reputation = str(intel.get("reputation", "unknown"))
            if reputation not in {"malicious", "suspicious"}:
                continue

            enriched_count += 1
            confidence = float(intel.get("confidence", 0.0))
            severity = _severity_for_result(reputation, observation.indicator_type, confidence)
            summary = (
                f"{observation.indicator} is marked {reputation} by {len(intel.get('sources', []))} "
                "threat intelligence source(s)."
            )
            recommendation = (
                "Block the indicator where appropriate, review affected accounts or endpoints, and verify related alerts."
            )
            tags = ["threat-intel", observation.indicator_type, reputation]
            if observation.indicator_type == "url":
                tags.append("phishing")
                recommendation = "Do not open the link, block it in mail or web controls, and investigate the sender."
            elif observation.indicator_type == "domain":
                recommendation = "Block or monitor the domain and validate whether any communication with it was expected."
            elif observation.indicator_type == "ip":
                recommendation = "Review whether the IP should be blocked and investigate any related outbound or inbound activity."

            findings.append(
                self.build_finding(
                    severity=severity,
                    confidence="high" if confidence >= 0.85 else "medium",
                    title=f"Threat intelligence match for {observation.indicator_type}",
                    summary=summary,
                    evidence={
                        "indicator": observation.indicator,
                        "indicator_type": observation.indicator_type,
                        "reputation": reputation,
                        "confidence": round(confidence, 2),
                        "sources": intel.get("sources", []),
                    },
                    location=observation.source,
                    recommendation=recommendation,
                    tags=tags,
                )
            )

        return ModuleResult(
            module=self.name,
            description=self.description,
            status="completed",
            findings=findings,
            metadata={
                "indicators_scanned": len(unique_keys),
                "indicators_enriched": enriched_count,
                "feed_paths": settings.feed_paths,
                "allow_online": settings.allow_online,
                "cache_path": str(cache_path),
            },
        )
