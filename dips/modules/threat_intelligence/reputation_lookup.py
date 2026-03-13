"""Threat reputation lookup and aggregation."""

from __future__ import annotations

from dips.modules.threat_intelligence.intel_cache import ThreatIntelCache
from dips.modules.threat_intelligence.ioc_parser import normalize_indicator
from dips.modules.threat_intelligence.threat_feed_manager import ThreatFeedManager

REPUTATION_RANK = {
    "unknown": 0,
    "benign": 1,
    "suspicious": 2,
    "malicious": 3,
}


def _aggregate_result(indicator: str, indicator_type: str, matches: list[dict]) -> dict:
    if not matches:
        return {
            "indicator": indicator,
            "indicator_type": indicator_type,
            "reputation": "unknown",
            "confidence": 0.0,
            "sources": [],
            "matches": [],
        }

    best_reputation = max(
        (str(match.get("reputation", "unknown")).lower() for match in matches),
        key=lambda item: REPUTATION_RANK.get(item, 0),
    )
    confidence = max(float(match.get("confidence", 0.0)) for match in matches)
    sources = sorted({str(match.get("source", "")) for match in matches if match.get("source")})
    return {
        "indicator": indicator,
        "indicator_type": indicator_type,
        "reputation": best_reputation,
        "confidence": round(confidence, 2),
        "sources": sources,
        "matches": matches,
    }


def _cacheable_result(result: dict) -> dict:
    return {
        "indicator_type": str(result.get("indicator_type", "")),
        "reputation": str(result.get("reputation", "unknown")),
        "confidence": float(result.get("confidence", 0.0)),
        "sources": [str(item) for item in result.get("sources", []) if str(item).strip()],
    }


def lookup_reputation(
    indicator: str,
    indicator_type: str,
    *,
    manager: ThreatFeedManager,
    cache: ThreatIntelCache,
) -> dict:
    normalized = normalize_indicator(indicator, indicator_type)
    cached = cache.get(normalized, indicator_type)
    if cached is not None:
        return cached
    matches = manager.lookup(normalized, indicator_type)
    result = _aggregate_result(normalized, indicator_type, matches)
    cache.set(normalized, indicator_type, _cacheable_result(result))
    return result
