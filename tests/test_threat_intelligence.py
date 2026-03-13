from __future__ import annotations

import json
from pathlib import Path

from dips.modules.threat_intelligence.reputation_lookup import lookup_reputation
from dips.modules.threat_intelligence.intel_cache import ThreatIntelCache
from dips.modules.threat_intelligence.threat_analyzer import ThreatIntelligenceScanner
from dips.modules.threat_intelligence.threat_feed_manager import ThreatFeedManager


FIXTURE_FEED = Path(__file__).parent / "fixtures" / "threat" / "malicious_feed.json"
FIXTURE_EMAIL = Path(__file__).parent / "fixtures" / "email" / "phish.eml"


def test_threat_intelligence_scanner_enriches_email_indicators(default_config, make_context):
    config = default_config
    config.threat_intelligence.feed_paths = [str(FIXTURE_FEED)]

    context = make_context(
        config=config,
        email_inputs=[FIXTURE_EMAIL],
        candidate_files=[],
    )
    result = ThreatIntelligenceScanner().run(context)

    assert result.status == "completed"
    assert len(result.findings) == 3
    titles = {finding.title for finding in result.findings}
    assert "Threat intelligence match for url" in titles
    assert "Threat intelligence match for domain" in titles
    assert "Threat intelligence match for ip" in titles
    url_finding = next(finding for finding in result.findings if "url" in finding.tags)
    assert url_finding.severity == "critical"
    assert url_finding.evidence["reputation"] == "malicious"
    assert url_finding.evidence["sources"] == ["threat_feed_1"]


def test_threat_reputation_lookup_uses_cache(tmp_path, default_config):
    feed_path = tmp_path / "malicious_feed.json"
    feed_path.write_text(FIXTURE_FEED.read_text(encoding="utf-8"), encoding="utf-8")
    config = default_config
    config.threat_intelligence.feed_paths = [str(feed_path)]
    manager = ThreatFeedManager(config.threat_intelligence, working_directory=tmp_path)
    cache = ThreatIntelCache(tmp_path / "threat_cache.json", ttl_seconds=3600)

    first = lookup_reputation(
        "http://192.168.1.10/login",
        "url",
        manager=manager,
        cache=cache,
    )
    feed_path.unlink()
    second = lookup_reputation(
        "http://192.168.1.10/login",
        "url",
        manager=manager,
        cache=cache,
    )

    assert first["reputation"] == "malicious"
    assert second["reputation"] == "malicious"
    assert second["sources"] == first["sources"]
    cache_payload = json.loads((tmp_path / "threat_cache.json").read_text(encoding="utf-8"))
    assert "http://192.168.1.10/login" not in json.dumps(cache_payload)
