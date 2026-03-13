from __future__ import annotations

from pathlib import Path

from dips.modules.breach_intelligence.breach_analyzer import BreachIntelligenceScanner
from dips.modules.breach_intelligence.breach_cache import BreachCache
from dips.modules.breach_intelligence.breach_lookup import (
    build_dataset_index,
    load_offline_datasets,
    lookup_identifier,
)


FIXTURE_DATASET = Path(__file__).parent / "fixtures" / "breach" / "offline_dataset.json"


def test_breach_intelligence_scanner_matches_offline_dataset(default_config, make_context):
    config = default_config
    config.breach_intelligence.identifiers = ["security.user@example.com"]
    config.breach_intelligence.offline_datasets = [str(FIXTURE_DATASET)]

    context = make_context(
        config=config,
        user_identifiers=["security.user@example.com"],
    )
    result = BreachIntelligenceScanner().run(context)

    assert result.status == "completed"
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity == "high"
    assert finding.evidence["identifier"] == "se***@example.com"
    assert finding.evidence["breach_count"] == 3
    assert finding.evidence["identifier_hash"] == "b7b9c63088f3"
    assert finding.evidence["sources"] == ["breach_archive_2021", "credential_leak", "forum_dump"]
    assert result.metadata["identifiers_scanned"] == 1
    assert result.metadata["identifiers_with_hits"] == 1


def test_breach_lookup_uses_cache_when_dataset_is_removed(tmp_path, default_config):
    dataset_path = tmp_path / "offline_dataset.json"
    dataset_path.write_text(FIXTURE_DATASET.read_text(encoding="utf-8"), encoding="utf-8")
    cache = BreachCache(tmp_path / "breach_cache.json", ttl_seconds=3600)

    config = default_config
    config.breach_intelligence.offline_datasets = [str(dataset_path)]

    first = lookup_identifier(
        "security.user@example.com",
        config=config,
        working_directory=tmp_path,
        cache=cache,
    )
    dataset_path.unlink()
    second = lookup_identifier(
        "security.user@example.com",
        config=config,
        working_directory=tmp_path,
        cache=cache,
    )

    assert first["breach_count"] == 3
    assert second["breach_count"] == 3
    assert second["sources"] == first["sources"]


def test_breach_lookup_uses_prebuilt_index_without_reloading_dataset(tmp_path, default_config):
    dataset_path = tmp_path / "offline_dataset.json"
    dataset_path.write_text(FIXTURE_DATASET.read_text(encoding="utf-8"), encoding="utf-8")
    cache = BreachCache(tmp_path / "breach_cache.json", ttl_seconds=0)

    config = default_config
    config.breach_intelligence.offline_datasets = [str(dataset_path)]

    datasets, warnings = load_offline_datasets([dataset_path])
    offline_index = build_dataset_index(datasets)
    dataset_path.unlink()

    result = lookup_identifier(
        "security.user@example.com",
        config=config,
        working_directory=tmp_path,
        cache=cache,
        offline_index=offline_index,
    )

    assert warnings == []
    assert result["breach_count"] == 3
    assert sorted(result["sources"]) == ["breach_archive_2021", "credential_leak", "forum_dump"]


def test_breach_intelligence_warns_on_invalid_dataset(default_config, make_context, tmp_path):
    invalid_dataset = tmp_path / "broken.json"
    invalid_dataset.write_text("{not-json", encoding="utf-8")
    config = default_config
    config.breach_intelligence.identifiers = ["security.user@example.com"]
    config.breach_intelligence.offline_datasets = [str(invalid_dataset)]

    context = make_context(config=config, user_identifiers=["security.user@example.com"])
    result = BreachIntelligenceScanner().run(context)

    assert result.status == "completed"
    assert result.findings == []
    assert any("not valid JSON" in warning for warning in result.warnings)
