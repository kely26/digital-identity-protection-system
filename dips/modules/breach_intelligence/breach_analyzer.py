"""Breach intelligence scanner module."""

from __future__ import annotations

from dips.core.models import ModuleResult
from dips.modules.base import ScannerModule
from dips.modules.breach_intelligence.breach_cache import BreachCache
from dips.modules.breach_intelligence.breach_lookup import (
    build_dataset_index,
    load_offline_datasets,
    lookup_identifier,
    mask_identifier,
    normalize_identifier,
    resolve_dataset_paths,
)
from dips.utils.paths import path_from_input
from dips.utils.text import unique_preserve_order


def _severity_for_breach_count(count: int) -> str:
    if count >= 5:
        return "critical"
    if count >= 2:
        return "high"
    if count == 1:
        return "medium"
    return "info"


class BreachIntelligenceScanner(ScannerModule):
    name = "breach_intelligence"
    description = "Checks hashed identity targets against local breach data and optional approved providers."

    def run(self, context) -> ModuleResult:
        identifiers = unique_preserve_order(
            normalize_identifier(value)
            for value in context.user_identifiers
            if normalize_identifier(value)
        )
        if not identifiers:
            return self.skipped(
                "No identity targets were available; provide --identifier or breach_intelligence.identifiers."
            )

        cache_path = path_from_input(context.config.breach_intelligence.cache_path)
        if not cache_path.is_absolute():
            cache_path = (context.working_directory / cache_path).resolve()
        cache = BreachCache(
            cache_path,
            ttl_seconds=context.config.breach_intelligence.cache_ttl_seconds,
        )
        dataset_records, dataset_warnings = load_offline_datasets(
            resolve_dataset_paths(
                context.config.breach_intelligence.offline_datasets,
                working_directory=context.working_directory,
            )
        )
        dataset_index = build_dataset_index(dataset_records)

        findings = []
        hit_count = 0
        for identifier in identifiers:
            result = lookup_identifier(
                identifier,
                config=context.config,
                working_directory=context.working_directory,
                cache=cache,
                offline_datasets=dataset_records,
                offline_index=dataset_index,
            )
            if result["breach_count"] <= 0:
                continue
            hit_count += 1
            masked = mask_identifier(identifier)
            severity = _severity_for_breach_count(int(result["breach_count"]))
            findings.append(
                self.build_finding(
                    severity=severity,
                    confidence="high" if result["offline_match_count"] else "medium",
                    title="Identity exposure detected in breach intelligence",
                    summary=(
                        f"{masked} appeared in {result['breach_count']} breach intelligence record(s) "
                        f"across {len(result['sources'])} source(s)."
                    ),
                    evidence={
                        "identifier": masked,
                        "identifier_type": result["identifier_type"],
                        "identifier_hash": result["identifier_hash"][:12],
                        "breach_count": result["breach_count"],
                        "sources": result["sources"],
                    },
                    location=masked,
                    recommendation=(
                        "Rotate affected passwords, enable MFA, and review whether reused credentials or tokens are still active."
                    ),
                    tags=["breach", "identity", result["identifier_type"]],
                )
            )

        return ModuleResult(
            module=self.name,
            description=self.description,
            status="completed",
            findings=findings,
            warnings=dataset_warnings,
            metadata={
                "identifiers_scanned": len(identifiers),
                "identifiers_with_hits": hit_count,
                "offline_dataset_count": len(dataset_records),
                "offline_identifier_count": len(dataset_index),
                "offline_dataset_warning_count": len(dataset_warnings),
                "cache_path": str(cache_path),
            },
        )
