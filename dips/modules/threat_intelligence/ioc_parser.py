"""IOC parsing helpers for threat intelligence enrichment."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from dips.utils.files import safe_read_text
from dips.utils.patterns import DOMAIN_RE, IPV4_RE, URL_RE


@dataclass(slots=True)
class IndicatorObservation:
    indicator: str
    indicator_type: str
    source: str


def normalize_indicator(value: str, indicator_type: str) -> str:
    normalized = value.strip().strip("()[]{}<>\"'`,;")
    if indicator_type == "url":
        return normalized.rstrip("/").lower()
    if indicator_type == "domain":
        return normalized.rstrip(".").lower()
    return normalized.lower()


def _add_observation(
    observations: list[IndicatorObservation],
    seen: set[tuple[str, str, str]],
    *,
    indicator: str,
    indicator_type: str,
    source: str,
) -> None:
    normalized = normalize_indicator(indicator, indicator_type)
    if not normalized:
        return
    key = (normalized, indicator_type, source)
    if key in seen:
        return
    seen.add(key)
    observations.append(
        IndicatorObservation(
            indicator=normalized,
            indicator_type=indicator_type,
            source=source,
        )
    )


def extract_iocs(text: str, *, source: str) -> list[IndicatorObservation]:
    observations: list[IndicatorObservation] = []
    seen: set[tuple[str, str, str]] = set()

    for raw_url in URL_RE.findall(text):
        _add_observation(observations, seen, indicator=raw_url, indicator_type="url", source=source)
        host = (urlparse(raw_url).hostname or "").strip().lower()
        if not host:
            continue
        if IPV4_RE.fullmatch(host):
            _add_observation(observations, seen, indicator=host, indicator_type="ip", source=source)
        else:
            _add_observation(observations, seen, indicator=host, indicator_type="domain", source=source)

    for match in IPV4_RE.finditer(text):
        _add_observation(observations, seen, indicator=match.group(0), indicator_type="ip", source=source)

    for match in DOMAIN_RE.finditer(text):
        start = match.start()
        if start > 0 and text[start - 1] == "@":
            continue
        _add_observation(observations, seen, indicator=match.group(0), indicator_type="domain", source=source)

    return observations


def extract_iocs_from_paths(paths: list[Path]) -> list[IndicatorObservation]:
    observations: list[IndicatorObservation] = []
    for path in paths:
        observations.extend(extract_iocs(safe_read_text(path), source=str(path)))
    return observations
