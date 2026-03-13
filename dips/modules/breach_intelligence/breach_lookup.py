"""Offline and optional provider-backed breach lookup helpers."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from dips.core.config import AppConfig, BreachProviderSettings
from dips.modules.breach_intelligence.breach_cache import BreachCache
from dips.utils.paths import path_from_input
from dips.utils.secure_io import read_json_file

OfflineDatasetRecords = dict[Path, list[dict[str, Any]]]
OfflineDatasetIndex = dict[str, list[dict[str, Any]]]

_DATASET_RECORD_CACHE: dict[tuple[str, int, int], list[dict[str, Any]]] = {}
_DATASET_INDEX_CACHE: dict[tuple[tuple[str, int, int], ...], OfflineDatasetIndex] = {}


def normalize_identifier(value: str) -> str:
    return value.strip().lower()


def identifier_type(value: str) -> str:
    return "email" if "@" in value else "username"


def hash_identifier(value: str, *, salt: str = "") -> str:
    normalized = normalize_identifier(value)
    return hashlib.sha256(f"{salt}{normalized}".encode("utf-8")).hexdigest()


def mask_identifier(value: str) -> str:
    normalized = normalize_identifier(value)
    if "@" in normalized:
        local_part, domain = normalized.split("@", 1)
        if len(local_part) <= 2:
            return f"{local_part[:1]}***@{domain}"
        return f"{local_part[:2]}***@{domain}"
    if len(normalized) <= 3:
        return normalized[:1] + "***"
    return normalized[:3] + "***"


def _resolve_path(value: str, working_directory: Path) -> Path:
    path = path_from_input(value)
    if path.is_absolute():
        return path
    return (working_directory / path).resolve()


def resolve_dataset_paths(paths: list[str], *, working_directory: Path) -> list[Path]:
    return [_resolve_path(value, working_directory) for value in paths]


def _dataset_signature(path: Path) -> tuple[str, int, int] | None:
    try:
        resolved = path.resolve()
        stat_result = resolved.stat()
    except OSError:
        return None
    return (str(resolved), stat_result.st_mtime_ns, stat_result.st_size)


def _load_dataset(path: Path) -> tuple[list[dict[str, Any]], str | None]:
    try:
        payload = read_json_file(path, max_bytes=25 * 1024 * 1024)
    except FileNotFoundError:
        return [], f"Breach dataset was not found and was skipped: {path}"
    except UnicodeDecodeError:
        return [], f"Breach dataset must be UTF-8 text and was skipped: {path}"
    except json.JSONDecodeError:
        return [], f"Breach dataset is not valid JSON and was skipped: {path}"
    except ValueError as exc:
        return [], f"Breach dataset was skipped: {exc}"
    except OSError as exc:
        return [], f"Breach dataset could not be read and was skipped: {path} ({exc})"
    if isinstance(payload, dict):
        records = payload.get("records", [])
        if isinstance(records, list):
            return records, None
        return [], f"Breach dataset does not contain a 'records' list and was skipped: {path}"
    if isinstance(payload, list):
        return payload, None
    return [], f"Breach dataset has an unsupported JSON structure and was skipped: {path}"


def load_offline_datasets(paths: list[Path]) -> tuple[OfflineDatasetRecords, list[str]]:
    loaded: OfflineDatasetRecords = {}
    warnings: list[str] = []
    for path in paths:
        signature = _dataset_signature(path)
        if signature is not None and signature in _DATASET_RECORD_CACHE:
            loaded[path] = _DATASET_RECORD_CACHE[signature]
            continue
        records, warning = _load_dataset(path)
        if warning:
            warnings.append(warning)
            continue
        loaded[path] = records
        if signature is not None:
            _DATASET_RECORD_CACHE[signature] = records
    return loaded, warnings


def build_dataset_index(datasets: OfflineDatasetRecords) -> OfflineDatasetIndex:
    signatures: list[tuple[str, int, int]] = []
    for path in datasets:
        signature = _dataset_signature(path)
        if signature is None:
            signatures = []
            break
        signatures.append(signature)
    cache_key = tuple(sorted(signatures))
    if cache_key and cache_key in _DATASET_INDEX_CACHE:
        return _DATASET_INDEX_CACHE[cache_key]

    index: OfflineDatasetIndex = {}
    for dataset, records in datasets.items():
        default_source = dataset.stem
        for record in records:
            if not isinstance(record, dict):
                continue
            candidate_hash = str(
                record.get("identifier_hash")
                or record.get("sha256")
                or record.get("hash")
                or ""
            ).lower()
            if not candidate_hash:
                continue
            index.setdefault(candidate_hash, []).append(
                {
                    "source": str(record.get("source", default_source)),
                    "breach_name": str(record.get("breach_name", record.get("source", default_source))),
                    "compromised_at": str(record.get("compromised_at", "")),
                    "record_type": str(record.get("type", "")),
                }
            )
    if cache_key:
        _DATASET_INDEX_CACHE[cache_key] = index
    return index


def _parse_provider_response(data: Any, provider_name: str) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        records = data.get("exposures", data.get("records", data.get("results", [])))
        if isinstance(records, list):
            return [
                {
                    "source": str(record.get("source", provider_name)),
                    "breach_name": str(record.get("breach_name", record.get("source", provider_name))),
                    "compromised_at": str(record.get("compromised_at", "")),
                    "record_type": str(record.get("type", "")),
                }
                for record in records
                if isinstance(record, dict)
            ]
    if isinstance(data, list):
        return [
            {
                "source": str(record.get("source", provider_name)),
                "breach_name": str(record.get("breach_name", record.get("source", provider_name))),
                "compromised_at": str(record.get("compromised_at", "")),
                "record_type": str(record.get("type", "")),
            }
            for record in data
            if isinstance(record, dict)
        ]
    return []


def _query_provider(provider: BreachProviderSettings, *, identifier_hash: str, identifier_kind: str) -> list[dict[str, Any]]:
    params = urlencode({"hash": identifier_hash, "type": identifier_kind})
    url = provider.endpoint
    separator = "&" if "?" in url else "?"
    request = Request(f"{url}{separator}{params}")
    api_key = os.environ.get(provider.api_key_env, "") if provider.api_key_env else ""
    if api_key:
        request.add_header("Authorization", f"Bearer {api_key}")
    request.add_header("Accept", "application/json")
    try:
        with urlopen(request, timeout=provider.timeout_seconds) as response:  # noqa: S310
            payload = json.loads(response.read().decode("utf-8"))
    except (URLError, json.JSONDecodeError, TimeoutError, OSError):
        return []
    return _parse_provider_response(payload, provider.name)


def lookup_identifier(
    identifier: str,
    *,
    config: AppConfig,
    working_directory: Path,
    cache: BreachCache,
    offline_datasets: OfflineDatasetRecords | None = None,
    offline_index: OfflineDatasetIndex | None = None,
) -> dict[str, Any]:
    identifier_kind = identifier_type(identifier)
    identifier_hash = hash_identifier(identifier, salt=config.breach_intelligence.hash_salt)
    cached = cache.get(identifier_hash)
    if cached is not None:
        return cached

    dataset_index = offline_index
    if dataset_index is None:
        dataset_records = offline_datasets
        if dataset_records is None:
            dataset_records, _warnings = load_offline_datasets(
                resolve_dataset_paths(
                    config.breach_intelligence.offline_datasets,
                    working_directory=working_directory,
                )
            )
        dataset_index = build_dataset_index(dataset_records)
    offline_matches = list(dataset_index.get(identifier_hash, ()))

    provider_matches: list[dict[str, Any]] = []
    if config.breach_intelligence.allow_external:
        for provider in config.breach_intelligence.providers:
            if not provider.enabled:
                continue
            provider_matches.extend(
                _query_provider(
                    provider,
                    identifier_hash=identifier_hash,
                    identifier_kind=identifier_kind,
                )
            )

    all_matches = offline_matches + provider_matches
    sources = sorted({match["source"] for match in all_matches if match.get("source")})
    result = {
        "identifier_hash": identifier_hash,
        "identifier_type": identifier_kind,
        "breach_count": len(all_matches),
        "sources": sources,
        "matches": all_matches,
        "offline_match_count": len(offline_matches),
        "provider_match_count": len(provider_matches),
    }
    cache.set(identifier_hash, result)
    return result
