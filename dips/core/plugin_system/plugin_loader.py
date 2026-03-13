"""Dynamic plugin loading for DIPS."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import re
from types import ModuleType
from typing import Any

from dips.core.exceptions import PluginError
from dips.core.plugin_system.plugin_interface import LoadedPlugin, SecurityPlugin
from dips.modules.base import ScannerModule
from dips.utils.secure_io import read_json_file

PLUGIN_FILE = "plugin.py"
PLUGIN_CONFIG_FILE = "config.json"
PLUGIN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


def load_plugin_from_directory(
    plugin_name: str,
    plugin_dir: Path,
    *,
    config_override: dict[str, Any] | None = None,
) -> LoadedPlugin:
    if not PLUGIN_NAME_RE.fullmatch(plugin_name):
        raise PluginError(
            f"Plugin name {plugin_name!r} is invalid. Use letters, numbers, underscores, or hyphens only."
        )
    if not plugin_dir.exists():
        raise PluginError(f"Plugin {plugin_name!r} was not found at {plugin_dir}.")
    if not plugin_dir.is_dir():
        raise PluginError(f"Plugin path for {plugin_name!r} is not a directory: {plugin_dir}.")

    plugin_file = plugin_dir / PLUGIN_FILE
    if not plugin_file.exists():
        raise PluginError(f"Plugin {plugin_name!r} is missing {PLUGIN_FILE}.")

    merged_config = _deep_merge(_read_default_config(plugin_dir), config_override or {})
    try:
        module = _load_python_module(plugin_name, plugin_file)
        instance = _build_plugin_instance(module, plugin_name, merged_config, plugin_dir)
        modules = instance.create_modules()
    except PluginError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise PluginError(f"Plugin {plugin_name!r} failed to load: {exc}") from exc
    _validate_plugin(plugin_name, instance, modules)

    return LoadedPlugin(
        name=instance.plugin_name,
        version=instance.version,
        description=instance.description,
        path=plugin_dir.resolve(),
        config=merged_config,
        instance=instance,
        modules=modules,
    )


def resolve_plugin_directory(plugin_name: str, search_paths: list[Path]) -> Path:
    if not PLUGIN_NAME_RE.fullmatch(plugin_name):
        raise PluginError(
            f"Plugin name {plugin_name!r} is invalid. Use letters, numbers, underscores, or hyphens only."
        )
    for search_path in search_paths:
        candidate = search_path / plugin_name
        if candidate.exists():
            resolved_search = search_path.resolve()
            resolved_candidate = candidate.resolve()
            if not resolved_candidate.is_relative_to(resolved_search):
                raise PluginError(f"Plugin {plugin_name!r} resolves outside the configured plugin directory.")
            return resolved_candidate
    raise PluginError(
        f"Plugin {plugin_name!r} was not found in the configured search paths: "
        + ", ".join(str(path) for path in search_paths)
    )


def _read_default_config(plugin_dir: Path) -> dict[str, Any]:
    config_path = plugin_dir / PLUGIN_CONFIG_FILE
    if not config_path.exists():
        return {}
    try:
        payload = read_json_file(config_path, max_bytes=1_048_576)
    except UnicodeDecodeError as exc:
        raise PluginError(f"Plugin config must be UTF-8 text: {config_path}") from exc
    except json.JSONDecodeError as exc:
        raise PluginError(f"Plugin config is not valid JSON: {config_path}") from exc
    except ValueError as exc:
        raise PluginError(str(exc)) from exc
    except OSError as exc:
        raise PluginError(f"Failed to read plugin config {config_path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise PluginError(f"Plugin config must contain a JSON object: {config_path}")
    return payload


def _load_python_module(plugin_name: str, plugin_file: Path) -> ModuleType:
    sanitized = plugin_name.replace("-", "_")
    module_name = f"dips_external_plugin_{sanitized}"
    spec = importlib.util.spec_from_file_location(module_name, plugin_file)
    if spec is None or spec.loader is None:
        raise PluginError(f"Failed to create an import spec for plugin {plugin_name!r}.")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        raise PluginError(f"Failed to import plugin {plugin_name!r}: {exc}") from exc
    return module


def _build_plugin_instance(
    module: ModuleType,
    plugin_name: str,
    config: dict[str, Any],
    plugin_dir: Path,
) -> SecurityPlugin:
    if hasattr(module, "get_plugin"):
        instance = module.get_plugin(config=config, plugin_path=plugin_dir)
    elif hasattr(module, "PLUGIN_CLASS"):
        plugin_class = getattr(module, "PLUGIN_CLASS")
        instance = plugin_class(config=config, plugin_path=plugin_dir)
    elif hasattr(module, "plugin"):
        candidate = getattr(module, "plugin")
        instance = candidate if isinstance(candidate, SecurityPlugin) else candidate(config=config, plugin_path=plugin_dir)
    else:
        raise PluginError(
            f"Plugin {plugin_name!r} must expose get_plugin(), PLUGIN_CLASS, or plugin."
        )
    if not isinstance(instance, SecurityPlugin):
        raise PluginError(f"Plugin {plugin_name!r} did not return a SecurityPlugin instance.")
    return instance


def _validate_plugin(plugin_name: str, instance: SecurityPlugin, modules: list[ScannerModule]) -> None:
    try:
        instance.validate()
    except Exception as exc:  # noqa: BLE001
        raise PluginError(f"Plugin {plugin_name!r} failed validation: {exc}") from exc

    if instance.plugin_name != plugin_name:
        raise PluginError(
            f"Plugin directory {plugin_name!r} does not match plugin_name {instance.plugin_name!r}."
        )

    if not isinstance(modules, list):
        raise PluginError(f"Plugin {plugin_name!r} create_modules() must return a list.")
    module_names: set[str] = set()
    for module in modules:
        if not isinstance(module, ScannerModule):
            raise PluginError(f"Plugin {plugin_name!r} returned a non-scanner module object.")
        if not module.name.strip():
            raise PluginError(f"Plugin {plugin_name!r} returned a scanner without a name.")
        if module.name in module_names:
            raise PluginError(
                f"Plugin {plugin_name!r} returned duplicate scanner module {module.name!r}."
            )
        module_names.add(module.name)

    has_enrich = type(instance).enrich_results is not SecurityPlugin.enrich_results
    has_extend = type(instance).extend_report is not SecurityPlugin.extend_report
    if not modules and not has_enrich and not has_extend:
        raise PluginError(
            f"Plugin {plugin_name!r} does not expose scanners, result enrichment, or report extensions."
        )


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged
