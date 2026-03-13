"""Plugin registry and lifecycle hooks for DIPS."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from dips.core.config import AppConfig
from dips.core.exceptions import PluginError
from dips.core.models import ModuleResult, ScanContext, ScanReport
from dips.core.plugin_system.plugin_interface import LoadedPlugin
from dips.core.plugin_system.plugin_loader import load_plugin_from_directory, resolve_plugin_directory
from dips.modules.registry import BUILTIN_MODULES
from dips.utils.paths import path_from_input


@dataclass(slots=True)
class PluginRegistry:
    plugins: list[LoadedPlugin] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def module_map(self) -> dict[str, object]:
        return {
            module.name: module
            for plugin in self.plugins
            for module in plugin.modules
        }

    def enrich_results(self, context: ScanContext, results: list[ModuleResult], logger: logging.Logger) -> None:
        for plugin in self.plugins:
            try:
                plugin.instance.enrich_results(context, results)
            except Exception as exc:  # noqa: BLE001
                message = f"Plugin {plugin.name} failed to enrich findings: {exc}"
                self.warnings.append(message)
                context.notes.append(message)
                logger.exception(message, extra={"scan_id": context.scan_id, "plugin_name": plugin.name})

    def extend_report(self, context: ScanContext, report: ScanReport, logger: logging.Logger) -> None:
        if not self.plugins:
            return
        plugin_sections: dict[str, dict[str, object]] = {}
        for plugin in self.plugins:
            entry: dict[str, object] = {
                "version": plugin.version,
                "description": plugin.description,
                "modules": [module.name for module in plugin.modules],
            }
            try:
                extension = plugin.instance.extend_report(context, report)
            except Exception as exc:  # noqa: BLE001
                message = f"Plugin {plugin.name} failed to extend the report: {exc}"
                self.warnings.append(message)
                report.notes.append(message)
                logger.exception(message, extra={"scan_id": context.scan_id, "plugin_name": plugin.name})
                extension = None
            if extension:
                entry["report"] = extension
            plugin_sections[plugin.name] = entry
        if plugin_sections:
            report.extensions.setdefault("plugins", {}).update(plugin_sections)


def load_plugin_registry(
    config: AppConfig,
    *,
    base_directory: Path,
    logger: logging.Logger,
) -> PluginRegistry:
    registry = PluginRegistry()
    if not config.plugin_system.enabled_plugins:
        return registry

    search_paths = _resolve_search_paths(config.plugin_system.search_paths, base_directory)
    builtin_names = set(BUILTIN_MODULES)
    plugin_module_names: set[str] = set()

    for plugin_name in config.plugin_system.enabled_plugins:
        try:
            plugin_dir = resolve_plugin_directory(plugin_name, search_paths)
            loaded = load_plugin_from_directory(
                plugin_name,
                plugin_dir,
                config_override=config.plugin_system.plugin_configs.get(plugin_name, {}),
            )
            for module in loaded.modules:
                if module.name in builtin_names or module.name in plugin_module_names:
                    raise PluginError(
                        f"Plugin scanner module {module.name!r} conflicts with an existing module name."
                    )
                plugin_module_names.add(module.name)
            registry.plugins.append(loaded)
        except PluginError as exc:
            if config.plugin_system.strict_validation:
                raise
            message = f"Plugin {plugin_name} was skipped: {exc}"
            registry.warnings.append(message)
            logger.warning(message)

    return registry


def _resolve_search_paths(search_paths: list[str], base_directory: Path) -> list[Path]:
    resolved: list[Path] = []
    for raw_path in search_paths:
        path = path_from_input(raw_path)
        if not path.is_absolute():
            path = (base_directory / path).resolve()
        resolved.append(path)
    return resolved
