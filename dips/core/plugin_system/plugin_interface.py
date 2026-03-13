"""Interfaces for external DIPS plugins."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dips.core.models import ModuleResult, ScanContext, ScanReport
from dips.modules.base import ScannerModule


class SecurityPlugin:
    """Base interface for external DIPS plugins."""

    plugin_name = "base_plugin"
    version = "0.1.0"
    description = "Base DIPS plugin"

    def __init__(self, *, config: dict[str, Any] | None = None, plugin_path: Path | None = None) -> None:
        self.config = dict(config or {})
        self.plugin_path = plugin_path or Path.cwd()

    def validate(self) -> None:
        if not self.plugin_name.strip():
            raise ValueError("Plugin name must not be empty.")
        if not self.version.strip():
            raise ValueError(f"Plugin {self.plugin_name!r} must declare a version.")

    def create_modules(self) -> list[ScannerModule]:
        return []

    def enrich_results(self, context: ScanContext, results: list[ModuleResult]) -> None:
        del context, results

    def extend_report(self, context: ScanContext, report: ScanReport) -> dict[str, Any] | None:
        del context, report
        return None


@dataclass(slots=True)
class LoadedPlugin:
    name: str
    version: str
    description: str
    path: Path
    config: dict[str, Any]
    instance: SecurityPlugin
    modules: list[ScannerModule] = field(default_factory=list)
