"""Example external plugin for the DIPS plugin system."""

from __future__ import annotations

from typing import Any

from dips.core.models import ModuleResult
from dips.core.plugin_system.plugin_interface import SecurityPlugin
from dips.modules.base import ScannerModule


class CustomSensitiveFileScanner(ScannerModule):
    name = "custom_sensitive_file_scanner"
    description = "Detects exported identity and remote-access artifacts from a sample external plugin."

    def __init__(self, plugin: "CustomScannerPlugin") -> None:
        self.plugin = plugin

    def run(self, context) -> ModuleResult:
        keywords = [
            str(item).strip().lower()
            for item in self.plugin.config.get("watch_keywords", [])
            if str(item).strip()
        ]
        severity = str(self.plugin.config.get("severity", "medium")).lower()
        external_tool = str(self.plugin.config.get("external_tool_command", "")).strip()

        findings = []
        matched_files: list[str] = []
        for path in context.candidate_files:
            name = path.name.lower()
            matched_keyword = next((keyword for keyword in keywords if keyword in name), "")
            if not matched_keyword:
                continue
            matched_files.append(str(path))
            findings.append(
                self.build_finding(
                    severity=severity,
                    confidence="medium",
                    title="Custom plugin detected exported security artifact",
                    summary=(
                        f"The external custom scanner matched the file name against the keyword "
                        f"{matched_keyword!r}, which often signals an exported vault, session dump, or remote-access artifact."
                    ),
                    evidence={
                        "keyword": matched_keyword,
                        "plugin": self.plugin.plugin_name,
                        "external_tool_command": external_tool,
                    },
                    location=str(path),
                    recommendation=(
                        "Review whether the artifact should remain on disk, remove stale exports, and tighten access to the file."
                    ),
                    tags=["plugin", "custom-scanner", "artifact", "privacy"],
                )
            )

        self.plugin.last_detected_files = matched_files
        return ModuleResult(
            module=self.name,
            description=self.description,
            status="completed",
            findings=findings,
            metadata={
                "matched_files": matched_files,
                "external_tool_command": external_tool,
                "keyword_count": len(keywords),
            },
        )


class CustomScannerPlugin(SecurityPlugin):
    plugin_name = "custom_scanner"
    version = "1.0.0"
    description = "Example external plugin that adds a custom scanner, enriches findings, and extends reports."

    def __init__(self, *, config: dict[str, Any] | None = None, plugin_path=None) -> None:
        super().__init__(config=config, plugin_path=plugin_path)
        self.last_detected_files: list[str] = []
        self.last_enriched_findings = 0

    def validate(self) -> None:
        super().validate()
        if not isinstance(self.config.get("watch_keywords", []), list):
            raise ValueError("watch_keywords must be a list.")

    def create_modules(self) -> list[ScannerModule]:
        return [CustomSensitiveFileScanner(self)]

    def enrich_results(self, context, results: list[ModuleResult]) -> None:
        del context
        if not self.config.get("enrich_builtin_findings", True):
            return
        enriched = 0
        for result in results:
            if result.module not in {"identity_exposure", "privacy_risk"}:
                continue
            for finding in result.findings:
                tags = {tag.lower() for tag in finding.tags}
                if not ({"token", "private-key"} & tags or "token" in finding.title.lower()):
                    continue
                if "custom-plugin-reviewed" not in finding.tags:
                    finding.tags.append("custom-plugin-reviewed")
                enriched += 1
        self.last_enriched_findings = enriched

    def extend_report(self, context, report) -> dict[str, Any] | None:
        del context, report
        return {
            "title": str(self.config.get("report_title", "Custom Scanner Insights")),
            "summary": (
                f"Detected {len(self.last_detected_files)} custom artifact(s) and enriched "
                f"{self.last_enriched_findings} built-in finding(s)."
            ),
            "detected_files": self.last_detected_files,
            "enriched_findings": self.last_enriched_findings,
            "external_tool_command": str(self.config.get("external_tool_command", "")),
        }


PLUGIN_CLASS = CustomScannerPlugin
