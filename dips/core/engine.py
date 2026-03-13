"""Scan orchestration."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from dips.core.context import build_scan_context
from dips.core.event_timeline import build_event_timeline
from dips.core.exceptions import ReportError
from dips.core.config import AppConfig
from dips.core.models import ModuleResult, ScanContext, ScanReport, SEVERITY_ORDER
from dips.core.plugin_system import load_plugin_registry
from dips.modules.registry import load_enabled_modules_with_plugins
from dips.reporting.html_report import write_html_report
from dips.reporting.json_report import render_json_payload, write_json_report
from dips.scoring.engine import summarize_results
from dips.utils.paths import path_from_input
from dips.utils.redact import redact_string


SEVERITY_RANK = {name: index for index, name in enumerate(SEVERITY_ORDER)}


@dataclass(slots=True)
class ScanArtifacts:
    report: ScanReport
    outputs: dict[str, Path]


@dataclass(slots=True)
class ScanHooks:
    on_scan_started: Callable[[ScanContext, int], None] | None = None
    on_module_started: Callable[[str, int, int], None] | None = None
    on_module_finished: Callable[[ModuleResult, int, int], None] | None = None
    on_scan_finished: Callable[[ScanArtifacts], None] | None = None


def _result_from_error(module, exc: Exception) -> ModuleResult:
    return ModuleResult(
        module=module.name,
        description=module.description,
        status="error",
        warnings=[str(exc)],
        metadata={"exception": exc.__class__.__name__},
    )


def _sorted_findings(module_result: ModuleResult) -> ModuleResult:
    module_result.findings = sorted(
        module_result.findings,
        key=lambda item: (-SEVERITY_RANK.get(item.severity, -1), item.title, item.location),
    )
    return module_result


def build_report(context, results: list[ModuleResult], config: AppConfig) -> ScanReport:
    finished_at = datetime.now(timezone.utc).isoformat()
    duration_ms = int(
        (
            datetime.fromisoformat(finished_at).timestamp()
            - datetime.fromisoformat(context.started_at).timestamp()
        )
        * 1000
    )
    summary = summarize_results(results, config)
    return ScanReport(
        scan_id=context.scan_id,
        started_at=context.started_at,
        finished_at=finished_at,
        duration_ms=duration_ms,
        platform_name=context.platform_name,
        hostname=context.hostname,
        username=context.username,
        user_profile=str(context.user_profile),
        target_paths=[str(path) for path in context.target_paths],
        notes=context.notes,
        modules=results,
        summary=summary,
        config=config.to_dict(),
    )


def write_reports(report: ScanReport, config: AppConfig) -> dict[str, Path]:
    formats = set(config.reporting.formats)
    redact = config.reporting.redact_evidence
    output_dir = path_from_input(config.reporting.output_dir)
    if not output_dir.is_absolute():
        output_dir = Path.cwd() / output_dir
    outputs: dict[str, Path] = {}
    try:
        output_dir.mkdir(parents=True, exist_ok=True)
        payload = render_json_payload(report, redact=redact) if formats & {"json", "html"} else None
        if "json" in formats:
            outputs["json"] = write_json_report(
                report,
                output_dir / f"{report.scan_id}.json",
                redact=redact,
                payload=payload,
            )
        if "html" in formats:
            outputs["html"] = write_html_report(
                report,
                output_dir / f"{report.scan_id}.html",
                redact=redact,
                payload=payload,
            )
    except OSError as exc:
        raise ReportError(f"Failed to write reports into {output_dir}: {exc}") from exc
    except Exception as exc:  # noqa: BLE001
        raise ReportError(f"Failed to render reports for scan {report.scan_id}: {exc}") from exc
    return outputs


def _emit(callback, *args) -> None:
    if callback is not None:
        callback(*args)


def _log_module_warnings(
    logger: logging.Logger,
    *,
    scan_id: str,
    module_name: str,
    result: ModuleResult,
) -> None:
    if not result.warnings:
        return
    level = logging.INFO if result.status == "skipped" else logging.WARNING
    for warning in result.warnings:
        logger.log(level, warning, extra={"scan_id": scan_id, "module_name": module_name})


def run_scan(config: AppConfig, logger: logging.Logger, *, hooks: ScanHooks | None = None) -> ScanArtifacts:
    context_started = time.perf_counter()
    context = build_scan_context(config)
    context_build_ms = int((time.perf_counter() - context_started) * 1000)
    plugin_registry = load_plugin_registry(config, base_directory=context.working_directory, logger=logger)
    if plugin_registry.plugins:
        context.notes.append(
            "Loaded plugins: " + ", ".join(plugin.name for plugin in plugin_registry.plugins)
        )
    if plugin_registry.warnings:
        context.notes.extend(plugin_registry.warnings)
    modules = load_enabled_modules_with_plugins(config.modules.enabled, plugin_registry.module_map())
    results: list[ModuleResult] = []
    hook_set = hooks or ScanHooks()
    _emit(hook_set.on_scan_started, context, len(modules))
    logger.info(
        "scan started",
        extra={
            "scan_id": context.scan_id,
            "context_build_ms": context_build_ms,
            "target_path_count": len(context.target_paths),
            "candidate_file_count": len(context.candidate_files),
            "browser_profile_count": len(context.browser_profiles),
        },
    )

    total_modules = len(modules)
    for index, module in enumerate(modules, start=1):
        _emit(hook_set.on_module_started, module.name, index, total_modules)
        logger.info(
            f"running module {module.name}",
            extra={"scan_id": context.scan_id, "module_name": module.name},
        )
        try:
            if not module.supports(context):
                result = module.skipped("Module does not apply to the current host state.")
                results.append(result)
                _log_module_warnings(logger, scan_id=context.scan_id, module_name=module.name, result=result)
                _emit(hook_set.on_module_finished, result, index, total_modules)
                continue
            result = _sorted_findings(module.timed_run(context, list(results)))
            results.append(result)
            _log_module_warnings(logger, scan_id=context.scan_id, module_name=module.name, result=result)
            _emit(hook_set.on_module_finished, result, index, total_modules)
        except Exception as exc:  # noqa: BLE001
            logger.exception(
                f"module {module.name} failed",
                extra={"scan_id": context.scan_id, "module_name": module.name},
            )
            result = _result_from_error(module, exc)
            results.append(result)
            _emit(hook_set.on_module_finished, result, index, total_modules)

    plugin_registry.enrich_results(context, results, logger)
    report = build_report(context, results, config)
    try:
        report.timeline = build_event_timeline(context, results)
    except Exception as exc:  # noqa: BLE001
        report.notes.append(f"Event timeline generation failed: {exc}")
        logger.exception("event timeline generation failed", extra={"scan_id": context.scan_id})
    plugin_registry.extend_report(context, report, logger)
    report_write_started = time.perf_counter()
    outputs = write_reports(report, config)
    logger.info(
        "scan finished",
        extra={
            "scan_id": context.scan_id,
            "overall_score": report.summary.overall_score,
            "overall_label": report.summary.overall_label,
            "report_write_ms": int((time.perf_counter() - report_write_started) * 1000),
        },
    )
    artifacts = ScanArtifacts(report=report, outputs=outputs)
    _emit(hook_set.on_scan_finished, artifacts)
    return artifacts


def diff_reports(previous: ScanReport | None, current: ScanReport) -> dict[str, int]:
    if previous is None:
        return {"new": sum(len(module.findings) for module in current.modules), "resolved": 0}
    previous_ids = {finding.id for module in previous.modules for finding in module.findings}
    current_ids = {finding.id for module in current.modules for finding in module.findings}
    return {
        "new": len(current_ids - previous_ids),
        "resolved": len(previous_ids - current_ids),
    }


def render_terminal_summary(report: ScanReport, outputs: dict[str, Path]) -> str:
    findings = [finding for module in report.modules for finding in module.findings]
    warnings = [warning for module in report.modules for warning in module.warnings if warning]
    findings.sort(key=lambda item: SEVERITY_RANK.get(item.severity, -1), reverse=True)
    ai_module = next((module for module in report.modules if module.module == "ai_security_analysis"), None)
    lines = [
        f"Scan ID: {report.scan_id}",
        f"Overall Risk: {report.summary.overall_score}/100 ({report.summary.overall_label})",
        f"Risk Model: {report.summary.risk_model}",
        f"Modules: {', '.join(module.module for module in report.modules)}",
        "Severity Counts: "
        + ", ".join(f"{severity}={report.summary.severity_counts.get(severity, 0)}" for severity in SEVERITY_ORDER),
    ]
    if report.summary.category_scores:
        lines.append(
            "Risk Categories: "
            + ", ".join(
                f"{name}={value}"
                for name, value in sorted(
                    report.summary.category_scores.items(),
                    key=lambda item: (-int(item[1]), item[0]),
                )
            )
        )
    if outputs:
        lines.append(
            "Reports: " + ", ".join(f"{name}={path}" for name, path in sorted(outputs.items()))
        )
    plugin_extensions = report.extensions.get("plugins", {})
    if plugin_extensions:
        lines.append("Plugins: " + ", ".join(sorted(plugin_extensions)))
    if findings:
        lines.append("Top Findings:")
        for finding in findings[:5]:
            lines.append(
                f"- [{finding.severity}] {redact_string(finding.module)}: "
                f"{redact_string(finding.title)} ({redact_string(finding.location)})"
            )
    else:
        lines.append("Top Findings: none")
    if report.timeline.patterns:
        lines.append("Correlated Patterns:")
        for pattern in report.timeline.patterns[:3]:
            lines.append(f"- [{pattern.severity}] {pattern.name}")
    if report.summary.top_recommendations:
        lines.append("Recommendations:")
        for item in report.summary.top_recommendations[:3]:
            lines.append(f"- {redact_string(item)}")
    if report.notes or warnings:
        lines.append("Warnings:")
        for item in [*report.notes[:2], *warnings[:3]]:
            lines.append(f"- {redact_string(item)}")
    if ai_module and ai_module.metadata.get("summary"):
        lines.append(f"AI Summary: {redact_string(str(ai_module.metadata['summary']))}")
        explanation = str(ai_module.metadata.get("risk_explanation", "")).strip()
        if explanation:
            lines.append(f"AI Explanation: {redact_string(explanation)}")
        actions = [
            str(item)
            for item in ai_module.metadata.get("recommended_actions", [])
            if str(item).strip()
        ]
        if actions:
            lines.append("AI Actions:")
            for item in actions[:3]:
                lines.append(f"- {redact_string(item)}")
    return "\n".join(lines)


def watch_scans(config: AppConfig, logger: logging.Logger, *, cycles: int | None = None) -> int:
    previous_report: ScanReport | None = None
    interval = max(0, config.watch.interval_seconds)
    runs = 0
    while True:
        artifacts = run_scan(config, logger)
        print(render_terminal_summary(artifacts.report, artifacts.outputs))
        changes = diff_reports(previous_report, artifacts.report)
        print(f"Changes: new={changes['new']} resolved={changes['resolved']}")
        previous_report = artifacts.report
        runs += 1
        if cycles is not None and runs >= cycles:
            return 0
        try:
            time.sleep(interval)
        except KeyboardInterrupt:
            return 130
