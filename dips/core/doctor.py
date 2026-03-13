"""Runtime diagnostics for operator support workflows."""

from __future__ import annotations

import importlib.util
import logging
import platform
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from dips import __version__
from dips.core.config import AppConfig
from dips.core.plugin_system import load_plugin_registry
from dips.utils.paths import path_from_input

_CHECK_PASS = "pass"
_CHECK_WARN = "warn"
_CHECK_FAIL = "fail"


@dataclass(slots=True)
class DoctorCheck:
    name: str
    status: str
    summary: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "summary": self.summary,
            "details": self.details,
        }


@dataclass(slots=True)
class DoctorReport:
    overall_status: str
    version: str
    python_version: str
    platform_name: str
    working_directory: str
    checks: list[DoctorCheck]

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_status": self.overall_status,
            "version": self.version,
            "python_version": self.python_version,
            "platform": self.platform_name,
            "working_directory": self.working_directory,
            "checks": [check.to_dict() for check in self.checks],
        }


def _resolve_runtime_path(value: str) -> Path:
    path = path_from_input(value)
    if not path.is_absolute():
        path = Path.cwd() / path
    return path


def _writable_location_check(name: str, target: Path, *, kind: str) -> DoctorCheck:
    probe_root = target if kind == "directory" else target.parent
    resolved_probe = probe_root
    while not resolved_probe.exists() and resolved_probe.parent != resolved_probe:
        resolved_probe = resolved_probe.parent
    if not resolved_probe.exists():
        return DoctorCheck(
            name=name,
            status=_CHECK_FAIL,
            summary=f"No writable parent directory could be resolved for {target}.",
            details={"target": str(target), "probe_root": str(probe_root)},
        )
    try:
        with tempfile.NamedTemporaryFile(prefix=".dips-doctor-", dir=str(resolved_probe), delete=True) as handle:
            handle.write(b"dips-doctor")
            handle.flush()
    except OSError as exc:
        return DoctorCheck(
            name=name,
            status=_CHECK_FAIL,
            summary=f"Cannot write to {resolved_probe}: {exc}",
            details={"target": str(target), "probe_root": str(resolved_probe)},
        )

    target_state = "exists" if target.exists() else "will use existing parent"
    return DoctorCheck(
        name=name,
        status=_CHECK_PASS,
        summary=f"Writable {kind} check passed for {target} ({target_state}).",
        details={"target": str(target), "probe_root": str(resolved_probe)},
    )


def _input_presence_check(
    name: str,
    *,
    plural: str,
    values: list[str],
) -> DoctorCheck:
    if not values:
        return DoctorCheck(
            name=name,
            status=_CHECK_PASS,
            summary=f"No configured {plural}.",
        )
    missing: list[str] = []
    resolved: list[str] = []
    for value in values:
        path = _resolve_runtime_path(value)
        resolved.append(str(path))
        if not path.exists():
            missing.append(str(path))
    if missing:
        return DoctorCheck(
            name=name,
            status=_CHECK_WARN,
            summary=f"{len(missing)} configured {plural} do not exist.",
            details={"configured": resolved, "missing": missing},
        )
    return DoctorCheck(
        name=name,
        status=_CHECK_PASS,
        summary=f"All configured {plural} are present.",
        details={"configured": resolved},
    )


def _dashboard_runtime_check() -> DoctorCheck:
    if importlib.util.find_spec("PySide6") is None:
        return DoctorCheck(
            name="dashboard_runtime",
            status=_CHECK_WARN,
            summary="PySide6 is not installed in this environment. CLI commands are available but the dashboard is not.",
        )
    return DoctorCheck(
        name="dashboard_runtime",
        status=_CHECK_PASS,
        summary="PySide6 is installed and the dashboard runtime is available.",
    )


def _plugin_health_check(config: AppConfig) -> DoctorCheck:
    if not config.plugin_system.enabled_plugins:
        return DoctorCheck(
            name="plugin_system",
            status=_CHECK_PASS,
            summary="No external plugins are enabled.",
            details={"strict_validation": config.plugin_system.strict_validation},
        )

    logger = logging.getLogger("dips.doctor")
    logger.handlers.clear()
    logger.addHandler(logging.NullHandler())
    logger.propagate = False
    try:
        registry = load_plugin_registry(config, base_directory=Path.cwd(), logger=logger)
    except Exception as exc:  # noqa: BLE001
        return DoctorCheck(
            name="plugin_system",
            status=_CHECK_FAIL,
            summary=f"Plugin loading failed: {exc}",
            details={
                "enabled_plugins": config.plugin_system.enabled_plugins,
                "strict_validation": config.plugin_system.strict_validation,
            },
        )

    if registry.warnings:
        return DoctorCheck(
            name="plugin_system",
            status=_CHECK_WARN,
            summary=f"Loaded {len(registry.plugins)} plugin(s) with {len(registry.warnings)} warning(s).",
            details={
                "plugins": [plugin.name for plugin in registry.plugins],
                "warnings": registry.warnings,
                "strict_validation": config.plugin_system.strict_validation,
            },
        )
    return DoctorCheck(
        name="plugin_system",
        status=_CHECK_PASS,
        summary=f"Loaded {len(registry.plugins)} plugin(s) successfully.",
        details={
            "plugins": [plugin.name for plugin in registry.plugins],
            "strict_validation": config.plugin_system.strict_validation,
        },
    )


def _overall_status(checks: list[DoctorCheck]) -> str:
    statuses = {check.status for check in checks}
    if _CHECK_FAIL in statuses:
        return _CHECK_FAIL
    if _CHECK_WARN in statuses:
        return _CHECK_WARN
    return _CHECK_PASS


def build_doctor_report(config: AppConfig) -> DoctorReport:
    checks = [
        DoctorCheck(
            name="python_runtime",
            status=_CHECK_PASS if sys.version_info >= (3, 11) else _CHECK_FAIL,
            summary=(
                f"Python {platform.python_version()} satisfies the supported runtime requirement."
                if sys.version_info >= (3, 11)
                else f"Python {platform.python_version()} is below the required version of 3.11."
            ),
            details={"required": "3.11+", "current": platform.python_version()},
        ),
        DoctorCheck(
            name="configured_modules",
            status=_CHECK_PASS,
            summary=f"{len(config.modules.enabled)} module(s) are enabled for scanning.",
            details={"modules": config.modules.enabled},
        ),
        _dashboard_runtime_check(),
        _writable_location_check(
            "report_output_dir",
            _resolve_runtime_path(config.reporting.output_dir),
            kind="directory",
        ),
        _writable_location_check(
            "breach_cache",
            _resolve_runtime_path(config.breach_intelligence.cache_path),
            kind="file",
        ),
        _writable_location_check(
            "threat_cache",
            _resolve_runtime_path(config.threat_intelligence.cache_path),
            kind="file",
        ),
        _writable_location_check(
            "event_timeline_store",
            _resolve_runtime_path(config.event_timeline.store_path),
            kind="file",
        ),
        _input_presence_check(
            "scan_paths",
            plural="scan paths",
            values=config.scan.paths,
        ),
        _input_presence_check(
            "email_inputs",
            plural="email inputs",
            values=config.email.inputs,
        ),
        _input_presence_check(
            "breach_datasets",
            plural="breach datasets",
            values=config.breach_intelligence.offline_datasets,
        ),
        _input_presence_check(
            "threat_feeds",
            plural="threat feeds",
            values=config.threat_intelligence.feed_paths,
        ),
        _input_presence_check(
            "password_inputs",
            plural="password inputs",
            values=[config.credential.password_file] if config.credential.password_file else [],
        ),
        _plugin_health_check(config),
    ]
    return DoctorReport(
        overall_status=_overall_status(checks),
        version=__version__,
        python_version=platform.python_version(),
        platform_name=platform.platform(),
        working_directory=str(Path.cwd()),
        checks=checks,
    )


def render_doctor_text(report: DoctorReport) -> str:
    lines = [
        "DIPS Doctor",
        f"Overall Status: {report.overall_status}",
        f"Version: {report.version}",
        f"Python: {report.python_version}",
        f"Platform: {report.platform_name}",
        f"Working Directory: {report.working_directory}",
        "",
        "Checks:",
    ]
    for check in report.checks:
        lines.append(f"- [{check.status}] {check.name}: {check.summary}")
        if check.details:
            for key, value in sorted(check.details.items()):
                lines.append(f"  {key}: {value}")
    return "\n".join(lines)
