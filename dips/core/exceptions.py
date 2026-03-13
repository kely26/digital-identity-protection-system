"""Typed exceptions for DIPS."""

from __future__ import annotations


class DipsError(Exception):
    """Base application error."""

    exit_code = 1


class ConfigError(DipsError):
    """Raised when configuration is invalid or unreadable."""

    exit_code = 2


class ReportError(DipsError):
    """Raised when report generation or writing fails."""

    exit_code = 3


class LoggingError(DipsError):
    """Raised when logging cannot be initialized."""

    exit_code = 1


class ModuleExecutionError(DipsError):
    """Raised for scanner execution failures."""

    exit_code = 4


class PluginError(DipsError):
    """Raised when plugin discovery, validation, or execution fails."""

    exit_code = 5
