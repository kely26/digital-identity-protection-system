"""Structured logging for DIPS."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from dips.core.exceptions import LoggingError
from dips.utils.paths import path_from_input
from dips.utils.redact import redact_string, redact_value
from dips.utils.secure_io import set_private_file_permissions


_STANDARD_LOG_RECORD_FIELDS = {
    "args",
    "asctime",
    "created",
    "exc_info",
    "exc_text",
    "filename",
    "funcName",
    "levelname",
    "levelno",
    "lineno",
    "module",
    "msecs",
    "message",
    "msg",
    "name",
    "pathname",
    "process",
    "processName",
    "relativeCreated",
    "stack_info",
    "thread",
    "threadName",
}


def _exception_summary(record: logging.LogRecord) -> str:
    if not record.exc_info:
        return ""
    exc_type, exc_value, _traceback = record.exc_info
    if exc_value is None:
        return exc_type.__name__ if exc_type is not None else "Unknown error"
    detail = str(exc_value).strip()
    if not detail:
        return exc_type.__name__ if exc_type is not None else "Unknown error"
    if exc_type is None:
        return redact_string(detail)
    return redact_string(f"{exc_type.__name__}: {detail}")


class JsonFormatter(logging.Formatter):
    def __init__(self, *, include_traceback: bool = False) -> None:
        super().__init__()
        self.include_traceback = include_traceback

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname.lower(),
            "logger": record.name,
            "message": redact_string(record.getMessage()),
        }
        for key, value in record.__dict__.items():
            if key in _STANDARD_LOG_RECORD_FIELDS or key.startswith("_"):
                continue
            payload[key] = redact_value(value)
        if record.exc_info:
            payload["exception"] = _exception_summary(record)
            if self.include_traceback:
                payload["traceback"] = self.formatException(record.exc_info)
        return json.dumps(payload, separators=(",", ":"))


class HumanFormatter(logging.Formatter):
    def __init__(self, *, include_traceback: bool = False) -> None:
        super().__init__()
        self.include_traceback = include_traceback

    def format(self, record: logging.LogRecord) -> str:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        extras = []
        for key in ("scan_id", "module_name"):
            if hasattr(record, key):
                extras.append(f"{key}={getattr(record, key)}")
        extra_text = f" [{' '.join(extras)}]" if extras else ""
        message = f"{timestamp} {record.levelname:<8} {redact_string(record.getMessage())}{extra_text}"
        if record.exc_info:
            exception_text = _exception_summary(record)
            if exception_text:
                message = f"{message} ({exception_text})"
            if self.include_traceback:
                return f"{message}\n{self.formatException(record.exc_info)}"
        return message


def configure_logging(
    *,
    debug: bool = False,
    log_format: str = "text",
    log_file: str | None = None,
) -> logging.Logger:
    logger = logging.getLogger("dips")
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    logger.handlers.clear()
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(
        JsonFormatter(include_traceback=False)
        if log_format == "json"
        else HumanFormatter(include_traceback=False)
    )
    logger.addHandler(console_handler)
    if log_file:
        log_path = path_from_input(log_file)
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_path, encoding="utf-8")
            set_private_file_permissions(log_path)
        except OSError as exc:
            raise LoggingError(f"Failed to initialize log file {log_path}: {exc}") from exc
        file_handler.setFormatter(JsonFormatter(include_traceback=True))
        logger.addHandler(file_handler)
    logger.propagate = False
    return logger
