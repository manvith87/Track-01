"""Structured logging for BlastRadius.

Design goals:

* one obvious way to obtain a logger (:func:`get_logger`);
* machine-readable output on demand (:class:`JsonFormatter`);
* every log line can be correlated with an ingestion request through a
  context variable that is safe to use across threads (``contextvars`` are
  thread-local by design, which matches FastAPI's sync threadpool);
* untrusted values coming from repositories are always truncated and escaped
  before being logged (:func:`safe_text`).
"""

from __future__ import annotations

import contextvars
import json
import logging
import sys
import uuid
from datetime import datetime, timezone
from typing import Any

_LOGGER_NAMESPACE = "blastradius"
_CONFIGURED = False
_MAX_LOG_VALUE = 300

_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar("blastradius_request_id", default=None)


def new_request_id() -> str:
    """Generate a short correlation id."""
    return uuid.uuid4().hex[:12]


def set_request_id(request_id: str | None) -> None:
    """Bind a correlation id to the current context."""
    _request_id.set(request_id)


def get_request_id() -> str | None:
    """Return the correlation id bound to the current context, if any."""
    return _request_id.get()


def safe_text(value: object, limit: int = _MAX_LOG_VALUE) -> str:
    """Render an untrusted value as a single safe, truncated log token.

    Newlines, carriage returns and tabs are escaped so that content taken from
    an untrusted repository can never forge additional log lines.
    """
    text = str(value)
    text = text.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    if len(text) > limit:
        text = f"{text[:limit]}...<truncated {len(text) - limit} chars>"
    return text


class _ContextFilter(logging.Filter):
    """Attach the current request id (and nothing else) to every record."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003 - stdlib API
        record.request_id = get_request_id() or "-"
        return True


class TextFormatter(logging.Formatter):
    """Human readable, single-line format."""

    def __init__(self) -> None:
        super().__init__(
            fmt="%(asctime)s %(levelname)-8s [%(name)s] rid=%(request_id)s %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%S%z",
        )


class JsonFormatter(logging.Formatter):
    """One JSON object per line, suitable for log aggregation."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }
        if record.exc_info:
            payload["exception"] = safe_text(self.formatException(record.exc_info), limit=4000)
        extra = getattr(record, "extra_fields", None)
        if isinstance(extra, dict):
            payload.update({str(key): safe_text(value) for key, value in extra.items()})
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str | None = None, *, json_output: bool | None = None, force: bool = False) -> None:
    """Configure the ``blastradius`` logger tree exactly once.

    Configuration is idempotent unless ``force`` is set, which keeps test runs
    and repeated app factory calls from stacking handlers.
    """
    global _CONFIGURED

    from app.core.config import get_settings

    settings = get_settings()
    resolved_level = (level or settings.log_level).upper()
    resolved_json = settings.log_json if json_output is None else json_output

    logger = logging.getLogger(_LOGGER_NAMESPACE)
    logger.setLevel(resolved_level)
    logger.propagate = False

    if _CONFIGURED and not force:
        return

    for handler in list(logger.handlers):
        logger.removeHandler(handler)

    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setLevel(resolved_level)
    handler.setFormatter(JsonFormatter() if resolved_json else TextFormatter())
    handler.addFilter(_ContextFilter())
    logger.addHandler(handler)
    _CONFIGURED = True


def get_logger(name: str | None = None) -> logging.Logger:
    """Return a namespaced logger, e.g. ``get_logger("ingestion.service")``."""
    suffix = f".{name}" if name else ""
    return logging.getLogger(f"{_LOGGER_NAMESPACE}{suffix}")


__all__ = [
    "configure_logging",
    "get_logger",
    "get_request_id",
    "new_request_id",
    "safe_text",
    "set_request_id",
]
