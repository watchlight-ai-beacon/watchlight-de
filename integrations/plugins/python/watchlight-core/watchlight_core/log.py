"""Canonical logging for Watchlight.

One place to get a consistently-named, consistently-formatted logger across the
SDK and every framework plugin. Every Watchlight logger lives under the single
``watchlight`` root, so one call to :func:`configure_logging` styles them all —
in the Developer Edition (running locally) and in production alike.

Typical use in an application::

    from watchlight_core import configure_logging
    configure_logging()               # human-readable by default
    # or configure_logging(fmt="json")  # structured, one JSON object per line

Inside the SDK / a plugin, get a logger with :func:`get_logger`::

    from watchlight_core import get_logger
    log = get_logger("adk")           # -> logger "watchlight.adk"

Environment overrides (read by :func:`configure_logging`):

* ``WATCHLIGHT_LOG_LEVEL`` — e.g. ``DEBUG`` / ``INFO`` (default ``INFO``).
* ``WATCHLIGHT_LOG_FORMAT`` — ``text`` (default) or ``json``.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional

__all__ = ["get_logger", "configure_logging", "ROOT_LOGGER_NAME"]

#: The single root every Watchlight logger hangs off, so one configuration
#: call reaches the whole surface (SDK + plugins).
ROOT_LOGGER_NAME = "watchlight"

# Canonical context fields the SDK attaches to a record via ``extra={...}`` when
# they are known; surfaced in both the text and JSON formats.
_CONTEXT_FIELDS = ("execution_id", "agent_id", "session_id")


def get_logger(component: Optional[str] = None) -> logging.Logger:
    """Return a logger under the canonical ``watchlight`` namespace.

    ``component`` is a short dotted suffix (e.g. ``"adk"`` or
    ``"core.apdp_client"``); ``None`` returns the root ``watchlight`` logger.

    A leading ``watchlight_`` or ``watchlight.`` is stripped first, so a caller
    can pass ``__name__`` verbatim (e.g. ``"watchlight_adk.plugin"`` →
    ``"watchlight.adk.plugin"``) and a plain ``logging.getLogger(...)`` name maps
    cleanly onto the canonical tree.
    """
    if not component:
        return logging.getLogger(ROOT_LOGGER_NAME)
    suffix = component
    for prefix in (ROOT_LOGGER_NAME + "_", ROOT_LOGGER_NAME + "."):
        if suffix.startswith(prefix):
            suffix = suffix[len(prefix) :]
            break
    return logging.getLogger(f"{ROOT_LOGGER_NAME}.{suffix}")


class _CanonicalJsonFormatter(logging.Formatter):
    """One JSON object per line, with a stable set of fields."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "@timestamp": datetime.fromtimestamp(
                record.created, tz=timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for field in _CONTEXT_FIELDS:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        if record.exc_info:
            payload["error"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=True)


class _CanonicalTextFormatter(logging.Formatter):
    """Human-readable, one line per record, with any known context appended."""

    def __init__(self) -> None:
        super().__init__("%(asctime)s %(levelname)-5s %(name)s: %(message)s")

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        ctx = " ".join(
            f"{f}={getattr(record, f)}"
            for f in _CONTEXT_FIELDS
            if getattr(record, f, None) is not None
        )
        return f"{base} [{ctx}]" if ctx else base


def configure_logging(
    level: Optional[str] = None,
    fmt: Optional[str] = None,
) -> logging.Logger:
    """Install the canonical Watchlight log format. Call once from your app.

    Configures only the ``watchlight`` logger tree, so it never fights an
    application's own logging setup. Idempotent — repeated calls replace the
    Watchlight handler rather than stacking duplicates.

    :param level: log level name; defaults to ``WATCHLIGHT_LOG_LEVEL`` or ``INFO``.
    :param fmt: ``"text"`` (default) or ``"json"``; defaults to
        ``WATCHLIGHT_LOG_FORMAT`` or ``"text"``.
    :returns: the configured ``watchlight`` root logger.
    """
    level_name = (level or os.getenv("WATCHLIGHT_LOG_LEVEL", "INFO")).upper()
    fmt_name = (fmt or os.getenv("WATCHLIGHT_LOG_FORMAT", "text")).lower()

    root = logging.getLogger(ROOT_LOGGER_NAME)
    root.setLevel(level_name)

    # Replace any handler we previously installed so repeat calls don't duplicate
    # output; leave handlers the application may have added untouched.
    for existing in list(root.handlers):
        if getattr(existing, "_watchlight_managed", False):
            root.removeHandler(existing)

    handler = logging.StreamHandler(sys.stderr)
    handler._watchlight_managed = True  # type: ignore[attr-defined]
    handler.setFormatter(
        _CanonicalJsonFormatter() if fmt_name == "json" else _CanonicalTextFormatter()
    )
    root.addHandler(handler)
    # Don't also bubble up to the root logger — that would double-log once we
    # have our own handler.
    root.propagate = False
    return root
