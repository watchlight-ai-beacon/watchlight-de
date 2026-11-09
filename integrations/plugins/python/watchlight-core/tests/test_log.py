"""Canonical logging subsystem."""

from __future__ import annotations

import json
import logging

from watchlight_core import configure_logging, get_logger
from watchlight_core.log import ROOT_LOGGER_NAME


def test_get_logger_lives_under_the_watchlight_root():
    assert get_logger("adk").name == "watchlight.adk"
    assert get_logger("core.apdp_client").name == "watchlight.core.apdp_client"
    assert get_logger().name == ROOT_LOGGER_NAME
    # A caller passing an already-qualified name isn't double-prefixed.
    assert get_logger("watchlight.adk").name == "watchlight.adk"
    # __name__ / legacy underscore names map cleanly onto the canonical tree.
    assert get_logger("watchlight_adk").name == "watchlight.adk"
    assert get_logger("watchlight_adk.plugin").name == "watchlight.adk.plugin"
    assert get_logger("watchlight_core.apdp_client").name == "watchlight.core.apdp_client"


def test_configure_logging_is_idempotent():
    root = configure_logging()
    managed = [h for h in root.handlers if getattr(h, "_watchlight_managed", False)]
    configure_logging()
    managed_after = [
        h for h in root.handlers if getattr(h, "_watchlight_managed", False)
    ]
    # Repeat calls replace, not stack.
    assert len(managed) == 1
    assert len(managed_after) == 1


def test_text_format_is_human_readable(capsys):
    configure_logging(level="INFO", fmt="text")
    get_logger("core.demo").info("hello")
    err = capsys.readouterr().err
    assert "watchlight.core.demo" in err
    assert "hello" in err


def test_json_format_is_one_object_per_line_with_canonical_fields(capsys):
    configure_logging(level="INFO", fmt="json")
    get_logger("core.demo").info(
        "hello", extra={"execution_id": "exec_1", "agent_id": "a1"}
    )
    line = capsys.readouterr().err.strip().splitlines()[-1]
    obj = json.loads(line)
    assert obj["level"] == "INFO"
    assert obj["logger"] == "watchlight.core.demo"
    assert obj["message"] == "hello"
    assert obj["execution_id"] == "exec_1"
    assert obj["agent_id"] == "a1"
    assert "@timestamp" in obj


def test_configure_only_touches_the_watchlight_tree():
    configure_logging()
    # The application's root logger is left alone.
    assert logging.getLogger(ROOT_LOGGER_NAME).propagate is False
