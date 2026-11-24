"""A helper module that does not import ADK either."""

from typing import Any

from . import factory


def run_sub(model: Any, tools: Any) -> Any:
    return factory.make_runner(model, tools)
