"""The application's tools. This module never imports ADK."""

from typing import List

from . import helpers
from .factory import make_runner

BODIES: List[str] = []
CONTEXT: dict = {}


async def tool_builds_through_an_import(task: str) -> dict:
    BODIES.append("import")
    await CONTEXT["drain"](make_runner(CONTEXT["model"](), CONTEXT["tools"]))
    return {"ok": True}


async def tool_builds_through_a_module_attribute(task: str) -> dict:
    BODIES.append("module_attribute")
    await CONTEXT["drain"](helpers.run_sub(CONTEXT["model"](), CONTEXT["tools"]))
    return {"ok": True}


def plain_tool(task: str) -> dict:
    BODIES.append("plain")
    return {"length": len(task)}


