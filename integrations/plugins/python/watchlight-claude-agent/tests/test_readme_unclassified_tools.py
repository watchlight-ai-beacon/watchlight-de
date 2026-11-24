"""The README states the unclassified-tool refusal as the code enforces it.

A host tool that is not served through MCP is refused, and that is a
breaking change for an agent that used one; the README says so and shows how
to serve a tool through MCP. These checks pin that wording to the codes and
the classification the plugin uses, so the documentation cannot drift from
the behaviour.
"""

from __future__ import annotations

import re
from pathlib import Path

from watchlight_claude_agent.tool_classes import UNCLASSIFIED_TOOL, classify_tool

README = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8")


def _section(heading: str) -> str:
    match = re.search(rf"^### {re.escape(heading)}\n(.*?)(?=^#{{2,3}} )", README, re.S | re.M)
    assert match, f"README has no '### {heading}' section"
    return match.group(1)


def test_the_refusal_is_marked_breaking_and_names_its_code() -> None:
    assert f"**Breaking:** a host tool that is not served through MCP is refused the same way (`{UNCLASSIFIED_TOOL}`)" in README


def test_the_readme_links_to_the_section_that_shows_the_fix() -> None:
    assert "(see [Your own tools](#your-own-tools))" in README
    _section("Your own tools")


def test_the_example_serves_the_tool_through_an_sdk_mcp_server_and_allows_it() -> None:
    section = _section("Your own tools")
    for needed in ("create_sdk_mcp_server(", "@tool(", "mcp_servers=", 'allowed_tools=["mcp__orders__lookup_order"]'):
        assert needed in section, needed


def test_the_example_tool_is_governed_and_the_bare_name_is_unclassified() -> None:
    # The resource the README says a policy names is one the plugin sends to
    # the decision; the same tool not served through MCP is refused.
    section = _section("Your own tools")
    assert "resource `mcp__orders__lookup_order`" in section
    assert classify_tool("mcp__orders__lookup_order") == "governed"
    assert classify_tool("lookup_order") is None
    assert f"refused (`{UNCLASSIFIED_TOOL}`)" in section
