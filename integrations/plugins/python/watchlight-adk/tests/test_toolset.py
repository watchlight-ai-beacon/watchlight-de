"""Tests for ManifestDrivenToolset filtering."""

import pytest

from watchlight_adk.toolset import ManifestDrivenToolset


# In-process stand-in for unit tests only.
class _StubTool:
    def __init__(self, name: str):
        self.name = name


# In-process stand-in for unit tests only.
class _StubContext:
    def __init__(self, allowlist=None, slot="state"):
        manifest = {"tool_allowlist": allowlist} if allowlist is not None else None
        gov = {"manifest": manifest} if manifest is not None else None
        store = {"wl_governance": gov} if gov is not None else {}
        setattr(self, slot, store)


# ─── Allowlist filtering ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_filters_tools_by_allowlist():
    tools = [_StubTool("get_market_data"), _StubTool("send_email"), _StubTool("execute_trade")]
    ts = ManifestDrivenToolset(tools)
    ctx = _StubContext(allowlist=["get_market_data", "execute_trade"])
    result = await ts.get_tools(ctx)
    names = sorted(t.name for t in result)
    assert names == ["execute_trade", "get_market_data"]


@pytest.mark.asyncio
async def test_empty_allowlist_hides_everything():
    tools = [_StubTool("a"), _StubTool("b")]
    ts = ManifestDrivenToolset(tools)
    ctx = _StubContext(allowlist=[])
    result = await ts.get_tools(ctx)
    assert result == []


@pytest.mark.asyncio
async def test_no_manifest_passes_all_in_lenient_mode():
    tools = [_StubTool("a"), _StubTool("b")]
    ts = ManifestDrivenToolset(tools, strict=False)
    result = await ts.get_tools(None)
    assert len(result) == 2


@pytest.mark.asyncio
async def test_no_manifest_hides_all_in_strict_mode():
    tools = [_StubTool("a"), _StubTool("b")]
    ts = ManifestDrivenToolset(tools, strict=True)
    result = await ts.get_tools(None)
    assert result == []


@pytest.mark.asyncio
async def test_reads_from_session_state_attr():
    tools = [_StubTool("ok"), _StubTool("nope")]
    ts = ManifestDrivenToolset(tools)
    ctx = _StubContext(allowlist=["ok"], slot="session_state")
    result = await ts.get_tools(ctx)
    assert [t.name for t in result] == ["ok"]


@pytest.mark.asyncio
async def test_tools_property_returns_unfiltered_list():
    tools = [_StubTool("a"), _StubTool("b")]
    ts = ManifestDrivenToolset(tools)
    assert len(ts.tools) == 2


@pytest.mark.asyncio
async def test_close_is_a_no_op():
    ts = ManifestDrivenToolset([_StubTool("a")])
    # Should not raise
    await ts.close()
