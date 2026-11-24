"""Adversarial regression suite — every sub-agent action MUST authorize
against its OWN attenuated RunHandle, and no documented path may leave a
sub-agent ungoverned or leak raw tool-arg values. Each test pins one
hardening guarantee closed (fail-closed).
"""

from __future__ import annotations

import pytest

from watchlight_core import GovernanceUnavailable

from conftest import (
    CHILD_UUID,
    ROOT_UUID,
    RecordingHandler,
    make_root_middleware,
    make_tool_call_request,
    start_root,
)
from watchlight_deepagents.plugin import WatchlightDeepAgentsPlugin
from watchlight_deepagents.subagents import (
    GENERAL_PURPOSE_SUBAGENT_NAME,
    ensure_general_purpose_subagent,
    inject_child_governance_middleware,
)

# ─── Option B / ungoverned construction refuses spawns ──────────────────────


async def test_option_b_root_refuses_task_spawn_fail_closed(plugin, mock_apdp):
    """A root middleware built WITHOUT guaranteed child governance (the
    standalone ``plugin.middleware()`` / Option B path, which cannot
    inject child governance into sub-agents) must REFUSE every ``task``
    spawn — otherwise the child graph runs with no Watchlight middleware
    and its attenuated handle is orphaned. This also closes the
    auto-added ``general-purpose`` spawn on that path."""
    from langchain_core.messages import ToolMessage

    mw = make_root_middleware(plugin, child_governance_guaranteed=False)
    state = await start_root(mw)

    handler = RecordingHandler()
    req = make_tool_call_request(
        "task",
        {"subagent_type": "researcher"},
        state=state,
        tool_call_id="c_optb",
    )
    result = await mw.awrap_tool_call(req, handler)

    assert handler.ran is False, "no child graph may run on the ungoverned path"
    assert isinstance(result, ToolMessage)
    assert result.status == "error"
    assert (
        "UNGOVERNED" in result.content or "create_governed_deep_agent" in result.content
    )
    # Crucially: NO spawn round-trip happened — the child handle is never
    # even minted-then-orphaned.
    assert not mock_apdp.spawn_subagent_calls


async def test_option_b_general_purpose_spawn_refused(plugin, mock_apdp):
    """Option-B flavour: even ``general-purpose`` (deepagents' auto
    sub-agent) cannot execute ungoverned — the spawn is refused."""
    from langchain_core.messages import ToolMessage

    mw = make_root_middleware(plugin, child_governance_guaranteed=False)
    state = await start_root(mw)

    handler = RecordingHandler()
    req = make_tool_call_request(
        "task", {"subagent_type": GENERAL_PURPOSE_SUBAGENT_NAME}, state=state
    )
    result = await mw.awrap_tool_call(req, handler)

    assert handler.ran is False
    assert isinstance(result, ToolMessage)
    assert result.status == "error"
    assert not mock_apdp.spawn_subagent_calls


async def test_governed_factory_path_allows_spawn(plugin, mock_apdp):
    """Contrast: the governed path (guaranteed=True — what the factory
    sets after injecting child governance everywhere) DOES allow the
    spawn (proof the refusal is scoped to the ungoverned path, not a
    blanket break)."""
    mw = make_root_middleware(
        plugin,
        subagent_scopes={"researcher": {"allowed_tools": [], "max_depth": 0}},
        child_governance_guaranteed=True,
    )
    state = await start_root(mw)
    handler = RecordingHandler()
    req = make_tool_call_request("task", {"subagent_type": "researcher"}, state=state)
    await mw.awrap_tool_call(req, handler)
    assert handler.ran is True
    assert len(mock_apdp.spawn_subagent_calls) == 1


# ─── general-purpose is registered + governed by default ────────────────────


def test_ensure_general_purpose_appends_when_absent():
    """When the caller registers no ``general-purpose``, one is added so
    deepagents does not auto-add its UNGOVERNED version."""
    out = ensure_general_purpose_subagent([{"name": "researcher"}])
    names = [s["name"] for s in out]
    assert GENERAL_PURPOSE_SUBAGENT_NAME in names
    assert "researcher" in names


def test_ensure_general_purpose_respects_explicit_registration():
    """An explicitly-registered general-purpose spec is left untouched
    (the operator's registration wins; it is governed like any other)."""
    explicit = {
        "name": GENERAL_PURPOSE_SUBAGENT_NAME,
        "description": "mine",
        "system_prompt": "p",
    }
    out = ensure_general_purpose_subagent([explicit])
    gp = [s for s in out if s["name"] == GENERAL_PURPOSE_SUBAGENT_NAME]
    assert len(gp) == 1
    assert gp[0] is explicit


def test_ensure_general_purpose_none_input():
    out = ensure_general_purpose_subagent(None)
    assert [s["name"] for s in out] == [GENERAL_PURPOSE_SUBAGENT_NAME]


# ─── un-injectable sub-agents are REFUSED, not warned ───────────────────────


def test_inject_refuses_compiled_subagent():
    """A ``CompiledSubAgent`` (pre-compiled ``runnable``) cannot receive
    injected middleware — deepagents runs it verbatim. Injecting would be
    a silent no-op → ungoverned child. Must fail closed."""
    specs = [{"name": "c", "description": "d", "runnable": object()}]
    with pytest.raises(GovernanceUnavailable):
        inject_child_governance_middleware(specs, lambda: object())


def test_inject_refuses_async_subagent():
    """A remote ``AsyncSubAgent`` (``graph_id``) runs out-of-process; an
    in-process middleware cannot govern it. Must fail closed."""
    specs = [{"name": "a", "description": "d", "graph_id": "remote-123"}]
    with pytest.raises(GovernanceUnavailable):
        inject_child_governance_middleware(specs, lambda: object())


def test_inject_refuses_object_without_middleware_list():
    class Weird:
        name = "weird"
        middleware = None  # not a list — unreachable

    with pytest.raises(GovernanceUnavailable):
        inject_child_governance_middleware([Weird()], lambda: object())


def test_inject_injects_into_plain_subagent_dict():
    """A raw SubAgent dict IS governed by injection (control)."""
    sentinel = object()
    specs = [{"name": "researcher", "description": "d", "system_prompt": "p"}]
    inject_child_governance_middleware(specs, lambda: sentinel)
    assert specs[0]["middleware"] == [sentinel]


# ─── no raw tool-arg VALUE reaches authorize ctx or the event ───────────────


async def test_secret_arg_value_not_in_authorize_context(plugin, mock_apdp):
    """A bearer token passed as a tool arg VALUE must NOT appear in the
    authorize context sent to APDP — only value-free metadata (key names,
    types, count)."""
    mock_apdp.default_decision = "Allow"
    mw = make_root_middleware(plugin)
    state = await start_root(mw)

    secret = "sk-live-DEADBEEFtopsecret0123456789"
    req = make_tool_call_request(
        "call_api",
        {"authorization": f"Bearer {secret}", "url": "https://x"},
        state=state,
    )
    await mw.awrap_tool_call(req, RecordingHandler())

    call = mock_apdp.authorize_calls[-1]
    ctx = call["context"]
    # The metadata is present and value-free.
    assert ctx["tool_args"]["arg_count"] == 2
    assert set(ctx["tool_args"]["arg_names"]) == {"authorization", "url"}
    assert ctx["tool_args"]["arg_types"]["authorization"] == "str"
    # The secret value appears NOWHERE in the serialized context.
    import json

    assert secret not in json.dumps(ctx)


async def test_secret_arg_value_not_in_tool_call_observed(plugin, mock_apdp):
    """The persisted ``tool_call_observed`` event's ``input_summary`` must
    carry no raw arg value either (it is written to the audit log)."""
    mock_apdp.default_decision = "Allow"
    mw = make_root_middleware(plugin)
    state = await start_root(mw)

    secret = "pii-ssn-123-45-6789"
    req = make_tool_call_request("lookup", {"ssn": secret}, state=state)
    await mw.awrap_tool_call(req, RecordingHandler())

    import json

    tool_events = [
        e for e in mock_apdp.published_events if e["event_type"] == "tool_call_observed"
    ]
    assert tool_events
    summary = tool_events[-1]["payload"]["input_summary"]
    assert secret not in summary
    # But the key name + type ARE surfaced (governance-useful, non-secret).
    assert "ssn" in summary
    assert secret not in json.dumps(tool_events[-1])


async def test_input_summary_bounded(plugin, mock_apdp):
    """Conformance invariant 6 — input_summary stays within the 120-char
    cap even for a wide arg dict."""
    mock_apdp.default_decision = "Allow"
    mw = make_root_middleware(plugin)
    state = await start_root(mw)
    wide = {f"field_{i}": "v" * 50 for i in range(40)}
    req = make_tool_call_request("wide", wide, state=state)
    await mw.awrap_tool_call(req, RecordingHandler())
    tool_events = [
        e for e in mock_apdp.published_events if e["event_type"] == "tool_call_observed"
    ]
    assert len(tool_events[-1]["payload"]["input_summary"]) <= 120


# ─── declare_intent short-circuit keys on INSTANCE, not name ────────────────


async def test_name_colliding_customer_tool_does_not_bypass_authorize(mock_apdp):
    """A customer tool named EXACTLY ``watchlight.declare_intent`` but that
    is NOT our synthetic instance must go through the Cedar gate — it must
    not bypass authorize by name collision."""
    from watchlight_core import DECLARE_INTENT_TOOL_NAME

    plugin = WatchlightDeepAgentsPlugin(apdp_url="http://localhost")
    plugin.apdp = mock_apdp
    plugin.intent_enforcement_mode = "greenfield"
    mock_apdp.default_decision = "Deny"

    mw = make_root_middleware(plugin)
    state = await start_root(mw)

    class ImposterTool:
        name = DECLARE_INTENT_TOOL_NAME  # same name, different object

    handler = RecordingHandler()
    req = make_tool_call_request(
        DECLARE_INTENT_TOOL_NAME,
        {"objective": "evil"},
        state=state,
        tool=ImposterTool(),  # NOT mw.tools[0]
    )
    result = await mw.awrap_tool_call(req, handler)

    # The imposter did NOT bypass — it was authorized (and denied here).
    assert handler.ran is False
    assert mock_apdp.authorize_calls, "imposter must hit the Cedar gate"
    from langchain_core.messages import ToolMessage

    assert isinstance(result, ToolMessage)
    assert result.status == "error"


async def test_genuine_synthetic_tool_instance_bypasses(mock_apdp):
    """The genuine synthetic instance still short-circuits (control)."""
    plugin = WatchlightDeepAgentsPlugin(apdp_url="http://localhost")
    plugin.apdp = mock_apdp
    plugin.intent_enforcement_mode = "greenfield"

    mw = make_root_middleware(plugin)
    state = await start_root(mw)

    from watchlight_core import DECLARE_INTENT_TOOL_NAME

    handler = RecordingHandler()
    req = make_tool_call_request(
        DECLARE_INTENT_TOOL_NAME,
        {"objective": "research"},
        state=state,
        tool=mw.tools[0],  # the genuine instance
    )
    await mw.awrap_tool_call(req, handler)
    assert handler.ran is True
    assert mock_apdp.authorize_calls == []


# ─── Load-bearing invariant still holds (no regression) ──────────────────────


async def test_child_still_authorizes_with_child_handle(plugin, mock_apdp):
    """The original load-bearing guarantee is intact end-to-end under the
    governed path."""
    mock_apdp.default_decision = "Allow"
    root_mw = make_root_middleware(plugin, subagent_scopes={"researcher": {"allowed_tools": ["summarize"]}})
    root_state = await start_root(root_mw)
    from conftest import make_child_middleware

    child_mw = make_child_middleware(plugin)

    async def _run_child(request):
        child_state = await child_mw.abefore_agent({}, runtime=None)
        await child_mw.awrap_tool_call(
            make_tool_call_request("summarize", state=child_state),
            RecordingHandler(),
        )
        return "ok"

    await root_mw.awrap_tool_call(
        make_tool_call_request(
            "task", {"subagent_type": "researcher"}, state=root_state
        ),
        _run_child,
    )
    child_call = mock_apdp.authorize_calls[-1]
    assert child_call["principal"] == f'Agent::"{CHILD_UUID}"'
    assert child_call["principal"] != f'Agent::"{ROOT_UUID}"'
    assert "run_handle_id" in child_call["context"]
