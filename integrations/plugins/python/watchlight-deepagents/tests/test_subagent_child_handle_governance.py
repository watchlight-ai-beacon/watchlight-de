"""The sub-agent authorizes against its OWN attenuated handle, never the
root's — the load-bearing sub-agent governance invariant. Using the
parent handle for a child action is a privilege escalation and is what
this suite guards against."""

from __future__ import annotations

from conftest import (
    CHILD_UUID,
    ROOT_UUID,
    RecordingHandler,
    make_child_middleware,
    make_root_middleware,
    make_tool_call_request,
    start_root,
)


async def test_child_authorizes_with_child_handle_not_root(plugin, mock_apdp):
    mock_apdp.default_decision = "Allow"

    # 1. Root run starts; a root tool call authorizes under the root.
    root_mw = make_root_middleware(plugin, subagent_scopes={"researcher": {"allowed_tools": ["summarize"]}})
    root_state = await start_root(root_mw)
    await root_mw.awrap_tool_call(
        make_tool_call_request("search", state=root_state), RecordingHandler()
    )
    root_call = mock_apdp.authorize_calls[-1]
    assert root_call["principal"] == f'Agent::"{ROOT_UUID}"'
    assert "run_handle_id" not in root_call["context"]

    # 2. The root spawns a sub-agent via the task tool. The spawn grants
    #    the CHILD handle to the sub-agent graph the task call runs.
    child_mw = make_child_middleware(plugin)

    async def _run_child(request):
        # 3. The child governance middleware (injected into the SubAgent)
        #    starts inside the task call: it claims the granted handle.
        child_state = await child_mw.abefore_agent({}, runtime=None)
        # 4. A tool call INSIDE the sub-agent authorizes under the CHILD.
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
    child_run_handle_id = mock_apdp.spawn_subagent_calls[0]  # sanity: spawn happened
    assert child_run_handle_id is not None
    child_call = mock_apdp.authorize_calls[-1]

    assert child_call["principal"] == f'Agent::"{CHILD_UUID}"'
    assert child_call["principal"] != f'Agent::"{ROOT_UUID}"'
    # The child presents its OWN server-minted run_handle_id
    # (scope-membership binding) — proof the child handle, not the root,
    # was used.
    assert "run_handle_id" in child_call["context"]


async def test_child_middleware_fails_closed_without_child_handle(plugin, mock_apdp):
    """If no child handle is bound (parent never spawned via task), the
    child middleware refuses to start — it must not run ungoverned."""
    from watchlight_core import GovernanceUnavailable
    from watchlight_core.run_handle import _current_subagent_handle

    # Ensure no leaked child handle from a prior test in this context.
    _current_subagent_handle.set(None)

    child_mw = make_child_middleware(plugin)
    try:
        await child_mw.abefore_agent({}, runtime=None)
        raised = False
    except GovernanceUnavailable:
        raised = True
    assert raised, "sub-agent with no attenuated handle must fail closed"
