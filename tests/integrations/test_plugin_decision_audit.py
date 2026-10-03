"""Every decision a framework plugin makes is in the audit trail.

The direct path (``Watchlight.authorize`` and every governed tool) has always
written one value-free decision record per decision. The framework-plugin path
— ``watchlight.<framework>.governed_plugin`` — used to write only the run's
``execution_started`` and ``execution_completed`` lines, so a quota or a
forensics query that counts decisions saw none of the plugin's. These tests
hold the plugin path to the direct path's contract, for every registered
integration, against the REAL published plugin:

* an Allow and a Deny each write exactly one decision record, with the direct
  path's fields and nothing else;
* no value from the call — its Cedar ``context``, its declared intent — ever
  reaches the trail;
* the run's lifecycle lines are still written;
* the sink options mean what they mean on ``Watchlight``: a sink sees the same
  fields, a batching sink gets lists, an async sink is scheduled, and a failing
  sink never changes a decision;
* ``count_audit_records`` counts plugin decisions.
"""

from __future__ import annotations

import asyncio
import importlib
import json
import sys
import types

import pytest

pytest.importorskip("watchlight_engine")
pytest.importorskip("watchlight_core")

from watchlight import DecisionRecord, count_audit_records  # noqa: E402
from watchlight.integrations import INTEGRATIONS  # noqa: E402

NAMES = sorted(INTEGRATIONS)

POLICIES = [{"name": "read", "code": 'permit(principal, action == Action::"read", resource);'}]
ALLOWED = ('Action::"read"', 'Tool::"web_search"')
DENIED = ('Action::"delete"', 'Tool::"ticket_store"')

# Values a call carries. None of them may appear anywhere in the trail.
CANARIES = ("CANARY-ctx-7f3a9", "CANARY-objective-c41d", "CANARY-nested-0b2e")

#: The fields a decision record may carry, from the TypedDict itself, so a
#: field added on one side only fails here.
ALLOWED_FIELDS = set(DecisionRecord.__required_keys__) | set(DecisionRecord.__optional_keys__)
REQUIRED_FIELDS = set(DecisionRecord.__required_keys__)


def _plugin_module(name):
    integration = INTEGRATIONS[name]
    pytest.importorskip(integration.plugin_module)
    return importlib.import_module(f"watchlight.{name}")


def _context():
    return {"query": CANARIES[0], "nested": {"value": CANARIES[2]}}


async def _run(plugin, agent="research-agent"):
    """One run: an allowed action, then a denied one, both carrying values."""
    async with await plugin.start_run(agent) as handle:
        allowed = await handle.authorize_action(
            *ALLOWED, context=_context(), intent={"objective": CANARIES[1]}
        )
        denied = await handle.authorize_action(
            *DENIED, context=_context(), intent={"objective": CANARIES[1]}
        )
    return allowed, denied


def _lines(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def _decisions(lines):
    return [r for r in lines if r.get("event") == "decision"]


@pytest.fixture(autouse=True)
def _in_process(monkeypatch):
    # The plugin path is in-process unless WATCHLIGHT_APDP_URL is set.
    monkeypatch.delenv("WATCHLIGHT_APDP_URL", raising=False)


@pytest.mark.parametrize("name", NAMES)
def test_each_decision_writes_exactly_one_value_free_record(name, tmp_path):
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    allowed, denied = asyncio.run(_run(plugin))
    assert (allowed, denied) == (True, False)

    raw = audit.read_text(encoding="utf-8")
    for canary in CANARIES:
        assert canary not in raw, f"{name}: a call value reached the audit trail"

    lines = _lines(audit)
    decisions = _decisions(lines)
    assert [(r["intent"], r["resource"], r["decision"]) for r in decisions] == [
        (*ALLOWED, "Allow"),
        (*DENIED, "Deny"),
    ]
    started = [r for r in lines if r.get("event_type") == "execution_started"]
    completed = [r for r in lines if r.get("event_type") == "execution_completed"]
    assert len(started) == 1 and len(completed) == 1, f"{name}: the run lifecycle lines are gone"
    execution_id = started[0]["execution_id"]

    for record in decisions:
        assert REQUIRED_FIELDS <= set(record), record
        assert set(record) <= ALLOWED_FIELDS, set(record) - ALLOWED_FIELDS
        assert record["event"] == "decision"
        assert record["agent"] == "research-agent"
        # The subject the engine decided for: the run's agent, typed.
        assert record["principal"].startswith('Agent::"')
        # The decision joins the run it belongs to.
        assert record["execution_id"] == execution_id
        # The direct path writes no reason, and neither does this one.
        assert "reason" not in record and "context" not in record


@pytest.mark.parametrize("name", NAMES)
def test_a_per_call_principal_is_the_recorded_subject(name, tmp_path):
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("ticket-agent") as handle:
            return await handle.authorize_action(*ALLOWED, principal='User::"alice"')

    assert asyncio.run(run()) is True
    (record,) = _decisions(_lines(audit))
    assert record["principal"] == 'User::"alice"'
    assert record["agent"] == "ticket-agent"


@pytest.mark.parametrize("name", NAMES)
def test_plugin_decisions_are_counted(name, tmp_path):
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("quota-agent") as handle:
            for _ in range(3):
                await handle.authorize_action(*ALLOWED, principal='User::"u1"')
            await handle.authorize_action(*DENIED, principal='User::"u1"')

    asyncio.run(run())
    allowed = count_audit_records(audit, principal='User::"u1"', intent=ALLOWED[0], window="1h")
    denied = count_audit_records(
        audit, principal='User::"u1"', intent=DENIED[0], window="1h", outcome="denied"
    )
    assert allowed["count"] == 3
    assert denied["count"] == 1
    # The filter the quota and forensics examples use counts the same four, and
    # the lifecycle lines (which carry `event_type`, not `event`) are not
    # decisions: they carry no `decision` field.
    lines = _lines(audit)
    assert sum(1 for r in lines if r.get("event", "decision") == "decision" and "decision" in r) == 4


@pytest.mark.parametrize("name", NAMES)
def test_a_sink_receives_the_same_record_the_file_carries(name, tmp_path):
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    received = []
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit), audit_sink=received.append)

    asyncio.run(_run(plugin))
    assert received == _decisions(_lines(audit))
    assert len(received) == 2
    for canary in CANARIES:
        assert canary not in json.dumps(received)


@pytest.mark.parametrize("name", NAMES)
def test_an_async_sink_is_scheduled_on_the_running_loop(name, tmp_path):
    module = _plugin_module(name)
    received = []

    async def sink(record):
        received.append(record)

    plugin = module.governed_plugin(POLICIES, audit_path=str(tmp_path / "audit.jsonl"), audit_sink=sink)

    async def run():
        result = await _run(plugin)
        await asyncio.sleep(0)  # let the scheduled sink tasks run
        return result

    assert asyncio.run(run()) == (True, False)
    assert [r["decision"] for r in received] == ["Allow", "Deny"]


@pytest.mark.parametrize("name", NAMES)
def test_a_batching_sink_gets_lists(name, tmp_path):
    module = _plugin_module(name)
    batches = []
    plugin = module.governed_plugin(
        POLICIES,
        audit_path=None,
        audit_sink=batches.append,
        audit_sink_batch=10,
        audit_sink_interval=0.05,
    )
    asyncio.run(_run(plugin))
    plugin.apdp._wl_trail.flush()
    records = [r for batch in batches for r in batch]
    assert all(isinstance(batch, list) for batch in batches)
    assert [r["decision"] for r in records] == ["Allow", "Deny"]


@pytest.mark.parametrize("name", NAMES)
def test_a_failing_sink_never_changes_a_decision(name, tmp_path, capsys):
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"

    def sink(record):
        raise ValueError(f"sink down {record}")

    plugin = module.governed_plugin(POLICIES, audit_path=str(audit), audit_sink=sink)
    assert asyncio.run(_run(plugin)) == (True, False)
    # The file is still written, and the failure is reported once, by type only.
    assert len(_decisions(_lines(audit))) == 2
    err = capsys.readouterr().err
    assert err.count("audit sink failed (ValueError)") == 1
    for canary in CANARIES:
        assert canary not in err


@pytest.mark.parametrize("name", NAMES)
def test_an_engine_refusal_is_recorded_as_a_deny(name, tmp_path):
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("research-agent") as handle:
            # An empty action is a request the engine cannot evaluate.
            await plugin.apdp.authorize(
                principal="", action="", resource="", context={"v": CANARIES[0]},
                session_id=handle.session_id,
            )

    with pytest.raises(Exception):
        asyncio.run(run())
    decisions = _decisions(_lines(audit))
    assert [r["decision"] for r in decisions] == ["Deny"]
    assert CANARIES[0] not in audit.read_text(encoding="utf-8")


@pytest.mark.parametrize("name", NAMES)
def test_a_preflight_writes_no_decision_record(name, tmp_path):
    # A preflight is a read-only what-if: it does not count toward the run's
    # budget, and it is not a decision anything acted on.
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("research-agent") as handle:
            return await handle.preflight_step(*ALLOWED)

    asyncio.run(run())
    assert _decisions(_lines(audit)) == []


def test_sink_options_are_never_forwarded_to_the_plugin(monkeypatch):
    # The options configure the trail; the plugin constructor has no place for
    # them, in either mode.
    from watchlight.integrations import langgraph as integration

    built = []

    class _Plugin:
        def __init__(self, **kwargs):
            built.append(kwargs)

    stub = types.ModuleType(integration.INTEGRATION.plugin_module)
    setattr(stub, integration.INTEGRATION.plugin_class, _Plugin)
    monkeypatch.setitem(sys.modules, integration.INTEGRATION.plugin_module, stub)

    integration.governed_plugin(None, audit_path=None, audit_sink=print, audit_sink_batch=5, tenant_id="t")
    monkeypatch.setenv("WATCHLIGHT_APDP_URL", "https://apdp.example.test")
    integration.governed_plugin(None, audit_sink=print, tenant_id="t")

    for kwargs in built:
        assert not {"audit_sink", "audit_sink_batch", "audit_sink_interval"} & set(kwargs)
        assert kwargs["tenant_id"] == "t"
    assert "governance" in built[0] and built[1]["apdp_url"] == "https://apdp.example.test"


# ── refusals the handle makes on its own ───────────────────────────────────

ENFORCING = [
    {"name": "everything", "code": "permit(principal, action, resource);"},
    {
        "name": "quarantine-on-exfiltrate",
        "code": '@enforcement_effect("quarantine")\n'
        'forbid(principal, action == Action::"exfiltrate", resource);',
    },
    {
        "name": "sever-on-escalate",
        "code": '@enforcement_effect("sever_subtree")\n'
        'forbid(principal, action == Action::"escalate", resource);',
    },
]


@pytest.mark.parametrize("trigger", ['Action::"exfiltrate"', 'Action::"escalate"'])
@pytest.mark.parametrize("name", NAMES)
def test_every_refusal_after_a_quarantine_or_sever_is_recorded(name, trigger, tmp_path):
    # Once a run is quarantined or severed, the SDK's handle refuses every later
    # call itself, without asking the backend. Each of those refusals is a
    # decision, and each one is recorded — once.
    from watchlight_core import AgentQuarantinedError, SubtreeSeveredError

    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(ENFORCING, audit_path=str(audit))
    refusals = []

    async def run():
        async with await plugin.start_run("contained-agent") as handle:
            calls = [
                (handle.authorize_action, trigger),
                (handle.authorize_action, 'Action::"read"'),
                (handle.authorize_action_detailed, 'Action::"read"'),
            ]
            for method, action in calls:
                try:
                    await method(action, 'Tool::"x"', context={"v": CANARIES[0]})
                except (AgentQuarantinedError, SubtreeSeveredError) as exc:
                    refusals.append(type(exc).__name__)

    asyncio.run(run())
    assert len(refusals) == 3, refusals
    decisions = _decisions(_lines(audit))
    assert [(r["intent"], r["decision"]) for r in decisions] == [
        (trigger, "Deny"),
        ('Action::"read"', "Deny"),
        ('Action::"read"', "Deny"),
    ]
    assert all(r["agent"] == "contained-agent" for r in decisions)
    assert CANARIES[0] not in audit.read_text(encoding="utf-8")


def test_a_guarded_tool_refused_after_a_quarantine_is_recorded(tmp_path):
    # Pydantic AI's `guarded_tool` calls the SDK handle's own authorize_action,
    # not the wrapper's; the decorated tool is watched instead.
    from watchlight_core import AgentQuarantinedError

    module = _plugin_module("pydantic_ai")
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(ENFORCING, audit_path=str(audit))
    ran = []

    async def run():
        async with await plugin.start_run("tool-agent") as handle:

            @handle.guarded_tool(action='Action::"read"')
            async def fetch(query):
                ran.append(query)
                return query

            assert await fetch("first") == "first"
            with pytest.raises(AgentQuarantinedError):
                await handle.authorize_action('Action::"exfiltrate"', 'Tool::"x"')
            with pytest.raises(AgentQuarantinedError):
                await fetch(CANARIES[0])

    asyncio.run(run())
    assert ran == ["first"]
    decisions = _decisions(_lines(audit))
    assert [(r["intent"], r["resource"], r["decision"]) for r in decisions] == [
        ('Action::"read"', "fetch", "Allow"),
        ('Action::"exfiltrate"', 'Tool::"x"', "Deny"),
        ('Action::"read"', "fetch", "Deny"),
    ]
    assert CANARIES[0] not in audit.read_text(encoding="utf-8")


# ── sub-agents ─────────────────────────────────────────────────────────────


async def _spawn(plugin, handle, slug, **scope):
    # LangGraph and Pydantic AI take the child's name and resolve it; the base
    # handle (Claude Agent SDK) takes the child's agent id.
    import inspect as _inspect

    sdk_handle = getattr(handle, "_wl_inner", handle)  # the SDK's own handle
    first = next(iter(_inspect.signature(sdk_handle.spawn_subagent).parameters))
    if first == "child_agent_slug":
        return await handle.spawn_subagent(slug, **scope)
    agent = await plugin.apdp.resolve_agent(slug)
    return await handle.spawn_subagent(agent["id"], **scope)


@pytest.mark.parametrize("name", NAMES)
def test_a_sub_agent_decision_names_the_sub_agent_and_its_chain(name, tmp_path):
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("lead-agent") as handle:
            child = await _spawn(plugin, handle, "research-sub", allowed_tools=["web_search"], max_depth=1)
            assert await child.authorize_action(*ALLOWED) is True
            assert await child.authorize_action(*DENIED) is False
            grandchild = await _spawn(plugin, child, "fetch-sub", allowed_tools=["web_search"])
            assert await grandchild.authorize_action(*ALLOWED) is True
            assert await handle.authorize_action(*ALLOWED) is True

    asyncio.run(run())
    decisions = _decisions(_lines(audit))
    rows = [(r["agent"], r.get("actor_chain"), r["decision"]) for r in decisions]
    assert rows == [
        ("research-sub", ["lead-agent", "research-sub"], "Allow"),
        ("research-sub", ["lead-agent", "research-sub"], "Deny"),
        ("fetch-sub", ["lead-agent", "research-sub", "fetch-sub"], "Allow"),
        ("lead-agent", None, "Allow"),
    ]
    assert all(r["agent"] != "<unconfigured>" for r in decisions)


# ── record hygiene ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("name", NAMES)
def test_control_characters_and_overlong_terms_are_stored_cleaned(name, tmp_path):
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("hygiene-agent") as handle:
            await handle.authorize_action('Action::"read"', "tool/a\nforged line")
            await handle.authorize_action('Action::"read"', "r" * 5000)

    asyncio.run(run())
    first, second = _decisions(_lines(audit))
    assert first["resource"] == "tool/a�forged�line"
    assert len(second["resource"]) == 1025 and second["resource"].endswith("…")


@pytest.mark.parametrize("name", NAMES)
@pytest.mark.parametrize("slug", ["", "bad\nname", "x" * 300, "<unconfigured>"])
def test_an_unusable_agent_name_is_refused_at_start_run(name, slug, tmp_path):
    module = _plugin_module(name)
    plugin = module.governed_plugin(POLICIES, audit_path=str(tmp_path / "audit.jsonl"))
    with pytest.raises(TypeError):
        asyncio.run(plugin.start_run(slug))


def test_verdicts_are_read_the_way_the_sdk_reads_them(monkeypatch, tmp_path):
    # The SDK treats the verdict case- and space-insensitively; so does the record.
    from watchlight_core import InProcessClient

    from watchlight.inprocess import in_process_backend

    async def answer(self, *args, **kwargs):
        return {"decision": " ALLOW ", "reason": "", "details": {}}

    monkeypatch.setattr(InProcessClient, "authorize", answer)
    audit = tmp_path / "audit.jsonl"
    backend = in_process_backend(POLICIES, audit_path=str(audit))
    asyncio.run(backend.authorize('Agent::"a"', 'Action::"read"', 'Tool::"x"'))
    assert [r["decision"] for r in _decisions(_lines(audit))] == ["Allow"]


@pytest.mark.parametrize("engine_raises", [False, True])
def test_a_record_that_cannot_be_built_never_changes_the_decision(monkeypatch, tmp_path, capsys, engine_raises):
    import watchlight.inprocess as inprocess

    def broken(**kwargs):
        raise ValueError(f"cannot build {kwargs}")

    monkeypatch.setattr(inprocess, "decision_record", broken)
    backend = inprocess.in_process_backend(POLICIES, audit_path=str(tmp_path / "audit.jsonl"))

    async def run():
        if engine_raises:
            # An empty principal is a request the engine cannot evaluate.
            with pytest.raises(Exception):
                await backend.authorize("", "", "")
            with pytest.raises(Exception):
                await backend.authorize("", "", "")
        else:
            first = await backend.authorize('Agent::"a"', 'Action::"read"', 'Tool::"x"')
            second = await backend.authorize('Agent::"a"', 'Action::"read"', 'Tool::"x"')
            assert first["decision"] == second["decision"] == "Allow"

    asyncio.run(run())
    err = capsys.readouterr().err
    assert err.count("could not be recorded (ValueError)") == 1
    assert "cannot build" not in err


@pytest.mark.parametrize("name", NAMES)
def test_no_destination_warning_names_the_plugin_option(name, capsys):
    module = _plugin_module(name)
    plugin = module.governed_plugin(POLICIES, audit_path=None)

    async def run():
        async with await plugin.start_run("quiet-agent") as handle:
            await handle.authorize_action(*ALLOWED)

    asyncio.run(run())
    err = capsys.readouterr().err
    assert "audit_path" in err and "audit_file" not in err


# ── the SDK surface this depends on ────────────────────────────────────────

#: Every public coroutine method of the SDK's InProcessClient, and how the
#: recording backend treats it. A method added in a later SDK release fails
#: here until it is classified: if it can make a decision, it must be recorded
#: exactly once (an override that writes a record, or a path through
#: `authorize`); if not, it is listed as not a decision.
SDK_METHODS = {
    "authorize": "recorded: one decision record per call",
    "preflight_step": "not recorded: an advisory what-if that gates nothing",
    "spawn_subagent": "observed for the child's name; the SDK writes the attenuation line",
    "submit_plan": "not a decision: raises NotImplementedError in-process",
    "resolve_agent": "observed for the agent's name",
    "create_session": "observed for the session's agent",
    "complete_session": "bookkeeping",
    "terminate_session": "bookkeeping",
    "get_manifest": "not a decision",
    "check_agent_trust": "not a decision",
    "publish_events": "lifecycle lines, written by the SDK",
    "health_check": "not a decision",
    "probe": "not a decision",
    "close": "not a decision",
}


def test_every_public_sdk_client_method_is_classified():
    import inspect as _inspect

    from watchlight_core import InProcessClient

    public = {
        name
        for name, member in _inspect.getmembers(InProcessClient)
        if not name.startswith("_") and _inspect.iscoroutinefunction(member)
    }
    assert public == set(SDK_METHODS), (
        "the SDK's InProcessClient changed: classify "
        f"{sorted(public - set(SDK_METHODS))} / drop {sorted(set(SDK_METHODS) - public)}"
    )


# ── lifecycle lines are not decisions ──────────────────────────────────────


@pytest.mark.parametrize("name", NAMES)
def test_lifecycle_lines_are_neither_decisions_nor_malformed(name, tmp_path):
    from watchlight.cli import _read_events

    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))
    asyncio.run(_run(plugin))
    counted = count_audit_records(audit, principal=_decisions(_lines(audit))[0]["principal"], window="1h", outcome="all")
    assert counted["skipped"] == 0
    assert counted["count"] == 2
    events = _read_events(audit)
    assert [e["decision"] for e in events] == ["Allow", "Deny"]
