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


def _intent():
    # A typed intent: an objective and a category. Since watchlight-agent-sdk
    # 0.10.1 an intent without a category is refused before any request.
    return {"objective": CANARIES[1], "category": "research"}


async def _run(plugin, agent="research-agent"):
    """One run: an allowed action, then a denied one, both carrying values."""
    async with await plugin.start_run(agent) as handle:
        allowed = await handle.authorize_action(*ALLOWED, context=_context(), intent=_intent())
        denied = await handle.authorize_action(*DENIED, context=_context(), intent=_intent())
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
            # An empty action is a request the engine cannot evaluate. (An
            # empty principal is refused before the engine, unrecorded, as on
            # the direct path: see the name-bounds tests below.)
            await plugin.apdp.authorize(
                principal='Agent::"a"', action="", resource="", context={"v": CANARIES[0]},
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
    {
        "name": "terminate-on-halt",
        "code": '@enforcement_effect("terminate")\n'
        'forbid(principal, action == Action::"halt", resource);',
    },
]


@pytest.mark.parametrize("trigger", ['Action::"exfiltrate"', 'Action::"escalate"', 'Action::"halt"'])
@pytest.mark.parametrize("name", NAMES)
def test_every_refusal_after_a_quarantine_or_sever_is_recorded(name, trigger, tmp_path):
    # Once a run is quarantined, severed or terminated, the SDK's handle refuses
    # every later call itself, without asking the backend. Each of those
    # refusals is a decision, and each one is recorded — once.
    from watchlight_core import AgentQuarantinedError, ExecutionTerminatedError, SubtreeSeveredError

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
                except (AgentQuarantinedError, SubtreeSeveredError, ExecutionTerminatedError) as exc:
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
            # Each delegation names a time budget: the engine refuses a child
            # whose resolved budget is zero (it could make no call at all), so
            # a grandchild needs one at or under its parent's. The child is
            # granted both tools it calls: a sub-agent's call outside its
            # grant is denied before the policies are read, and invalidates
            # its handle (see the scope tests below). The Deny here is the
            # policy's.
            child = await _spawn(
                plugin, handle, "research-sub",
                allowed_tools=["web_search", "ticket_store"], max_depth=1, time_budget_seconds=300,
            )
            assert await child.authorize_action(*ALLOWED) is True
            assert await child.authorize_action(*DENIED) is False
            grandchild = await _spawn(
                plugin, child, "fetch-sub", allowed_tools=["web_search"], time_budget_seconds=60
            )
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


@pytest.mark.parametrize("name", NAMES)
def test_a_sub_agent_call_outside_its_grant_is_denied_and_recorded_once(name, tmp_path):
    # watchlight-agent-sdk 0.10.1: a sub-agent's call is checked against the
    # scope its spawn granted. A call outside it is denied even though a policy
    # permits it, and the denial invalidates the sub-agent's handle: every later
    # call on it is denied, and it cannot spawn. Each of those denials is a
    # decision the backend answered, recorded once, under the sub-agent.
    from watchlight_core import ScopeAttenuationDenied

    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    everything = [{"name": "everything", "code": "permit(principal, action, resource);"}]
    plugin = module.governed_plugin(everything, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("lead-agent") as handle:
            child = await _spawn(
                plugin, handle, "research-sub",
                allowed_tools=["web_search"], max_depth=1, time_budget_seconds=300,
            )
            assert await child.authorize_action(*ALLOWED) is True
            result = await child.authorize_action_detailed(*DENIED, context={"v": CANARIES[0]})
            assert result.decision == "deny"
            assert result.reason.startswith("scope_attenuation_violation")
            # The handle is invalidated: an in-scope call is denied now too.
            result = await child.authorize_action_detailed(*ALLOWED)
            assert result.decision == "deny"
            assert result.reason == "run_handle_invalidated (out_of_scope_tool_call)"
            with pytest.raises(ScopeAttenuationDenied):
                await _spawn(plugin, child, "fetch-sub", allowed_tools=["web_search"], time_budget_seconds=60)
            # The parent is unaffected.
            assert await handle.authorize_action(*DENIED) is True

    asyncio.run(run())
    lines = _lines(audit)
    decisions = _decisions(lines)
    rows = [(r["agent"], r["intent"], r["decision"]) for r in decisions]
    assert rows == [
        ("research-sub", ALLOWED[0], "Allow"),
        ("research-sub", DENIED[0], "Deny"),
        ("research-sub", ALLOWED[0], "Deny"),
        ("lead-agent", DENIED[0], "Allow"),
    ]
    # The SDK also writes its value-free `scope_violation_observed` line, which
    # is not a decision and is never counted as one.
    assert [r["event"] for r in lines if r.get("event") == "scope_violation_observed"] == [
        "scope_violation_observed"
    ]
    assert CANARIES[0] not in audit.read_text(encoding="utf-8")
    counted = count_audit_records(audit, principal=decisions[0]["principal"], window="1h", outcome="all")
    assert counted["count"] == 3 and counted["skipped"] == 0


# ── record hygiene ─────────────────────────────────────────────────────────


LONG_RESOURCE = 'Tool::"' + "r" * 1100 + '"'
TAB_RESOURCE = 'Tool::"web\tsearch"'
TWIN_RESOURCE = 'Tool::"web search \\"quoted\\""'


@pytest.mark.parametrize("name", NAMES)
def test_terms_are_stored_in_full_so_counting_matches_them(name, tmp_path):
    # A quota matches principal, action and resource EXACTLY. A term cut or
    # rewritten in the record is a decision no count can find — a quota that
    # fails open. They are stored as given; JSON escapes what needs escaping.
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))
    twin = LONG_RESOURCE[:-2] + 'x"'  # differs only near the end

    async def run():
        async with await plugin.start_run("quota-agent") as handle:
            for _ in range(3):
                assert await handle.authorize_action('Action::"read"', LONG_RESOURCE, principal='User::"u1"')
            for _ in range(2):
                assert await handle.authorize_action('Action::"read"', TWIN_RESOURCE, principal='User::"u1"')
            assert await handle.authorize_action('Action::"read"', twin, principal='User::"u1"')

    asyncio.run(run())

    def count(resource):
        return count_audit_records(audit, principal='User::"u1"', resource=resource, window="1h")["count"]

    assert count(LONG_RESOURCE) == 3
    assert count(TWIN_RESOURCE) == 2
    assert count(twin) == 1
    # Every record is still exactly one line of valid JSON.
    raw = audit.read_text(encoding="utf-8")
    assert len(raw.splitlines()) == len(_lines(audit))


@pytest.mark.parametrize("name", NAMES)
def test_a_term_the_backend_refuses_is_a_recorded_deny_without_its_value(name, tmp_path):
    # The backend refuses a term that breaks the direct path's bounds (here a
    # control character) before the engine, with a TypeError. Since
    # watchlight-agent-sdk 0.10.1 the handle turns any backend error into a
    # deny, so the agent sees a refusal: that refusal is recorded once, as a
    # Deny. The term itself is never written: it is replaced by a value-free
    # marker, and the record is marked `refused_term`. The principal is intact,
    # so the counters count it as a denied decision of that principal only,
    # inside its window, with the marker matching any resource filter.
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("quota-agent") as handle:
            result = await handle.authorize_action_detailed(
                'Action::"read"', TAB_RESOURCE, principal='User::"u1"'
            )
            assert result.decision == "deny"

    asyncio.run(run())
    raw = audit.read_text(encoding="utf-8")
    assert "web\tsearch" not in raw and "web\\tsearch" not in raw
    (record,) = _decisions(_lines(audit))
    assert record["decision"] == "Deny"
    assert record["refused_term"] is True and "oversized" not in record
    assert record["principal"] == 'User::"u1"'
    assert record["resource"] == {"omitted": "refused", "bytes": len(TAB_RESOURCE)}
    assert record["agent"] == "quota-agent"
    assert set(record) <= ALLOWED_FIELDS

    def count(principal, outcome, **kw):
        return count_audit_records(audit, principal=principal, window="1h", outcome=outcome, **kw)

    denied = count('User::"u1"', "denied", resource='Tool::"anything"')
    assert (denied["count"], denied["unreadable"]) == (1, 0)
    assert count('User::"u1"', "all")["count"] == 1
    # Never as allowed, never for another principal.
    assert count('User::"u1"', "allowed")["count"] == 0
    assert count('User::"alice"', "all")["count"] == 0


@pytest.mark.parametrize("name", NAMES)
def test_unusual_agent_names_are_recorded_as_given_and_never_refused(name, tmp_path):
    # Agent names — the root's and a sub-agent's — are recorded exactly as
    # given, and the record stays one valid JSON line.
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))
    root, child = "lead\nagent\u2028x", "sub\tagent"

    async def run():
        async with await plugin.start_run(root) as handle:
            assert await handle.authorize_action(*ALLOWED)
            sub = await _spawn(plugin, handle, child, allowed_tools=["web_search"], time_budget_seconds=60)
            assert await sub.authorize_action(*ALLOWED)

    asyncio.run(run())
    raw = audit.read_text(encoding="utf-8")
    assert "\u2028" not in raw and "\t" not in raw
    first, second = _decisions(_lines(audit))
    assert first["agent"] == root
    assert second["agent"] == child and second["actor_chain"] == [root, child]


@pytest.mark.parametrize(
    "answer, expected",
    [
        ({"decision": "Allow", "reason": "", "details": {}}, "Allow"),
        ({"decision": "allow", "reason": "", "details": {}}, "Allow"),
        # The SDK lower-cases but does not strip: a padded verdict is a deny.
        ({"decision": " Allow", "reason": "", "details": {}}, "Deny"),
        ({"decision": " ALLOW ", "reason": "", "details": {}}, "Deny"),
        # An answer the SDK will not trust is a deny, whatever it names.
        ({"decision": "Allow", "reason": "", "details": {}, "error": "x"}, "Deny"),
        ({"decision": "Allow", "reason": 7, "details": {}}, "Deny"),
        ({"decision": "Deny", "reason": "", "details": {}}, "Deny"),
    ],
)
@pytest.mark.parametrize("name", NAMES)
def test_verdicts_are_read_the_way_the_sdk_reads_them(name, answer, expected, monkeypatch, tmp_path):
    # The record says what the handle acted on: the verdict is reduced by the
    # SDK's own functions, never by a looser reading of the answer.
    from watchlight_core import InProcessClient

    async def reply(self, *args, **kwargs):
        return dict(answer)

    monkeypatch.setattr(InProcessClient, "authorize", reply)
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("verdict-agent") as handle:
            return await handle.authorize_action(*ALLOWED)

    allowed = asyncio.run(run())
    assert allowed is (expected == "Allow")
    assert [r["decision"] for r in _decisions(_lines(audit))] == [expected]


@pytest.mark.parametrize("engine_raises", [False, True])
def test_a_record_that_cannot_be_built_never_changes_the_decision(monkeypatch, tmp_path, capsys, engine_raises):
    import watchlight.inprocess as inprocess

    def broken(**kwargs):
        raise ValueError(f"cannot build {kwargs}")

    monkeypatch.setattr(inprocess, "decision_record", broken)
    backend = inprocess.in_process_backend(POLICIES, audit_path=str(tmp_path / "audit.jsonl"))

    async def run():
        if engine_raises:
            # An empty action is a request the engine cannot evaluate.
            with pytest.raises(Exception):
                await backend.authorize('Agent::"a"', "", "")
            with pytest.raises(Exception):
                await backend.authorize('Agent::"a"', "", "")
        else:
            first = await backend.authorize('Agent::"a"', 'Action::"read"', 'Tool::"x"')
            second = await backend.authorize('Agent::"a"', 'Action::"read"', 'Tool::"x"')
            assert first["decision"] == second["decision"] == "Allow"

    asyncio.run(run())
    err = capsys.readouterr().err
    assert err.count("could not be recorded in full (ValueError); a value-free placeholder") == 1
    assert "cannot build" not in err
    # Each decision is still in the trail, as a placeholder that holds no name
    # and counts toward every query.
    records = _decisions(_lines(tmp_path / "audit.jsonl"))
    expected = "Deny" if engine_raises else "Allow"
    assert [(r["decision"], r["oversized"], r["principal"]) for r in records] == [
        (expected, True, {"omitted": "unrecorded"})
    ] * 2


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
    "create_session": "observed for the session's agent; refuses application_id and subject_token in-process (SDK 0.9.0)",
    "complete_session": "bookkeeping (names the run by its reference since SDK 0.10.0)",
    "terminate_session": "bookkeeping (names the run by its reference since SDK 0.10.0)",
    "drain": "not a decision: lineage is written synchronously in-process",
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


def _audited_client(tmp_path):
    from watchlight._audit import AuditTrail
    from watchlight.inprocess import _audited_client_class

    trail = AuditTrail(str(tmp_path / "audit.jsonl"))
    return _audited_client_class()(POLICIES, audit_path=str(tmp_path / "sdk.jsonl"), trail=trail)


def test_every_override_accepts_what_the_sdk_method_accepts():
    """An override must take every argument the SDK's own method takes.

    The SDK's handles call the backend with arguments that a release can add or
    rename (0.10.0 names the run by its reference, ``run``). An override
    with the older signature raises ``TypeError`` there, and the run cannot
    complete — so a new SDK parameter fails here, by name, instead."""
    import inspect as _inspect

    from watchlight.inprocess import _audited_client_class
    from watchlight_core import InProcessClient

    audited = _audited_client_class()
    checked = []
    for name, member in vars(audited).items():
        if name.startswith("_") or not _inspect.iscoroutinefunction(member):
            continue
        base = getattr(InProcessClient, name, None)
        assert base is not None, f"{name} overrides nothing on the SDK client"
        ours = _inspect.signature(member).parameters
        has_var_kw = any(p.kind is p.VAR_KEYWORD for p in ours.values())
        missing = [
            p
            for p in _inspect.signature(base).parameters
            if p not in ours and not has_var_kw
        ]
        assert not missing, f"AuditedInProcessClient.{name} does not accept {missing}"
        checked.append(name)
    assert {"authorize", "complete_session", "create_session", "spawn_subagent"} <= set(checked)


def test_complete_session_forwards_the_run(tmp_path, monkeypatch):
    from watchlight_core import InProcessClient

    seen = {}

    async def spy(self, run):
        seen["args"] = (run,)
        return True

    monkeypatch.setattr(InProcessClient, "complete_session", spy)
    client = _audited_client(tmp_path)
    assert asyncio.run(client.complete_session("run_1")) is True
    assert seen["args"] == ("run_1",)


def test_ending_a_run_forgets_its_session(tmp_path):
    """The SDK ends a run by its reference; the recording backend maps it back
    to the session and drops that session's chain, so its bookkeeping does not
    grow with every run."""
    client = _audited_client(tmp_path)

    async def run():
        info = await client.create_session("agent-1")
        assert client._wl_sessions[info.session_id] == ("agent-1",)
        assert await client.complete_session(info.run) is True
        assert info.session_id not in client._wl_sessions
        assert info.run not in client._wl_runs
        # An ended run is ended once; a second close is refused by the SDK.
        assert await client.complete_session(info.run) is False

    asyncio.run(run())


async def _named_run(client, slug):
    agent = await client.resolve_agent(slug)
    return await client.create_session(agent["id"])


def test_a_decision_is_filed_under_its_run_not_the_session_id_it_names(tmp_path):
    """The SDK names the run by its reference; a `session_id` that names a
    different run must not move the record to that run's agent."""
    client = _audited_client(tmp_path)

    async def run():
        alpha = await _named_run(client, "alpha-agent")
        beta = await _named_run(client, "beta-agent")
        await client.authorize(
            'Agent::"x"', *ALLOWED, {}, session_id=alpha.session_id, run=beta.run
        )
        # A call that names no run is filed under the session it names.
        await client.authorize('Agent::"x"', *ALLOWED, {}, session_id=alpha.session_id)

    asyncio.run(run())
    agents = [r["agent"] for r in _decisions(_lines(tmp_path / "audit.jsonl"))]
    assert agents == ["beta-agent", "alpha-agent"]


def test_a_sub_agent_chain_comes_from_the_parent_run_not_the_request(tmp_path):
    """The chain a sub-agent's records carry is its parent RUN's chain. The
    agent and handle ids in the spawn request are the caller's words and are
    never used for it."""
    from uuid import UUID, uuid4

    from watchlight_core.scope import (
        RequestedScope,
        SpawnSubagentRequest,
        spawn_subagent_request_to_dict,
    )

    client = _audited_client(tmp_path)

    async def run():
        lead = await _named_run(client, "lead-agent")
        decoy = await client.resolve_agent("decoy-agent")
        child = await client.resolve_agent("child-agent")
        request = spawn_subagent_request_to_dict(
            SpawnSubagentRequest(
                # Names another agent as the parent: ignored for the chain.
                parent_agent_id=UUID(decoy["id"]),
                child_agent_id=UUID(child["id"]),
                parent_run_handle_id=UUID(lead.root_run_handle_id or str(uuid4())),
                requested_scope=RequestedScope(
                    allowed_tools=["web_search"], time_budget_seconds=60
                ),
            )
        )
        response = await client.spawn_subagent(lead.run, request)
        await client.authorize('Agent::"x"', *ALLOWED, {}, run=response["child_run"])

    asyncio.run(run())
    decisions = _decisions(_lines(tmp_path / "audit.jsonl"))
    assert [(r["agent"], r.get("actor_chain")) for r in decisions] == [
        ("child-agent", ["lead-agent", "child-agent"])
    ]


def test_a_decision_after_the_run_ended_still_names_its_agent(tmp_path):
    client = _audited_client(tmp_path)

    async def run():
        info = await _named_run(client, "ended-agent")
        assert await client.complete_session(info.run) is True
        # The SDK refuses a call for an ended run; the refusal is recorded
        # under the run's agent, not as unconfigured.
        result = await client.authorize('Agent::"x"', *ALLOWED, {}, run=info.run)
        assert result["decision"] == "Deny"

    asyncio.run(run())
    decisions = _decisions(_lines(tmp_path / "audit.jsonl"))
    assert [(r["agent"], r["decision"]) for r in decisions] == [("ended-agent", "Deny")]


def test_the_ended_run_memory_is_bounded(tmp_path, monkeypatch):
    import watchlight.inprocess as inprocess

    monkeypatch.setattr(inprocess, "_MAX_ENDED_RUNS", 3)
    client = _audited_client(tmp_path)

    async def run():
        for i in range(5):
            info = await _named_run(client, f"agent-{i}")
            await client.complete_session(info.run)

    asyncio.run(run())
    assert len(client._wl_ended_runs) == 3
    assert len(client._wl_ended_sessions) == 3
    assert not client._wl_runs and not client._wl_sessions


@pytest.mark.parametrize("kwarg", ["application_id", "subject_token"])
def test_enterprise_only_session_arguments_are_still_refused(tmp_path, kwarg):
    """The SDK's in-process client refuses a run it cannot verify (an AI
    application, an end-user subject); the recording override forwards every
    argument, so it refuses exactly the same way and records no session."""
    from watchlight_core.errors import WatchlightContractError

    client = _audited_client(tmp_path)
    with pytest.raises(WatchlightContractError):
        asyncio.run(client.create_session("agent-1", **{kwarg: "x"}))
    assert client._wl_sessions == {}


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


# ── handles a framework opens on its own ───────────────────────────────────


#: The in-process root's time ceiling (the SDK's default, wl-apdp's default
#: ``subagent_time_budget_threshold_seconds``).
ROOT_CEILING_SECONDS = 3600


def _assert_budget_bounded_by_root(child):
    """A sub-agent that named no budget was granted one: no more than the
    root's ceiling (the in-process root has no deadline of its own), with a
    deadline inside it."""
    from datetime import datetime, timedelta, timezone

    granted = getattr(child, "_wl_inner", child).granted_scope
    assert granted is not None
    assert 0 < granted.time_budget_seconds <= ROOT_CEILING_SECONDS
    assert granted.deadline is not None
    assert granted.deadline <= datetime.now(timezone.utc) + timedelta(seconds=ROOT_CEILING_SECONDS)


def test_a_native_task_sub_agent_refusal_is_recorded(tmp_path):
    # The Claude Agent SDK plugin opens a native Task sub-agent through the
    # run's SubagentRegistry. Its child handle must be the recording wrapper,
    # so a refusal it makes on its own after a quarantine is recorded too.
    from watchlight_core import AgentQuarantinedError

    module = _plugin_module("claude_agent")
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(ENFORCING, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("claude-root") as handle:
            capture = {"subagent_id": "task-1", "agent_type": "task-researcher", "allowed_tools": ["web_search"]}
            child = await plugin.on_subagent_start(handle, capture)
            assert child is not None
            # The Task capture names no time budget: the sub-agent runs, bounded
            # by the root's 3600-second ceiling, never more.
            _assert_budget_bounded_by_root(child)
            assert plugin.resolve_subagent(handle, "task-1") is child
            assert await child.authorize_action('Action::"read"', 'Tool::"web_search"') is True
            with pytest.raises(AgentQuarantinedError):
                await child.authorize_action('Action::"exfiltrate"', 'Tool::"web_search"')
            with pytest.raises(AgentQuarantinedError):
                await plugin.resolve_subagent(handle, "task-1").authorize_action(
                    'Action::"read"', 'Tool::"web_search"'
                )

    asyncio.run(run())
    decisions = _decisions(_lines(audit))
    assert [(r["agent"], r.get("actor_chain"), r["intent"], r["decision"]) for r in decisions] == [
        ("task-researcher", ["claude-root", "task-researcher"], 'Action::"read"', "Allow"),
        ("task-researcher", ["claude-root", "task-researcher"], 'Action::"exfiltrate"', "Deny"),
        ("task-researcher", ["claude-root", "task-researcher"], 'Action::"read"', "Deny"),
    ]


def test_pydantic_ai_auto_instrumented_handles_are_wrapped(tmp_path):
    # Pydantic AI's auto-instrumentation opens the root with plugin.start_run
    # and a nested agent with parent.spawn_subagent on the handle it keeps in a
    # context variable. Both must be the recording wrapper.
    #
    # The nested agent is spawned with no tools granted, and (since
    # watchlight-pydantic-ai 0.4.1 with watchlight-agent-sdk 0.10.1) every call
    # it makes is checked against that grant: its first call is denied before
    # any policy is read, and the denial invalidates its handle, so its next
    # call is denied too. The root keeps its own scope, and a quarantine there
    # is short-circuited by the handle itself on the next call.
    from watchlight_core import AgentQuarantinedError
    from watchlight_pydantic_ai import instrumentation

    module = _plugin_module("pydantic_ai")
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(ENFORCING, audit_path=str(audit))

    async def run():
        root, root_token = await instrumentation._open_handle_for_call(plugin, types.SimpleNamespace(name="planner"))
        try:
            assert type(root).__name__ == "_AuditedRunHandle"
            assert instrumentation.current_handle() is root
            child, child_token = await instrumentation._open_handle_for_call(
                plugin, types.SimpleNamespace(name="worker")
            )
            try:
                assert type(child).__name__ == "_AuditedRunHandle"
                # The nested agent names no time budget: it runs, bounded by the
                # root's 3600-second ceiling, never more.
                _assert_budget_bounded_by_root(child)
                result = await child.authorize_action_detailed('Action::"exfiltrate"', 'Tool::"x"')
                assert result.decision == "deny"
                assert result.reason.startswith("scope_attenuation_violation")
                assert instrumentation.current_handle() is child
                assert await instrumentation.current_handle().authorize_action('Action::"read"', 'Tool::"x"') is False
            finally:
                instrumentation._current_handle.reset(child_token)
            with pytest.raises(AgentQuarantinedError):
                await root.authorize_action('Action::"exfiltrate"', 'Tool::"x"')
            with pytest.raises(AgentQuarantinedError):
                await instrumentation.current_handle().authorize_action('Action::"read"', 'Tool::"x"')
        finally:
            instrumentation._current_handle.reset(root_token)

    asyncio.run(run())
    decisions = _decisions(_lines(audit))
    assert [(r["agent"], r.get("actor_chain"), r["intent"], r["decision"]) for r in decisions] == [
        ("worker", ["planner", "worker"], 'Action::"exfiltrate"', "Deny"),
        ("worker", ["planner", "worker"], 'Action::"read"', "Deny"),
        ("planner", None, 'Action::"exfiltrate"', "Deny"),
        ("planner", None, 'Action::"read"', "Deny"),
    ]


@pytest.mark.parametrize("name", NAMES)
def test_a_wrapped_handle_supports_weak_references(name, tmp_path):
    import weakref

    module = _plugin_module(name)
    plugin = module.governed_plugin(POLICIES, audit_path=str(tmp_path / "audit.jsonl"))

    async def run():
        async with await plugin.start_run("weak-agent") as handle:
            ref = weakref.ref(handle)
            assert ref() is handle

    asyncio.run(run())


# ── the SDK handle surface the wrapper depends on ──────────────────────────

#: Every public method of the SDK's run handles (the base class and each
#: plugin's subclass), and how the wrapper treats it. A method added in a later
#: release fails here until it is classified: one that can make or refuse a
#: decision must be intercepted, so its refusals are recorded.
HANDLE_METHODS = {
    "authorize_action": "intercepted: a refusal the handle makes itself is recorded",
    "authorize_action_detailed": "intercepted: a refusal the handle makes itself is recorded",
    "spawn_subagent": "intercepted: the child is wrapped",
    "guarded_tool": "intercepted: the decorated tool is watched",
    "preflight_step": "not recorded: advisory, gates nothing",
    "submit_plan": "not a decision in-process: raises NotImplementedError",
    "complete": "lifecycle",
    "terminate": "lifecycle",
    "publish_observation": "telemetry, not a decision",
    "publish_observation_for_execution": "telemetry, not a decision",
    # Synchronous methods: none of them makes or refuses a decision.
    "activate_lineage": "lineage context, not a decision",
    "lineage_snapshot": "lineage context, not a decision",
    "get_attenuations": "reads recorded effects",
    "get_escalations": "reads recorded effects",
    "get_observations": "reads recorded effects",
    "has_attenuations": "reads recorded effects",
    "has_escalations": "reads recorded effects",
    "has_observations": "reads recorded effects",
    "was_scope_attenuated": "reads recorded effects",
    "mark_execution_started_emitted": "lifecycle bookkeeping",
    "mark_execution_completed_emitted": "lifecycle bookkeeping",
    "mark_execution_failed_emitted": "lifecycle bookkeeping",
    "parse_root_run_handle_id": "parses a session response",
    "record_declared_intent": "stores the declared intent; the next authorize reads it",
    "synthetic_tools": "tool descriptors, not a decision",
    "synthetic_langchain_tools": "tool descriptors, not a decision (LangGraph)",
    "bind_tools": "binds tool descriptors to a model, not a decision (LangGraph)",
    "callback_handler": "builds a lineage callback handler, not a decision (LangGraph)",
    "detach_callbacks": "releases the callback handler's context, not a decision (LangGraph)",
}


def _handle_classes():
    from watchlight_core.run_handle import BaseRunHandle

    classes = [BaseRunHandle]
    for name in NAMES:
        integration = INTEGRATIONS[name]
        module = importlib.import_module(integration.plugin_module)
        classes.append(getattr(module, "RunHandle"))
    return classes


def test_every_public_handle_method_is_classified():
    import inspect as _inspect

    found = set()
    for cls in _handle_classes():
        for attr, member in _inspect.getmembers(cls):
            if attr.startswith("_") or isinstance(_inspect.getattr_static(cls, attr), property):
                continue
            # Coroutine AND synchronous methods: a synchronous decorator in the
            # style of `guarded_tool` can gate a call just as well.
            if callable(member):
                found.add(attr)
    assert found == set(HANDLE_METHODS), (
        "the SDK's run handle changed: classify "
        f"{sorted(found - set(HANDLE_METHODS))} / drop {sorted(set(HANDLE_METHODS) - found)}"
    )


#: Every way the SDK handle's ``authorize_action_detailed`` can end, and how the
#: decision it ends with reaches the trail. A path added in a later release
#: fails ``test_every_handle_decision_path_is_classified`` until it is listed
#: here. The wrapper records any call the backend wrote no record for (see
#: ``_AuditedRunHandle._wl_run``), so a new path is recorded even before it is
#: classified; the test makes sure someone looked.
HANDLE_EXITS = {
    # Before the backend is asked.
    ("raise", "WatchlightContractError"): (
        "not a decision: a caller bug (authorize outside `async with`), raised "
        "before anything is decided and never recorded, as on the direct path"
    ),
    ("call", "self._raise_if_run_ended"): (
        "short-circuit after a Quarantine, SeverSubtree, Terminate or Revoke: "
        "the wrapper records the Deny"
    ),
    ("return", "deny", "intent_refused"): (
        "a malformed intent refused locally (SDK 0.10.1): the wrapper records the Deny"
    ),
    # After the backend is asked.
    ("return", "deny", "governance backend failed"): (
        "the backend raised: it recorded the Deny before raising, or, for a term "
        "it refused before deciding, wrote none and the wrapper records the Deny"
    ),
    ("return", "deny", "governance backend returned an unrecognised answer"): (
        "the backend recorded it as a Deny: it applies the SDK's own answer check"
    ),
    ("return", "AuthorizeResult.deny_transport_failure()"): "the backend's answer, recorded by the backend",
    ("raise", "AgentQuarantinedError"): (
        "a Quarantine answer the backend recorded, or the quarantine short-circuit "
        "the wrapper records"
    ),
    ("raise", "SubtreeSeveredError"): (
        "a SeverSubtree answer the backend recorded, or the sever short-circuit "
        "the wrapper records"
    ),
    ("raise", "ExecutionTerminatedError"): "a Terminate answer the backend recorded",
    ("raise", "AgentRevokedError"): "a Revoke answer the backend recorded",
    ("return", "result"): "the backend's answer, recorded by the backend",
}

#: The refusals the handle makes BEFORE it asks the backend. The backend never
#: sees them, so only the wrapper can record them.
LOCAL_EXITS = {
    ("raise", "WatchlightContractError"),
    ("raise", "AgentQuarantinedError"),
    ("raise", "SubtreeSeveredError"),
    ("call", "self._raise_if_run_ended"),
    ("return", "deny", "intent_refused"),
}


def _exit_key(node):
    import ast
    import re as _re

    if isinstance(node, ast.Call):
        return ("call", ast.unparse(node.func))
    if isinstance(node, ast.Raise):
        exc = node.exc
        while isinstance(exc, ast.Call):
            exc = exc.func
        while isinstance(exc, ast.Attribute):
            exc = exc.value
        return ("raise", exc.id if isinstance(exc, ast.Name) else ast.unparse(node.exc))
    value = node.value
    if isinstance(value, ast.Call) and ast.unparse(value.func) == "AuthorizeResult":
        # The verdict literal is part of the key, so a new `return
        # AuthorizeResult("allow", …)` can never pass as a classified deny.
        verdict = value.args[0] if value.args else next(
            (k.value for k in value.keywords if k.arg == "decision"), None
        )
        verdict = verdict.value if isinstance(verdict, ast.Constant) else ast.unparse(verdict)
        reason = next((k.value for k in value.keywords if k.arg == "reason"), None)
        if isinstance(reason, ast.JoinedStr):
            reason = next((v for v in reason.values if isinstance(v, ast.Constant)), None)
        if isinstance(reason, ast.Constant) and isinstance(reason.value, str):
            return ("return", verdict, _re.split(r"[:;(]", reason.value)[0].strip())
        return ("return", verdict, ast.unparse(reason) if reason is not None else "")
    return ("return", ast.unparse(value) if value is not None else "None")


def _handle_exits():
    """(key, before_backend) for every exit of the SDK handle's authorize."""
    import ast
    import inspect as _inspect
    import textwrap

    from watchlight_core.run_handle import BaseRunHandle

    tree = ast.parse(textwrap.dedent(_inspect.getsource(BaseRunHandle.authorize_action_detailed)))
    backend = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "authorize"
        and ast.unparse(node.func.value) == "self._plugin.apdp"
    ]
    assert len(backend) == 1, "the handle's single backend call moved"
    exits = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.Return, ast.Raise)) or (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr.startswith("_raise")
        ):
            exits.append((_exit_key(node), node.lineno < backend[0]))
    return exits


def test_every_handle_decision_path_is_classified():
    # Every plugin's handle uses the base class's authorize methods unchanged,
    # so the checks below on the base class cover all of them.
    import ast
    import inspect as _inspect
    import textwrap

    from watchlight_core.run_handle import BaseRunHandle

    for cls in _handle_classes()[1:]:
        assert cls.authorize_action is BaseRunHandle.authorize_action, cls
        assert cls.authorize_action_detailed is BaseRunHandle.authorize_action_detailed, cls

    # `authorize_action` only awaits `authorize_action_detailed`, so it has no
    # refusal path of its own.
    outer = ast.parse(textwrap.dedent(_inspect.getsource(BaseRunHandle.authorize_action)))
    awaited = [ast.unparse(n.value.func) for n in ast.walk(outer) if isinstance(n, ast.Await)]
    assert awaited == ["self.authorize_action_detailed"], awaited
    assert not [n for n in ast.walk(outer) if isinstance(n, ast.Raise)]

    exits = _handle_exits()
    found = {key for key, _ in exits}
    assert found == set(HANDLE_EXITS), (
        "the SDK handle's authorize changed: classify "
        f"{sorted(found - set(HANDLE_EXITS))} / drop {sorted(set(HANDLE_EXITS) - found)}"
    )
    # Before the backend is asked, only the classified local refusals.
    local = {key for key, before in exits if before}
    assert local == LOCAL_EXITS, (
        "a new path decides before asking the backend: record it, then classify "
        f"{sorted(local - LOCAL_EXITS)} / drop {sorted(LOCAL_EXITS - local)}"
    )
    # Every verdict the handle returns before asking the backend is a deny.
    for key in LOCAL_EXITS:
        if key[0] == "return":
            assert len(key) == 3 and key[1] == "deny", key

    # The short-circuit helper raises only the run-ending errors.
    helper = ast.parse(textwrap.dedent(_inspect.getsource(BaseRunHandle._raise_if_run_ended)))
    raised = {_exit_key(n)[1] for n in ast.walk(helper) if isinstance(n, ast.Raise)}
    assert raised == {
        "AgentQuarantinedError",
        "SubtreeSeveredError",
        "ExecutionTerminatedError",
        "AgentRevokedError",
    }, raised


@pytest.mark.parametrize("name", NAMES)
def test_a_malformed_intent_refused_by_the_handle_is_recorded_once(name, tmp_path):
    # watchlight-agent-sdk 0.10.1 refuses an intent that is not a typed intent
    # (an objective AND a category) before any request: the backend never sees
    # the call. The wrapper records that refusal as a Deny, once, and nothing
    # the intent carried reaches the trail.
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("intent-agent") as handle:
            detailed = await handle.authorize_action_detailed(*ALLOWED, intent={"objective": CANARIES[1]})
            assert detailed.decision == "deny" and detailed.reason.startswith("intent_refused")
            assert await handle.authorize_action(*ALLOWED, intent={"category": "research"}) is False
            # A well-formed intent on the same handle is decided as usual.
            assert await handle.authorize_action(*ALLOWED, intent=_intent()) is True

    asyncio.run(run())
    decisions = _decisions(_lines(audit))
    assert [(r["agent"], r["intent"], r["decision"]) for r in decisions] == [
        ("intent-agent", ALLOWED[0], "Deny"),
        ("intent-agent", ALLOWED[0], "Deny"),
        ("intent-agent", ALLOWED[0], "Allow"),
    ]
    for record in decisions:
        assert set(record) <= ALLOWED_FIELDS
        assert record["principal"].startswith('Agent::"')
    assert len({r["execution_id"] for r in decisions}) == 1
    assert CANARIES[1] not in audit.read_text(encoding="utf-8")


def test_a_guarded_tool_refused_without_a_backend_record_is_recorded(tmp_path):
    # Pydantic AI's `guarded_tool` calls the SDK handle directly. Here the
    # tool's action carries a control character: the backend refuses the term
    # before deciding, the handle turns that into a deny (SDK 0.10.1), and the
    # decorator raises. The refusal is recorded through the watched tool, with
    # a value-free marker in place of the term, and the tool body never runs.
    module = _plugin_module("pydantic_ai")
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))
    ran = []

    async def run():
        async with await plugin.start_run("tool-agent") as handle:

            @handle.guarded_tool(action='Action::"re\tad"')
            async def fetch(query):
                ran.append(query)
                return query

            with pytest.raises(PermissionError):
                await fetch("q")

    asyncio.run(run())
    assert ran == []
    (record,) = _decisions(_lines(audit))
    assert (record["resource"], record["decision"], record.get("refused_term")) == ("fetch", "Deny", True)
    assert record["intent"] == {"omitted": "refused", "bytes": len('Action::"re\tad"')}


def test_the_guard_key_tells_an_allow_from_a_deny():
    # A new pre-backend `return AuthorizeResult("allow", …)` must not pass as
    # the classified local deny, even with the same reason.
    import ast

    allow = ast.parse('return AuthorizeResult("allow", reason=f"intent_refused: {x}")').body[0]
    deny = ast.parse('return AuthorizeResult("deny", reason=f"intent_refused: {x}")').body[0]
    assert _exit_key(deny) in LOCAL_EXITS
    assert _exit_key(allow) not in LOCAL_EXITS and _exit_key(allow) not in HANDLE_EXITS


# ── regressions from the review of the 0.10.1 adaptation ───────────────────


class _HashFails(str):
    """A str subclass whose hash raises: no cache may need to hash a term."""

    def __hash__(self):
        raise TypeError("unhashable")


@pytest.mark.parametrize(
    "label, kwargs",
    [
        ("resource is a list", {"action": 'Action::"read"', "resource": ["x"]}),
        ("action is a list", {"action": ["a"], "resource": 'Tool::"x"'}),
        ("principal is a dict", {"action": 'Action::"read"', "resource": 'Tool::"x"', "principal": {"k": 1}}),
        ("resource hash raises", {"action": 'Action::"read"', "resource": _HashFails('Tool::"a\nb"')}),
    ],
)
@pytest.mark.parametrize("name", NAMES)
def test_an_unhashable_refused_term_is_still_recorded_once(name, label, kwargs, tmp_path):
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("odd-agent") as handle:
            return await handle.authorize_action(**kwargs)

    assert asyncio.run(run()) is False, label
    (record,) = _decisions(_lines(audit))
    assert record["decision"] == "Deny", label
    if "principal" in kwargs:
        # Whose decision it was cannot be read: a denied decision of every
        # principal, inside its window.
        assert record["refused_principal"] is True and "oversized" not in record
        assert record["principal"] == {"omitted": "refused"}
    else:
        assert record["refused_term"] is True and "oversized" not in record


def test_refused_terms_are_not_kept_in_memory(tmp_path):
    import gc
    import tracemalloc

    from watchlight import inprocess

    assert not hasattr(inprocess._refused_marker, "cache_info")
    module = _plugin_module("langgraph")
    plugin = module.governed_plugin(POLICIES, audit_path=str(tmp_path / "audit.jsonl"))

    async def run():
        async with await plugin.start_run("mem-agent") as handle:
            for i in range(24):
                assert await handle.authorize_action('Action::"read"', str(i) + "y" * (1 << 20)) is False

    tracemalloc.start()
    try:
        asyncio.run(run())
        gc.collect()
        current, _peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    # 24 MiB of refused terms went through; none of them is retained.
    assert current < 8 * (1 << 20), current


def test_a_refused_term_never_inflates_another_principals_quota(tmp_path):
    import datetime

    module = _plugin_module("langgraph")
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("attacker-agent") as handle:
            assert await handle.authorize_action('Action::"read"', 'Tool::"x\ny"', principal='User::"mallory"') is False

    asyncio.run(run())
    (record,) = _decisions(_lines(audit))
    assert (record["principal"], record["refused_term"]) == ('User::"mallory"', True)
    later = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=30)).isoformat()
    for when in (None, later):
        for outcome in ("allowed", "denied", "all"):
            r = count_audit_records(audit, 'User::"alice"', *ALLOWED, window="1m", outcome=outcome, now=when)
            assert r["count"] == 0, (when, outcome)
    # Mallory's own denied count includes it now, and it ages out of the window.
    assert count_audit_records(audit, 'User::"mallory"', window="1m", outcome="denied")["count"] == 1
    assert count_audit_records(audit, 'User::"mallory"', window="1m", outcome="allowed")["count"] == 0
    assert count_audit_records(audit, 'User::"mallory"', window="1m", outcome="denied", now=later)["count"] == 0


@pytest.mark.parametrize("name", NAMES)
def test_a_cancelled_call_is_recorded_as_a_deny(name, tmp_path, monkeypatch):
    # A framework hook that bounds the call (asyncio.wait_for) cancels it; the
    # action does not run on that call, and the refusal is recorded once.
    from watchlight_core import InProcessClient

    original = InProcessClient.authorize

    async def slow(self, *a, **k):
        await asyncio.sleep(5)
        return await original(self, *a, **k)

    monkeypatch.setattr(InProcessClient, "authorize", slow)
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("cancel-agent") as handle:
            with pytest.raises(asyncio.TimeoutError):
                await asyncio.wait_for(handle.authorize_action(*ALLOWED), timeout=0.05)

    asyncio.run(run())
    decisions = _decisions(_lines(audit))
    assert [(r["agent"], r["intent"], r["decision"]) for r in decisions] == [("cancel-agent", ALLOWED[0], "Deny")]


def test_a_guarded_tool_records_its_outcome_from_whether_the_body_ran(tmp_path, monkeypatch):
    # The decorated tool's own return value says nothing about the decision.
    # With no backend record, the wrapper records an Allow only when the tool's
    # body actually started, and a Deny otherwise.
    from watchlight import inprocess

    module = _plugin_module("pydantic_ai")
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("tool-agent") as handle:
            watched = handle._wl_guarded_tool(lambda action="execute": (lambda fn: fn))(action='Action::"read"')

            async def fetch():
                return None

            async def refuse():
                return "refused without running"

            # A decorator that lets the body run, and one that never does;
            # neither asks the backend, so neither writes a backend record.
            ran = watched(fetch)
            blocked = handle._wl_guarded_tool(
                lambda action="execute": (lambda fn: (lambda *a, **k: refuse()))
            )(action='Action::"read"')(fetch)
            assert await ran() is None
            assert await blocked() == "refused without running"

    asyncio.run(run())
    decisions = _decisions(_lines(audit))
    assert [(r["resource"], r["decision"]) for r in decisions] == [("fetch", "Allow"), ("fetch", "Deny")]
    assert inprocess._BODY_RAN.get() is None


def test_a_nested_call_through_the_wrapper_is_recorded_once(tmp_path):
    # A decorated tool whose decorator authorizes through the wrapped handle
    # (as Pydantic AI's does inside an instrumented run) writes one record,
    # not one for the inner call and another for the outer.
    module = _plugin_module("pydantic_ai")
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("tool-agent") as handle:

            def decorator_factory(action="execute"):
                def decorate(fn):
                    async def governed(*a, **k):
                        if not await handle.authorize_action(action, 'Tool::"web_search"'):
                            raise PermissionError("denied")
                        return await fn(*a, **k)

                    return governed

                return decorate

            async def fetch():
                return "ok"

            tool = handle._wl_guarded_tool(decorator_factory)(action='Action::"read"')(fetch)
            assert await tool() == "ok"

    asyncio.run(run())
    assert [r["decision"] for r in _decisions(_lines(audit))] == ["Allow"]


def test_a_spawn_refused_by_the_handle_is_not_a_decision_record(tmp_path):
    # Documented scope: a refused spawn raises and the child never runs, but it
    # is not an authorize call, so it writes no decision record.
    from watchlight_core import AgentQuarantinedError

    module = _plugin_module("langgraph")
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(ENFORCING, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("q-agent") as handle:
            with pytest.raises(AgentQuarantinedError):
                await handle.authorize_action('Action::"exfiltrate"', 'Tool::"x"')
            with pytest.raises(Exception):
                await handle.spawn_subagent("child", allowed_tools=["web_search"], time_budget_seconds=60)

    asyncio.run(run())
    assert [(r["intent"], r["decision"]) for r in _decisions(_lines(audit))] == [('Action::"exfiltrate"', "Deny")]


def test_a_refused_principal_is_a_windowed_denial_of_every_principal(tmp_path):
    # Whose decision it was cannot be read from a record whose principal was
    # refused, so it counts for every principal — but only as denied, only
    # inside its window, and never as allowed.
    import datetime

    module = _plugin_module("langgraph")
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("odd-agent") as handle:
            assert await handle.authorize_action(*ALLOWED, principal='User::"a\nb"') is False

    asyncio.run(run())
    (record,) = _decisions(_lines(audit))
    assert record["refused_principal"] is True and "oversized" not in record
    assert record["principal"] == {"omitted": "refused", "bytes": len('User::"a\nb"')}
    assert record["ts"]
    later = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=2)).isoformat()
    for principal in ('User::"alice"', 'User::"bob"'):
        assert count_audit_records(audit, principal, window="1h", outcome="denied")["count"] == 1
        assert count_audit_records(audit, principal, window="1h", outcome="all")["count"] == 1
        assert count_audit_records(audit, principal, window="1h", outcome="allowed")["count"] == 0
        assert count_audit_records(audit, principal, window="1h", outcome="denied", now=later)["count"] == 0
    # The action is intact, so a filter on another action does not match it.
    assert count_audit_records(audit, 'User::"alice"', 'Action::"write"', window="1h", outcome="denied")["count"] == 0


@pytest.mark.parametrize("name", NAMES)
def test_a_sink_that_raises_a_cancellation_leaves_exactly_one_record(name, tmp_path):
    # A synchronous sink runs after the file line is written. If it raises a
    # cancellation, the call already has its record: the wrapper must not add
    # a second one while the cancellation goes on.
    module = _plugin_module(name)
    audit = tmp_path / "audit.jsonl"

    def sink(record):
        raise asyncio.CancelledError()

    plugin = module.governed_plugin(POLICIES, audit_path=str(audit), audit_sink=sink)

    async def run():
        async with await plugin.start_run("sink-agent") as handle:
            with pytest.raises(asyncio.CancelledError):
                await handle.authorize_action(*ALLOWED)

    asyncio.run(run())
    decisions = _decisions(_lines(audit))
    assert [(r["intent"], r["decision"]) for r in decisions] == [(ALLOWED[0], "Allow")]


def test_a_nested_call_in_a_tool_body_never_stands_in_for_the_tools_record(tmp_path):
    # The tool's guard decision is not recorded by the backend here (the
    # decorator runs the body without asking), and the body makes its own
    # audited calls. Those records belong to the body's calls; the tool's own
    # call is still recorded, as an Allow, because its body ran.
    module = _plugin_module("pydantic_ai")
    audit = tmp_path / "audit.jsonl"
    plugin = module.governed_plugin(POLICIES, audit_path=str(audit))

    async def run():
        async with await plugin.start_run("tool-agent") as handle:

            async def body():
                inner = await handle.authorize_action('Action::"read"', 'Tool::"inner"')
                both = await asyncio.gather(
                    handle.authorize_action('Action::"read"', 'Tool::"g1"'),
                    handle.authorize_action('Action::"delete"', 'Tool::"g2"'),
                )
                return inner, both

            tool = handle._wl_guarded_tool(lambda action="execute": (lambda fn: fn))(action='Action::"read"')(body)
            assert await tool() == (True, [True, False])

    asyncio.run(run())
    rows = sorted((r["resource"], r["decision"]) for r in _decisions(_lines(audit)))
    assert rows == sorted([
        ('Tool::"inner"', "Allow"),
        ('Tool::"g1"', "Allow"),
        ('Tool::"g2"', "Deny"),
        ("body", "Allow"),
    ])
