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
