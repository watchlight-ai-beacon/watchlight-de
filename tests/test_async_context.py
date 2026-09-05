"""An async ``context`` binding (Python), mirroring the TS suite.

A counter source may be asynchronous — that is its purpose, since a durable
store is a network call. A quota policy reads the count out of Cedar
``context``. This asserts the two compose through ``tool()``: an ``async def``
``context`` binding is AWAITED before the decision, so the count the policy
evaluates is the one the binding returned. The synchronous form is asserted to
behave exactly as before, and an async binding on a *synchronous* tool body is
refused fail-closed rather than authorized against a half-built context.
"""
import asyncio

import pytest

pytest.importorskip("watchlight_engine")

from watchlight import ASYNC_CONTEXT_MESSAGE, Denied, NeedsApproval, CounterSourceError, Watchlight

# The quotas pattern's policy, verbatim.
UNDER_QUOTA = 'permit(principal, action == Action::"read", resource) when { context.reads_this_hour < 100 };'
CEILING = 'forbid(principal, action == Action::"read", resource) when { context.reads_this_hour >= 100 };'
USER = 'User::"u1"'


def _gov(tmp_path, **kw):
    g = Watchlight(agent="actx-agent", audit_dir=str(tmp_path / ".watchlight"), **kw)
    g.allow(UNDER_QUOTA, "reads-within-hourly-quota")
    g.allow(CEILING, "hard-ceiling-on-reads")
    return g


# ── the synchronous form is unchanged ───────────────────────────────────────


def test_a_fixed_context_object_still_allows_under_quota(tmp_path):
    g = _gov(tmp_path)

    @g.tool("read", principal=lambda o: USER, resource=lambda o: f"doc/{o['docId']}",
            context={"reads_this_hour": 3})
    def fetch_doc(o):
        return f"doc:{o['docId']}"

    assert fetch_doc({"docId": "a"}) == "doc:a"


def test_a_synchronous_callable_context_is_unchanged(tmp_path):
    g = _gov(tmp_path)
    seen = []
    ran = []

    def quota(o):
        seen.append(o)
        return {"reads_this_hour": o["count"]}

    @g.tool("read", principal=lambda o: USER, context=quota)
    def fetch_doc(o):
        ran.append(o)
        return "doc"

    assert fetch_doc({"count": 99}) == "doc"
    assert len(seen) == 1 and seen[0]["count"] == 99
    with pytest.raises(Denied) as e:
        fetch_doc({"count": 100})
    assert e.value.reason == "not authorized"
    assert len(ran) == 1  # the body never ran on the denial


def test_a_raising_synchronous_binding_still_propagates(tmp_path):
    g = _gov(tmp_path)
    ran = []

    def quota(o):
        raise RuntimeError("binding failed")

    @g.tool("read", principal=lambda o: USER, context=quota)
    def fetch_doc(o):
        ran.append(o)
        return "doc"

    with pytest.raises(RuntimeError, match="binding failed"):
        fetch_doc({})
    assert ran == []


def test_a_synchronous_binding_on_an_async_body_is_unchanged(tmp_path):
    g = _gov(tmp_path)

    @g.tool("read", principal=lambda o: USER, context=lambda o: {"reads_this_hour": o["count"]})
    async def fetch_doc(o):
        return "doc"

    assert asyncio.run(fetch_doc({"count": 1})) == "doc"
    with pytest.raises(Denied):
        asyncio.run(fetch_doc({"count": 100}))


# ── an async binding is awaited before the decision ─────────────────────────


def test_an_async_binding_is_awaited_before_the_body_runs(tmp_path):
    g = _gov(tmp_path)
    order = []
    seen = []

    async def quota(o):
        seen.append(o)
        await asyncio.sleep(0)
        order.append("context")
        return {"reads_this_hour": o["count"]}

    @g.tool("read", principal=lambda o: USER, resource=lambda o: f"doc/{o['docId']}", context=quota)
    async def fetch_doc(o):
        order.append("body")
        return "doc"

    assert asyncio.run(fetch_doc({"docId": "a", "count": 99})) == "doc"
    assert order == ["context", "body"]
    assert len(seen) == 1 and seen[0]["docId"] == "a"


def test_an_async_binding_over_quota_denies_and_the_body_never_runs(tmp_path):
    g = _gov(tmp_path)
    order = []

    async def quota(o):
        return {"reads_this_hour": o["count"]}

    @g.tool("read", principal=lambda o: USER, context=quota)
    async def fetch_doc(o):
        order.append("body")
        return "doc"

    with pytest.raises(Denied) as e:
        asyncio.run(fetch_doc({"count": 100}))
    assert e.value.reason == "not authorized"
    assert order == []


def test_a_raising_async_binding_fails_closed(tmp_path):
    g = _gov(tmp_path)
    ran = []

    async def quota(o):
        raise RuntimeError("store unreachable")

    @g.tool("read", principal=lambda o: USER, context=quota)
    async def fetch_doc(o):
        ran.append(o)
        return "doc"

    with pytest.raises(RuntimeError, match="store unreachable"):
        asyncio.run(fetch_doc({}))
    assert ran == []


def test_a_binding_returning_an_awaitable_is_awaited_too(tmp_path):
    g = _gov(tmp_path)

    async def _count():
        return {"reads_this_hour": 1}

    @g.tool("read", principal=lambda o: USER, context=lambda o: _count())
    async def fetch_doc(o):
        return "doc"

    assert asyncio.run(fetch_doc({})) == "doc"


def test_the_approval_path_sees_the_awaited_context(tmp_path):
    g = Watchlight(agent="actx-agent", audit_dir=str(tmp_path / ".watchlight"))
    g.allow(
        '@enforcement_effect("require_approval")\n'
        'permit(principal, action == Action::"read", resource) when { context.reads_this_hour < 100 };',
        "read-hitl",
    )
    resolved = []

    async def quota(o):
        resolved.append(o)
        return {"reads_this_hour": 1}

    @g.tool("read", principal=lambda o: USER, context=quota, on_needs_approval=lambda d: True)
    async def fetch_doc(o):
        return "doc"

    assert asyncio.run(fetch_doc({})) == "doc"
    assert len(resolved) == 1  # resolved once for the call, not once per authorize

    @g.tool("read", principal=lambda o: USER, context=quota)
    async def hold_doc(o):
        return "doc"

    with pytest.raises(NeedsApproval):
        asyncio.run(hold_doc({}))


# ── the path that cannot await ──────────────────────────────────────────────


def test_an_async_binding_on_a_synchronous_body_is_refused(tmp_path):
    g = _gov(tmp_path)
    ran = []

    async def quota(o):
        return {"reads_this_hour": 1}

    @g.tool("read", principal=lambda o: USER, context=quota)
    def fetch_doc(o):
        ran.append(o)
        return "doc"

    with pytest.raises(TypeError) as e:
        fetch_doc({})
    assert str(e.value) == ASYNC_CONTEXT_MESSAGE
    assert "counters_async" in ASYNC_CONTEXT_MESSAGE  # it names the async entry point
    assert ran == []  # nothing was authorized and nothing ran


def test_the_refusal_leaves_no_pending_awaitable(tmp_path, recwarn):
    """The refused awaitable is closed, so it never surfaces later as an
    un-awaited coroutine attached to some unrelated call."""
    g = _gov(tmp_path)

    async def quota(o):
        return {"reads_this_hour": 1}

    @g.tool("read", principal=lambda o: USER, context=quota)
    def fetch_doc(o):
        return "doc"

    with pytest.raises(TypeError):
        fetch_doc({})
    assert not [w for w in recwarn if issubclass(w.category, RuntimeWarning)]


# ── a durable counter source feeding a quota policy through tool() ──────────


def test_a_durable_counter_source_feeds_a_quota_through_tool(tmp_path):
    """The end-to-end case: no local audit file at all, every record mirrored to
    a store, and the count read back from that store — asynchronously."""
    store = []
    queries = []
    stored = {"n": 0}

    async def source(query):
        queries.append(query)
        return stored["n"]

    g = Watchlight(
        agent="actx-agent",
        audit_dir=str(tmp_path / ".watchlight"),
        audit_file=False,
        audit_sink=store.append,
        counter_source=source,
    )
    g.allow(UNDER_QUOTA, "reads-within-hourly-quota")
    g.allow(CEILING, "hard-ceiling-on-reads")

    ran = []

    async def quota(o):
        c = await g.counters_async(principal=USER, intent="read", window="1h")
        return {} if c["truncated"] else {"reads_this_hour": c["count"]}

    @g.tool("read", principal=lambda o: USER, resource=lambda o: f"doc/{o['docId']}", context=quota)
    async def fetch_doc(o):
        ran.append(o["docId"])
        return f"doc:{o['docId']}"

    stored["n"] = 99
    assert asyncio.run(fetch_doc({"docId": "a"})) == "doc:a"
    assert len(queries) == 1 and queries[0]["principal"] == USER and queries[0]["intent"] == "read"
    assert any(r.get("decision") == "Allow" for r in store)

    stored["n"] = 100
    with pytest.raises(Denied):
        asyncio.run(fetch_doc({"docId": "b"}))
    assert ran == ["a"]
    assert any(r.get("decision") == "Deny" for r in store)


def test_a_synchronous_binding_over_an_async_source_still_fails_closed(tmp_path):
    """The old workaround stays refused BY NAME, rather than silently answered
    from a local file that is not even being written."""

    async def source(query):
        return 0

    g = Watchlight(
        agent="actx-agent",
        audit_dir=str(tmp_path / ".watchlight"),
        audit_file=False,
        audit_sink=lambda record: None,
        counter_source=source,
    )
    g.allow(UNDER_QUOTA, "reads-within-hourly-quota")
    ran = []

    @g.tool("read", principal=lambda o: USER,
            context=lambda o: {"reads_this_hour": g.counters(principal=USER, intent="read")["count"]})
    def fetch_doc(o):
        ran.append(o)
        return "doc"

    with pytest.raises(CounterSourceError, match="counters_async"):
        fetch_doc({})
    assert ran == []
