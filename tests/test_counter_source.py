"""``counter_source`` (Python), mirroring the TS suite.

``counters()`` folds the local audit file, which is per-container and does not
survive a deploy. A ``counter_source`` folds the durable store the sink writes to
instead, so a quota spans every replica. This asserts: no source → unchanged
local behaviour; a source → its number, with the SAME validated query; an async
source is refused by the synchronous path BY NAME rather than answered with a
local count; and every source failure fails the read closed.
"""
import asyncio
import datetime

import pytest

pytest.importorskip("watchlight_engine")

from watchlight import AuditTrailUnreadable, CounterSourceError, Watchlight

READ = 'permit(principal, action == Action::"read", resource);'
CAP = 'forbid(principal, action == Action::"read", resource) when { context.reads_this_hour >= 100 };'
USER = 'User::"u1"'


def _gov(tmp_path, **kw):
    g = Watchlight(agent="csrc-agent", audit_dir=str(tmp_path / ".watchlight"), **kw)
    g.allow(READ, "read")
    return g


def _seed_local(g, n=3):
    for _ in range(n):
        g.authorize(action="read", principal=USER, resource="doc/1")


# ── no source configured ────────────────────────────────────────────────────


def test_counters_still_folds_the_local_file(tmp_path):
    g = _gov(tmp_path)
    _seed_local(g)
    c = g.counters(principal=USER, intent="read", window="1h")
    assert c["count"] == 3
    assert c["source"] == "local"
    assert (c["records"], c["skipped"], c["truncated"]) == (3, 0, False)


def test_counters_async_reads_the_same_local_file(tmp_path):
    g = _gov(tmp_path)
    _seed_local(g)
    c = asyncio.run(g.counters_async(principal=USER, intent="read", window="1h"))
    assert c["count"] == 3 and c["source"] == "local"


# ── a synchronous source ────────────────────────────────────────────────────


def test_a_source_replaces_the_local_count(tmp_path):
    seen = []

    def source(query):
        seen.append(query)
        return 42

    g = _gov(tmp_path, counter_source=source)
    _seed_local(g)
    c = g.counters(principal=USER, intent="read", resource="doc/1", window="15m", outcome="all")
    assert c["count"] == 42
    assert c["source"] == "external"
    # `records` / `skipped` describe the local scan that did not happen.
    assert (c["records"], c["skipped"], c["truncated"]) == (0, 0, False)
    q = seen[0]
    assert (q["principal"], q["intent"], q["resource"], q["outcome"]) == (USER, "read", "doc/1", "all")
    assert q["window"]["seconds"] == 900
    start = datetime.datetime.fromisoformat(q["window"]["start"].replace("Z", "+00:00"))
    end = datetime.datetime.fromisoformat(q["window"]["end"].replace("Z", "+00:00"))
    assert (end - start).total_seconds() == 900


def test_defaults_are_applied_before_the_source_sees_them(tmp_path):
    seen = []
    g = _gov(tmp_path, counter_source=lambda q: seen.append(q) or 0)
    c = g.counters(principal=USER)
    assert seen[0]["intent"] is None and seen[0]["resource"] is None
    assert seen[0]["window"]["seconds"] == 3600 and seen[0]["outcome"] == "allowed"
    assert c["count"] == 0


def test_a_quota_policy_denies_on_the_durable_count(tmp_path):
    g = _gov(tmp_path, counter_source=lambda q: 100)
    g.allow(CAP, "cap")
    c = g.counters(principal=USER, intent="read")
    d = g.authorize(
        action="read", principal=USER, resource="doc/1", context={"reads_this_hour": c["count"]}
    )
    assert d["decision"] == "Deny"


# ── an asynchronous source ──────────────────────────────────────────────────


def test_the_sync_path_refuses_an_async_source_by_name(tmp_path):
    async def source(query):
        return 7

    g = _gov(tmp_path, counter_source=source)
    with pytest.raises(CounterSourceError) as exc:
        g.counters(principal=USER)
    assert "counters_async" in str(exc.value)


def test_counters_async_reads_an_async_source(tmp_path):
    async def source(query):
        return 7

    g = _gov(tmp_path, counter_source=source)
    c = asyncio.run(g.counters_async(principal=USER))
    assert c["count"] == 7 and c["source"] == "external"


def test_a_refused_coroutine_is_closed(tmp_path, recwarn):
    async def source(query):
        return 7

    g = _gov(tmp_path, counter_source=source)
    with pytest.raises(CounterSourceError):
        g.counters(principal=USER)
    assert not [w for w in recwarn if "never awaited" in str(w.message)]


# ── fail closed ─────────────────────────────────────────────────────────────


def test_a_raising_source_never_falls_back_to_the_local_file(tmp_path):
    def source(query):
        raise RuntimeError("store down")

    g = _gov(tmp_path, counter_source=source)
    _seed_local(g)
    with pytest.raises(CounterSourceError) as exc:
        g.counters(principal=USER)
    assert "store down" not in str(exc.value)  # fixed, value-free message
    assert isinstance(exc.value.__cause__, RuntimeError)


def test_a_raising_async_source_fails_closed(tmp_path):
    async def source(query):
        raise RuntimeError("store down")

    g = _gov(tmp_path, counter_source=source)
    with pytest.raises(CounterSourceError):
        asyncio.run(g.counters_async(principal=USER))


@pytest.mark.parametrize("value", [-1, 1.5, float("nan"), "12", None, True, {"count": 12}])
def test_a_non_count_return_is_refused(tmp_path, value):
    g = _gov(tmp_path, counter_source=lambda q: value)
    with pytest.raises(CounterSourceError):
        g.counters(principal=USER)


def test_validation_happens_before_the_source_is_called(tmp_path):
    calls = []
    g = _gov(tmp_path, counter_source=lambda q: calls.append(q) or 1)
    with pytest.raises(TypeError):
        g.counters(principal="")
    with pytest.raises(ValueError):
        g.counters(principal=USER, window="nope")
    with pytest.raises(ValueError):
        g.counters(principal=USER, outcome="some")
    assert calls == []


def test_an_unreadable_local_file_does_not_affect_a_sourced_count(tmp_path):
    g = _gov(tmp_path, counter_source=lambda q: 5)
    (tmp_path / ".watchlight").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".watchlight" / "audit.jsonl").mkdir()  # a directory is unreadable
    assert g.counters(principal=USER)["count"] == 5
    plain = Watchlight(agent="csrc-agent", audit_dir=str(tmp_path / ".watchlight"))
    with pytest.raises(AuditTrailUnreadable):
        plain.counters(principal=USER)
