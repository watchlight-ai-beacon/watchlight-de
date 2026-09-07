"""The `on_result` deadline on `@govern.tool` (Python), mirroring the TS suite.

The regression this file was written for: an egress hook had no deadline, so a
hook that took 12 s released the payload after 12 s while the record type said
``withheld`` meant "the hook raised, or outran its deadline". The deadline now
exists, and this pins what it does — and what it deliberately refuses to do on a
synchronous body, where Python cannot interrupt the hook.

Every test uses a SMALL explicit deadline (tens of ms); the 8 s default is
asserted as a value, never waited on. Runs the real watchlight_engine.
"""
import asyncio
import json
import time

import pytest

from watchlight import (
    DEFAULT_ON_RESULT_TIMEOUT_MS,
    EGRESS_TIMEOUT_MESSAGE,
    SYNC_TIMEOUT_MESSAGE,
    EgressTimeout,
    Watchlight,
)

READ = 'permit(principal, action == Action::"read", resource);'


def _records(tmp_path):
    """Every audit record written by a governor from :func:`_gov`."""
    path = tmp_path / "audit.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _gov(tmp_path):
    g = Watchlight(agent="deadline-agent", audit_dir=str(tmp_path))
    g.allow(READ, "read")
    return g


def _egress(tmp_path):
    return [
        r
        for r in (json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines())
        if r.get("event") == "egress"
    ]


def test_hook_past_its_deadline_withholds_the_payload(tmp_path):
    g = _gov(tmp_path)

    async def slow(result, info):
        await asyncio.sleep(2)
        return "TOO-LATE"

    @g.tool("read", on_result=slow, on_result_timeout_ms=30)
    async def leaky():
        return "SECRET"

    async def main():
        started = asyncio.get_event_loop().time()
        with pytest.raises(EgressTimeout) as exc:
            await leaky()
        return asyncio.get_event_loop().time() - started, exc.value

    elapsed, err = asyncio.run(main())
    # It returns AT the deadline, not at the hook's own pace.
    assert elapsed < 1.0
    # Value-free and safe to log: a fixed message, nothing from the payload.
    assert str(err) == EGRESS_TIMEOUT_MESSAGE
    assert "SECRET" not in str(err)

    egress = _egress(tmp_path)
    assert len(egress) == 1
    assert egress[0]["withheld"] is True and egress[0]["replaced"] is False
    assert egress[0]["resource"] == "tool/leaky" and egress[0]["decision_id"]
    assert "SECRET" not in json.dumps(egress) and "TOO-LATE" not in json.dumps(egress)


def test_hook_within_its_deadline_is_unaffected(tmp_path):
    g = _gov(tmp_path)

    async def quick_passthrough(result, info):
        await asyncio.sleep(0)

    async def quick_replace(result, info):
        await asyncio.sleep(0)
        return "REDACTED"

    @g.tool("read", on_result=quick_passthrough, on_result_timeout_ms=5000)
    async def passthrough():
        return "PAYLOAD"

    @g.tool("read", on_result=quick_replace, on_result_timeout_ms=5000)
    async def replacing():
        return "PAYLOAD"

    async def main():
        return await passthrough(), await replacing()

    assert asyncio.run(main()) == ("PAYLOAD", "REDACTED")
    egress = _egress(tmp_path)
    assert [r["replaced"] for r in egress] == [False, True]
    assert all("withheld" not in r for r in egress)


def test_a_late_hook_is_cancelled_and_can_never_release_the_payload(tmp_path):
    """The deadline is not just a caller-side give-up: the hook is cancelled, so
    it cannot complete later and hand the payload on."""
    g = _gov(tmp_path)
    reached_the_end = []

    async def late(result, info):
        await asyncio.sleep(0.4)
        reached_the_end.append(result)  # must never run
        return "TOO-LATE"

    @g.tool("read", on_result=late, on_result_timeout_ms=20)
    async def leaky():
        return "SECRET"

    async def main():
        with pytest.raises(EgressTimeout):
            await leaky()
        before = len(asyncio.all_tasks())
        # Well past the hook's own sleep: a surviving hook would finish here.
        await asyncio.sleep(0.6)
        return before, len(asyncio.all_tasks())

    before, after = asyncio.run(main())
    assert reached_the_end == []          # cancelled, not merely abandoned
    assert before == after == 1           # no hook task outlives the call
    assert len(_egress(tmp_path)) == 1    # and it is never audited twice


def test_a_timeout_and_a_raise_agree(tmp_path):
    """The deadline reuses the refusal a raising hook already had: the call
    raises, the payload is not returned, one withheld record — and the trail
    records the disposition, not the cause."""
    g = _gov(tmp_path)

    async def raiser(result, info):
        raise RuntimeError("screen failed")

    async def slow(result, info):
        await asyncio.sleep(2)

    @g.tool("read", on_result=raiser)
    async def a():
        return "SECRET"

    @g.tool("read", on_result=slow, on_result_timeout_ms=20)
    async def b():
        return "SECRET"

    async def main():
        with pytest.raises(RuntimeError, match="screen failed"):
            await a()
        with pytest.raises(EgressTimeout):
            await b()

    asyncio.run(main())
    egress = _egress(tmp_path)
    assert len(egress) == 2
    assert all(r["withheld"] is True and r["replaced"] is False for r in egress)
    shape = [{k: v for k, v in r.items() if k not in ("ts", "decision_id", "resource")} for r in egress]
    assert shape[0] == shape[1]


def test_a_hook_that_raises_its_own_timeout_is_not_reported_as_the_deadline(tmp_path):
    """A hook whose own work times out (a classifier call, say) keeps its own
    error — our deadline is not blamed for it."""
    g = _gov(tmp_path)

    async def hook(result, info):
        raise TimeoutError("the classifier timed out")

    @g.tool("read", on_result=hook, on_result_timeout_ms=5000)
    async def leaky():
        return "SECRET"

    async def main():
        with pytest.raises(TimeoutError) as exc:
            await leaky()
        return exc.value

    err = asyncio.run(main())
    assert not isinstance(err, EgressTimeout)
    assert str(err) == "the classifier timed out"
    assert _egress(tmp_path)[0]["withheld"] is True


def test_the_default_is_eight_seconds_and_applies_without_being_asked_for(tmp_path):
    g = _gov(tmp_path)
    assert DEFAULT_ON_RESULT_TIMEOUT_MS == 8000

    # Not waited on: the hook is fast, and the assertion is that a tool with no
    # `on_result_timeout_ms` still goes through the deadline-bearing path.
    seen = {}

    async def hook(result, info):
        seen["ran"] = True

    @g.tool("read", on_result=hook)
    async def fast():
        return "PAYLOAD"

    assert asyncio.run(fast()) == "PAYLOAD"
    assert seen["ran"] is True


@pytest.mark.parametrize("bad", [0, -1, float("inf"), float("nan"), True, "5000", object()])
def test_a_deadline_that_cannot_bound_anything_is_refused(tmp_path, bad):
    """There is no value that switches the deadline off — the unbounded hook is
    the defect being closed, so it is not reachable by passing 0 or inf."""
    g = _gov(tmp_path)

    async def hook(result, info):
        return None

    with pytest.raises(ValueError, match="positive number of milliseconds"):

        @g.tool("read", on_result=hook, on_result_timeout_ms=bad)
        async def leaky():
            return "SECRET"


def test_a_deliberately_long_deadline_is_allowed(tmp_path):
    """The opt-out for a genuinely long hook: a larger, explicit number."""
    g = _gov(tmp_path)

    async def hook(result, info):
        return None

    @g.tool("read", on_result=hook, on_result_timeout_ms=300_000)
    async def slow_but_wanted():
        return "PAYLOAD"

    assert asyncio.run(slow_but_wanted()) == "PAYLOAD"


def test_a_deadline_on_a_synchronous_body_withholds_the_payload(tmp_path):
    """Asking for a deadline on a synchronous body moves the hook to a worker
    thread so the calling thread can hold the clock. Python still cannot
    interrupt the hook, so what is bounded is the decision to RELEASE: the
    payload is withheld and the hook runs on to nothing.

    This combination used to raise, which left the shape most likely to carry a
    slow hook — a synchronous framework tool — as the one that could not bound
    it."""
    g = _gov(tmp_path)

    @g.tool("read", on_result=lambda result, info: time.sleep(2), on_result_timeout_ms=100)
    def sync_body():
        return "SECRET"

    started = time.monotonic()
    with pytest.raises(EgressTimeout):
        sync_body()
    assert time.monotonic() - started < 1.0, "the deadline did not fire"

    records = _records(tmp_path)
    egress = [r for r in records if r.get("event") == "egress"]
    assert len(egress) == 1, "exactly one egress record per call"
    assert egress[0]["withheld"] is True and egress[0]["replaced"] is False
    assert "SECRET" not in json.dumps(records)


def test_a_late_synchronous_hook_cannot_release_the_payload(tmp_path):
    """The abandoned hook keeps running — Python cannot kill it — so its late
    return value must be discarded rather than released."""
    g = _gov(tmp_path)
    finished = []

    def slow(result, info):
        time.sleep(0.4)
        finished.append(result)
        return "LATE"

    @g.tool("read", on_result=slow, on_result_timeout_ms=80)
    def sync_body():
        return "SECRET"

    with pytest.raises(EgressTimeout):
        sync_body()
    time.sleep(0.6)  # let the abandoned hook finish
    assert finished, "the hook did keep running"
    records = _records(tmp_path)
    assert len([r for r in records if r.get("event") == "egress"]) == 1
    assert "LATE" not in json.dumps(records) and "SECRET" not in json.dumps(records)


def test_a_bounded_synchronous_hook_inside_its_deadline_still_replaces(tmp_path):
    g = _gov(tmp_path)

    @g.tool("read", on_result=lambda result, info: "REDACTED", on_result_timeout_ms=2_000)
    def sync_body():
        return "SECRET"

    assert sync_body() == "REDACTED"


def test_a_raising_bounded_synchronous_hook_still_fails_closed(tmp_path):
    g = _gov(tmp_path)

    def boom(result, info):
        raise RuntimeError("hook failed")

    @g.tool("read", on_result=boom, on_result_timeout_ms=2_000)
    def sync_body():
        return "SECRET"

    with pytest.raises(RuntimeError):
        sync_body()
    egress = [r for r in _records(tmp_path) if r.get("event") == "egress"]
    assert egress and egress[-1]["withheld"] is True


def test_a_synchronous_body_without_a_deadline_still_works_as_before(tmp_path):
    g = _gov(tmp_path)

    @g.tool("read", on_result=lambda result, info: "REDACTED")
    def sync_body():
        return "SECRET"

    assert sync_body() == "REDACTED"
    assert _egress(tmp_path)[0]["replaced"] is True
