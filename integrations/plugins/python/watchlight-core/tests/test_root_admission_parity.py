"""The shared root-admission cases, run against watchlight_core.

``tests/fixtures/root_admission_cases.json`` is the one rule for both SDKs;
``watchlight-agent-sdk-ts/tests/root-admission-parity.test.ts`` runs the
same cases against the TypeScript SDK.
"""

from __future__ import annotations

import json
import pathlib
import uuid
from typing import Any, Dict, List, Optional

import httpx
import pytest

from watchlight_core import ApdpClient, DeclaredRootRefused, NestedRunEscapedError
from watchlight_core import root_admission
from watchlight_core.errors import (
    DECLARED_ROOT_FORBIDDEN,
    DECLARED_ROOT_INVALID,
    DECLARED_ROOT_UNSUPPORTED,
)

CASES = json.loads(
    (pathlib.Path(__file__).parent / "fixtures" / "root_admission_cases.json").read_text()
)
AGENT = "11111111-1111-4111-8111-111111111111"


class _Run:
    """What admission reads from a run handle."""

    def __init__(self, root: str) -> None:
        self.root_execution_id = root
        self.state = None
        self._completed = False


@pytest.fixture(autouse=True)
def _fresh_registry():
    with root_admission._lock:
        saved = (set(root_admission._runs), root_admission._pending_roots, set(root_admission._refused_spawns))
        root_admission._runs.clear()
        root_admission._pending_roots = 0
        root_admission._refused_spawns.clear()
    yield
    with root_admission._lock:
        root_admission._runs.clear()
        root_admission._runs.update(saved[0])
        root_admission._pending_roots = saved[1]
        root_admission._refused_spawns.clear()
        root_admission._refused_spawns.update(saved[2])


def test_codes_and_bound_match() -> None:
    assert root_admission.MAX_DECLARED_LIVE_ROOTS == CASES["max_declared_live_roots"]
    assert CASES["codes"] == {
        "forbidden": DECLARED_ROOT_FORBIDDEN,
        "invalid": DECLARED_ROOT_INVALID,
        "unsupported": DECLARED_ROOT_UNSUPPORTED,
    }


@pytest.mark.parametrize("scenario", CASES["scenarios"], ids=lambda s: s["name"])
def test_scenario(scenario: Dict[str, Any]) -> None:
    runs: Dict[str, _Run] = {}
    keep: List[_Run] = []  # the registry is weak
    for step in scenario["steps"]:
        if "register" in step:
            run = _Run(step["root"])
            runs[step["register"]] = run
            root_admission.register_run(run)
        elif "register_many" in step:
            for i in range(step["register_many"]):
                run = _Run(f"exec_many_{i}")
                keep.append(run)
                root_admission.register_run(run)
        elif "end" in step:
            runs[step["end"]]._completed = True
        elif "refuse_spawn" in step:
            root_admission.record_refused_spawn(step["refuse_spawn"], _Run(step["root"]))
        elif "release" in step:
            root_admission.release_root(None)
        else:
            reserve = lambda: root_admission.reserve_root(  # noqa: E731
                step["reserve"], declared=step["declared"], hint="hint"
            )
            if "refused" in step:
                with pytest.raises((NestedRunEscapedError, DeclaredRootRefused)) as exc:
                    reserve()
                err = exc.value
                code = err.reason if isinstance(err, NestedRunEscapedError) else err.code
                assert code == step["refused"]
            elif "admitted_count" in step:
                assert len(reserve() or []) == step["admitted_count"]
            else:
                assert reserve() == step["admitted"]


def _client(status: int, answer: Dict[str, Any]) -> ApdpClient:
    apdp = ApdpClient("https://apdp.test")
    apdp._probed = True
    apdp._client = httpx.AsyncClient(
        base_url="https://apdp.test",
        transport=httpx.MockTransport(lambda _req: httpx.Response(status, json=answer)),
    )
    return apdp


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES["session_refusals"], ids=lambda c: f"{c['status']}-{c['code']}")
async def test_session_refusal(case: Dict[str, Any]) -> None:
    apdp = _client(case["status"], case["body"])
    if case["code"] is None:
        assert await apdp.create_session(agent_id=AGENT, declared_root=["exec_a"]) is None
        return
    with pytest.raises(DeclaredRootRefused) as exc:
        await apdp.create_session(agent_id=AGENT, declared_root=["exec_a"])
    assert exc.value.code == case["code"]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", CASES["session_confirmations"], ids=lambda c: repr(c.get("echo", "absent")))
async def test_session_confirmation(case: Dict[str, Any]) -> None:
    answer: Dict[str, Any] = {
        "session": {"id": "ses_x", "agent_id": AGENT},
        "session_token": "sst_" + uuid.uuid4().hex,
        "execution_id": "exec_x",
    }
    if not case.get("absent"):
        answer["declared_root"] = case["echo"]
    info: Optional[Any] = await _client(200, answer).create_session(agent_id=AGENT, declared_root=[])
    assert info is not None and info.declared_root is case["confirmed"]
