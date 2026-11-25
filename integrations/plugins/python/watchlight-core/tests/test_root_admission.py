"""The shared root admission.

Plugins' root paths call :func:`reserve_root` before anything is sent. These
tests pin its rules directly; each plugin's suite drives them through the
framework (``watchlight-deepagents/tests/test_nested_root_escape.py``).
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from watchlight_core import (
    DeclaredRootRefused,
    NestedRunEscapedError,
    RunHandleState,
    SpawnRefusedRootRunError,
    root_admission,
)
from watchlight_core.errors import DECLARED_ROOT_INVALID


class _Handle:
    def __init__(self, root: str | None = None) -> None:
        self._completed = False
        self.state = RunHandleState.ACTIVE
        self.root_execution_id = root or f"exec_{uuid.uuid4()}"


def _open_root(handle: Any) -> None:
    assert root_admission.reserve_root("a", declared=False, hint="") is None
    root_admission.release_root(handle)


def test_an_implicit_root_opens_when_nothing_is_live() -> None:
    _open_root(_Handle())


def test_an_implicit_root_is_refused_while_a_run_is_live() -> None:
    live = _Handle()
    _open_root(live)
    with pytest.raises(NestedRunEscapedError) as exc:
        root_admission.reserve_root("b", declared=False, hint="the hint")
    assert exc.value.reason == "implicit_root_while_run_live"
    assert "the hint" in str(exc.value)


def test_a_dropped_handle_does_not_pin_a_run_as_live() -> None:
    _open_root(_Handle())
    _open_root(_Handle())


def test_an_implicit_root_is_refused_while_another_is_opening() -> None:
    assert root_admission.reserve_root("a", declared=False, hint="") is None
    with pytest.raises(NestedRunEscapedError):
        root_admission.reserve_root("b", declared=False, hint="")
    # The first open failed: nothing is live any more.
    root_admission.release_root(None)
    assert root_admission.reserve_root("b", declared=False, hint="") is None


def test_an_ended_run_is_not_live() -> None:
    handle = _Handle()
    _open_root(handle)
    handle._completed = True
    _open_root(_Handle())


@pytest.mark.parametrize("state", [RunHandleState.QUARANTINED, RunHandleState.SEVERED])
def test_a_quarantined_or_severed_run_is_not_live(state: RunHandleState) -> None:
    handle = _Handle()
    _open_root(handle)
    handle.state = state
    _open_root(_Handle())


def test_a_declared_root_gets_the_live_root_ids() -> None:
    first, second = _Handle(), _Handle()
    _open_root(first)
    root_admission.register_run(second)
    ids = root_admission.reserve_root("b", declared=True, hint="")
    assert ids == sorted({first.root_execution_id, second.root_execution_id})
    root_admission.release_root(None)


def test_a_child_shares_its_roots_id() -> None:
    root = _Handle()
    _open_root(root)
    root_admission.register_run(_Handle(root.root_execution_id))
    assert root_admission.reserve_root("b", declared=True, hint="") == [root.root_execution_id]
    root_admission.release_root(None)


def test_more_live_roots_than_wl_apdp_accepts_is_refused() -> None:
    handles = [_Handle() for _ in range(root_admission.MAX_DECLARED_LIVE_ROOTS + 1)]
    for handle in handles:
        root_admission.register_run(handle)
    with pytest.raises(DeclaredRootRefused) as exc:
        root_admission.reserve_root("b", declared=True, hint="")
    assert exc.value.code == DECLARED_ROOT_INVALID
    handles[0]._completed = True
    assert len(root_admission.reserve_root("b", declared=True, hint="")) == 64
    root_admission.release_root(None)


def test_a_refused_spawn_holds_only_while_its_tree_is_live() -> None:
    root = _Handle()
    _open_root(root)
    root_admission.record_refused_spawn("child", root)
    with pytest.raises(SpawnRefusedRootRunError):
        root_admission.reserve_root("child", declared=True, hint="")
    # Another agent may still be declared.
    assert root_admission.reserve_root("other", declared=True, hint="") is not None
    root_admission.release_root(None)
    root._completed = True
    assert root_admission.reserve_root("child", declared=True, hint="") == []
    root_admission.release_root(None)


def test_root_run_marks_the_context_and_refuses_inside_a_live_run() -> None:
    class _Live(root_admission.RootRun):
        def _in_live_run(self) -> bool:
            return True

    assert not root_admission.declared_root_requested()
    with root_admission.RootRun():
        assert root_admission.declared_root_requested()
    assert not root_admission.declared_root_requested()
    with pytest.raises(NestedRunEscapedError) as exc:
        with _Live():
            raise AssertionError("entering a live run must raise")
    assert exc.value.reason == "declared_root_inside_live_run"
    assert not root_admission.declared_root_requested()
