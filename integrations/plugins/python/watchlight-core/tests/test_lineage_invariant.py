"""Unit tests for the sub-agent lineage continuity invariant (invariant 9).

Added 2026-06-12 as part of PR-LINEAGE — locks in the lineage
stitching fix (lineage continuity section).

Exercises ``_assert_subagent_lineage_continuity`` directly so the
invariant has explicit tests independent of the larger
``run_conformance`` harness.

Mirrors the LangGraph reference implementation at
``watchlight-langgraph/watchlight_langgraph/plugin.py``.
"""

from typing import Any, Dict, List

import pytest

from watchlight_core_testing.conformance import _assert_subagent_lineage_continuity
from watchlight_core_testing import ConformanceFailure


def _event(
    *,
    event_type: str,
    execution_id: str,
    root_execution_id: str = None,
    parent_execution_id: str = None,
    payload: Dict[str, Any] = None,
) -> Dict[str, Any]:
    ev: Dict[str, Any] = {
        "event_id": f"evt_{execution_id}_{event_type}",
        "event_type": event_type,
        "timestamp": "2026-06-12T00:00:00Z",
        "execution_id": execution_id,
        "agent_id": f"agent-{execution_id}",
        "payload": payload or {},
    }
    if root_execution_id is not None:
        ev["root_execution_id"] = root_execution_id
    if parent_execution_id is not None:
        ev["parent_execution_id"] = parent_execution_id
    return ev


def _spawn_event(
    *,
    parent_execution_id: str,
    child_execution_id: str,
    root_execution_id: str = None,
) -> Dict[str, Any]:
    payload = {
        "spawned_agent": {"principal_type": "agent", "id": f"agent-{child_execution_id}"},
        "spawner": {"principal_type": "agent", "id": f"agent-{parent_execution_id}"},
        "child_execution_id": child_execution_id,
    }
    return _event(
        event_type="agent_spawn_observed",
        execution_id=parent_execution_id,
        root_execution_id=root_execution_id,
        payload=payload,
    )


class TestLineageInvariant:
    def test_passes_vacuously_when_no_spawn_observed(self):
        events: List[Dict[str, Any]] = [
            _event(
                event_type="execution_started",
                execution_id="exec_root",
                root_execution_id="exec_root",
            ),
            _event(
                event_type="tool_call_observed",
                execution_id="exec_root",
                root_execution_id="exec_root",
            ),
        ]
        # No agent_spawn_observed → invariant 9 passes vacuously.
        _assert_subagent_lineage_continuity(events)

    def test_passes_at_depth_1_when_child_carries_root_and_parent(self):
        events: List[Dict[str, Any]] = [
            _event(
                event_type="execution_started",
                execution_id="exec_root",
                root_execution_id="exec_root",
            ),
            _spawn_event(
                parent_execution_id="exec_root",
                child_execution_id="exec_child",
                root_execution_id="exec_root",
            ),
            _event(
                event_type="execution_started",
                execution_id="exec_child",
                root_execution_id="exec_root",
                parent_execution_id="exec_root",
            ),
            _event(
                event_type="tool_call_observed",
                execution_id="exec_child",
                root_execution_id="exec_root",
                parent_execution_id="exec_root",
            ),
        ]
        _assert_subagent_lineage_continuity(events)

    def test_fails_when_child_root_does_not_match_workflow_root(self):
        events: List[Dict[str, Any]] = [
            _event(
                event_type="execution_started",
                execution_id="exec_root",
                root_execution_id="exec_root",
            ),
            _spawn_event(
                parent_execution_id="exec_root",
                child_execution_id="exec_child",
                root_execution_id="exec_root",
            ),
            # BUG: the child claims itself as root instead of exec_root.
            _event(
                event_type="tool_call_observed",
                execution_id="exec_child",
                root_execution_id="exec_child",
                parent_execution_id="exec_root",
            ),
        ]
        with pytest.raises(ConformanceFailure) as exc:
            _assert_subagent_lineage_continuity(events)
        assert exc.value.args[0] == 9
        assert "root_execution_id" in exc.value.args[1]

    def test_fails_when_child_parent_does_not_match_direct_spawner(self):
        events: List[Dict[str, Any]] = [
            _event(
                event_type="execution_started",
                execution_id="exec_root",
                root_execution_id="exec_root",
            ),
            _spawn_event(
                parent_execution_id="exec_root",
                child_execution_id="exec_child",
                root_execution_id="exec_root",
            ),
            # BUG: child claims a different agent as parent.
            _event(
                event_type="tool_call_observed",
                execution_id="exec_child",
                root_execution_id="exec_root",
                parent_execution_id="exec_someone_else",
            ),
        ]
        with pytest.raises(ConformanceFailure) as exc:
            _assert_subagent_lineage_continuity(events)
        assert exc.value.args[0] == 9
        assert "parent_execution_id" in exc.value.args[1]

    def test_depth_2_grandchild_inherits_root_from_workflow_not_intermediate(self):
        """The load-bearing case: root → A → B. B's events must
        carry root = workflow root (exec_root), NOT exec_A. Without
        this, /lineage renders B's subtree as a separate root.
        """
        events: List[Dict[str, Any]] = [
            _event(
                event_type="execution_started",
                execution_id="exec_root",
                root_execution_id="exec_root",
            ),
            # Root spawns A.
            _spawn_event(
                parent_execution_id="exec_root",
                child_execution_id="exec_A",
                root_execution_id="exec_root",
            ),
            _event(
                event_type="execution_started",
                execution_id="exec_A",
                root_execution_id="exec_root",
                parent_execution_id="exec_root",
            ),
            # A spawns B — the spawn event itself is attributed to A.
            _spawn_event(
                parent_execution_id="exec_A",
                child_execution_id="exec_B",
                root_execution_id="exec_root",
            ),
            # B's events MUST carry root=exec_root, parent=exec_A.
            _event(
                event_type="execution_started",
                execution_id="exec_B",
                root_execution_id="exec_root",
                parent_execution_id="exec_A",
            ),
            _event(
                event_type="tool_call_observed",
                execution_id="exec_B",
                root_execution_id="exec_root",
                parent_execution_id="exec_A",
            ),
        ]
        # Should pass.
        _assert_subagent_lineage_continuity(events)

    def test_depth_2_grandchild_fails_if_root_collapses_to_intermediate(self):
        """The bug shape: B claims A as its root instead of the
        workflow root.
        """
        events: List[Dict[str, Any]] = [
            _event(
                event_type="execution_started",
                execution_id="exec_root",
                root_execution_id="exec_root",
            ),
            _spawn_event(
                parent_execution_id="exec_root",
                child_execution_id="exec_A",
                root_execution_id="exec_root",
            ),
            _event(
                event_type="execution_started",
                execution_id="exec_A",
                root_execution_id="exec_root",
                parent_execution_id="exec_root",
            ),
            _spawn_event(
                parent_execution_id="exec_A",
                child_execution_id="exec_B",
                root_execution_id="exec_root",
            ),
            # BUG: B reports its root as A instead of exec_root.
            _event(
                event_type="tool_call_observed",
                execution_id="exec_B",
                root_execution_id="exec_A",
                parent_execution_id="exec_A",
            ),
        ]
        with pytest.raises(ConformanceFailure) as exc:
            _assert_subagent_lineage_continuity(events)
        assert exc.value.args[0] == 9
