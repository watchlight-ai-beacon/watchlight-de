"""Tests for the PlanReActPlanner output parser."""

from watchlight_adk.plan_parser import parse_planning_block, governance_mode


# ─── Happy path ──────────────────────────────────────────────────────


def test_parses_fenced_json_inside_planning_block():
    text = """
    Some thinking before...

    /*PLANNING*/
    Here's my plan:

    ```json
    {
      "plan": [
        {"step_id": "s1", "action": "get_market_data", "resource_pattern": "MarketData::*"},
        {"step_id": "s2", "action": "summarize", "resource_pattern": "*"}
      ]
    }
    ```
    /*REASONING*/
    """
    plan = parse_planning_block(text)
    assert plan is not None
    assert len(plan) == 2
    assert plan[0]["action"] == "get_market_data"
    assert plan[0]["resource_pattern"] == "MarketData::*"
    assert plan[1]["step_id"] == "s2"


def test_parses_bare_json_object():
    text = """
    /*PLANNING*/
    {"plan": [{"action": "read", "resource_pattern": "Document::*"}]}
    """
    plan = parse_planning_block(text)
    assert plan is not None
    assert len(plan) == 1
    assert plan[0]["action"] == "read"
    # step_id auto-filled
    assert plan[0]["step_id"] == "s1"


def test_parses_bare_json_array():
    text = """
    /*PLANNING*/
    [{"action": "search", "resource_pattern": "*"}]
    """
    plan = parse_planning_block(text)
    assert plan is not None
    assert len(plan) == 1
    assert plan[0]["action"] == "search"


def test_resource_field_alias():
    """Models sometimes emit `resource` instead of `resource_pattern`."""
    text = """
    /*PLANNING*/
    ```json
    [{"action": "read", "resource": "Document::x"}]
    ```
    """
    plan = parse_planning_block(text)
    assert plan is not None
    assert plan[0]["resource_pattern"] == "Document::x"


def test_tolerates_trailing_commas():
    text = """
    /*PLANNING*/
    ```json
    {"plan": [
        {"action": "read", "resource_pattern": "x",},
    ]}
    ```
    """
    plan = parse_planning_block(text)
    assert plan is not None
    assert plan[0]["action"] == "read"


def test_finds_json_outside_planning_marker():
    """Some PlanReActPlanner configs emit the JSON outside the marker."""
    text = """
    Plan summary.

    ```json
    [{"step_id": "s1", "action": "read", "resource_pattern": "*"}]
    ```
    """
    plan = parse_planning_block(text)
    assert plan is not None
    assert len(plan) == 1


# ─── Failure modes / edge cases ──────────────────────────────────────


def test_returns_none_when_no_plan():
    assert parse_planning_block("Just an answer with no planning block.") is None


def test_returns_none_on_unparseable():
    text = "/*PLANNING*/ this is not json at all */"
    assert parse_planning_block(text) is None


def test_empty_text_returns_none():
    assert parse_planning_block("") is None
    assert parse_planning_block(None) is None  # type: ignore[arg-type]


def test_drops_steps_missing_action():
    text = """
    /*PLANNING*/
    ```json
    [{"step_id": "s1"}, {"action": "read", "resource_pattern": "x"}]
    ```
    """
    plan = parse_planning_block(text)
    assert plan is not None
    assert len(plan) == 1
    assert plan[0]["action"] == "read"


def test_drops_non_dict_items():
    text = """
    /*PLANNING*/
    ```json
    ["a string", {"action": "read", "resource_pattern": "x"}]
    ```
    """
    plan = parse_planning_block(text)
    assert plan is not None
    assert len(plan) == 1


def test_normalises_defaults():
    text = """
    /*PLANNING*/
    ```json
    [{"action": "read"}]
    ```
    """
    plan = parse_planning_block(text)
    assert plan is not None
    assert plan[0]["resource_pattern"] == "*"
    assert plan[0]["estimated_risk"] == "medium"
    assert plan[0]["depends_on"] == []


def test_preserves_provided_fields():
    text = """
    /*PLANNING*/
    ```json
    [{
      "step_id": "custom_id",
      "action": "execute",
      "resource_pattern": "Tool::trade",
      "estimated_risk": "high",
      "depends_on": ["s0"],
      "reasoning": "needed for follow-up"
    }]
    ```
    """
    plan = parse_planning_block(text)
    assert plan is not None
    assert plan[0]["step_id"] == "custom_id"
    assert plan[0]["estimated_risk"] == "high"
    assert plan[0]["depends_on"] == ["s0"]
    assert plan[0]["reasoning"] == "needed for follow-up"


def test_case_insensitive_planning_marker():
    text = """
    /*planning*/
    ```json
    [{"action": "read", "resource_pattern": "x"}]
    ```
    """
    plan = parse_planning_block(text)
    assert plan is not None


def test_handles_multiple_json_blocks_takes_first_plan():
    """If multiple JSON blocks appear, take the first that looks like a plan."""
    text = """
    /*PLANNING*/
    ```json
    {"unrelated": true}
    ```

    ```json
    [{"action": "read", "resource_pattern": "x"}]
    ```
    """
    plan = parse_planning_block(text)
    assert plan is not None
    assert plan[0]["action"] == "read"


# ─── Governance mode ─────────────────────────────────────────────────


def test_governance_mode_default_is_strict(monkeypatch):
    monkeypatch.delenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", raising=False)
    assert governance_mode() == "strict"


def test_governance_mode_strict(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "strict")
    assert governance_mode() == "strict"


def test_governance_mode_unknown_falls_back_to_strict(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "yolo")
    assert governance_mode() == "strict"


def test_governance_mode_case_insensitive(monkeypatch):
    monkeypatch.setenv("WATCHLIGHT_PLAN_GOVERNANCE_MODE", "STRICT")
    assert governance_mode() == "strict"
