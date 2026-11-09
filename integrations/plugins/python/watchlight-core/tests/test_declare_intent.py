"""Tests for the synthetic ``watchlight.declare_intent`` tool
contract and its plumbing into :class:`BaseRunHandle`.

Six load-bearing tests mirror the per-plugin invariants the
implementation guide lists (in order):

1. ``greenfield_mode_injects_synthetic_tool_at_construction`` — the
   ``should_inject_synthetic_tool`` predicate fires for greenfield
   and only greenfield.
2. ``brownfield_mode_does_not_inject_synthetic_tool`` — mirror.
3. ``declare_intent_call_stamps_provenance_to_declared`` — the
   handle's ``_intent_provenance`` flips to ``DECLARED`` and the
   stored objective matches the (truncated) input.
4. ``declare_intent_truncates_objective_to_256_bytes`` — the
   ``truncate_intent_objective`` helper byte-truncates without
   splitting a UTF-8 codepoint.
5. ``synthetic_tool_call_bypasses_authorize`` — handled by the
   plugin layer (not BaseRunHandle); covered as a unit test on the
   ``is_declare_intent_tool_call`` predicate the plugins use as the
   short-circuit gate.
6. ``subsequent_authorize_action_after_declare_intent_carries_declared_intent``
   — load-bearing integration: after ``declare_intent`` is processed,
   the next ``authorize_action`` call auto-injects
   ``intent={"objective": <stored>}`` into the APDP request body, which
   the Cedar projection treats as ``provenance: "declared"``.

The 6th test is the proof that the declare-intent gate closes end-to-end.
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from watchlight_core import (
    ApdpClient,
    BaseRunHandle,
    GovernanceTelemetry,
    IntentProvenance,
    handle_declare_intent_call,
    is_declare_intent_tool_call,
    is_declare_intent_tool_name,
    resolve_intent_enforcement_mode,
    should_inject_synthetic_tool,
    truncate_intent_objective,
)
from watchlight_core.declare_intent import (
    DECLARE_INTENT_TOOL_NAME,
    INTENT_ENFORCEMENT_MODE_ENV_VAR,
    WATCHLIGHT_DECLARE_INTENT_TOOL,
)
from watchlight_core.events_schema import INTENT_OBJECTIVE_MAX_BYTES


# ─── Contract — wire shape ────────────────────────────────────────────


def test_tool_definition_carries_canonical_name():
    """The exported tool definition's ``name`` field must be the
    canonical wire spelling — Cedar templates pattern-match on it."""
    assert WATCHLIGHT_DECLARE_INTENT_TOOL["name"] == "watchlight.declare_intent"


def test_tool_definition_requires_objective_and_category():
    """``objective`` and ``category`` are both required: wl-apdp's intent
    is typed and answers a category-less intent with 422, so an LLM that
    omits either gets a tool-shape validation error from the framework
    before the call ever reaches the plugin."""
    schema = WATCHLIGHT_DECLARE_INTENT_TOOL["parameters"]
    assert schema["required"] == ["objective", "category"]
    assert schema["properties"]["category"]["type"] == "string"
    assert schema["properties"]["objective"]["type"] == "string"
    assert schema["properties"]["objective"]["maxLength"] == INTENT_OBJECTIVE_MAX_BYTES


def test_tool_definition_forbids_extra_properties():
    """``additionalProperties: False`` defends against prompt-injection
    attacks that try to smuggle extra fields into the tool call."""
    schema = WATCHLIGHT_DECLARE_INTENT_TOOL["parameters"]
    assert schema["additionalProperties"] is False


# ─── Predicate — is_declare_intent_tool_name / _call ──────────────────


def test_is_declare_intent_tool_name_matches_canonical():
    assert is_declare_intent_tool_name(DECLARE_INTENT_TOOL_NAME) is True


def test_is_declare_intent_tool_name_case_insensitive():
    assert is_declare_intent_tool_name("Watchlight.Declare_Intent") is True


def test_is_declare_intent_tool_name_rejects_other_names():
    assert is_declare_intent_tool_name("declare_intent") is False
    assert is_declare_intent_tool_name("watchlight.other_tool") is False
    assert is_declare_intent_tool_name(None) is False


def test_is_declare_intent_tool_call_recognises_canonical_shape():
    """Anthropic / OpenAI canonical: ``{"name": "...", "arguments": ...}``."""
    assert is_declare_intent_tool_call(
        {"name": "watchlight.declare_intent", "arguments": {"objective": "x"}}
    ) is True


def test_is_declare_intent_tool_call_recognises_langchain_shape():
    """LangChain convention: top-level ``tool`` key."""
    assert is_declare_intent_tool_call(
        {"tool": "watchlight.declare_intent", "args": {"objective": "x"}}
    ) is True


def test_is_declare_intent_tool_call_recognises_openai_nested_shape():
    """OpenAI legacy: nested under ``function``."""
    assert is_declare_intent_tool_call(
        {"function": {"name": "watchlight.declare_intent", "arguments": "{}"}}
    ) is True


def test_is_declare_intent_tool_call_rejects_other_tool_calls():
    assert is_declare_intent_tool_call(
        {"name": "search_documents", "arguments": {}}
    ) is False
    assert is_declare_intent_tool_call({}) is False
    assert is_declare_intent_tool_call("not_a_dict") is False


# ─── Mode resolution ──────────────────────────────────────────────────


def test_greenfield_mode_injects_synthetic_tool():
    """Injection predicate fires for greenfield."""
    assert should_inject_synthetic_tool("greenfield") is True


def test_brownfield_mode_does_not_inject_synthetic_tool():
    """Brownfield agents never see the synthetic tool. The
    brownfield matrix accepts inferred provenance and the gate would
    be inert."""
    assert should_inject_synthetic_tool("brownfield") is False


def test_unknown_mode_does_not_inject_synthetic_tool():
    """A typo'd env var must NOT auto-inject — it would surprise the
    operator (who set the wrong value) with the synthetic tool in
    their agent's tool list."""
    assert should_inject_synthetic_tool("greefield") is False  # typo
    assert should_inject_synthetic_tool(None) is False
    assert should_inject_synthetic_tool("") is False


def test_resolve_mode_uses_explicit_argument_first(monkeypatch):
    """Constructor kwarg wins over env var."""
    monkeypatch.setenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, "greenfield")
    assert resolve_intent_enforcement_mode(explicit="brownfield") == "brownfield"


def test_resolve_mode_uses_env_var_when_no_explicit(monkeypatch):
    monkeypatch.setenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, "greenfield")
    assert resolve_intent_enforcement_mode() == "greenfield"


def test_resolve_mode_defaults_to_brownfield(monkeypatch):
    """Locked default — onboarding tenants
    see warn-only enforcement until they explicitly opt into greenfield."""
    monkeypatch.delenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, raising=False)
    assert resolve_intent_enforcement_mode() == "brownfield"


def test_resolve_mode_handles_whitespace(monkeypatch):
    monkeypatch.setenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, "  Greenfield  ")
    assert resolve_intent_enforcement_mode() == "greenfield"


def test_resolve_mode_falls_back_on_typo(monkeypatch):
    """Unrecognised env values warn and fall back to brownfield —
    breaking a customer's deployment on an env-var typo would be
    worse than running brownfield with the warn-only matrix."""
    monkeypatch.setenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, "stict")
    assert resolve_intent_enforcement_mode() == "brownfield"


# ─── Truncation ───────────────────────────────────────────────────────


def test_truncate_keeps_short_input_unchanged():
    assert truncate_intent_objective("audit Q3 invoices") == "audit Q3 invoices"


def test_truncate_collapses_whitespace():
    assert (
        truncate_intent_objective("audit\n\tQ3   invoices")
        == "audit Q3 invoices"
    )


def test_truncate_strips_surrounding_whitespace():
    assert truncate_intent_objective("   audit Q3   ") == "audit Q3"


def test_truncate_returns_none_for_empty():
    assert truncate_intent_objective("") is None
    assert truncate_intent_objective("   ") is None
    assert truncate_intent_objective("\n\t") is None


def test_truncate_returns_none_for_non_string():
    assert truncate_intent_objective(None) is None
    assert truncate_intent_objective(42) is None
    assert truncate_intent_objective({"objective": "x"}) is None


def test_declare_intent_truncates_objective_to_256_bytes():
    """Byte cap enforced; never exceeds 256 bytes."""
    long = "a" * 1000
    out = truncate_intent_objective(long)
    assert out is not None
    assert len(out.encode("utf-8")) <= INTENT_OBJECTIVE_MAX_BYTES


def test_truncate_never_splits_multibyte_codepoint():
    """A multi-byte UTF-8 codepoint at the cap boundary must NOT
    appear as a partial sequence in the output. The round-trip
    encode/decode is the invariant."""
    # Each pile-of-poo emoji is 4 bytes — 80 of them = 320 bytes, over
    # the 256 cap. The truncation must drop the partial codepoint at
    # the boundary, not include half of it.
    pile = "\U0001f4a9" * 80
    out = truncate_intent_objective(pile)
    assert out is not None
    encoded = out.encode("utf-8")
    assert len(encoded) <= INTENT_OBJECTIVE_MAX_BYTES
    # Round-trip — proves no partial multi-byte sequence remained.
    assert out == encoded.decode("utf-8")


# ─── handle_declare_intent_call — mutation semantics ──────────────────


@pytest.fixture
def plugin():
    """Minimal :class:`GovernedPlugin` for BaseRunHandle tests."""

    class Plugin(GovernanceTelemetry):
        def __init__(self):
            super().__init__()
            self.apdp = ApdpClient("https://apdp.test")
            self.apdp.submit_plan = AsyncMock()
            self.apdp.preflight_step = AsyncMock()
            self.apdp.authorize = AsyncMock()
            self.apdp.complete_session = AsyncMock(return_value=True)
            self.apdp.terminate_session = AsyncMock(return_value=True)
            self.apdp.publish_events = AsyncMock()
            self.tenant_id = "acme"
            self.log_decisions = False

    return Plugin()


@pytest_asyncio.fixture
async def handle(plugin):
    h = BaseRunHandle(plugin=plugin, agent_uuid="uuid-x", session_id="ses_x")
    # flip the contract-guard flag; the synthetic
    # test handle bypasses the production ``async with`` entry path.
    h._aentered = True
    return h


def test_handle_starts_with_no_declared_intent(handle):
    """A fresh handle has no declared intent — Cedar will treat the
    next authorize_action as having ``provenance: "absent"`` and the
    greenfield-Custodial gate will fire."""
    assert handle.declared_intent_objective is None
    assert handle.declared_intent_provenance is None
    assert handle._intent_objective is None
    assert handle._intent_provenance is None


def test_declare_intent_call_stamps_provenance_to_declared(handle):
    """The load-bearing mutation: provenance flips to
    ``DECLARED``, objective stored verbatim."""
    response = handle_declare_intent_call(
        handle, {"objective": "audit Q3 invoices", "category": "financial_operation"}
    )
    assert response["status"] == "intent_declared"
    assert response["objective"] == "audit Q3 invoices"
    assert response["category"] == "financial_operation"
    assert handle.declared_intent_category == "financial_operation"
    assert handle.declared_intent_objective == "audit Q3 invoices"
    assert handle.declared_intent_provenance == IntentProvenance.DECLARED
    # Public surface mirrors the internal state.
    assert handle._intent_provenance == IntentProvenance.DECLARED


def test_declare_intent_call_truncates_long_objective(handle):
    """Truncation happens at mutation time so the stored value is
    schema-safe and the agent's tool response reflects what was
    actually persisted."""
    long = "x" * 1000
    response = handle_declare_intent_call(handle, {"objective": long, "category": "research"})
    assert response["status"] == "intent_declared"
    assert len(response["objective"].encode("utf-8")) <= INTENT_OBJECTIVE_MAX_BYTES
    assert (
        len(handle.declared_intent_objective.encode("utf-8"))
        <= INTENT_OBJECTIVE_MAX_BYTES
    )


def test_declare_intent_call_with_empty_objective_rejects(handle):
    """An empty objective doesn't mutate the handle — the agent's
    next action will still hit the greenfield-Custodial gate. This
    is fail-closed by design."""
    response = handle_declare_intent_call(handle, {"objective": ""})
    assert response["status"] == "rejected"
    assert handle.declared_intent_objective is None
    assert handle.declared_intent_provenance is None


def test_declare_intent_call_with_missing_objective_rejects(handle):
    response = handle_declare_intent_call(handle, {})
    assert response["status"] == "rejected"
    assert handle.declared_intent_objective is None


def test_declare_intent_call_with_none_arguments_rejects(handle):
    response = handle_declare_intent_call(handle, None)
    assert response["status"] == "rejected"
    assert handle.declared_intent_objective is None


def test_record_declared_intent_convenience(handle):
    """The convenience method on the handle mirrors the contract."""
    stored = handle.record_declared_intent("review the Q3 audit findings", "security_compliance")
    assert stored == "review the Q3 audit findings"
    assert handle.declared_intent_provenance == IntentProvenance.DECLARED


def test_record_declared_intent_raises_on_empty(handle):
    with pytest.raises(ValueError):
        handle.record_declared_intent("", "research")
    assert handle.declared_intent_objective is None


def test_record_declared_intent_without_a_category_raises(handle):
    """A programmatic declaration fails loudly, never silently."""
    with pytest.raises(ValueError, match="category"):
        handle.record_declared_intent("audit the ledger")
    assert handle.declared_intent_objective is None


# ─── Integration — Cedar gate satisfaction (test #6) ──────────────────


@pytest.mark.asyncio
async def test_authorize_action_without_declared_intent_carries_no_intent(
    plugin, handle
):
    """Pre-declare baseline: the APDP request body has no ``intent``
    field, so the Cedar projection falls through to ``provenance:
    "absent"`` — the greenfield-Custodial gate would fire."""
    plugin.apdp.authorize.return_value = {"decision": "Allow"}
    await handle.authorize_action("read", "Document::x")
    call_kwargs = plugin.apdp.authorize.call_args.kwargs
    assert call_kwargs.get("intent") is None


@pytest.mark.asyncio
async def test_subsequent_authorize_action_after_declare_intent_carries_declared_intent(
    plugin, handle
):
    """LOAD-BEARING INTEGRATION TEST.

    After the synthetic tool fires, the next ``authorize_action`` MUST
    auto-inject ``intent={"objective": "<stored>"}`` into the APDP
    request body. The Cedar context projection
    (`compute_execution_intent_projection`) reads
    ``request.intent.objective`` and stamps the
    evaluation context with ``provenance: "declared"`` —
    which clears the greenfield-Custodial Cedar gate.

    This test proves the declare-intent gate closes end-to-end by
    asserting the exact wire shape APDP receives on the authorize
    request body.
    """
    # Step 1 — agent calls watchlight.declare_intent("audit Q3 invoices").
    declare_response = handle_declare_intent_call(
        handle, {"objective": "audit Q3 invoices", "category": "financial_operation"}
    )
    assert declare_response["status"] == "intent_declared"

    # Step 2 — agent's next authorize_action.
    plugin.apdp.authorize.return_value = {"decision": "Allow"}
    await handle.authorize_action("read", "Document::ledger")

    # Step 3 — verify the APDP request body carries the declared
    # intent. This is the wire shape `compute_execution_intent_projection`
    # treats as Declared.
    call_kwargs = plugin.apdp.authorize.call_args.kwargs
    assert call_kwargs["intent"] == {
        "objective": "audit Q3 invoices",
        "category": "financial_operation",
    }


@pytest.mark.asyncio
async def test_caller_supplied_intent_overrides_stored_declared(plugin, handle):
    """A caller-supplied typed ``intent`` (objective AND category) wins
    over the stored declared intent."""
    handle_declare_intent_call(
        handle, {"objective": "audit Q3 invoices", "category": "financial_operation"}
    )

    plugin.apdp.authorize.return_value = {"decision": "Allow"}
    await handle.authorize_action(
        "read",
        "Document::ledger",
        intent={"objective": "explicit caller override", "category": "data_analysis"},
    )

    call_kwargs = plugin.apdp.authorize.call_args.kwargs
    assert call_kwargs["intent"] == {
        "objective": "explicit caller override",
        "category": "data_analysis",
    }


@pytest.mark.asyncio
async def test_a_caller_objective_is_never_sent_under_the_declared_category(plugin, handle):
    """A "wire funds" objective must not travel as the declared "research":
    a caller objective without its own category is refused locally."""
    handle_declare_intent_call(handle, {"objective": "look things up", "category": "research"})
    result = await handle.authorize_action_detailed(
        "execute", "wire_funds", intent={"objective": "wire funds"}
    )
    assert result.is_deny()
    assert result.reason.startswith("intent_refused")
    plugin.apdp.authorize.assert_not_called()


def test_handle_synthetic_tools_in_greenfield(handle):
    """Synthetic tool is exposed when the handle reports
    greenfield mode. The plugin's tool-list construction path calls
    ``handle.synthetic_tools(mode=...)`` and unions the result with
    the customer's own tools."""
    tools = handle.synthetic_tools(mode="greenfield")
    assert len(tools) == 1
    assert tools[0]["name"] == DECLARE_INTENT_TOOL_NAME


def test_handle_synthetic_tools_empty_in_brownfield(handle):
    """Synthetic tool is NOT exposed in brownfield. The
    brownfield matrix accepts inferred provenance at every tier so
    the synthetic-tool gate would be inert; surfacing the tool
    would confuse operators."""
    assert handle.synthetic_tools(mode="brownfield") == []


def test_handle_synthetic_tools_reads_env_var_by_default(handle, monkeypatch):
    """When ``mode`` is omitted, the handle falls back to
    :func:`resolve_intent_enforcement_mode` which reads the
    ``WATCHLIGHT_INTENT_ENFORCEMENT_MODE`` env var."""
    monkeypatch.setenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, "greenfield")
    assert len(handle.synthetic_tools()) == 1
    monkeypatch.setenv(INTENT_ENFORCEMENT_MODE_ENV_VAR, "brownfield")
    assert handle.synthetic_tools() == []


@pytest.mark.asyncio
async def test_synthetic_tool_call_bypasses_authorize_predicate(plugin, handle):
    """The predicate plugins use to short-circuit the
    synthetic tool's invocation BEFORE authorize fires. The bypass
    itself happens in each plugin's tool-call interceptor; this test
    asserts the predicate distinguishes synthetic from real tool
    calls. Plugins call ``is_declare_intent_tool_call`` then
    ``handle_declare_intent_call`` instead of round-tripping through
    ``authorize_action``."""
    # Synthetic tool call → handled in-process; no authorize round-trip.
    synthetic = {
        "name": "watchlight.declare_intent",
        "arguments": {"objective": "audit Q3 invoices", "category": "financial_operation"},
    }
    assert is_declare_intent_tool_call(synthetic) is True

    # A real tool call → falls through to authorize.
    real = {"name": "search_documents", "arguments": {"query": "Q3"}}
    assert is_declare_intent_tool_call(real) is False

    # Confirm that the synthetic short-circuit path mutates the handle
    # without ever touching APDP authorize.
    handle_declare_intent_call(handle, synthetic["arguments"])
    plugin.apdp.authorize.assert_not_called()
    assert handle.declared_intent_provenance == IntentProvenance.DECLARED


# ─── Typed intent: wl-apdp requires objective AND category ─────────────


def test_a_declare_without_a_category_is_rejected(handle):
    response = handle_declare_intent_call(handle, {"objective": "audit Q3 invoices"})
    assert response["status"] == "rejected"
    assert "category" in response["reason"]
    assert handle.declared_intent_objective is None
    assert handle.declared_intent_category is None
    assert handle.declared_intent_provenance is None


@pytest.mark.parametrize("category", ["", "Research", "foo", {"custom": ""}, {"other": "x"}, 3])
def test_a_declare_with_an_invalid_category_is_rejected(handle, category):
    response = handle_declare_intent_call(
        handle, {"objective": "audit Q3 invoices", "category": category}
    )
    assert response["status"] == "rejected"
    assert handle.declared_intent_category is None


@pytest.mark.parametrize(
    "given, wire",
    [
        ("research", "research"),
        ("custom:quarterly-audit", {"custom": "quarterly-audit"}),
        ({"custom": "quarterly-audit"}, {"custom": "quarterly-audit"}),
    ],
)
def test_a_custom_category_is_stored_in_its_wire_form(handle, given, wire):
    response = handle_declare_intent_call(handle, {"objective": "audit", "category": given})
    assert response["status"] == "intent_declared"
    assert handle.declared_intent_category == wire


@pytest.mark.asyncio
async def test_an_objective_only_declare_sends_no_intent(plugin, handle):
    handle_declare_intent_call(handle, {"objective": "audit Q3 invoices"})
    plugin.apdp.authorize.return_value = {"decision": "Allow"}
    await handle.authorize_action("read", "Document::ledger")
    assert plugin.apdp.authorize.call_args.kwargs.get("intent") is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "intent",
    [
        {"objective": "x"},
        {"approval_token": "appr_1"},
        {"objective": "x", "category": "financial-operation"},
        {"objective": "x", "category": None},
        {"objective": None, "category": "research"},
    ],
    ids=["objective_only", "token_only", "category_typo", "null_category", "null_objective"],
)
async def test_a_malformed_caller_intent_is_refused_never_dropped(plugin, handle, intent):
    """Nothing typed can be built: refused locally, before any request.
    Sending NO intent in its place would make wl-apdp skip intent
    validation, including its approval gates."""
    result = await handle.authorize_action_detailed("read", "Document::x", intent=intent)
    assert result.is_deny()
    assert result.reason.startswith("intent_refused")
    plugin.apdp.authorize.assert_not_called()


@pytest.mark.asyncio
async def test_an_approval_retry_carries_the_declared_typed_intent(plugin, handle):
    handle_declare_intent_call(handle, {"objective": "pay invoice", "category": "financial_operation"})
    plugin.apdp.authorize.return_value = {"decision": "Allow"}
    await handle.authorize_action("pay", "Invoice::1", intent={"approval_token": "appr_1"})
    assert plugin.apdp.authorize.call_args.kwargs["intent"] == {
        "approval_token": "appr_1",
        "objective": "pay invoice",
        "category": "financial_operation",
    }


def test_the_tool_schema_offers_an_optional_justification():
    schema = WATCHLIGHT_DECLARE_INTENT_TOOL["parameters"]
    assert schema["properties"]["justification"]["type"] == "string"
    assert "justification" not in schema["required"]


@pytest.mark.asyncio
async def test_a_declared_justification_travels_with_the_intent(plugin, handle):
    response = handle_declare_intent_call(
        handle,
        {"objective": "pay invoice 7", "category": "financial_operation",
         "justification": "approved by finance"},
    )
    assert response["justification"] == "approved by finance"
    plugin.apdp.authorize.return_value = {"decision": "Allow"}
    await handle.authorize_action("pay", "Invoice::7")
    assert plugin.apdp.authorize.call_args.kwargs["intent"] == {
        "objective": "pay invoice 7",
        "category": "financial_operation",
        "justification": "approved by finance",
    }


def test_a_non_string_justification_is_rejected(handle):
    response = handle_declare_intent_call(
        handle, {"objective": "pay", "category": "financial_operation", "justification": 7}
    )
    assert response["status"] == "rejected"
    assert handle.declared_intent_provenance is None


def test_the_category_is_fixed_once_declared(handle, caplog):
    """Re-declaring a DIFFERENT category is intent drift: refused, recorded,
    and the declared intent is unchanged. A refined objective under the
    same category is allowed."""
    assert handle_declare_intent_call(
        handle, {"objective": "look things up", "category": "research"}
    )["status"] == "intent_declared"
    with caplog.at_level("WARNING"):
        drift = handle_declare_intent_call(
            handle, {"objective": "wire funds", "category": "financial_operation"}
        )
    assert drift["status"] == "rejected"
    assert "fixed" in drift["reason"]
    assert any(getattr(r, "event", None) == "intent_drift" for r in caplog.records)
    assert handle.declared_intent_category == "research"
    assert handle.declared_intent_objective == "look things up"

    refined = handle_declare_intent_call(
        handle, {"objective": "look up Q3 filings", "category": "research"}
    )
    assert refined["status"] == "intent_declared"
    assert handle.declared_intent_objective == "look up Q3 filings"
