"""Sub-agent scope attenuation wire shapes (Python mirror).

This module is the Python lane of the sub-agent scope request/response
contract. The **canonical Rust shapes** for the cross-service scope
types live in ``wl-lineage::events``. The wl-apdp endpoint envelope
types (``SpawnSubagentRequest`` / ``SpawnSubagentResponse``) and the
reserved ``ParentSignature`` signing scaffolding live on the wl-apdp
side. This mirror is wire-shape-equivalent across both banks.

Mirror parity is load-bearing: every field name, every JSON encoding,
every fail-closed default in this module must match the Rust struct
field-for-field. Tests in ``tests/test_scope.py`` assert the JSON
round-trip against a fixture taken verbatim from the Rust tests.

See the Watchlight documentation for the six locked scope-attenuation
invariants and the design-intent data shapes.

Public API:

- :class:`RequestedScope` — what the parent declares at the call site.
  Empty defaults = zero privileges (locked fail-closed invariant).
- :class:`GrantedScope` — server-attested response from APDP after
  strict-subset validation.
- :class:`ResourceMatcher` — string-identifier resource matcher
  (canonical wl-lineage shape).
- :class:`ParentSignature` — a signing envelope reserved for a future
  canonical ``GrantedScope`` extension. **Not present on the canonical
  wire ``GrantedScope`` today** — included here so SDK consumers can
  decode a future signature-enabled response without a schema
  migration.
- :class:`SpawnSubagentRequest` / :class:`SpawnSubagentResponse` —
  the bodies of ``POST /v1/spawn_subagent``.
- :class:`ChildIntent` — the intent and goal a parent declares for the
  child it spawns. REQUIRED on every spawn: wl-apdp
  refuses a spawn without one (``CHILD_INTENT_REQUIRED``).
- :func:`plugin_child_intent` — how a framework plugin derives a
  :class:`ChildIntent` from the framework's delegation signal.
- :func:`to_jsonable` / :func:`requested_scope_from_dict` etc. — the
  JSON conversion helpers used by the SDK + plugins to bridge Python
  dataclasses ↔ the canonical snake_case wire format.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

__all__ = [
    "RequestedScope",
    "GrantedScope",
    "ResourceMatcher",
    "ParentSignature",
    "SpawnSubagentRequest",
    "SpawnSubagentResponse",
    "ChildIntent",
    "CHILD_INTENT_CATEGORY_MAX_BYTES",
    "CHILD_INTENT_OBJECTIVE_MAX_BYTES",
    "DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY",
    "child_intent_to_dict",
    "child_intent_from_dict",
    "coerce_child_intent",
    "plugin_child_intent",
    "requested_scope_to_dict",
    "requested_scope_from_dict",
    "granted_scope_to_dict",
    "granted_scope_from_dict",
    "resource_matcher_to_dict",
    "resource_matcher_from_dict",
    "parent_signature_to_dict",
    "parent_signature_from_dict",
    "spawn_subagent_request_to_dict",
    "spawn_subagent_request_from_dict",
    "spawn_subagent_response_to_dict",
    "spawn_subagent_response_from_dict",
]


# ─── ResourceMatcher ─────────────────────────────────────────────


@dataclass
class ResourceMatcher:
    """String-identifier resource matcher (canonical wl-lineage shape).

    Mirrors ``wl_lineage::events::ResourceMatcher``. The ``matcher``
    field is a stable ``kind::pattern`` identifier — the ``kind`` half
    maps to a Cedar entity type; the ``pattern`` half is the literal /
    prefix match the strict-subset validator runs.

    v1 uses literal-list set membership over the rendered string form;
    richer matcher grammars (glob predicates, regex) are deferred to a
    future version.
    """

    matcher: str


# ─── RequestedScope ──────────────────────────────────────────────


@dataclass
class RequestedScope:
    """Scope the parent declares to grant a sub-agent at spawn time.

    Mirrors ``wl_lineage::events::RequestedScope``.

    **Fail-closed default** (locked invariant): every list field
    defaults to an empty list, ``max_depth`` to ``0`` and the time
    budget to ``None``. A bare ``RequestedScope()`` yields a sub-agent
    with zero privileges: empty allowlists deny every tool, resource
    and intent, and a ``0`` depth means the child cannot spawn further.
    With no budget named, the child inherits the parent's remaining
    time, bounded by the tenant threshold, and never more.

    Field semantics:

    - ``allowed_tools`` — Cedar action UIDs / tool slugs the child
      may invoke. Empty = none.
    - ``allowed_resources`` — list of :class:`ResourceMatcher` the
      child may access. Empty = none.
    - ``allowed_intents`` — intent objectives the child may declare.
      Empty = none. v1 uses exact-string matching.
    - ``max_depth`` — maximum further spawn depth (``0`` = child
      cannot spawn descendants). The strict-subset validator
      enforces ``requested ≤ parent_effective.max_depth - 1``.
    - ``time_budget_seconds`` — per-spawn time budget in seconds, or
      ``None`` when the spawn names none. ``None`` is left off the wire,
      and the child then inherits the parent's REMAINING time (bounded
      by the parent's deadline and the tenant threshold; it never
      widens). A named budget is granted exactly or refused, never
      clamped: ``0`` is refused as unsatisfiable, and a budget above the
      parent's granted budget, its remaining time or the tenant threshold
      as a ``TimeBudget`` scope violation. The budget never resets on
      re-spawn.
    """

    allowed_tools: List[str] = field(default_factory=list)
    allowed_resources: List[ResourceMatcher] = field(default_factory=list)
    allowed_intents: List[str] = field(default_factory=list)
    max_depth: int = 0
    time_budget_seconds: Optional[int] = None

    def is_empty(self) -> bool:
        """True when the scope grants no privileges along any
        dimension.

        Mirrors the Rust ``RequestedScope::validate`` semantics for
        the empty case. The per-tool scope-membership pre-check uses
        this to short-circuit: an empty scope can only deny.
        """
        return (
            not self.allowed_tools
            and not self.allowed_resources
            and not self.allowed_intents
        )


# ─── GrantedScope ────────────────────────────────────────────────


@dataclass
class GrantedScope:
    """Server-attested grant returned by APDP after the strict-subset
    validator accepts a parent's :class:`RequestedScope`.

    Mirrors ``wl_lineage::events::GrantedScope``.

    Lives on the child's RunHandle, propagates onto every
    ``agent_spawn_observed`` lineage event, and is rendered
    as a node overlay on the dashboard lineage tree.

    The list + numeric fields equal the parent's request when the
    validator accepts (the validator accepts or denies whole; there
    is no narrowing on the way in). APDP appends three resolved
    fields:

    - ``deadline`` — absolute UTC timestamp at which the child's
      RunHandle is invalidated. Optional because test fixtures
      sometimes construct a ``GrantedScope`` without the APDP-side
      data; the conformance suite asserts presence on every
      real spawn.
    - ``parent_run_handle_id`` — the parent's RunHandle ID so the
      spawn-tree walker can invalidate descendants when the kill
      switch invalidates the parent.
    - ``depth`` — sub-agent's depth in the spawn tree (root = 0).

    **Note on ``ParentSignature``** — the canonical wire shape does
    NOT carry a ``parent_signature`` field. The signing envelope is
    reserved as a future cutover target; today's deployments instead
    have APDP sign the surrounding event envelope, with the parent's
    identity riding in the ``agent_spawn_observed`` payload's
    ``spawner: PrincipalRef``.
    """

    allowed_tools: List[str]
    allowed_resources: List[ResourceMatcher]
    allowed_intents: List[str]
    max_depth: int
    time_budget_seconds: int
    deadline: Optional[datetime] = None
    parent_run_handle_id: Optional[str] = None
    depth: int = 0


# ─── ParentSignature ─────────────────────────────────────────────


@dataclass
class ParentSignature:
    """Parent signature envelope — reserved for a future canonical
    :class:`GrantedScope` extension.

    Carries the signing parameters but **does not appear on the
    canonical wire ``GrantedScope`` today** — current deployments use
    the envelope-signing fallback instead. The dataclass exists so SDK
    consumers wiring to a future signature-enabled APDP can decode
    the field without a schema migration.
    """

    kid: str
    algorithm: str
    signature_b64: str
    signed_at: datetime


# ─── ChildIntent ─────────────────────────────────────────────────

#: The longest child intent category wl-apdp accepts, in bytes.
CHILD_INTENT_CATEGORY_MAX_BYTES = 128
#: The longest child objective wl-apdp accepts, in bytes
#: (``wl_lineage::INTENT_OBJECTIVE_MAX_BYTES``).
CHILD_INTENT_OBJECTIVE_MAX_BYTES = 256
#: The category a framework plugin declares for a child when neither the
#: plugin configuration nor the parent's own derived intent names one. A
#: parent whose goal restricts intent categories refuses it
#: (``INTENT_NOT_DERIVED``) until the plugin is configured with a category
#: the goal allows: fail closed, never a guessed category.
DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY = "custom:delegated_task"


@dataclass
class ChildIntent:
    """The intent and goal a parent declares for the child it spawns.

    Sent as ``child_intent`` on ``POST /v1/spawn_subagent``. REQUIRED on
    every spawn. wl-apdp accepts it only when:

    - ``category`` is one intent category (the ``IntentCategory`` wire form,
      such as ``research`` or ``custom:<name>``), never ``*``, and lies
      within the parent's intent bounds (its granted intents and its run
      goal's allowed categories);
    - ``objective`` says what the parent asks the child to do (non-blank, at
      most :data:`CHILD_INTENT_OBJECTIVE_MAX_BYTES` bytes, no control
      characters);
    - ``max_actions``, when named, is at least one and no larger than the
      parent's remaining action budget (refused, never clamped). Absent: the
      child inherits the parent's remaining budget.

    The child is then granted exactly ``category``, so any later call that
    declares another intent is refused and invalidates the child's handle.
    """

    category: str
    objective: str
    max_actions: Optional[int] = None


def child_intent_to_dict(intent: ChildIntent) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "category": intent.category,
        "objective": intent.objective,
    }
    if intent.max_actions is not None:
        out["max_actions"] = int(intent.max_actions)
    return out


def child_intent_from_dict(d: Dict[str, Any]) -> ChildIntent:
    if not isinstance(d, dict):
        raise ValueError("child_intent must be an object")
    unknown = set(d) - {"category", "objective", "max_actions"}
    if unknown:
        raise ValueError(f"child_intent has unknown fields {sorted(unknown)!r}")
    category = d.get("category")
    objective = d.get("objective")
    if not isinstance(category, str) or not isinstance(objective, str):
        raise ValueError("child_intent.category and child_intent.objective must be strings")
    max_actions = d.get("max_actions")
    if max_actions is not None and (
        isinstance(max_actions, bool) or not isinstance(max_actions, int)
    ):
        raise ValueError("child_intent.max_actions must be an integer")
    return ChildIntent(category=category, objective=objective, max_actions=max_actions)


def coerce_child_intent(value: Any) -> ChildIntent:
    """Accept a :class:`ChildIntent` or its dict form; refuse anything else.

    ``None`` is refused: a spawn always declares the child's intent. The
    checks here are structural only; wl-apdp validates the derivation.
    """
    if value is None:
        raise ValueError(
            "spawn_subagent: child_intent is required; declare the child's intent "
            "category and the objective the parent gives it (ChildIntent)"
        )
    intent = value if isinstance(value, ChildIntent) else child_intent_from_dict(value)
    if not isinstance(intent.category, str) or not intent.category.strip():
        raise ValueError("spawn_subagent: child_intent.category is blank")
    if not isinstance(intent.objective, str) or not intent.objective.strip():
        raise ValueError("spawn_subagent: child_intent.objective is blank")
    if intent.max_actions is not None and (
        isinstance(intent.max_actions, bool) or not isinstance(intent.max_actions, int)
    ):
        raise ValueError("spawn_subagent: child_intent.max_actions must be an integer")
    return intent


_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]+")


def _bounded_objective(text: str) -> str:
    """Collapse control characters and whitespace, and cut to the wire bound
    on a UTF-8 character boundary."""
    cleaned = " ".join(_CONTROL_RE.sub(" ", text).split())
    encoded = cleaned.encode("utf-8")
    if len(encoded) <= CHILD_INTENT_OBJECTIVE_MAX_BYTES:
        return cleaned
    return encoded[:CHILD_INTENT_OBJECTIVE_MAX_BYTES].decode("utf-8", "ignore").rstrip()


def plugin_child_intent(
    objective: Optional[str],
    *,
    category: Optional[str] = None,
    parent: Any = None,
    max_actions: Optional[int] = None,
    fallback_objective: Optional[str] = None,
) -> ChildIntent:
    """Derive a :class:`ChildIntent` from a framework's delegation signal.

    Used by framework plugins that spawn a sub-agent on the framework's
    behalf (a ``Task`` tool call, an agent transfer, a collaborator
    invocation). The derived intent's provenance is at most
    ``plugin_derived``; wl-apdp records it that way.

    - ``objective``: the task text the framework hands the child (its
      description or prompt), bounded to the wire limit. Blank: the
      ``fallback_objective``, else a fixed delegation text.
    - ``category``: the plugin's configured category. Absent: the parent
      handle's own derived category when the parent is itself a derived
      sub-agent, else :data:`DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY`.
    """
    text = _bounded_objective(objective or "")
    if not text:
        text = _bounded_objective(fallback_objective or "") or "Delegated sub-task"
    resolved = category
    if not resolved and parent is not None:
        derived = getattr(parent, "derived_intent", None)
        if isinstance(derived, dict):
            parent_category = derived.get("intent_category")
            if isinstance(parent_category, str) and parent_category:
                resolved = parent_category
    return ChildIntent(
        category=resolved or DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY,
        objective=text,
        max_actions=max_actions,
    )


# ─── SpawnSubagentRequest / SpawnSubagentResponse ───────────────


@dataclass
class SpawnSubagentRequest:
    """Body of a ``POST /v1/spawn_subagent`` call.

    Carries the parent's identity + RunHandle + the requested scope.
    The structural decode lives here; the strict-subset validator that
    consumes it lives server-side.

    Execution-lineage integrity. The former lineage
    fields (``child_execution_id`` / ``parent_execution_id`` /
    ``root_execution_id``) have been REMOVED: the child's tree position is
    no longer client-supplied. wl-apdp authenticates the spawn with the
    PARENT's ``sst_`` credential, derives the child's parent-exec + root
    from the parent's VERIFIED claims, and SERVER-mints the child
    ``execution_id`` — returning it (plus the child ``sst_`` credential +
    the tree root) on :class:`SpawnSubagentResponse`. This closes the
    graft where a caller set ``root_execution_id`` to a victim run's root.
    """

    parent_agent_id: UUID
    #: The registered agent the child runs as. ``None`` for a labelled
    #: child that is not a registered agent (see :attr:`child_label`).
    child_agent_id: Optional[UUID]
    parent_run_handle_id: UUID
    requested_scope: RequestedScope
    #: The child's type or label (a deepagents / Claude ``subagent_type``,
    #: an ADK ``agent.name``, a Strands node id). With no ``child_agent_id``
    #: the child is identified by its parent run and this label: it runs as
    #: the agent an operator mapped the label to, else as its parent's
    #: agent. Evidence only, never an authority. At least one of
    #: ``child_agent_id`` and ``child_label`` is set.
    child_label: Optional[str] = None
    # The child's own intent and goal, derived from the parent's. REQUIRED on
    # the wire (wl-apdp refuses a spawn without it, ``CHILD_INTENT_REQUIRED``);
    # ``Optional`` here only so a decoder can report its absence.
    child_intent: Optional[ChildIntent] = None


@dataclass
class SpawnSubagentResponse:
    """Successful response from ``POST /v1/spawn_subagent``.

    On a denial APDP responds with the standard error envelope
    instead of this shape.
    """

    child_run_handle_id: UUID
    granted_scope: GrantedScope
    lineage_event_id: Optional[UUID] = None
    # The child run's canonical execution_id (server-resolved). The
    # child's emitted events MUST carry this id.
    child_execution_id: Optional[str] = None
    # The shared execution-tree root, when the parent passed one through.
    root_execution_id: Optional[str] = None
    # Execution-lineage integrity. The SERVER-derived
    # ``session_id`` for the child run (canonical ``ses_<child-run-handle>``).
    # This is the SINGLE authoritative session id the child uses: it is the
    # ``sid`` claim inside the child's run credential AND the value the child
    # handle stamps as ``envelope.session_id`` on every ``POST /v1/events``.
    # The child adopts this verbatim (rather than reconstructing it), which is
    # what makes the ingest binding gate's ``session_id == sid`` check hold —
    # fixing the v0.9.11 child-``execution_started`` 409 (the child used to
    # stamp the bare run-handle id, which did not match the credential).
    child_session_id: Optional[str] = None
    # The child run's opaque reference, issued by the backend that ran the
    # spawn (``GovernanceBackend.spawn_subagent``). The child's own
    # credentials (its ``sst_`` session token and its egress token)
    # stay inside that backend under this reference; the response the SDK
    # sees never carries them.
    child_run: Optional[str] = None
    #: The agent the child runs as, as wl-apdp names it: the registered
    #: agent requested, the agent an operator mapped the child's label to,
    #: or the parent's agent for an anonymous labelled child. ``None`` from
    #: a server that predates labelled spawns.
    child_agent_id: Optional[str] = None
    #: The child's label, echoed back (``None`` when none was sent).
    child_label: Optional[str] = None
    #: ``"registered"``, ``"mapped"`` or ``"anonymous"``.
    child_identity: Optional[str] = None
    # The child's intent and goal as wl-apdp validated them
    # (``SubagentDerivedIntent``): ``intent_category``, ``objective``,
    # ``max_actions``, ``parent_intent_categories``, ``parent_goal_id``,
    # ``sub_goal_id`` and ``provenance``. Kept as a dict, like the event
    # mirror.
    derived_intent: Optional[Dict[str, Any]] = None


# ─── JSON conversion helpers ─────────────────────────────────────
#
# We intentionally hand-roll the JSON conversion rather than reaching
# for ``dataclasses.asdict`` so the wire-shape matches the Rust
# ``#[serde(skip_serializing_if = "Option::is_none")]`` semantics on
# the optional APDP-side fields of ``GrantedScope`` (``deadline``,
# ``parent_run_handle_id``) and on ``lineage_event_id``.


def _iso(dt: datetime) -> str:
    """Render a datetime as RFC 3339 (UTC), matching the Rust
    ``chrono::DateTime<Utc>`` wire format."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    # Use the Z suffix to match chrono's default. Python's isoformat
    # emits +00:00 — both are RFC 3339 valid, but Z is the canonical
    # form for the cross-lane fixture tests.
    s = dt.astimezone(timezone.utc).isoformat()
    if s.endswith("+00:00"):
        s = s[:-6] + "Z"
    return s


def _parse_iso(s: str) -> datetime:
    """Parse an RFC 3339 datetime string, tolerating the trailing Z
    that Rust's chrono emits."""
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return datetime.fromisoformat(s)


def resource_matcher_to_dict(m: ResourceMatcher) -> Dict[str, Any]:
    return {"matcher": m.matcher}


def resource_matcher_from_dict(d: Dict[str, Any]) -> ResourceMatcher:
    return ResourceMatcher(matcher=str(d["matcher"]))


def requested_scope_to_dict(scope: RequestedScope) -> Dict[str, Any]:
    """Serialize a :class:`RequestedScope` to a JSON-able dict
    using the canonical snake_case field names."""
    return {
        "allowed_tools": list(scope.allowed_tools),
        "allowed_resources": [
            resource_matcher_to_dict(m) for m in scope.allowed_resources
        ],
        "allowed_intents": list(scope.allowed_intents),
        "max_depth": scope.max_depth,
        # Absent when the caller named no budget: the backend then resolves
        # it to the parent's remaining time. Never sent as 0.
        **(
            {"time_budget_seconds": scope.time_budget_seconds}
            if scope.time_budget_seconds is not None
            else {}
        ),
    }


#: The largest time budget the wire's ``u32`` field holds.
MAX_TIME_BUDGET_SECONDS = 2**32 - 1


def time_budget_from_wire(value: Any) -> Optional[int]:
    """A requested time budget as wl-apdp reads it: ``None`` (absent or
    ``null``) inherits the parent's remaining time; anything else must be
    an integer from 0 to 2**32 - 1. A float, a string or a bool is refused,
    not coerced (wl-apdp answers 422), with :class:`ValueError`."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError("time_budget_seconds must be an integer number of seconds")
    if not 0 <= value <= MAX_TIME_BUDGET_SECONDS:
        raise ValueError(
            f"time_budget_seconds must be between 0 and {MAX_TIME_BUDGET_SECONDS}"
        )
    return value


def _coerce_resource_matchers(raw: Any) -> List[ResourceMatcher]:
    """Decode `allowed_resources` from either the canonical object
    form (`{"matcher": "doc::*"}`) or a bare string form (for
    backwards-compatibility with an early preview the Python/TS
    lanes shipped before the object form landed). Bare strings are
    wrapped in `ResourceMatcher`."""
    if raw is None:
        return []
    out: List[ResourceMatcher] = []
    for entry in raw:
        if isinstance(entry, str):
            out.append(ResourceMatcher(matcher=entry))
        elif isinstance(entry, dict):
            out.append(resource_matcher_from_dict(entry))
        else:
            raise TypeError(
                f"allowed_resources entry must be str or dict, got {type(entry).__name__}"
            )
    return out


def requested_scope_from_dict(d: Dict[str, Any]) -> RequestedScope:
    """Decode a dict produced by :func:`requested_scope_to_dict` or
    by the canonical Rust serializer.

    Every field is treated as ``#[serde(default)]`` — missing fields
    fall back to empty / 0, and a missing time budget to ``None``
    (inherit the parent's remaining time). This is the wire-side
    enforcement of locked invariant #2. A time budget that is present
    but not an integer in range raises :class:`ValueError`.
    """
    return RequestedScope(
        allowed_tools=list(d.get("allowed_tools") or []),
        allowed_resources=_coerce_resource_matchers(d.get("allowed_resources")),
        allowed_intents=list(d.get("allowed_intents") or []),
        max_depth=int(d.get("max_depth") or 0),
        time_budget_seconds=time_budget_from_wire(d.get("time_budget_seconds")),
    )


def parent_signature_to_dict(sig: ParentSignature) -> Dict[str, Any]:
    return {
        "kid": sig.kid,
        "algorithm": sig.algorithm,
        "signature_b64": sig.signature_b64,
        "signed_at": _iso(sig.signed_at),
    }


def parent_signature_from_dict(d: Dict[str, Any]) -> ParentSignature:
    return ParentSignature(
        kid=d["kid"],
        algorithm=d["algorithm"],
        signature_b64=d["signature_b64"],
        signed_at=_parse_iso(d["signed_at"]),
    )


def granted_scope_to_dict(scope: GrantedScope) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "allowed_tools": list(scope.allowed_tools),
        "allowed_resources": [
            resource_matcher_to_dict(m) for m in scope.allowed_resources
        ],
        "allowed_intents": list(scope.allowed_intents),
        "max_depth": scope.max_depth,
        "time_budget_seconds": scope.time_budget_seconds,
        "depth": scope.depth,
    }
    if scope.deadline is not None:
        out["deadline"] = _iso(scope.deadline)
    if scope.parent_run_handle_id is not None:
        out["parent_run_handle_id"] = scope.parent_run_handle_id
    return out


def granted_scope_from_dict(d: Dict[str, Any]) -> GrantedScope:
    raw_deadline = d.get("deadline")
    deadline = _parse_iso(raw_deadline) if raw_deadline is not None else None
    raw_handle = d.get("parent_run_handle_id")
    return GrantedScope(
        allowed_tools=list(d.get("allowed_tools") or []),
        allowed_resources=_coerce_resource_matchers(d.get("allowed_resources")),
        allowed_intents=list(d.get("allowed_intents") or []),
        max_depth=int(d["max_depth"]),
        time_budget_seconds=int(d["time_budget_seconds"]),
        deadline=deadline,
        parent_run_handle_id=str(raw_handle) if raw_handle is not None else None,
        depth=int(d.get("depth") or 0),
    )


def spawn_subagent_request_to_dict(req: SpawnSubagentRequest) -> Dict[str, Any]:
    # Execution-lineage integrity. The request carries
    # ONLY the parent identity + handle + requested scope. The child's
    # execution/parent/root ids are no longer client-supplied — wl-apdp
    # derives them from the parent's VERIFIED credential + server-mints
    # the child id.
    if req.child_agent_id is None and req.child_label is None:
        raise ValueError(
            "spawn_subagent: name the child by child_agent_id or child_label"
        )
    out: Dict[str, Any] = {
        "parent_agent_id": str(req.parent_agent_id),
        "parent_run_handle_id": str(req.parent_run_handle_id),
        "requested_scope": requested_scope_to_dict(req.requested_scope),
        **(
            {"child_intent": child_intent_to_dict(req.child_intent)}
            if req.child_intent is not None
            else {}
        ),
    }
    if req.child_agent_id is not None:
        out["child_agent_id"] = str(req.child_agent_id)
    if req.child_label is not None:
        from .root_identity import validate_child_label

        out["child_label"] = validate_child_label(req.child_label)
    return out


def spawn_subagent_request_from_dict(d: Dict[str, Any]) -> SpawnSubagentRequest:
    raw_child = d.get("child_agent_id")
    raw_label = d.get("child_label")
    if raw_child is None and raw_label is None:
        raise ValueError(
            "spawn_subagent: the request names the child by neither "
            "child_agent_id nor child_label"
        )
    label: Optional[str] = None
    if raw_label is not None:
        from .root_identity import validate_child_label

        label = validate_child_label(raw_label)
    raw_intent = d.get("child_intent")
    return SpawnSubagentRequest(
        parent_agent_id=UUID(d["parent_agent_id"]),
        child_agent_id=UUID(raw_child) if raw_child is not None else None,
        parent_run_handle_id=UUID(d["parent_run_handle_id"]),
        requested_scope=requested_scope_from_dict(
            d.get("requested_scope") or {}
        ),
        child_label=label,
        child_intent=(
            child_intent_from_dict(raw_intent) if raw_intent is not None else None
        ),
    )


def spawn_subagent_response_to_dict(resp: SpawnSubagentResponse) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "child_run_handle_id": str(resp.child_run_handle_id),
        "granted_scope": granted_scope_to_dict(resp.granted_scope),
    }
    if resp.lineage_event_id is not None:
        out["lineage_event_id"] = str(resp.lineage_event_id)
    if resp.child_agent_id is not None:
        out["child_agent_id"] = resp.child_agent_id
    if resp.child_label is not None:
        out["child_label"] = resp.child_label
    if resp.child_identity is not None:
        out["child_identity"] = resp.child_identity
    if resp.derived_intent is not None:
        out["derived_intent"] = dict(resp.derived_intent)
    return out


def spawn_subagent_response_from_dict(d: Dict[str, Any]) -> SpawnSubagentResponse:
    raw_lineage = d.get("lineage_event_id")
    return SpawnSubagentResponse(
        child_run_handle_id=UUID(d["child_run_handle_id"]),
        granted_scope=granted_scope_from_dict(d["granted_scope"]),
        lineage_event_id=UUID(raw_lineage) if raw_lineage else None,
        # Execution-lineage integrity. `child_execution_id` is
        # required in the current wire shape but tolerated-absent here so a
        # mock/older server that omits it doesn't crash the parse.
        child_execution_id=d.get("child_execution_id"),
        root_execution_id=d.get("root_execution_id"),
        child_session_id=d.get("child_session_id"),
        child_run=_opt_nonempty_str(d.get("child_run")),
        child_agent_id=_opt_nonempty_str(d.get("child_agent_id")),
        child_label=_opt_nonempty_str(d.get("child_label")),
        child_identity=_opt_nonempty_str(d.get("child_identity")),
        derived_intent=(
            dict(d["derived_intent"]) if isinstance(d.get("derived_intent"), dict) else None
        ),
    )


def _opt_nonempty_str(value: Any) -> Optional[str]:
    return value if isinstance(value, str) and value else None


def _parse_rfc3339(value: Any) -> Optional[datetime]:
    """Parse an RFC 3339 timestamp; ``None`` when absent or malformed
    (the token stays usable, its issuer-side expiry still applies)."""
    if not isinstance(value, str) or not value:
        return None
    # chrono may emit nanoseconds; ``fromisoformat`` takes at most six
    # fractional digits.
    value = re.sub(r"(\.\d{6})\d+", r"\1", value)
    try:
        return _parse_iso(value)
    except ValueError:
        return None


# Quiet ``mypy`` / readers — `fields` is imported above to make this
# module self-documenting w.r.t. dataclass introspection in tests.
_ = fields
