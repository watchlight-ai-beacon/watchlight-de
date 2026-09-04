"""watchlight — Developer Edition.

Govern an AI agent in-process, with zero infrastructure. Decorate a tool with
an *intent*, load a local policy, run your script, and the policy engine
authorizes every call — allowing what a policy permits and refusing everything
else **before the tool body runs**.

    from watchlight import govern, Denied

    govern.load("watchlight.policy.json")     # or govern.allow("permit(...);")

    @govern.tool(intent="research")
    def web_search(query: str) -> str:
        ...

The engine is the Watchlight authorization engine (Cedar evaluation plus the
surrounding pipeline) embedded via the ``watchlight-engine`` extension — the
same authorization model that runs in production, in-process. Point it at a
networked policy service to run the same code against a remote APDP.

Guarantees that are identical to production and MUST NOT be relaxed here:
  * **Fail-closed** — no matching policy denies; an unreachable decision denies.
  * **Explicit intent** — a tool is governed by the intent you declare, never
    inferred from its name or body.
  * **Value-free audit** — argument *values* never enter the trail; only who,
    what intent, which resource, and the decision.
"""

from __future__ import annotations

import datetime
import functools
import hashlib
import hmac
import inspect
import json
import os
import pathlib
import re
import secrets
import time
from typing import Any, Callable, Optional, Sequence, TypeVar, Union

import watchlight_engine as _engine

from .attenuation import DE_MAX_DEPTH, AttenuationDenied, DevEditionCeiling, Scope
from .policytest import load_test_suite, run_policy_tests

__all__ = [
    "Watchlight",
    "Denied",
    "NeedsApproval",
    "sanitize",
    "govern",
    "Scope",
    "AttenuationDenied",
    "DevEditionCeiling",
    "DE_MAX_DEPTH",
    "run_policy_tests",
    "load_test_suite",
]

_F = TypeVar("_F", bound=Callable[..., Any])


class Denied(PermissionError):
    """Raised when the policy engine refuses a governed tool call (fail-closed).

    The decorated function's body never runs — the refusal happens *before* the
    side effect.
    """

    def __init__(self, tool: str, intent: str, reason: str) -> None:
        self.tool = tool
        self.intent = intent
        self.reason = reason
        super().__init__(f"watchlight denied intent '{intent}' on tool/{tool}: {reason}")


class NeedsApproval(PermissionError):
    """Raised when a governed call is permitted only after a human confirmation
    (the matched permit carries the ``require_approval`` enforcement effect) and
    no valid approval was supplied. Fail-closed: the body never ran."""

    def __init__(self, tool: str, intent: str, decision_id: Optional[str], reason: str) -> None:
        self.tool = tool
        self.intent = intent
        self.decision_id = decision_id
        self.reason = reason
        super().__init__(f"watchlight requires human approval for intent '{intent}' on tool/{tool}")


# ── approval tokens (DE: local, single-use, HMAC, TTL) ──────────────────────
# Enterprise mints these KMS-signed and records them in signed lineage.
_APPROVAL_SECRET = secrets.token_bytes(32)
_USED_APPROVALS: set[str] = set()


def _mint_approval_token(principal: str, action: str, resource: str, ttl_ms: int) -> str:
    exp = int(time.time() * 1000) + ttl_ms
    # A per-mint nonce makes every token unique, so two approvals for the same
    # (principal, action, resource) minted in the same millisecond never collide
    # — and "single-use" is genuinely per-mint, not per-(challenge, exp).
    nonce = secrets.token_hex(8)
    payload = f"{principal} {action} {resource} {exp} {nonce}".encode()
    sig = hmac.new(_APPROVAL_SECRET, payload, hashlib.sha256).hexdigest()
    return f"{exp}.{nonce}.{sig}"


def _consume_approval_token(token: str, principal: str, action: str, resource: str) -> bool:
    """Verify + consume (single-use). Bound to the exact (principal, action,
    resource); rejects expired, tampered, or reused tokens."""
    parts = token.split(".")
    if len(parts) != 3:
        return False
    exp_str, nonce, sig = parts
    try:
        exp = int(exp_str)
    except ValueError:
        return False
    if int(time.time() * 1000) > exp:
        return False
    payload = f"{principal} {action} {resource} {exp} {nonce}".encode()
    expected = hmac.new(_APPROVAL_SECRET, payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(sig, expected):
        return False
    if token in _USED_APPROVALS:
        return False
    _USED_APPROVALS.add(token)
    return True


def _needs_approval(details: Any) -> bool:
    """A permitting policy result (``applicable: true``) annotated
    ``require_approval``. A non-matching require_approval policy elsewhere in the
    set must not flag this decision."""
    results = (details or {}).get("policy_results") if isinstance(details, dict) else None
    if not isinstance(results, list):
        return False
    return any(
        isinstance(r, dict) and r.get("applicable") is True
        and r.get("enforcement_effect") == "require_approval"
        for r in results
    )


def _resolve(binding: Any, args: tuple, kwargs: dict) -> Optional[str]:
    """Resolve a per-call binding: a fixed value, or a callable of the tool's
    ``(*args, **kwargs)``."""
    if binding is None:
        return None
    return binding(*args, **kwargs) if callable(binding) else binding


# ── sanitize: deterministic PII redaction (mirrors the TS detector) ─────────
DETECTOR_VERSION = "de-rules-1"


class SanitizeError(RuntimeError):
    """Fail-closed: sanitization could not complete; do NOT use raw content."""


def _luhn_ok(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        if not ch.isdigit():
            return False
        d = int(ch)
        if alt:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        alt = not alt
    return total % 10 == 0


_DETECTORS: list[tuple[str, re.Pattern, Optional[Callable[[str], bool]]]] = [
    ("EMAIL", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
    ("API_KEY", re.compile(r"\b(?:sk-[A-Za-z0-9]{16,}|ghp_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b"), None),
    ("SSN", re.compile(r"\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"), None),
    ("CREDIT_CARD", re.compile(r"\b(?:\d[ -]?){13,19}\b"),
     lambda m: 13 <= len(re.sub(r"[ -]", "", m)) <= 19 and _luhn_ok(re.sub(r"[ -]", "", m))),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?:[ ]?[A-Za-z0-9]{4}){2,7}(?:[ ]?[A-Za-z0-9]{1,3})?\b"), None),
    ("IPV4", re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
     lambda m: all(int(o) <= 255 for o in m.split("."))),
    ("PHONE", re.compile(r"(?<!\d)(?:\+?\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?)?\d{3}[ .-]?\d{4}(?!\d)"),
     lambda m: len(re.sub(r"\D", "", m)) >= 10),
]


def sanitize(text: str, *, mode: str = "tag", types: Optional[Sequence[str]] = None) -> dict:
    """Redact PII from ``text``. Deterministic, fail-closed. Returns
    ``{"text": ..., "report": {mode, detector_version, counts, total}}`` where the
    report is value-free (counts by type — never the values). ``mode`` is
    ``tag`` (consistent ``<EMAIL_1>``), ``mask`` (``[EMAIL]``), or ``hash``."""
    if not isinstance(text, str):
        raise SanitizeError("input must be a string (extract document text first)")
    enabled = set(types) if types is not None else {d[0] for d in _DETECTORS}
    try:
        spans: list[tuple[int, int, str, str]] = []
        for typ, pat, valid in _DETECTORS:
            if typ not in enabled:
                continue
            for m in pat.finditer(text):
                val = m.group(0)
                if valid and not valid(val):
                    continue
                spans.append((m.start(), m.end(), typ, val))
        # resolve overlaps: earliest start, then longest
        spans.sort(key=lambda s: (s[0], -(s[1] - s[0])))
        kept: list[tuple[int, int, str, str]] = []
        last_end = -1
        for s in spans:
            if s[0] >= last_end:
                kept.append(s)
                last_end = s[1]
        counters: dict[str, str] = {}
        per_type: dict[str, int] = {}
        counts: dict[str, int] = {}
        out, cursor = [], 0
        for start, end, typ, val in kept:
            out.append(text[cursor:start])
            if mode == "mask":
                rep = f"[{typ}]"
            elif mode == "hash":
                rep = f"<{typ}_{hashlib.sha256(val.encode()).hexdigest()[:8]}>"
            else:
                key = f"{typ}:{val}"
                rep = counters.get(key)
                if rep is None:
                    per_type[typ] = per_type.get(typ, 0) + 1
                    rep = f"<{typ}_{per_type[typ]}>"
                    counters[key] = rep
            out.append(rep)
            cursor = end
            counts[typ] = counts.get(typ, 0) + 1
        out.append(text[cursor:])
        return {
            "text": "".join(out),
            "report": {"mode": mode, "detector_version": DETECTOR_VERSION, "counts": counts, "total": len(kept)},
        }
    except Exception as exc:  # noqa: BLE001 - fail-closed
        raise SanitizeError(str(exc)) from exc


# ── caller-facing decision reasons (SECURITY: uniform + non-revealing) ──────
# The reason surfaced to the caller NEVER explains WHY a request was denied — a
# specific reason ("no matching policy" vs "forbidden by X" vs "amount exceeds
# limit") would leak the authorization boundary to an attacker probing it, who
# could then tune an attack. Every denial returns the SAME opaque reason; the
# Denied message still names the caller's own request (intent + tool), which is
# their input, not a leak. Operators reconstruct the true cause from signed
# lineage / the decisionId (Enterprise), never from this string.
DENY_REASON = "not authorized"
APPROVAL_REASON = "approval required"


def _reason_for_verdict(verdict: str) -> str:
    if verdict == "Deny":
        return DENY_REASON
    if verdict == "NeedsApproval":
        return APPROVAL_REASON
    return ""


class Watchlight:
    """An in-process policy decision point for a single agent.

    Wraps the ``watchlight-engine`` in-process authorization core. Policies are
    loaded from a local file or added inline; each governed tool call is
    authorized against them.
    """

    def __init__(self, agent: str | None = None, audit_dir: str | os.PathLike[str] = ".watchlight") -> None:
        self._engine = _engine.PolicyEngine()
        self.agent = agent or os.environ.get("WATCHLIGHT_AGENT", "my-agent")
        self._audit_path = pathlib.Path(audit_dir) / "audit.jsonl"
        self._announced = False
        self._policy_count = 0

    # ── policy loading ──────────────────────────────────────────────

    def allow(self, cedar_code: str, name: str | None = None) -> "Watchlight":
        """Add one Cedar policy inline. Returns self for chaining."""
        self._engine.add_policy(
            json.dumps({"name": name or f"policy-{self._policy_count}", "code": cedar_code})
        )
        self._policy_count += 1
        return self

    def load(self, path: str | os.PathLike[str]) -> "Watchlight":
        """Load policies from a JSON file — a list of ``{"name", "code"}`` objects
        (or ``{"policies": [...]}``). Fail-closed: a missing file loads nothing,
        so every governed call is denied until a policy permits it."""
        p = pathlib.Path(path)
        if not p.exists():
            return self
        data = json.loads(p.read_text())
        entries = data if isinstance(data, list) else data.get("policies", [])
        for entry in entries:
            self.allow(entry["code"], entry.get("name"))
        return self

    # ── sub-agent scope attenuation ─────────────────────────────────

    def scope(
        self,
        *,
        tools: Sequence[str] | None = None,
        resources: Sequence[str] | None = None,
        intents: Sequence[str] | None = None,
        max_depth: int = DE_MAX_DEPTH,
        time_budget_seconds: int = 3600,
    ) -> Scope:
        """Create a root capability scope for this agent, from which sub-agent
        scopes are attenuated (strict-subset).

        The Developer Edition governs the tree up to depth
        :data:`~watchlight.attenuation.DE_MAX_DEPTH` (5); Enterprise removes the
        ceiling and enforces it server-side. See
        :class:`~watchlight.attenuation.Scope`.
        """
        root = Scope(
            engine=self._engine,
            audit_path=self._audit_path,
            agent=self.agent,
            allowed_tools=tools,
            allowed_resources=resources,
            allowed_intents=intents,
            max_depth=min(int(max_depth), DE_MAX_DEPTH),
            time_budget_seconds=time_budget_seconds,
            depth=0,
        )
        root._emit_root()  # record the tree's starting authority for `watchlight dev`
        return root

    # ── governing tools ─────────────────────────────────────────────

    def tool(
        self,
        intent: str,
        *,
        principal: Union[str, Callable[..., str], None] = None,
        resource: Union[str, Callable[..., str], None] = None,
        context: Union[dict, Callable[..., dict], None] = None,
        on_needs_approval: Optional[Callable[[dict], bool]] = None,
        on_result: Optional[Callable[[Any, dict], Any]] = None,
    ) -> Callable[[_F], _F]:
        """Decorate a function as a governed tool.

        ``principal`` / ``resource`` / ``context`` may each be a fixed value or a
        callable of the tool's ``(*args, **kwargs)`` — so per-call runtime facts
        (amount, refundable, acting user, …) flow into Cedar evaluation. On a
        ``NeedsApproval`` decision, ``on_needs_approval(decision)`` (if given) is
        called; return ``True`` to proceed after a human confirms. Fail-closed:
        DENY raises :class:`Denied`; unconfirmed approval raises
        :class:`NeedsApproval`; the body never runs in either case.

        ``on_result(result, info)`` is the egress hook: called AFTER the body
        returns and BEFORE the result is handed back, with ``info = {"intent",
        "resource", "principal", "decision_id"}`` — the ``decision_id`` of the
        decision that let the body run. This is where you run ``sanitize``, a
        screen, or a second ``authorize`` against the result's classification.
        Return a value to replace the payload; return ``None`` to pass it
        through; raise to withhold it — the exception propagates and the raw
        result is never returned (fail-closed). A value-free ``egress`` audit
        record is written, joined to the decision record by ``decision_id``. If
        the body is a coroutine the hook runs once it is awaited (an awaitable
        hook return is awaited too). An async hook on a *synchronous* body is
        refused fail-closed: the payload is withheld and ``TypeError`` is raised.
        """

        def decorator(fn: _F) -> _F:
            name = fn.__name__

            @functools.wraps(fn)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                prin = _resolve(principal, args, kwargs) or self.agent
                res = _resolve(resource, args, kwargs) or f"tool/{name}"
                ctx = context(*args, **kwargs) if callable(context) else (context or {})

                def run(decision_id: Optional[str]) -> Any:
                    # Run the body, then the egress hook (if any) over its result.
                    out = fn(*args, **kwargs)
                    if on_result is None:
                        return out
                    info = {"intent": intent, "resource": res, "principal": prin, "decision_id": decision_id}
                    if inspect.isawaitable(out):
                        return self._apply_on_result_async(out, on_result, info)
                    return self._apply_on_result(out, on_result, info)[0]

                d = self.authorize(action=intent, principal=prin, resource=res, context=ctx)
                if d["allowed"]:
                    return run(d.get("decision_id"))
                if d["needs_approval"]:
                    if on_needs_approval is not None and on_needs_approval(d):
                        token = self.mint_approval(action=intent, principal=prin, resource=res)
                        d2 = self.authorize(
                            action=intent, principal=prin, resource=res, context=ctx, approval=token
                        )
                        if d2["allowed"]:
                            return run(d2.get("decision_id"))
                    raise NeedsApproval(name, intent, d.get("decision_id"), d["reason"])
                raise Denied(name, intent, d["reason"] or DENY_REASON)

            return wrapper  # type: ignore[return-value]

        return decorator

    def authorize(
        self,
        *,
        action: str,
        principal: Optional[str] = None,
        resource: Optional[str] = None,
        context: Optional[dict] = None,
        approval: Optional[str] = None,
    ) -> dict:
        """Authorize an action with full control — per-call ``principal``,
        ``resource``, and Cedar ``context`` — returning a three-state verdict and
        a correlation id. ``NeedsApproval`` (matched permit annotated
        ``require_approval``) is downgraded to ``Allow`` when a valid single-use
        ``approval`` token (from :meth:`mint_approval`, after a human confirms) is
        supplied. Fail-closed and audited (value-free)."""
        result, prin, res, decision_id = self._decide(
            action=action, principal=principal, resource=resource, context=context, approval=approval
        )
        self._audit(
            action, res, result["decision"], result["reason"],
            principal=prin, decision_id=decision_id, approved=result["approved"],
        )
        return result

    def _decide(
        self,
        *,
        action: str,
        principal: Optional[str] = None,
        resource: Optional[str] = None,
        context: Optional[dict] = None,
        approval: Optional[str] = None,
    ) -> tuple[dict, str, str, Optional[str]]:
        """The pure decision core behind :meth:`authorize`: run the engine, apply
        the approval-token downgrade, and compute the three-state verdict —
        WITHOUT writing to the audit trail. Used by :meth:`authorize` (which then
        audits) and by :meth:`test` (which must not pollute the trail)."""
        prin = principal or self.agent
        res = resource or "resource"
        raw = json.loads(
            self._engine.authorize(
                json.dumps({"principal": prin, "action": action, "resource": res, "context": context or {}})
            )
        )
        decision_id = raw.get("request_id")
        allowed = raw.get("decision") == "Allow"
        needs = allowed and _needs_approval(raw.get("details"))
        approved = False
        if needs:
            if approval and _consume_approval_token(approval, prin, action, res):
                approved, needs = True, False
            else:
                allowed = False
        verdict = "Allow" if allowed else ("NeedsApproval" if needs else "Deny")
        # Non-revealing, uniform reason (never the engine's specific one).
        reason = _reason_for_verdict(verdict)
        return (
            {
                "decision": verdict,
                "allowed": allowed,
                "needs_approval": needs,
                "approved": approved,
                "decision_id": decision_id,
                "reason": reason,
            },
            prin,
            res,
            decision_id,
        )

    def test(self, cases: Sequence[dict]) -> dict:
        """Run policy fixtures against the loaded policies and report which pass —
        a golden-test harness for CI, so a policy change is verified before it
        gates a real action. Each case is a dict with ``action`` and ``expect``
        (``"Allow"`` / ``"Deny"`` / ``"NeedsApproval"``), plus optional
        ``principal`` / ``resource`` / ``context``; set ``"approved": True`` to
        mint a valid approval token and assert the human-confirmed downgrade.
        Does NOT write to the audit trail. A verdict mismatch is a failed result
        (inspect ``report["failed"]`` and assert on it in your test runner); a
        malformed fixture missing ``action`` or ``expect`` raises ``ValueError``."""
        return run_policy_tests(
            lambda **req: self._decide(**req)[0],
            lambda **ch: self.mint_approval(**ch),
            cases,
        )

    def mint_approval(
        self,
        *,
        action: str,
        principal: Optional[str] = None,
        resource: Optional[str] = None,
        ttl_ms: int = 120_000,
    ) -> str:
        """Mint a single-use approval token bound to ``(principal, action,
        resource)``, to pass to :meth:`authorize` after a human confirms a
        ``NeedsApproval``. Local HMAC, TTL-bounded (default 2 min)."""
        return _mint_approval_token(principal or self.agent, action, resource or "resource", ttl_ms)

    def sanitize(
        self,
        content: str,
        *,
        intent: str = "read",
        resource: str = "document",
        mode: str = "tag",
        types: Optional[Sequence[str]] = None,
    ) -> dict:
        """Strip PII from text before an agent reads it (governed data
        minimization). Fail-closed; writes a value-free ``sanitization`` audit
        record. Extract a document to text first (never a "redacted PDF")."""
        result = sanitize(content, mode=mode, types=types)
        self._audit_sanitize(intent, resource, result)
        return result

    # ── internals ───────────────────────────────────────────────────

    def _apply_on_result(self, result: Any, on_result: Callable[[Any, dict], Any], info: dict) -> tuple[Any, bool]:
        """Run an egress hook over a governed tool's result and audit the outcome
        (shared by every governed wrapper so they behave identically). ``None``
        passes the payload through; any other value replaces it. If the hook
        raises, the exception propagates and NO value is returned — the raw
        result is withheld (fail-closed) — after an ``egress`` record marks the
        payload as withheld. Value-free: never the result, nor anything derived
        from it. Internal — not part of the public API."""
        try:
            replacement = on_result(result, info)
        except BaseException:
            self._audit_egress(info, replaced=False, withheld=True)
            raise
        if inspect.isawaitable(replacement):
            # An async hook on a synchronous body: there is no loop to await it
            # on, and handing back the coroutine object as the "payload" would
            # release nothing and audit a replacement that never happened.
            # Fail closed: withhold, and say so with a fixed, payload-free message.
            close = getattr(replacement, "close", None)
            if callable(close):
                close()
            self._audit_egress(info, replaced=False, withheld=True)
            raise TypeError(
                "on_result returned an awaitable for a synchronous tool body; "
                "an async hook requires an async tool body"
            )
        replaced = replacement is not None
        self._audit_egress(info, replaced=replaced)
        return (replacement if replaced else result), replaced

    async def _apply_on_result_async(self, awaitable: Any, on_result: Callable[[Any, dict], Any], info: dict) -> Any:
        """:meth:`_apply_on_result` for a coroutine body: await the result, run
        the hook (awaiting its return if awaitable), same fail-closed semantics."""
        result = await awaitable
        try:
            replacement = on_result(result, info)
            if inspect.isawaitable(replacement):
                replacement = await replacement
        except BaseException:
            self._audit_egress(info, replaced=False, withheld=True)
            raise
        replaced = replacement is not None
        self._audit_egress(info, replaced=replaced)
        return replacement if replaced else result

    def _audit_egress(self, info: dict, *, replaced: bool, withheld: bool = False) -> None:
        self._announce()
        disposition = "withheld" if withheld else ("replaced" if replaced else "passthrough")
        print(f"watchlight: EGRESS {info['intent']:9} {info['resource']}     {disposition}")
        # Value-free: the disposition of the payload only — never the payload,
        # its size, or anything derived from it. `decision_id` joins this line to
        # the call's decision record.
        record: dict[str, Any] = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "agent": self.agent,
            "principal": info["principal"],
            "intent": info["intent"],
            "event": "egress",
            "resource": info["resource"],
            "replaced": replaced,
        }
        if info.get("decision_id"):
            record["decision_id"] = info["decision_id"]
        if withheld:
            record["withheld"] = True
        self._write_audit(record)

    def _announce(self) -> None:
        if not self._announced:
            print(f"watchlight: governing '{self.agent}' (dev mode, in-process engine)")
            self._announced = True

    def _audit(
        self,
        intent: str,
        resource: str,
        decision: str,
        reason: str,
        *,
        principal: Optional[str] = None,
        decision_id: Optional[str] = None,
        approved: bool = False,
    ) -> None:
        self._announce()
        if decision == "Allow":
            tag = "OK✓" if approved else "ALLOW"
        elif decision == "NeedsApproval":
            tag = "APPRV?"
        else:
            tag = "DENY"
        trailer = "" if decision == "Allow" else f"     {reason or DENY_REASON}"
        print(f"watchlight: {tag:6} {intent:9} {resource}{trailer}")
        # Value-free audit: argument VALUES never enter the trail — only the
        # governance decision + correlation id. Mirrors the production contract.
        record: dict[str, Any] = {
            "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "agent": self.agent,
            "principal": principal or self.agent,
            "intent": intent,
            "resource": resource,
            "decision": decision,
        }
        if decision_id:
            record["decision_id"] = decision_id
        if approved:
            record["approved"] = True
        self._write_audit(record)

    def _audit_sanitize(self, intent: str, resource: str, result: dict) -> None:
        self._announce()
        report = result["report"]
        print(
            f"watchlight: SANIT  {intent:9} {resource}"
            f"     redacted {report['total']} ({report['mode']})"
        )
        # Value-free: counts by PII type + mode only — never the PII values.
        self._write_audit(
            {
                "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "agent": self.agent,
                "intent": intent,
                "event": "sanitization",
                "resource": resource,
                "mode": report["mode"],
                "detector": report["detector_version"],
                "counts": report["counts"],
                "total": report["total"],
            }
        )

    def _write_audit(self, record: dict) -> None:
        try:
            self._audit_path.parent.mkdir(parents=True, exist_ok=True)
            with self._audit_path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(record) + "\n")
        except OSError:
            # Audit is best-effort in dev mode; never let it break the app.
            pass


# A ready-to-use default governor so `from watchlight import govern` just works.
# It starts with NO policies — fail-closed by default — until you `govern.load(...)`
# a policy file or `govern.allow(...)` a policy inline.
govern = Watchlight()
