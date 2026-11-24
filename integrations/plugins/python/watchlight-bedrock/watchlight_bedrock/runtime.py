"""Governed ``bedrock-runtime``: tool use outside Bedrock Agents.

A workload that calls the Bedrock runtime directly (``Converse``,
``ConverseStream``, ``InvokeModel``) runs its own tool loop: the model
answers with ``toolUse`` blocks and the calling code runs each tool. No
Bedrock Agents Lambda is involved, so :func:`watchlight_bedrock_action`
never fires. :class:`GovernedBedrockRuntime` is the enforcement point for
that loop:

.. code-block:: python

    async with await plugin.start_run("payments-agent") as run:
        runtime = run.bedrock_runtime(boto3.client("bedrock-runtime"))
        response = await runtime.converse(modelId=..., messages=..., toolConfig=...)
        # every toolUse in ``response`` is allowed; run them

Each model call:

1. **Before the call**, the FINAL request (``toolConfig`` and
   ``additionalModelRequestFields`` included) goes through the shared
   provider-hosted tool gate (:func:`watchlight_core.authorize_hosted_request`).
   Anything but Allow refuses the call (:class:`watchlight_core.HostedToolRefused`).
2. **After the call, before the caller sees it**, every ``toolUse`` the
   model asked for is authorized on the run
   (``authorize_action_detailed(action="execute", resource=<tool>)``,
   with value-free argument metadata). Anything but Allow (a deny, an
   approval requirement, an error, a timeout, a tool the request never
   declared) raises :class:`BedrockToolUseRefused` and the response is
   withheld. A run-ending decision raises its typed error.
3. Each decision is published as a value-free ``tool_call_observed``
   event on the run (best effort; wl-apdp's decision log is the record).

Wrapping the client also registers a boto3 ``before-parameter-build`` hook on it:
any model-invoking operation made on that client *outside* the wrapper is
refused, so the governed client cannot be bypassed by calling it directly.

Not covered (refused, never passed through): ``InvokeModel`` /
``InvokeModelWithResponseStream`` with tools for any model family other
than Anthropic Claude (Messages API), streamed ``InvokeModel`` with tools,
a Prompt Management ARN as ``modelId`` (a stored prompt can carry its own
tools), and every other model-invoking operation
(``InvokeModelWithBidirectionalStream``, ``StartAsyncInvoke``). Tool calls
a caller parses out of free text are invisible at this layer.
"""

from __future__ import annotations

import asyncio
import contextvars
import io
import json
import re
from typing import Any, AsyncIterator, Dict, Iterable, List, Mapping, Optional, Tuple

from watchlight_core import (
    AgentQuarantinedError,
    AuthorizeResult,
    WatchlightError,
    get_logger,
)
from watchlight_core.decision import (
    AgentRevokedError,
    ExecutionTerminatedError,
    SubtreeSeveredError,
)
from watchlight_core.errors import RunHandleInvalidated
from watchlight_core.events_schema import summarize_arg_keys
from watchlight_core.hosted_tools import HostedToolTurn, require_hosted_request_allowed

logger = get_logger(__name__)

__all__ = [
    "BedrockRequestRefused",
    "BedrockToolUseRefused",
    "GovernedBedrockRuntime",
]

#: Operations a governed client may still make directly: they invoke no
#: model and run no tool. Every other operation is refused unless it is
#: made through the wrapper.
_DIRECT_OPERATIONS = frozenset({"ApplyGuardrail", "CountTokens", "GetAsyncInvoke", "ListAsyncInvokes"})

#: Keys that declare tools in an ``InvokeModel`` body, for any family.
_TOOL_BODY_KEYS = ("tools", "tool_choice", "toolConfig", "tool_config", "functions", "tool_definitions")

_MAX_ARG_NAMES = 32
_MAX_TYPE_LEN = 32
#: An argument name the model sends: letters, digits, ``_``, ``-`` and
#: ``.``, at most 64 characters. Anything else is refused, never sent.
_ARG_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")

_TERMINAL_ERRORS: Tuple[type, ...] = (
    AgentQuarantinedError,
    ExecutionTerminatedError,
    SubtreeSeveredError,
    AgentRevokedError,
    RunHandleInvalidated,
)

#: Model-facing texts for :meth:`BedrockToolUseRefused.tool_results`.
#: Opaque: the decision's reason stays in Watchlight's audit trail.
_REFUSED_TEXT = {
    "denied": "Denied by Watchlight policy. The tool was not run.",
    "approval_required": "This tool needs human approval in Watchlight. The tool was not run.",
    "unavailable": "Watchlight could not authorize this tool call, so it was not run.",
    "undeclared_tool": "The model asked for a tool this request did not declare. It was not run.",
    "malformed": "The tool call could not be read, so it was not run.",
    "undeclared_argument": "The tool call named an argument the tool does not declare. It was not run.",
}
_NOT_RUN_TEXT = "Not run: another tool call in this turn was refused by Watchlight."

#: The client whose call is being made through a wrapper right now (its
#: ``id``), read by the bypass hook on the calling thread.
_THROUGH_WRAPPER: contextvars.ContextVar[Optional[int]] = contextvars.ContextVar(
    "watchlight_bedrock_runtime_through_wrapper", default=None
)


async def gate_hosted_request(
    handle: Any,
    request: Mapping[str, Any],
    *,
    provider: str,
    registered_mcp_servers: Optional[Mapping[str, str]],
    timeout_seconds: Optional[float],
) -> HostedToolTurn:
    """The hosted-tool gate every governed model call goes through: raises
    :class:`watchlight_core.HostedToolRefused` on anything but Allow and
    returns the turn of its decisions."""
    turn = HostedToolTurn()
    await require_hosted_request_allowed(
        handle,
        request,
        turn,
        provider=provider,
        registered_mcp_servers=registered_mcp_servers,
        timeout_seconds=timeout_seconds,
    )
    return turn


class BedrockRequestRefused(WatchlightError):
    """A Bedrock runtime request Watchlight cannot govern was refused
    before it was sent. ``reason`` is a short code."""

    def __init__(self, reason: str, message: str) -> None:
        self.reason = reason
        super().__init__(f"Watchlight refused the Bedrock request ({reason}): {message}")


class BedrockToolUseRefused(WatchlightError):
    """A ``toolUse`` the model asked for was refused: none of this turn's
    tool calls may run.

    ``tool_name`` and ``tool_use_id`` name the refused call; ``reason`` is
    ``denied``, ``approval_required``, ``unavailable``, ``undeclared_tool``,
    ``undeclared_argument`` or ``malformed``; ``tool_use_ids`` are every tool call of the turn
    seen so far. :meth:`tool_results` builds the ``toolResult`` blocks to
    send back to the model so it learns none of them ran.

    ``assistant_message`` is the model's turn that asked for them (a
    Converse message, or the Anthropic Messages turn for ``InvokeModel``),
    so the conversation can continue with the ``toolResult`` errors. It is
    ``None`` for a stream: the gate holds the whole turn back, so none of
    that turn's events reached the caller, and the turn was never assembled
    into a message.
    """

    def __init__(self, *, tool_name: str, tool_use_id: str, reason: str, tool_use_ids: Iterable[str]) -> None:
        self.tool_name = tool_name
        self.tool_use_id = tool_use_id
        self.reason = reason
        self.tool_use_ids = tuple(tool_use_ids)
        self.assistant_message: Optional[Dict[str, Any]] = None
        super().__init__(
            f"Watchlight refused the tool call '{tool_name}' ({reason}); no tool call of this turn may run"
        )

    def tool_results(self) -> List[Dict[str, Any]]:
        """Converse ``toolResult`` content blocks, one per tool call of the
        turn, each with ``status: error``."""
        out = []
        for tid in self.tool_use_ids:
            text = _REFUSED_TEXT[self.reason] if tid == self.tool_use_id else _NOT_RUN_TEXT
            out.append({"toolResult": {"toolUseId": tid, "status": "error", "content": [{"text": text}]}})
        return out


#: The tools a request declares: name -> the argument names its input
#: schema declares (empty when the schema names no properties).
Declared = Dict[str, frozenset]


def _schema_properties(schema: Any) -> frozenset:
    props = schema.get("properties") if isinstance(schema, Mapping) else None
    if not isinstance(props, Mapping):
        return frozenset()
    return frozenset(str(k) for k in props)


def _arguments_ok(tool_input: Any, declared_args: frozenset) -> bool:
    """A tool call's input is an object whose argument names are safe to
    send (at most 32, each a short plain name) and all declared in the
    tool's schema ``properties``. A schema that declares no properties
    admits only an empty input. The names come from the model, so nothing
    else is sent to Watchlight."""
    if tool_input is None:
        return True
    if not isinstance(tool_input, Mapping) or len(tool_input) > _MAX_ARG_NAMES:
        return False
    for key in tool_input:
        if not isinstance(key, str) or not _ARG_NAME.match(key):
            return False
        if key not in declared_args:
            return False
    return True


def _arg_metadata(tool_args: Any) -> Dict[str, Any]:
    """Value-free metadata of a checked tool call's input (see
    :func:`_arguments_ok`): argument names (sorted), the count and each
    value's type name. Never a value."""
    if isinstance(tool_args, Mapping):
        return {
            "arg_count": len(tool_args),
            "arg_names": sorted(tool_args),
            "arg_types": {k: type(v).__name__[:_MAX_TYPE_LEN] for k, v in tool_args.items()},
        }
    return {"arg_count": 0, "arg_names": []}


def _converse_declared_tools(request: Mapping[str, Any]) -> Declared:
    """The ``toolSpec`` tools a Converse request declares, with the
    properties of each one's ``inputSchema.json``."""
    cfg = request.get("toolConfig")
    tools = cfg.get("tools") if isinstance(cfg, Mapping) else None
    declared: Declared = {}
    for entry in tools or ():
        spec = entry.get("toolSpec") if isinstance(entry, Mapping) else None
        name = spec.get("name") if isinstance(spec, Mapping) else None
        if isinstance(name, str) and name:
            schema = spec.get("inputSchema")
            declared[name] = _schema_properties(schema.get("json") if isinstance(schema, Mapping) else None)
    return declared


def _anthropic_declared_tools(body: Mapping[str, Any]) -> Declared:
    """The client tools (no ``type``, or ``custom``) an Anthropic Messages
    body declares, with each one's ``input_schema`` properties. Server
    tools come back as ``server_tool_use`` and are governed by the
    hosted-tool gate instead."""
    declared: Declared = {}
    for entry in body.get("tools") or ():
        if not isinstance(entry, Mapping) or entry.get("type") not in (None, "custom"):
            continue
        name = entry.get("name")
        if isinstance(name, str) and name:
            declared[name] = _schema_properties(entry.get("input_schema"))
    return declared


def _is_anthropic(model_id: Any, body: Mapping[str, Any]) -> bool:
    return "anthropic_version" in body or (isinstance(model_id, str) and "anthropic." in model_id)


def _refuse_prompt_arn(model_id: Any) -> None:
    if isinstance(model_id, str) and ":prompt/" in model_id:
        raise BedrockRequestRefused(
            "stored_prompt",
            "a Prompt Management ARN can carry its own tools; pass the model id and the request instead",
        )


class GovernedBedrockRuntime:
    """A ``bedrock-runtime`` client whose model calls and tool uses are
    governed on one Watchlight run. See the module docstring.

    ``client`` is a boto3 ``bedrock-runtime`` client; ``handle`` is the
    open run (a :class:`watchlight_core.BaseRunHandle`, entered with
    ``async with``). The boto3 calls run in a worker thread, so the event
    loop is never blocked.
    """

    def __init__(
        self,
        client: Any,
        handle: Any,
        *,
        authorize_timeout_seconds: float = 10.0,
        registered_mcp_servers: Optional[Mapping[str, str]] = None,
    ) -> None:
        meta = getattr(client, "meta", None)
        service = getattr(getattr(meta, "service_model", None), "service_name", None)
        if service != "bedrock-runtime":
            raise TypeError("GovernedBedrockRuntime needs a boto3 'bedrock-runtime' client")
        self._client = client
        self._handle = handle
        self._timeout = authorize_timeout_seconds
        self._mcp_servers = registered_mcp_servers
        # ``before-parameter-build`` fires before the request is built or
        # sent, and before any ``before-call`` handler (a Stubber, say) can
        # answer the call in its place.
        meta.events.register_first(
            "before-parameter-build.bedrock-runtime",
            self._refuse_direct_call,
            unique_id=f"watchlight-governed-{id(client)}",
        )

    # ── the bypass hook ─────────────────────────────────────────────

    def _refuse_direct_call(self, model: Any = None, **_: Any) -> None:
        name = getattr(model, "name", None)
        if name in _DIRECT_OPERATIONS or _THROUGH_WRAPPER.get() == id(self._client):
            return None
        raise BedrockRequestRefused(
            "ungoverned_call",
            f"{name} on a governed client must be made through GovernedBedrockRuntime",
        )

    async def _call(self, method: str, kwargs: Dict[str, Any]) -> Any:
        client_id = id(self._client)

        def call() -> Any:
            token = _THROUGH_WRAPPER.set(client_id)
            try:
                return getattr(self._client, method)(**kwargs)
            finally:
                _THROUGH_WRAPPER.reset(token)

        return await asyncio.to_thread(call)

    async def _gate_request(self, request: Mapping[str, Any], provider: str) -> HostedToolTurn:
        return await gate_hosted_request(
            self._handle,
            request,
            provider=provider,
            registered_mcp_servers=self._mcp_servers,
            timeout_seconds=self._timeout,
        )

    # ── the tool-use gate ───────────────────────────────────────────

    async def _authorize_tool_use(
        self, name: Any, tool_use_id: Any, tool_input: Any, declared: Declared, seen: List[str]
    ) -> None:
        """Authorize one tool call, raising :class:`BedrockToolUseRefused`
        on anything but Allow."""
        tid = str(tool_use_id)
        tool = name if isinstance(name, str) else "unknown"

        def refuse(reason: str) -> BedrockToolUseRefused:
            return BedrockToolUseRefused(tool_name=tool, tool_use_id=tid, reason=reason, tool_use_ids=seen)

        if tool not in declared:
            logger.warning("[DENY-UNDECLARED] the model asked for an undeclared tool; refused")
            await self._observe(tool, None, "Deny")
            raise refuse("undeclared_tool")
        if not _arguments_ok(tool_input, declared[tool]):
            logger.warning("[DENY-ARGUMENTS] tool %s: undeclared or unsafe argument names; refused", tool)
            await self._observe(tool, None, "Deny")
            raise refuse("undeclared_argument")
        try:
            result = await asyncio.wait_for(
                self._handle.authorize_action_detailed(
                    action="execute",
                    resource=tool,
                    context={"tool_args": _arg_metadata(tool_input)},
                ),
                timeout=self._timeout,
            )
            if not isinstance(result, AuthorizeResult):
                raise WatchlightError("authorization returned an unexpected result")
        except _TERMINAL_ERRORS:
            raise
        except Exception as exc:  # noqa: BLE001 — every other failure refuses
            logger.warning("[DENY-UNAVAILABLE] tool %s: authorization failed (%s); refused", tool, type(exc).__name__)
            raise refuse("unavailable") from None
        if result.is_allow():
            await self._observe(tool, tool_input, "Allow")
            return
        await self._observe(tool, tool_input, "Deny")
        raise refuse("approval_required" if result.needs_approval() else "denied")

    async def _authorize_blocks(self, uses: List[Tuple[Any, Any, Any]], declared: Declared) -> None:
        seen = [str(tid) for _, tid, _ in uses]
        for name, tid, tool_input in uses:
            await self._authorize_tool_use(name, tid, tool_input, declared, seen)

    async def _observe(self, tool_name: str, tool_args: Any, decision: str) -> None:
        """Publish a value-free ``tool_call_observed`` (best effort)."""
        payload: Dict[str, Any] = {
            "tool": {
                "resource_type": "tool",
                "identifier": tool_name,
                "endpoint": f"bedrock://tool/{tool_name}",
            },
            "action": {"action": "execute"},
            "decision": decision,
        }
        keys = summarize_arg_keys(tool_args) if isinstance(tool_args, Mapping) else None
        if keys:
            payload["arg_key_summary"] = keys
        try:
            await self._handle.publish_observation(
                event_type="tool_call_observed",
                payload=payload,
                extra_metadata={"bedrock_surface": "runtime"},
            )
        except Exception:  # noqa: BLE001 — lineage here is best effort
            logger.debug("tool_call_observed emit failed", exc_info=True)

    # ── Converse ────────────────────────────────────────────────────

    async def converse(self, **kwargs: Any) -> Dict[str, Any]:
        """``bedrock-runtime.converse``, governed. Returns the response
        unchanged once every ``toolUse`` in it is allowed."""
        _refuse_prompt_arn(kwargs.get("modelId"))
        turn = await self._gate_request(kwargs, "bedrock")
        try:
            response = await self._call("converse", kwargs)
        finally:
            turn.seal()
        content = (((response.get("output") or {}).get("message") or {}).get("content")) or []
        uses = []
        for block in content:
            use = block.get("toolUse") if isinstance(block, Mapping) else None
            if isinstance(use, Mapping):
                uses.append((use.get("name"), use.get("toolUseId"), use.get("input")))
        try:
            await self._authorize_blocks(uses, _converse_declared_tools(kwargs))
        except BedrockToolUseRefused as refused:
            refused.assistant_message = (response.get("output") or {}).get("message")
            raise
        return response

    async def converse_stream(self, **kwargs: Any) -> Dict[str, Any]:
        """``bedrock-runtime.converse_stream``, governed. ``response["stream"]``
        is an async iterator of the same events. The whole turn is held back
        until ``messageStop``, so nothing from it reaches the caller before
        every tool use in it is decided (as with ``converse``). A refusal, or
        a stream whose blocks cannot be read (a block or delta that is not
        an object, a tool delta for a block that is not a started tool use,
        a block started twice, a tool use that never stops, content after
        the turn), raises
        :class:`BedrockToolUseRefused` from the iterator and closes the
        stream."""
        _refuse_prompt_arn(kwargs.get("modelId"))
        turn = await self._gate_request(kwargs, "bedrock")
        try:
            response = await self._call("converse_stream", kwargs)
        finally:
            turn.seal()
        out = dict(response)
        out["stream"] = self._govern_converse_events(response["stream"], _converse_declared_tools(kwargs))
        return out

    async def _govern_converse_events(self, stream: Any, declared: Declared) -> AsyncIterator[Dict[str, Any]]:
        it = iter(stream)
        done = object()
        held: List[Dict[str, Any]] = []
        tools: Dict[int, Dict[str, Any]] = {}  # contentBlockIndex -> tool-use block
        others: set = set()  # indexes of the turn's other blocks
        released = False

        def malformed(name: Any = None, tid: Any = None) -> BedrockToolUseRefused:
            ids = [b["id"] for _, b in sorted(tools.items())]
            return BedrockToolUseRefused(
                tool_name=str(name or "unknown"),
                tool_use_id=str(tid or "unknown"),
                reason="malformed",
                tool_use_ids=ids,
            )

        try:
            while True:
                event = await asyncio.to_thread(next, it, done)
                if event is done:
                    break
                if not isinstance(event, Mapping):
                    raise malformed()
                start = event.get("contentBlockStart")
                delta = event.get("contentBlockDelta")
                stop = event.get("contentBlockStop")
                block = start if start is not None else delta if delta is not None else stop
                if released:
                    if block is not None:
                        raise malformed()  # content after the turn
                    yield event
                    continue
                if block is not None:
                    index = block.get("contentBlockIndex") if isinstance(block, Mapping) else None
                    if not isinstance(index, int) or isinstance(index, bool):
                        raise malformed()
                    if start is not None:
                        if index in tools or index in others:
                            raise malformed()  # a block started twice
                        body = start.get("start")
                        if body is not None and not isinstance(body, Mapping):
                            raise malformed()
                        tool_start = body.get("toolUse") if body is not None else None
                        if tool_start is not None and not isinstance(tool_start, Mapping):
                            raise malformed()
                        if isinstance(tool_start, Mapping):
                            tools[index] = {
                                "name": tool_start.get("name"),
                                "id": str(tool_start.get("toolUseId")),
                                "input": [],
                                "stopped": False,
                            }
                        else:
                            others.add(index)
                    elif delta is not None:
                        body = delta.get("delta")
                        if not isinstance(body, Mapping):
                            raise malformed()
                        piece = body.get("toolUse")
                        tool = tools.get(index)
                        if piece is not None:
                            # A tool delta must be an object with string input,
                            # inside a started, open tool use.
                            if (
                                not isinstance(piece, Mapping)
                                or tool is None
                                or tool["stopped"]
                                or not isinstance(piece.get("input"), str)
                            ):
                                raise malformed()
                            tool["input"].append(piece["input"])
                        elif tool is not None:
                            raise malformed()  # other content inside a tool use
                        else:
                            others.add(index)
                    else:
                        tool = tools.get(index)
                        if tool is not None:
                            if tool["stopped"]:
                                raise malformed(tool["name"], tool["id"])
                            tool["stopped"] = True
                held.append(event)
                if "messageStop" not in event:
                    continue
                uses = []
                for _, tool in sorted(tools.items()):
                    if not tool["stopped"]:
                        raise malformed(tool["name"], tool["id"])
                    raw = "".join(tool["input"])
                    try:
                        uses.append((tool["name"], tool["id"], json.loads(raw) if raw else {}))
                    except ValueError:
                        raise malformed(tool["name"], tool["id"]) from None
                await self._authorize_blocks(uses, declared)
                for e in held:
                    yield e
                held, released = [], True
            if not released:
                # The stream ended before the turn did.
                if tools:
                    first = tools[min(tools)]
                    raise malformed(first["name"], first["id"])
                for e in held:
                    yield e
        except BedrockToolUseRefused as refused:
            if refused.reason == "malformed":
                # Every refusal leaves a record: a value-free Deny, named by
                # the tool only when the request declared it.
                name = refused.tool_name if refused.tool_name in declared else "unknown"
                await self._observe(name, None, "Deny")
            raise
        finally:
            close = getattr(stream, "close", None)
            if callable(close):
                close()

    # ── InvokeModel ─────────────────────────────────────────────────

    async def invoke_model(self, **kwargs: Any) -> Dict[str, Any]:
        """``bedrock-runtime.invoke_model``, governed. An Anthropic Claude
        (Messages API) body is gated like Converse; a body of any other
        family that declares tools is refused. ``response["body"]`` is a
        fresh stream over the bytes Watchlight read."""
        model_id = kwargs.get("modelId")
        _refuse_prompt_arn(model_id)
        body = self._read_request_body(kwargs)
        anthropic = _is_anthropic(model_id, body)
        if not anthropic and any(k in body for k in _TOOL_BODY_KEYS):
            raise BedrockRequestRefused(
                "tool_use_not_covered",
                "InvokeModel tool use is governed for Anthropic Claude only; use Converse for other models",
            )
        turn = await self._gate_request(body, "anthropic") if anthropic else None
        try:
            response = await self._call("invoke_model", kwargs)
        finally:
            if turn is not None:
                turn.seal()
        raw = response["body"].read()
        if anthropic:
            try:
                answer = json.loads(raw)
            except ValueError:
                raise BedrockRequestRefused("malformed", "the model response could not be read") from None
            content = answer.get("content") if isinstance(answer, Mapping) else None
            uses = [
                (b.get("name"), b.get("id"), b.get("input"))
                for b in content or ()
                if isinstance(b, Mapping) and b.get("type") == "tool_use"
            ]
            try:
                await self._authorize_blocks(uses, _anthropic_declared_tools(body))
            except BedrockToolUseRefused as refused:
                refused.assistant_message = {"role": "assistant", "content": content}
                raise
        out = dict(response)
        out["body"] = _streaming_body(raw)
        return out

    async def invoke_model_with_response_stream(self, **kwargs: Any) -> Dict[str, Any]:
        """``bedrock-runtime.invoke_model_with_response_stream``, governed
        only without tools: a body that declares tools is refused (use
        ``converse_stream``). The response is returned as boto3 gives it."""
        _refuse_prompt_arn(kwargs.get("modelId"))
        body = self._read_request_body(kwargs)
        if any(k in body for k in _TOOL_BODY_KEYS) or "mcp_servers" in body:
            raise BedrockRequestRefused(
                "tool_use_not_covered",
                "streamed InvokeModel with tools is not governed; use converse_stream",
            )
        return await self._call("invoke_model_with_response_stream", kwargs)

    @staticmethod
    def _read_request_body(kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """The request body as a mapping. A file-like body is read once and
        replaced by its bytes; a body that is not a JSON object is refused,
        since what it enables cannot be read."""
        body = kwargs.get("body")
        if hasattr(body, "read"):
            body = body.read()
            kwargs["body"] = body
        try:
            parsed = json.loads(body) if isinstance(body, (bytes, bytearray, str)) else None
        except ValueError:
            parsed = None
        if not isinstance(parsed, dict):
            raise BedrockRequestRefused("unreadable_body", "the request body is not a JSON object")
        return parsed


def _streaming_body(raw: bytes) -> Any:
    from botocore.response import StreamingBody

    return StreamingBody(io.BytesIO(raw), len(raw))
