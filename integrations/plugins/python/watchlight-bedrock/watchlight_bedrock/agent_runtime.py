"""Governed ``bedrock-agent-runtime``: hosted capabilities on Bedrock Agents.

A Bedrock agent can run capabilities inside AWS that never reach a
customer Lambda: the code interpreter (``AMAZON.CodeInterpreter``), user
input (``AMAZON.UserInput``), the Anthropic computer, bash and text-editor
tools, and knowledge-base retrieval. :func:`watchlight_bedrock_action`
never sees them, so they are decided here, before the agent is invoked:

.. code-block:: python

    async with await plugin.start_run("research-analyst") as run:
        agents = run.bedrock_agent_runtime(
            boto3.client("bedrock-agent-runtime"),
            agent_client=boto3.client("bedrock-agent"),
        )
        response = await agents.invoke_agent(
            agentId=..., agentAliasId=..., sessionId=run.session_id, inputText=question,
        )

Each ``invoke_agent``:

1. Resolves the alias to its version with ``bedrock:GetAgentAlias``, on
   every call (an alias can be repointed at any time).
2. Reads that version's definition: ``GetAgentVersion`` (``GetAgent`` for
   ``DRAFT``), ``ListAgentActionGroups`` plus ``GetAgentActionGroup`` for
   each enabled group, and ``ListAgentKnowledgeBases``. The definition is
   cached per agent and version; ``DRAFT`` is never cached, because it
   changes without a new version.
3. Authorizes every hosted capability through the shared hosted-tool gate
   (``Tool::"<kind>"``, ``builtin_tool: true``), and every knowledge base
   the call itself names in ``sessionState.knowledgeBaseConfigurations``.
   Anything but Allow refuses the call
   (:class:`watchlight_core.HostedToolRefused`).
4. Authorizes a numbered version as ``invoke_agent_version`` on
   ``bedrock://agent/<agentId>/version/<n>``, on every call. No
   API shows whether a numbered version runs a custom orchestrator, so the
   policy author attests it by granting the version. ``DRAFT`` needs no
   grant.
5. Adds the Watchlight session attributes the action-group Lambdas need,
   and makes the call with the trace on. A ``customOrchestrationTrace``
   part in the stream ends the run (:class:`CustomOrchestrationObserved`).

Refused before the call, never passed through: a definition that can't be
read (a missing permission, an error, a timeout), a signature this plugin
does not know, a knowledge base without a valid id, a supervisor agent
(multi-agent collaboration), a custom orchestration Lambda or a prompt
override Lambda (customer code Bedrock runs on every step, outside
:func:`watchlight_bedrock_action`), and caller session attributes that use the
``watchlight_`` prefix. ``invoke_inline_agent`` is gated from what the
request carries, with the same rules.

Wrapping the client also registers a boto3 ``before-parameter-build`` hook
on it: ``InvokeAgent``, ``InvokeInlineAgent`` and every other operation
that runs an agent, a flow, a model or a retrieval are refused when they are
made on that client outside the wrapper.

A client nobody wrapped is refused the same way: constructing the plugin
installs the check for every ``bedrock-agent-runtime`` client in the process,
including clients created before it (:func:`install_unwrapped_call_guard`).
Such an operation goes through only when a wrapper makes it on that same
client.
"""

from __future__ import annotations

import asyncio
import contextvars
import re
import threading
from collections import OrderedDict
from typing import Any, Callable, Dict, Iterator, List, Mapping, Optional, Tuple

from watchlight_core import AuthorizeResult, get_logger
from watchlight_core.hosted_tools import (
    HostedTool,
    HostedToolRefused,
    HostedToolTurn,
    authorize_hosted_tools,
)

from .runtime import _TERMINAL_ERRORS, BedrockRequestRefused

logger = get_logger(__name__)

__all__ = ["GovernedBedrockAgentRuntime", "install_unwrapped_call_guard"]

#: ``parentActionGroupSignature`` → the hosted kind a policy names.
_SIGNATURE_KINDS: Dict[str, str] = {
    "AMAZON.CodeInterpreter": "code_interpreter",
    "AMAZON.UserInput": "user_input",
    "ANTHROPIC.Computer": "computer_use",
    "ANTHROPIC.Bash": "bash",
    "ANTHROPIC.TextEditor": "text_editor",
}
_KNOWLEDGE_BASE_KIND = "knowledge_base_retrieval"
#: Why a capability is refused before any decision (``HostedTool.problem``).
_UNKNOWN_SIGNATURE = "unknown_signature"

#: Operations any client may still make directly: the lifecycle of a
#: session and of an invocation, and tags. They run no agent, flow, model or
#: retrieval, return no stored content, and delete nothing. Everything else
#: (memory and invocation-step reads and writes, flow reads and control,
#: and every Delete*) is refused unless a wrapper makes it.
_DIRECT_OPERATIONS = frozenset(
    {
        "CreateSession",
        "EndSession",
        "GetSession",
        "ListSessions",
        "UpdateSession",
        "CreateInvocation",
        "ListInvocations",
        "ListTagsForResource",
        "TagResource",
        "UntagResource",
    }
)

_SESSION_ATTR_PREFIX = "watchlight_"
_DRAFT = "DRAFT"
#: A Bedrock knowledge-base id: ten letters or digits.
_KB_ID = re.compile(r"^[0-9A-Za-z]{10}$")
#: A Bedrock agent id: ten letters or digits.
_AGENT_ID = re.compile(r"^[0-9A-Za-z]{10}$")
#: A numbered agent version.
_VERSION_NUMBER = re.compile(r"^[1-9][0-9]{0,8}$")
#: The action a numbered agent version is authorized as, on
#: ``bedrock://agent/<agentId>/version/<n>``.
_VERSION_ACTION = "invoke_agent_version"
#: The trace part Bedrock sends while a custom orchestration Lambda runs.
_CUSTOM_ORCHESTRATION_TRACE = "customOrchestrationTrace"
_CUSTOM_ORCHESTRATION_OBSERVED = "custom_orchestration_observed"
_SUPERVISOR_MODES = frozenset({"SUPERVISOR", "SUPERVISOR_ROUTER"})
_COLLABORATION_OFF = "DISABLED"
#: Pages read from one list operation before the definition counts as
#: unreadable (an agent has at most a few dozen groups and bases).
_MAX_PAGES = 20
_CACHE_MAX = 256

#: The client whose call is being made through a wrapper right now.
_THROUGH_WRAPPER: contextvars.ContextVar[Optional[int]] = contextvars.ContextVar(
    "watchlight_bedrock_agent_runtime_through_wrapper", default=None
)


#: The botocore event the guard on unwrapped clients listens on.
_GUARD_EVENT = "before-parameter-build.bedrock-agent-runtime"
_GUARD_ID = "watchlight-unwrapped-agent-runtime"
_guard_lock = threading.Lock()


def _refuse_unwrapped_call(model: Any = None, **_: Any) -> None:
    """The ``before-parameter-build`` form of the check, for client classes
    that do not go through ``BaseClient._make_api_call``. Runs before the
    request is built, so nothing is sent."""
    name = getattr(model, "name", None)
    if name in _DIRECT_OPERATIONS or _THROUGH_WRAPPER.get() is not None:
        return None
    raise BedrockRequestRefused(
        "ungoverned_call",
        f"{name} must be made through a Watchlight run's bedrock_agent_runtime()",
    )


_guard_installed = False


def install_unwrapped_call_guard() -> bool:
    """Refuse ungoverned operations on every ``bedrock-agent-runtime``
    client in the process, wrapped or not.

    ``botocore.client.BaseClient._make_api_call``, which every operation of
    every botocore client goes through, is wrapped once at class level, so
    clients created before this call are covered too. On a
    ``bedrock-agent-runtime`` client, an operation outside
    ``_DIRECT_OPERATIONS`` is refused unless a wrapper is making it on that
    same client (a call on another client made from inside a wrapped call
    is refused).

    For client classes that override ``_make_api_call`` (aiobotocore's, for
    one), the same check is also added to ``botocore.handlers.BUILTIN_HANDLERS``,
    which every session created afterwards registers, and to boto3's default
    session. Returns ``False`` when botocore is not installed (there is no
    client to guard). Installing again does nothing.
    """
    global _guard_installed
    try:
        from botocore import handlers
        from botocore.client import BaseClient
    except ImportError:
        return False
    with _guard_lock:
        if not _guard_installed:
            original = BaseClient._make_api_call

            def _make_api_call(self: Any, operation_name: str, api_params: Any) -> Any:
                if (
                    _service(self) == "bedrock-agent-runtime"
                    and operation_name not in _DIRECT_OPERATIONS
                    and _THROUGH_WRAPPER.get() != id(self)
                ):
                    raise BedrockRequestRefused(
                        "ungoverned_call",
                        f"{operation_name} must be made through a Watchlight run's bedrock_agent_runtime()",
                    )
                return original(self, operation_name, api_params)

            _make_api_call.__wrapped__ = original  # type: ignore[attr-defined]
            _make_api_call.__watchlight_guard__ = True  # type: ignore[attr-defined]
            BaseClient._make_api_call = _make_api_call  # type: ignore[method-assign]
            _guard_installed = True
        spec = (_GUARD_EVENT, _refuse_unwrapped_call, handlers.REGISTER_FIRST)
        if spec not in handlers.BUILTIN_HANDLERS:
            handlers.BUILTIN_HANDLERS.append(spec)
    try:
        import boto3
    except ImportError:
        return True
    default = boto3.DEFAULT_SESSION
    if default is not None:
        default.events.register_first(_GUARD_EVENT, _refuse_unwrapped_call, unique_id=_GUARD_ID)
    return True


class _DefinitionUnreadable(Exception):
    pass


def _capability(kind: str, name: str, *, problem: Optional[str] = None) -> HostedTool:
    summary = f"bedrock:{kind}" + (f" name={name}" if name and name != kind else "")
    if problem:
        summary += f" problem={problem}"
    return HostedTool("bedrock", kind, name, summary[:120], problem=problem)


def _signature_capability(signature: Any) -> Optional[HostedTool]:
    """The hosted capability an action group's signature enables, or
    ``None`` for a customer group (a Lambda or return of control)."""
    if signature is None:
        return None
    kind = _SIGNATURE_KINDS.get(signature) if isinstance(signature, str) else None
    if kind is None:
        return _capability("unknown", "action_group_signature", problem=_UNKNOWN_SIGNATURE)
    return _capability(kind, kind)


def _knowledge_base(kb_id: Any) -> HostedTool:
    if not isinstance(kb_id, str) or not _KB_ID.match(kb_id):
        raise BedrockRequestRefused(
            "knowledge_base_unresolved", "a knowledge base on the call has no valid id"
        )
    return _capability(_KNOWLEDGE_BASE_KIND, f"kb:{kb_id}")


def _refuse_supervisor(collaboration: Any) -> None:
    if collaboration is None or collaboration == _COLLABORATION_OFF:
        return
    raise BedrockRequestRefused(
        "supervisor_unsupported",
        "multi-agent collaboration is not governed yet; a supervisor agent is refused",
    )


def _refuse_customer_lambdas(source: Mapping[str, Any]) -> None:
    """Refuse an agent whose loop runs a customer Lambda outside
    :func:`watchlight_bedrock_action`: a custom orchestrator, or a parser
    ``overrideLambda``. Bedrock calls these on every step, ungoverned."""
    custom = source.get("orchestrationType")
    if (custom is not None and custom != "DEFAULT") or source.get("customOrchestration"):
        raise BedrockRequestRefused(
            "custom_orchestration_unsupported",
            "an agent with a custom orchestration Lambda is not governed",
        )
    override = source.get("promptOverrideConfiguration")
    if override is not None and (not isinstance(override, Mapping) or override.get("overrideLambda")):
        raise BedrockRequestRefused(
            "prompt_override_lambda_unsupported",
            "an agent with a prompt override Lambda is not governed",
        )


def _enabled(state: Any) -> bool:
    return state != "DISABLED"


class CustomOrchestrationObserved(BedrockRequestRefused):
    """The agent's trace showed a custom orchestration Lambda running.
    The Lambda runs in AWS and was not stopped; the stream is no
    longer read and the run is ended."""

    def __init__(self) -> None:
        super().__init__(
            _CUSTOM_ORCHESTRATION_OBSERVED,
            "the agent's trace shows custom orchestration; the run was ended",
        )


def _version_uri(agent_id: str, version: str) -> str:
    return f"bedrock://agent/{agent_id}/version/{version}"


def _shows_custom_orchestration(event: Any) -> bool:
    trace = event.get("trace") if isinstance(event, Mapping) else None
    inner = trace.get("trace") if isinstance(trace, Mapping) else None
    return isinstance(inner, Mapping) and _CUSTOM_ORCHESTRATION_TRACE in inner


def _watch_completion(stream: Any, stop: Callable[[], None]) -> Iterator[Any]:
    """The events of ``stream``, until one shows custom orchestration: then
    ``stop`` runs, the stream is closed, and :class:`CustomOrchestrationObserved`
    is raised instead of that event."""
    try:
        for event in stream:
            if _shows_custom_orchestration(event):
                stop()
                raise CustomOrchestrationObserved()
            yield event
    finally:
        close = getattr(stream, "close", None)
        if callable(close):
            close()


class GovernedBedrockAgentRuntime:
    """A ``bedrock-agent-runtime`` client whose agent invocations are
    governed on one Watchlight run. See the module docstring.

    ``client`` is a boto3 ``bedrock-agent-runtime`` client and
    ``agent_client`` a boto3 ``bedrock-agent`` client, used only to read
    agent definitions. ``handle`` is the open run. The boto3 calls run in a
    worker thread, so the event loop is never blocked.
    """

    def __init__(
        self,
        client: Any,
        handle: Any,
        *,
        agent_client: Any,
        authorize_timeout_seconds: float = 10.0,
        definition_timeout_seconds: float = 10.0,
    ) -> None:
        meta = getattr(client, "meta", None)
        if _service(client) != "bedrock-agent-runtime":
            raise TypeError("GovernedBedrockAgentRuntime needs a boto3 'bedrock-agent-runtime' client")
        if _service(agent_client) != "bedrock-agent":
            raise TypeError("GovernedBedrockAgentRuntime needs a boto3 'bedrock-agent' client as agent_client")
        self._client = client
        self._agents = agent_client
        self._handle = handle
        self._timeout = authorize_timeout_seconds
        self._definition_timeout = definition_timeout_seconds
        self._definitions: "OrderedDict[Tuple[str, str], Tuple[HostedTool, ...]]" = OrderedDict()
        #: Set once custom orchestration was observed: the run is over.
        self._halted = False
        meta.events.register_first(
            "before-parameter-build.bedrock-agent-runtime",
            self._refuse_direct_call,
            unique_id=f"watchlight-governed-agents-{id(client)}",
        )

    # ── the bypass hook ─────────────────────────────────────────────

    def _refuse_direct_call(self, model: Any = None, **_: Any) -> None:
        name = getattr(model, "name", None)
        if name in _DIRECT_OPERATIONS or _THROUGH_WRAPPER.get() == id(self._client):
            return None
        raise BedrockRequestRefused(
            "ungoverned_call",
            f"{name} on a governed client must be made through GovernedBedrockAgentRuntime",
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

    # ── the definition read ─────────────────────────────────────────

    def _pages(self, method: str, key: str, **params: Any) -> List[Mapping[str, Any]]:
        items: List[Mapping[str, Any]] = []
        token: Optional[str] = None
        for _ in range(_MAX_PAGES):
            page = getattr(self._agents, method)(**params, **({"nextToken": token} if token else {}))
            items.extend(page.get(key) or [])
            token = page.get("nextToken")
            if not token:
                return items
        raise _DefinitionUnreadable(f"{method} returned more than {_MAX_PAGES} pages")

    def _versions(self, agent_id: str, alias_id: str) -> List[str]:
        alias = self._agents.get_agent_alias(agentId=agent_id, agentAliasId=alias_id)["agentAlias"]
        versions = [r.get("agentVersion") for r in alias.get("routingConfiguration") or []]
        if not versions or not all(isinstance(v, str) and v for v in versions):
            raise _DefinitionUnreadable("the alias names no agent version")
        return versions

    def _read_definition(self, agent_id: str, version: str) -> Tuple[HostedTool, ...]:
        draft = self._agents.get_agent(agentId=agent_id)["agent"]
        if version == _DRAFT:
            agent = draft
        else:
            agent = self._agents.get_agent_version(agentId=agent_id, agentVersion=version)["agentVersion"]
            # A version does not report its orchestration type; only the
            # working draft does. Refuse when the draft runs a custom
            # orchestrator. The version itself must be granted by policy
            # (_authorize_versions).
            _refuse_customer_lambdas(
                {k: draft.get(k) for k in ("orchestrationType", "customOrchestration")}
            )
        _refuse_supervisor(agent.get("agentCollaboration"))
        _refuse_customer_lambdas(agent)

        found: List[HostedTool] = []
        groups = self._pages(
            "list_agent_action_groups", "actionGroupSummaries", agentId=agent_id, agentVersion=version
        )
        for summary in groups:
            if not _enabled(summary.get("actionGroupState")):
                continue
            group = self._agents.get_agent_action_group(
                agentId=agent_id, agentVersion=version, actionGroupId=summary["actionGroupId"]
            )["agentActionGroup"]
            if not _enabled(group.get("actionGroupState")):
                continue
            capability = _signature_capability(group.get("parentActionSignature"))
            if capability is not None:
                found.append(capability)
        kbs = self._pages(
            "list_agent_knowledge_bases", "agentKnowledgeBaseSummaries", agentId=agent_id, agentVersion=version
        )
        for kb in kbs:
            if _enabled(kb.get("knowledgeBaseState")):
                found.append(_knowledge_base(kb.get("knowledgeBaseId")))
        return tuple(found)

    def _definition_capabilities(self, agent_id: str, alias_id: str) -> Tuple[List[HostedTool], List[str]]:
        found: List[HostedTool] = []
        versions = self._versions(agent_id, alias_id)
        for version in versions:
            key = (agent_id, version)
            cached = self._definitions.get(key)
            if cached is None:
                cached = self._read_definition(agent_id, version)
                if version != _DRAFT:
                    self._definitions[key] = cached
                    while len(self._definitions) > _CACHE_MAX:
                        self._definitions.popitem(last=False)
            found.extend(cached)
        return found, versions

    async def _agent_capabilities(self, agent_id: Any, alias_id: Any) -> Tuple[List[HostedTool], List[str]]:
        """The hosted capabilities of the versions the alias routes to, and
        those versions."""
        if not isinstance(agent_id, str) or not agent_id or not isinstance(alias_id, str) or not alias_id:
            raise BedrockRequestRefused("agent_definition_unreadable", "agentId and agentAliasId are required")
        if not _AGENT_ID.match(agent_id):
            raise BedrockRequestRefused("malformed", "agentId is not a Bedrock agent id")
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._definition_capabilities, agent_id, alias_id),
                self._definition_timeout,
            )
        except asyncio.CancelledError:
            raise
        except BedrockRequestRefused:
            raise
        except Exception as exc:  # noqa: BLE001 - fail closed: an unreadable definition refuses the call
            logger.warning(
                "Bedrock agent definition unreadable; invoke_agent refused (%s)", type(exc).__name__
            )
            raise BedrockRequestRefused(
                "agent_definition_unreadable",
                "the agent's definition could not be read (check the bedrock-agent read permissions)",
            ) from None

    # ── the gate ────────────────────────────────────────────────────

    async def _authorize_versions(self, agent_id: str, versions: List[str]) -> None:
        """A numbered version runs only when policy permits
        ``invoke_agent_version`` on ``bedrock://agent/<id>/version/<n>``:
        no API shows whether a numbered version uses a custom
        orchestrator, so the policy author attests it. Decided on every
        call, so an alias moved to another version is decided again.
        ``DRAFT`` is checked from its definition instead."""
        for version in versions:
            if version == _DRAFT:
                continue
            allowed = False
            if _VERSION_NUMBER.match(version):
                try:
                    result = await asyncio.wait_for(
                        self._handle.authorize_action_detailed(
                            action=_VERSION_ACTION, resource=_version_uri(agent_id, version)
                        ),
                        self._timeout,
                    )
                    allowed = isinstance(result, AuthorizeResult) and result.is_allow()
                except asyncio.CancelledError:
                    raise
                except _TERMINAL_ERRORS:
                    raise
                except Exception as exc:  # noqa: BLE001 - fail closed: no decision refuses the call
                    logger.warning(
                        "Bedrock agent version authorization failed (%s); invoke_agent refused",
                        type(exc).__name__,
                    )
                    raise BedrockRequestRefused(
                        "agent_version_not_permitted", "this agent version is not permitted"
                    ) from None
            if not allowed:
                logger.warning("[DENY-AGENT-VERSION] agent %s version %s is not permitted", agent_id, version)
                raise BedrockRequestRefused("agent_version_not_permitted", "this agent version is not permitted")

    def _refuse_if_halted(self) -> None:
        if self._halted:
            raise BedrockRequestRefused(
                _CUSTOM_ORCHESTRATION_OBSERVED, "custom orchestration was observed on this run; it was ended"
            )

    def _watched(self, response: Any, agent_id: str, alias_id: str, versions: List[str]) -> Any:
        """``response`` with its ``completion`` stream watched for custom
        orchestration. Seeing it halts this wrapper and ends the run. It
        does not stop the Lambda, which runs in AWS."""
        if not isinstance(response, Mapping) or "completion" not in response:
            return response
        loop = asyncio.get_running_loop()
        where = f"agent={agent_id} alias={alias_id} version={','.join(versions)}"

        def stop() -> None:
            self._halted = True
            logger.warning("[%s] %s: the stream is no longer read and the run is ended", _CUSTOM_ORCHESTRATION_OBSERVED, where)
            ending = self._handle.terminate(reason=f"{_CUSTOM_ORCHESTRATION_OBSERVED}: {where}")
            try:
                asyncio.run_coroutine_threadsafe(ending, loop)
            except RuntimeError:  # the run's loop is closed: the run already ended
                ending.close()

        return {**response, "completion": _watch_completion(response["completion"], stop)}

    async def _gate(self, capabilities: List[HostedTool]) -> None:
        turn = HostedToolTurn()
        try:
            gate = await authorize_hosted_tools(
                self._handle, capabilities, turn, provider="bedrock", timeout_seconds=self._timeout
            )
            if not gate.allowed:
                raise HostedToolRefused(gate)
        finally:
            turn.seal()

    def _session_state(self, state: Any, *, collaborator: bool) -> Dict[str, Any]:
        if state is None:
            state = {}
        if not isinstance(state, Mapping):
            raise BedrockRequestRefused("malformed", "sessionState must be a mapping")
        attrs = state.get("sessionAttributes") or {}
        if not isinstance(attrs, Mapping):
            raise BedrockRequestRefused("malformed", "sessionState.sessionAttributes must be a mapping")
        if any(isinstance(k, str) and k.startswith(_SESSION_ATTR_PREFIX) for k in attrs):
            raise BedrockRequestRefused(
                "session_attributes_conflict",
                f"session attributes starting with '{_SESSION_ATTR_PREFIX}' are set by Watchlight",
            )
        ours = (
            self._handle._bedrock_collaborator_session_attributes()
            if collaborator
            else self._handle._bedrock_session_attributes()
        )
        return {**state, "sessionAttributes": {**attrs, **ours}}

    @staticmethod
    def _call_knowledge_bases(entries: Any, where: str) -> List[HostedTool]:
        if entries is None:
            return []
        if not isinstance(entries, (list, tuple)):
            raise BedrockRequestRefused("knowledge_base_unresolved", f"{where} must be a list")
        return [_knowledge_base(e.get("knowledgeBaseId") if isinstance(e, Mapping) else None) for e in entries]

    # ── the operations ──────────────────────────────────────────────

    async def invoke_agent(self, *, collaborator: bool = False, **kwargs: Any) -> Any:
        """``InvokeAgent``, made only after every hosted capability the
        agent version and the call enable is allowed. ``collaborator=True``
        adds the parent-run reference a collaborator's Lambda reads (see
        :mod:`watchlight_bedrock.collaborator`)."""
        self._refuse_if_halted()
        state = self._session_state(kwargs.get("sessionState"), collaborator=collaborator)
        on_call = self._call_knowledge_bases(
            state.get("knowledgeBaseConfigurations"), "sessionState.knowledgeBaseConfigurations"
        )
        agent_id, alias_id = kwargs.get("agentId"), kwargs.get("agentAliasId")
        capabilities, versions = await self._agent_capabilities(agent_id, alias_id)
        await self._authorize_versions(agent_id, versions)
        await self._gate(capabilities + on_call)
        # The trace is how custom orchestration is seen, so it is always on.
        response = await self._call("invoke_agent", {**kwargs, "sessionState": state, "enableTrace": True})
        return self._watched(response, agent_id, alias_id, versions)

    async def invoke_inline_agent(self, **kwargs: Any) -> Any:
        """``InvokeInlineAgent``, made only after every hosted capability
        the request carries is allowed. Collaborators are refused."""
        self._refuse_if_halted()
        if kwargs.get("collaborators") or kwargs.get("collaboratorConfigurations"):
            _refuse_supervisor("SUPERVISOR")
        _refuse_supervisor(kwargs.get("agentCollaboration"))
        _refuse_customer_lambdas(kwargs)
        groups = kwargs.get("actionGroups") or []
        if not isinstance(groups, (list, tuple)):
            raise BedrockRequestRefused("malformed", "actionGroups must be a list")
        capabilities: List[HostedTool] = []
        for group in groups:
            if not isinstance(group, Mapping):
                raise BedrockRequestRefused("malformed", "an action group must be a mapping")
            capability = _signature_capability(group.get("parentActionGroupSignature"))
            if capability is not None:
                capabilities.append(capability)
        capabilities += self._call_knowledge_bases(kwargs.get("knowledgeBases"), "knowledgeBases")
        state = kwargs.get("inlineSessionState")
        if state is not None:
            state = self._session_state(state, collaborator=False)
        else:
            state = self._session_state({}, collaborator=False)
        await self._gate(capabilities)
        return await self._call("invoke_inline_agent", {**kwargs, "inlineSessionState": state})


def _service(client: Any) -> Optional[str]:
    meta = getattr(client, "meta", None)
    return getattr(getattr(meta, "service_model", None), "service_name", None)
