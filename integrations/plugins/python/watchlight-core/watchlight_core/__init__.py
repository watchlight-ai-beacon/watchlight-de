"""Watchlight AI shared governance primitives — used by every framework plugin.

This package is the single source of truth for:

- The HTTP wire format with WL-APDP (``ApdpClient``)
- The plan-validation / preflight result wrappers
- The plan-normalisation contract
- The framework-agnostic ``GovernanceState`` shape rendered by the
  Streamlit / Beacon Dashboard governance card
- The base run-handle lifecycle (resolve → session → manifest → close)
- Shared error types and the ``governance_mode`` env reader

Framework-specific behaviour stays in the plugin packages
(``watchlight-adk``, ``watchlight-langgraph``, ``watchlight-bedrock``,
…). When you bring up a new plugin, you only own the framework
integration surface; everything in this module is reused.

Public API is intentionally narrow. Anything not re-exported here is
considered internal to a future minor release.
"""

from .apdp_client import (
    TRUSTED_AGENT_STATES,
    ApdpClient,
    trust_from_resolved,
)
from .application import (
    APPLICATION_ID_ENV_VAR,
    application_id_from_env,
    resolve_application_id,
)
from .backend import (
    EgressBinding,
    GovernanceBackend,
    KillNotice,
    RunRef,
    SessionInfo,
    Unsubscribe,
)
from .in_process_client import InProcessClient
from .sidecar_backend import SidecarBackend, SidecarEgress, select_backend
from .log import configure_logging, get_logger
from .connect_proxy import (
    install_connect_proxy,
    is_connect_proxy_installed,
    uninstall_connect_proxy,
)
from .sidecar import (
    install_sidecar,
    is_sidecar_installed,
    uninstall_sidecar,
)
from .credentials import (
    Credential,
    CredentialKind,
    CredentialNotFound,
    InvalidCredential,
    PluginCredential,
    ServiceCredential,
    load_default_credential,
)
from .declare_intent import (
    BROWNFIELD,
    DECLARE_INTENT_RESPONSE_STATUS,
    DECLARE_INTENT_TOOL_DESCRIPTION,
    DECLARE_INTENT_TOOL_NAME,
    GREENFIELD,
    INTENT_ENFORCEMENT_MODE_ENV_VAR,
    WATCHLIGHT_DECLARE_INTENT_TOOL,
    handle_declare_intent_call,
    is_declare_intent_tool_call,
    is_declare_intent_tool_name,
    resolve_intent_enforcement_mode,
    should_inject_synthetic_tool,
    truncate_intent_objective,
    INTENT_CATEGORIES,
    normalize_intent_category,
    typed_intent,
    wire_intent,
    normalize_intent_justification,
    INTENT_JUSTIFICATION_MAX_BYTES,
)
from .decision import (
    AgentQuarantinedError,
    AgentRevokedError,
    AllowDecision,
    Attenuation,
    AuthorizationDecision,
    DenyDecision,
    Escalation,
    ExecutionTerminatedError,
    NeedsApprovalDecision,
    Observation,
    QuarantineDecision,
    RevokeDecision,
    RunHandleState,
    SeverSubtreeDecision,
    SubtreeSeveredError,
    TerminateDecision,
    parse_authorization_decision,
)
from .decorator import watchlight
from .errors import (
    AgentNotRegistered,
    CredentialBindsNoAgent,
    CredentialProbeFailed,
    EngineVersionUnsupported,
    GovernanceRefused,
    GovernanceUnavailable,
    ParentRunUncredentialed,
    RunUncredentialed,
    SidecarRunActive,
    InsecureChannelError,
    RunHandleInvalidated,
    ScopeAttenuationDenied,
    ScopeViolationDimension,
    WatchlightContractError,
    WatchlightError,
    IntentRefused,
)
from .env import governance_mode, require_manifest
from .events_schema import (
    EVENT_ID_PATTERN,
    EVENT_ID_RE,
    ERROR_MESSAGE_MAX_CHARS,
    INPUT_SUMMARY_MAX_CHARS,
    INTENT_OBJECTIVE_MAX_BYTES,
    LIFT_REASON_MAX_BYTES,
    MAX_CONTRIBUTING_FEATURES,
    REASON_MAX_BYTES,
    ActionRef,
    CredentialRef,
    EventEnvelope,
    EventType,
    ExecutionEvent,
    ExecutionQuarantinedPayload,
    ExecutionResumedPayload,
    FeatureContribution,
    IntentProvenance,
    PrincipalRef,
    ResourceRef,
    redacted_error_summary,
    redacted_arg_metadata,
    redacted_input_summary,
    summarize_arg_keys,
    truncate_error_message,
    truncate_summary,
)
from .kill_signal import (
    DISPOSITION_GRACEFUL,
    DISPOSITION_PROXY_HARD_KILL,
    DISPOSITION_UNCONFIRMED,
    DISPOSITIONS,
    ESCALATION_ATTEMPTED,
    ESCALATION_CONFIRMED,
    ESCALATION_FAILED,
    ESCALATION_SKIPPED,
    ESCALATION_UNKNOWN,
    ESCALATIONS,
    InterceptorKillRegistry,
    KILL_SIGNAL_GRACEFUL_WINDOW_MS,
    KillSignalResult,
    LLM_CALL_INTERRUPTED_REASON_HARD_TIMEOUT,
    LLM_CALL_INTERRUPTED_REASON_MANUAL_TERMINATE,
    LLM_CALL_INTERRUPTED_REASON_POLICY_TERMINATE,
    LLM_CALL_INTERRUPTED_REASON_QUARANTINE,
    LLM_CALL_INTERRUPTED_REASON_REVOKE,
    LLM_CALL_INTERRUPTED_REASON_SCOPE_VIOLATION,
    LLM_CALL_INTERRUPTED_REASON_SEVER_SUBTREE,
    LlmCallInterruptedPayload,
    LlmCallInterruptedValidationError,
    RegisterRequestOptions,
    classify_kill_endpoint_status,
    default_kill_signal_registry,
    httpx_hard_kill_escalator,
)
from .otlp import (
    OtlpConfig,
    OtlpProfile,
    WatchlightOtlpExporter,
)
from .plan import normalize_plan
from .plan_event import (
    PLAN_INTENDED_TOOLS_MAX,
    PLAN_RATIONALE_MAX_BYTES,
    PLAN_TOOL_NAME_PATTERN,
    PLAN_TOOL_NAME_RE,
    PlanKind,
    PlanValidationError,
    build_plan_payload,
    filter_valid_tool_names,
    is_valid_tool_name,
    truncate_rationale,
)
from .results import AuthorizeResult, PlanResult, PreflightResult
from .run_grant import RunGrant
from .run_handle import (
    BaseRunHandle,
    GovernedPlugin,
    HandleLineage,
    current_handle_lineage,
    current_subagent_handle,
)
from .root_identity import (
    CHILD_IDENTITIES,
    CHILD_IDENTITY_ANONYMOUS,
    CHILD_IDENTITY_MAPPED,
    CHILD_IDENTITY_REGISTERED,
    MAX_CHILD_LABEL_BYTES,
    SUBAGENT_LABEL_CONTEXT_KEY,
    open_root_session,
    validate_child_label,
)
from .scope import (
    CHILD_INTENT_CATEGORY_MAX_BYTES,
    CHILD_INTENT_OBJECTIVE_MAX_BYTES,
    DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY,
    ChildIntent,
    child_intent_from_dict,
    child_intent_to_dict,
    coerce_child_intent,
    plugin_child_intent,
    GrantedScope,
    ParentSignature,
    RequestedScope,
    ResourceMatcher,
    SpawnSubagentRequest,
    SpawnSubagentResponse,
    granted_scope_from_dict,
    granted_scope_to_dict,
    parent_signature_from_dict,
    parent_signature_to_dict,
    requested_scope_from_dict,
    requested_scope_to_dict,
    resource_matcher_from_dict,
    resource_matcher_to_dict,
    spawn_subagent_request_from_dict,
    spawn_subagent_request_to_dict,
    spawn_subagent_response_from_dict,
    spawn_subagent_response_to_dict,
)
from .state import GovernanceState, state_from_attrs
from .subagent_registry import (
    DEFAULT_SUBAGENT_SCOPE_ENV_VAR,
    SubagentRegistry,
    default_subagent_scope_from_env,
)
from .telemetry import GovernanceTelemetry
from .actions import ACTION_CONVENTIONS, DEFAULT_ACTION, resolve_action
from .hosted_tools import (
    ALLOWED_TOOLS_INVALID,
    HOSTED_MCP_SERVER_UNREGISTERED,
    HOSTED_TOOL_CONFIG_INVALID,
    MCP_SERVER_AMBIGUOUS,
    HOSTED_TOOL_METADATA,
    HOSTED_TOOL_PROVIDERS,
    HOSTED_TOOL_REFUSED_TIMEOUT,
    HOSTED_TOOL_REFUSED_UNAVAILABLE,
    HostedTool,
    HostedToolGateResult,
    HostedToolRefused,
    HostedToolRequest,
    HostedToolTurn,
    authorize_hosted_request,
    authorize_hosted_tools,
    hosted_tool_identity,
    hosted_tool_observation,
    hosted_tool_request,
    normalize_hosted_request,
    normalize_hosted_tools,
    normalize_mcp_server_url,
    publish_hosted_tool_observed,
    require_hosted_request_allowed,
    require_hosted_request_allowed_blocking,
)

__all__ = [
    # Client
    "ApdpClient",
    "TRUSTED_AGENT_STATES",
    "trust_from_resolved",
    "InProcessClient",
    "GovernanceBackend",
    "RunRef",
    "SessionInfo",
    "KillNotice",
    "EgressBinding",
    "Unsubscribe",
    "SidecarBackend",
    "SidecarEgress",
    "select_backend",
    "configure_logging",
    "get_logger",
    # CONNECT local sidecar proxy
    "install_connect_proxy",
    "is_connect_proxy_installed",
    "uninstall_connect_proxy",
    "install_sidecar",
    "is_sidecar_installed",
    "uninstall_sidecar",
    # Credentials
    "Credential",
    "CredentialKind",
    "CredentialNotFound",
    "InvalidCredential",
    "PluginCredential",
    "load_default_credential",
    "ServiceCredential",
    # Launcher-bound runs: the run-scoped grant handed into a workload
    "RunGrant",
    # Decorator (custom-agent SDK)
    "watchlight",
    # Errors
    "WatchlightError",
    "WatchlightContractError",
    "AgentNotRegistered",
    "CredentialBindsNoAgent",
    "CredentialProbeFailed",
    "EngineVersionUnsupported",
    "GovernanceRefused",
    "GovernanceUnavailable",
    "ParentRunUncredentialed",
    "RunUncredentialed",
    "SidecarRunActive",
    "InsecureChannelError",
    # Sub-agent scope attenuation typed errors
    "RunHandleInvalidated",
    "ScopeAttenuationDenied",
    "ScopeViolationDimension",
    # OTLP export
    "OtlpConfig",
    "OtlpProfile",
    "WatchlightOtlpExporter",
    # Result wrappers
    "AuthorizeResult",
    "PlanResult",
    "PreflightResult",
    # Plan
    "normalize_plan",
    # PlanObserved event helpers
    "PLAN_INTENDED_TOOLS_MAX",
    "PLAN_RATIONALE_MAX_BYTES",
    "PLAN_TOOL_NAME_PATTERN",
    "PLAN_TOOL_NAME_RE",
    "PlanKind",
    "PlanValidationError",
    "build_plan_payload",
    "filter_valid_tool_names",
    "is_valid_tool_name",
    "truncate_rationale",
    # State + telemetry
    "GovernanceState",
    "GovernanceTelemetry",
    "state_from_attrs",
    # Install once at the root: credential-bound root + labelled sub-agents
    "open_root_session",
    "validate_child_label",
    "CHILD_IDENTITIES",
    "CHILD_IDENTITY_ANONYMOUS",
    "CHILD_IDENTITY_MAPPED",
    "CHILD_IDENTITY_REGISTERED",
    "MAX_CHILD_LABEL_BYTES",
    "SUBAGENT_LABEL_CONTEXT_KEY",
    # Lifecycle base
    "BaseRunHandle",
    "GovernedPlugin",
    # Sub-agent contextvar accessor
    "current_subagent_handle",
    # Lineage snapshot contextvar (introspection only; never sent as a
    # header: wl-proxy takes identity from the verified proxy token).
    "HandleLineage",
    "current_handle_lineage",
    # Env
    "governance_mode",
    "require_manifest",
    # AI application attribution
    "APPLICATION_ID_ENV_VAR",
    "application_id_from_env",
    "resolve_application_id",
    # Events schema — pydantic mirror of the canonical lineage events
    "ActionRef",
    "CredentialRef",
    "EventEnvelope",
    "EventType",
    "ExecutionEvent",
    "PrincipalRef",
    "ResourceRef",
    "EVENT_ID_PATTERN",
    "EVENT_ID_RE",
    "INPUT_SUMMARY_MAX_CHARS",
    "ERROR_MESSAGE_MAX_CHARS",
    "redacted_error_summary",
    "redacted_arg_metadata",
    "redacted_input_summary",
    "summarize_arg_keys",
    "truncate_error_message",
    "truncate_summary",
    # Intent provenance enum + byte cap (mirrors the canonical
    # IntentProvenance + INTENT_OBJECTIVE_MAX_BYTES)
    "INTENT_OBJECTIVE_MAX_BYTES",
    "IntentProvenance",
    # Quarantine event payload mirrors + size constants
    "ExecutionQuarantinedPayload",
    "ExecutionResumedPayload",
    "FeatureContribution",
    "LIFT_REASON_MAX_BYTES",
    "MAX_CONTRIBUTING_FEATURES",
    "REASON_MAX_BYTES",
    # Typed authorization decision + handle state machine
    "AgentQuarantinedError",
    "AgentRevokedError",
    "AllowDecision",
    "Attenuation",
    "AuthorizationDecision",
    "DenyDecision",
    "Escalation",
    "ExecutionTerminatedError",
    "NeedsApprovalDecision",
    "Observation",
    "QuarantineDecision",
    "RevokeDecision",
    "RunHandleState",
    "SeverSubtreeDecision",
    "SubtreeSeveredError",
    "TerminateDecision",
    "parse_authorization_decision",
    # Kill-signal protocol for HTTP interceptors
    "InterceptorKillRegistry",
    "KILL_SIGNAL_GRACEFUL_WINDOW_MS",
    "DISPOSITION_GRACEFUL",
    "DISPOSITION_PROXY_HARD_KILL",
    "DISPOSITION_UNCONFIRMED",
    "DISPOSITIONS",
    "ESCALATION_SKIPPED",
    "ESCALATION_ATTEMPTED",
    "ESCALATION_FAILED",
    "ESCALATION_UNKNOWN",
    "ESCALATION_CONFIRMED",
    "ESCALATIONS",
    "classify_kill_endpoint_status",
    "default_kill_signal_registry",
    "LLM_CALL_INTERRUPTED_REASON_QUARANTINE",
    "LLM_CALL_INTERRUPTED_REASON_SCOPE_VIOLATION",
    "LLM_CALL_INTERRUPTED_REASON_MANUAL_TERMINATE",
    "LLM_CALL_INTERRUPTED_REASON_HARD_TIMEOUT",
    "LLM_CALL_INTERRUPTED_REASON_POLICY_TERMINATE",
    "LLM_CALL_INTERRUPTED_REASON_SEVER_SUBTREE",
    "LLM_CALL_INTERRUPTED_REASON_REVOKE",
    "LlmCallInterruptedPayload",
    "LlmCallInterruptedValidationError",
    "KillSignalResult",
    "RegisterRequestOptions",
    "httpx_hard_kill_escalator",
    # Synthetic ``watchlight.declare_intent`` tool contract.
    "BROWNFIELD",
    "DECLARE_INTENT_RESPONSE_STATUS",
    "DECLARE_INTENT_TOOL_DESCRIPTION",
    "DECLARE_INTENT_TOOL_NAME",
    "GREENFIELD",
    "INTENT_ENFORCEMENT_MODE_ENV_VAR",
    "WATCHLIGHT_DECLARE_INTENT_TOOL",
    "handle_declare_intent_call",
    "is_declare_intent_tool_call",
    "is_declare_intent_tool_name",
    "resolve_intent_enforcement_mode",
    "should_inject_synthetic_tool",
    "truncate_intent_objective",
    "INTENT_CATEGORIES",
    "normalize_intent_category",
    "typed_intent",
    "wire_intent",
    "normalize_intent_justification",
    "INTENT_JUSTIFICATION_MAX_BYTES",
    "IntentRefused",
    # Sub-agent scope attenuation wire shapes.
    "ChildIntent",
    "CHILD_INTENT_CATEGORY_MAX_BYTES",
    "CHILD_INTENT_OBJECTIVE_MAX_BYTES",
    "DEFAULT_PLUGIN_CHILD_INTENT_CATEGORY",
    "child_intent_from_dict",
    "child_intent_to_dict",
    "coerce_child_intent",
    "plugin_child_intent",
    "GrantedScope",
    "ParentSignature",
    "RequestedScope",
    "ResourceMatcher",
    "SpawnSubagentRequest",
    "SpawnSubagentResponse",
    "granted_scope_from_dict",
    "granted_scope_to_dict",
    "parent_signature_from_dict",
    "parent_signature_to_dict",
    "requested_scope_from_dict",
    "requested_scope_to_dict",
    "resource_matcher_from_dict",
    "resource_matcher_to_dict",
    "spawn_subagent_request_from_dict",
    "spawn_subagent_request_to_dict",
    "spawn_subagent_response_from_dict",
    "spawn_subagent_response_to_dict",
    # Uniform governed-spawn routing primitive.
    "SubagentRegistry",
    "DEFAULT_SUBAGENT_SCOPE_ENV_VAR",
    "default_subagent_scope_from_env",
    # Action verbs (shared prefix conventions)
    "ACTION_CONVENTIONS",
    "DEFAULT_ACTION",
    "resolve_action",
    # Provider-hosted tools: normalize, authorize per model call, record
    "ALLOWED_TOOLS_INVALID",
    "HOSTED_MCP_SERVER_UNREGISTERED",
    "HOSTED_TOOL_CONFIG_INVALID",
    "MCP_SERVER_AMBIGUOUS",
    "HOSTED_TOOL_METADATA",
    "HOSTED_TOOL_PROVIDERS",
    "HOSTED_TOOL_REFUSED_TIMEOUT",
    "HOSTED_TOOL_REFUSED_UNAVAILABLE",
    "HostedTool",
    "HostedToolGateResult",
    "HostedToolRefused",
    "HostedToolRequest",
    "HostedToolTurn",
    "authorize_hosted_request",
    "authorize_hosted_tools",
    "hosted_tool_identity",
    "hosted_tool_observation",
    "hosted_tool_request",
    "normalize_hosted_request",
    "normalize_hosted_tools",
    "normalize_mcp_server_url",
    "publish_hosted_tool_observed",
    "require_hosted_request_allowed",
    "require_hosted_request_allowed_blocking",
]

# Read from the installed distribution so this can never drift from
# pyproject.toml again — it had been reporting 0.5.0 while the package
# shipped as 0.6.0. The literal is only a fallback for a source checkout
# that was never installed.
try:  # pragma: no cover - trivial, and environment-dependent
    from importlib.metadata import PackageNotFoundError as _PkgNotFound
    from importlib.metadata import version as _dist_version

    __version__ = _dist_version("watchlight-agent-sdk")
except Exception:  # noqa: BLE001 - a version string must never fail an import
    __version__ = "0.10.2"
