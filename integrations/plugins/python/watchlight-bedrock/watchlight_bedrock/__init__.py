"""Watchlight governance plugin for AWS Bedrock Agents.

Public API::

    from watchlight_bedrock import (
        WatchlightBedrockPlugin,
        RunHandle,
        watchlight_bedrock_action,
        AgentNotRegistered,
        GovernanceUnavailable,
    )

See ``plugin.py`` for the integration patterns (orchestrator-side
``start_run`` + Lambda action-group decorator).
"""

from .apdp_client import ApdpClient
from .plugin import (
    AgentNotRegistered,
    GovernanceUnavailable,
    PlanResult,
    PreflightResult,
    RunHandle,
    WatchlightBedrockPlugin,
    WatchlightError,
    governance_mode,
    watchlight_bedrock_action,
)
from .agent_runtime import CustomOrchestrationObserved, GovernedBedrockAgentRuntime
from .runtime import BedrockRequestRefused, BedrockToolUseRefused, GovernedBedrockRuntime
from .collaborator import (
    ENV_DEFAULT_SUBAGENT_SCOPE,
    SESSION_ATTR_PARENT_AGENT_ID,
    SESSION_ATTR_PARENT_RUN_HANDLE_ID,
    SESSION_ATTR_PARENT_SESSION_ID,
    CollaboratorGovernanceUnavailable,
    CollaboratorSpawnRef,
    RequestedCollaboratorScope,
    extract_collaborator_spawn_ref,
    requested_scope_from_env,
    scope_from_action_group_tools,
    spawn_collaborator_subagent,
)
from .state_adapter import state_from_bedrock_plugin
from .synthetic_intent_tool import (
    SYNTHETIC_ACTION_GROUP_NAME,
    SYNTHETIC_API_PATH,
    SYNTHETIC_FUNCTION_NAME,
    build_synthetic_action_group_function_schema,
    build_synthetic_action_group_schema,
    handle_synthetic_bedrock_invocation,
    is_synthetic_bedrock_event,
    render_synthetic_lambda_handler,
)
from .traces import translate_bedrock_trace

__all__ = [
    "ApdpClient",
    "WatchlightBedrockPlugin",
    "RunHandle",
    "PlanResult",
    "PreflightResult",
    "WatchlightError",
    "AgentNotRegistered",
    "GovernanceUnavailable",
    "watchlight_bedrock_action",
    "state_from_bedrock_plugin",
    "governance_mode",
    "translate_bedrock_trace",
    # Bedrock runtime (Converse / InvokeModel) tool use.
    "GovernedBedrockRuntime",
    # Bedrock Agents hosted capabilities.
    "CustomOrchestrationObserved",
    "GovernedBedrockAgentRuntime",
    "BedrockToolUseRefused",
    "BedrockRequestRefused",
    # Cross-process collaborator pattern. Governed spawn itself is
    # deferred to a future single-use spawn-authorization token; these
    # are the pattern + non-sensitive reference plumbing.
    "CollaboratorGovernanceUnavailable",
    "CollaboratorSpawnRef",
    "RequestedCollaboratorScope",
    "extract_collaborator_spawn_ref",
    "requested_scope_from_env",
    "scope_from_action_group_tools",
    "spawn_collaborator_subagent",
    "SESSION_ATTR_PARENT_AGENT_ID",
    "SESSION_ATTR_PARENT_SESSION_ID",
    "SESSION_ATTR_PARENT_RUN_HANDLE_ID",
    "ENV_DEFAULT_SUBAGENT_SCOPE",
    # Synthetic ``watchlight.declare_intent`` Bedrock surface.
    "SYNTHETIC_ACTION_GROUP_NAME",
    "SYNTHETIC_FUNCTION_NAME",
    "SYNTHETIC_API_PATH",
    "build_synthetic_action_group_schema",
    "build_synthetic_action_group_function_schema",
    "is_synthetic_bedrock_event",
    "handle_synthetic_bedrock_invocation",
    "render_synthetic_lambda_handler",
]

__version__ = "0.4.0"
