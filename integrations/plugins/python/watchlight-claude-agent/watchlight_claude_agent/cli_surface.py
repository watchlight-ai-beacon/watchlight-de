"""The Claude Code environment variables and CLI flags a governed session
may carry.

Claude Code reads hundreds of environment variables, and several of them
switch Watchlight's layers off (bare mode, safe mode, redirected managed
settings). Checking for known bad names never ends, so layer 1 uses an
allowlist: a variable whose name starts with one of
:data:`GOVERNED_ENV_PREFIXES` is refused unless it is listed here, wherever
it is set (``options.env``, this process's environment, or the ``env`` of
any settings source). Each entry says why it is safe: it chooses the model
provider, the model or a credential, or it turns background traffic off.
None of them changes which tools run, the hooks, or the permission rules.

``extra_args`` flags work the same way: only :data:`ALLOWED_FLAGS` pass.

``tests/data/claude_code_env_names.txt`` lists every name with these
prefixes found in the bundled CLI that was reviewed and left refused. A
test reads the installed CLI, so a new Claude Code version with a new name
fails until that name is reviewed and placed in one list or the other.
"""

from __future__ import annotations

from typing import Dict, Tuple

#: Variables with these prefixes are refused unless listed below. Claude
#: Code's own (``CLAUDE_``, ``ANTHROPIC_``, ``DISABLE_``, ``ENABLE_``), its
#: remote-session and self-hosted-runner internals (``CCR_``,
#: ``SELF_HOSTED_RUNNER_``), and the runtime's (``BUN_``, ``NODE_``): the
#: compiled CLI runs ``BUN_OPTIONS="--preload <file>"`` as code inside its
#: own process, and ``NODE_OPTIONS``, ``NODE_PATH`` and
#: ``NODE_REPL_EXTERNAL_MODULE`` load code in any Node process the CLI
#: starts (hooks, MCP servers).
GOVERNED_ENV_PREFIXES: Tuple[str, ...] = (
    "CLAUDE_",
    "ANTHROPIC_",
    "DISABLE_",
    "ENABLE_",
    "CCR_",
    "SELF_HOSTED_RUNNER_",
    "BUN_",
    "NODE_",
)

_ENDPOINT = "where model requests go (a gateway or proxy); it changes no tool, hook or permission"
_MODEL = "which model answers; it changes no tool, hook or permission"
_PROVIDER = "which model provider is used; it changes no tool, hook or permission"
_QUIET = "turns background traffic off; it changes no tool, hook or permission"

#: Safe anywhere: ``options.env``, this process's environment, settings ``env``.
ALLOWED_ENV: Dict[str, str] = {
    "ANTHROPIC_API_KEY": "the model API credential",
    "ANTHROPIC_AUTH_TOKEN": "a bearer credential for the model API",
    "ANTHROPIC_BASE_URL": _ENDPOINT,
    "ANTHROPIC_BEDROCK_BASE_URL": _ENDPOINT,
    "ANTHROPIC_VERTEX_BASE_URL": _ENDPOINT,
    "ANTHROPIC_VERTEX_PROJECT_ID": "the Vertex AI project that is billed",
    "ANTHROPIC_MODEL": _MODEL,
    "ANTHROPIC_SMALL_FAST_MODEL": _MODEL,
    "ANTHROPIC_DEFAULT_OPUS_MODEL": _MODEL,
    "ANTHROPIC_DEFAULT_SONNET_MODEL": _MODEL,
    "ANTHROPIC_DEFAULT_HAIKU_MODEL": _MODEL,
    "CLAUDE_CODE_USE_BEDROCK": _PROVIDER,
    "CLAUDE_CODE_USE_VERTEX": _PROVIDER,
    "CLAUDE_CODE_MAX_OUTPUT_TOKENS": "the output length limit per model turn",
    "CLAUDE_CONFIG_DIR": (
        "where the user settings live; Watchlight reads the user settings from the "
        "same directory"
    ),
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": _QUIET,
    "DISABLE_AUTOUPDATER": _QUIET,
    "DISABLE_TELEMETRY": _QUIET,
    "DISABLE_ERROR_REPORTING": _QUIET,
    "NODE_ENV": "the host application's build mode; it loads no code and changes no tool, hook or permission",
    "NODE_EXTRA_CA_CERTS": (
        "extra certificate authorities to trust (a corporate proxy's); it loads no code and "
        "changes no tool, hook or permission"
    ),
}

#: Safe only in this process's environment, because the Claude Agent SDK
#: sets them itself in the CLI's environment, over the inherited value.
PROCESS_ONLY_ENV: Dict[str, str] = {
    "CLAUDE_CODE_ENTRYPOINT": "the SDK sets it to sdk-py over the inherited value",
    "CLAUDE_AGENT_SDK_VERSION": "the SDK sets it to its own version over the inherited value",
}

#: ``extra_args`` flags a governed session may pass.
ALLOWED_FLAGS: Dict[str, str] = {
    "debug-to-stderr": "debug output on stderr; it changes no tool, hook or permission",
}


def is_governed_env_name(name: str) -> bool:
    return name.upper().startswith(GOVERNED_ENV_PREFIXES)


__all__ = [
    "ALLOWED_ENV",
    "ALLOWED_FLAGS",
    "GOVERNED_ENV_PREFIXES",
    "PROCESS_ONLY_ENV",
    "is_governed_env_name",
]
