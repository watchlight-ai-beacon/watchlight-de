"""Action verb resolution for Watchlight Agent Runtime Governance.

Maps tool names to Cedar action verbs using explicit overrides and
convention-based defaults. Action verbs are load-bearing in Beacon's
authorization pipeline:

- Intent validation checks action alignment with intent category
- Delegation scopes constrain allowed_actions per delegate
- Cedar policies match on Action::"verb" in permit/forbid rules

The convention-based defaults use tool name prefixes to infer the
governance classification of an operation (read, execute, search, etc.).
"""

from typing import Optional

# Convention-based prefix → action mapping.
# Order matters: first match wins. Longer prefixes checked first.
ACTION_CONVENTIONS: list[tuple[list[str], str]] = [
    # Data retrieval (no side effects)
    (["get_", "fetch_", "load_", "read_"], "read"),
    # Collection enumeration
    (["list_", "show_"], "list"),
    # Filtered retrieval
    (["search_", "find_", "query_"], "search"),
    # Resource creation
    (["create_", "add_", "new_"], "create"),
    # Resource mutation
    (["update_", "set_", "modify_", "patch_"], "update"),
    # Resource destruction
    (["delete_", "remove_", "drop_"], "delete"),
    # Side-effecting execution
    (["execute_", "run_", "trigger_", "invoke_"], "execute"),
    # AI-specific
    (["analyze_"], "analyze"),
    (["summarize_"], "summarize"),
    (["generate_"], "generate"),
    (["embed_"], "embed"),
    # Approval workflow
    (["approve_", "confirm_"], "approve"),
    (["review_"], "review"),
]

# Default when no convention matches. "execute" is intentionally
# conservative: it's excluded from most intent categories (Research,
# DataAnalysis, SecurityCompliance, etc.), preventing unmapped tools
# from getting broader access than intended.
DEFAULT_ACTION = "execute"


def resolve_action(
    tool_name: str,
    action_map: Optional[dict[str, str]] = None,
) -> str:
    """Resolve a tool name to a Cedar action verb.

    Resolution order:
        1. Explicit action_map entry (highest priority)
        2. Convention-based prefix matching
        3. Default: "execute" (most restrictive)

    Args:
        tool_name: The tool function name (e.g., "get_market_data")
        action_map: Optional explicit overrides {tool_name: action}

    Returns:
        Cedar action name (e.g., "read", "execute", "search")
    """
    # 1. Explicit override
    if action_map and tool_name in action_map:
        return action_map[tool_name]

    # 2. Convention-based prefix matching
    lower_name = tool_name.lower()
    for prefixes, action in ACTION_CONVENTIONS:
        for prefix in prefixes:
            if lower_name.startswith(prefix):
                return action

    # 3. Conservative default
    return DEFAULT_ACTION
