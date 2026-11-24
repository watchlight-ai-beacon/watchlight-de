"""Action verb resolution shared by every plugin.

Maps a tool name to the Cedar action verb sent to wl-apdp, using an
explicit override map first and name-prefix conventions second. The
verb matters to authorization: intent validation checks it against the
intent category, delegation scopes constrain ``allowed_actions``, and
Cedar policies match ``Action::"<verb>"``.

The table is the same one the ADK plugin uses, so a tool resolves to the
same verb whichever plugin governs it. The TypeScript SDK carries the
identical table in ``actions.ts``.
"""

from __future__ import annotations

from typing import List, Mapping, Optional, Tuple

#: Prefix → action, first match wins.
ACTION_CONVENTIONS: List[Tuple[List[str], str]] = [
    (["get_", "fetch_", "load_", "read_"], "read"),
    (["list_", "show_"], "list"),
    (["search_", "find_", "query_"], "search"),
    (["create_", "add_", "new_"], "create"),
    (["update_", "set_", "modify_", "patch_"], "update"),
    (["delete_", "remove_", "drop_"], "delete"),
    (["execute_", "run_", "trigger_", "invoke_"], "execute"),
    (["analyze_"], "analyze"),
    (["summarize_"], "summarize"),
    (["generate_"], "generate"),
    (["embed_"], "embed"),
    (["approve_", "confirm_"], "approve"),
    (["review_"], "review"),
]

#: The verb when no convention matches. ``execute`` is deliberately
#: conservative: most intent categories exclude it, so an unmapped tool
#: never gets broader access than intended.
DEFAULT_ACTION = "execute"


def resolve_action(
    tool_name: str,
    action_map: Optional[Mapping[str, str]] = None,
) -> str:
    """Resolve a tool name to a Cedar action verb.

    Resolution order: an ``action_map`` entry, then the first matching
    prefix in :data:`ACTION_CONVENTIONS` (case-insensitive), then
    :data:`DEFAULT_ACTION`.
    """
    if action_map and tool_name in action_map:
        return action_map[tool_name]
    lower_name = tool_name.lower()
    for prefixes, action in ACTION_CONVENTIONS:
        for prefix in prefixes:
            if lower_name.startswith(prefix):
                return action
    return DEFAULT_ACTION


__all__ = ["ACTION_CONVENTIONS", "DEFAULT_ACTION", "resolve_action"]
