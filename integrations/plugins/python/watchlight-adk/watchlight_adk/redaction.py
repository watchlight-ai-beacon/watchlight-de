"""Value-free descriptions of tool-call arguments.

Raw tool arguments can carry bearer tokens, API keys or personal data.
Truncating them is not redaction: a 200-character prefix still holds a
secret. These helpers describe only the *shape* of the arguments (key
names, count and value types) and never a value. Their output is safe
to send to wl-apdp as authorize ``context`` and to put on a lineage
event.
"""

from __future__ import annotations

from typing import Any, Dict, List

_MAX_ARG_NAMES = 32
_MAX_SUMMARY_LEN = 120


def redacted_arg_metadata(tool_args: Any) -> Dict[str, Any]:
    """Return value-free metadata describing a tool call's arguments.

    A dict surfaces its key names (sorted, capped at 32), the count and
    each value's type name. Anything else (a bare positional value)
    surfaces only its type and a count of one. No value is ever
    rendered.
    """
    if isinstance(tool_args, dict):
        names: List[str] = [str(k) for k in tool_args.keys()]
        meta: Dict[str, Any] = {
            "arg_count": len(names),
            "arg_names": sorted(names)[:_MAX_ARG_NAMES],
            "arg_types": {
                str(k): type(v).__name__
                for k, v in list(tool_args.items())[:_MAX_ARG_NAMES]
            },
        }
        if len(names) > _MAX_ARG_NAMES:
            meta["arg_names_truncated"] = True
        return meta
    return {"arg_count": 1, "arg_names": [], "arg_type": type(tool_args).__name__}


def redacted_input_summary(tool_args: Any) -> str:
    """A bounded, value-free one-line summary of a tool call's arguments:
    ``"<n> args: name(type), name(type), ..."``, capped at 120 characters."""
    if isinstance(tool_args, dict):
        parts = [
            f"{k}({type(v).__name__})"
            for k, v in list(tool_args.items())[:_MAX_ARG_NAMES]
        ]
        summary = f"{len(tool_args)} args: " + ", ".join(parts) if parts else "0 args"
    else:
        summary = f"1 arg: ({type(tool_args).__name__})"
    return summary[:_MAX_SUMMARY_LEN]


__all__ = ["redacted_arg_metadata", "redacted_input_summary"]
