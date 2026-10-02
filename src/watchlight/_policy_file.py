"""Reading a policy file into the entries a governor loads.

One reader for every entry point that takes a policy file — ``Watchlight.load``,
``Watchlight.reload`` and ``watchlight policy test`` — so they accept the same
shapes and refuse the same mistakes.

A policy file is JSON in one of three shapes:

* a list of policy objects: ``[{"name": ..., "code": ...}, ...]``
* an object holding that list: ``{"policies": [...]}`` (a policy test suite has
  this shape, so a suite file loads as a policy file)
* ONE policy object: ``{"name": ..., "code": ...}`` — the shape the MCP PEP
  (``watchlight-mcp``) reads, one policy per file, so one file serves both

A policy object needs a non-empty string ``code``. ``name`` is optional. Other
keys (``id``, ``description``, …) are ignored, except ``active``: a policy
marked ``"active": false`` is refused, because the governor has no inactive
state and loading it would enforce it.

FAIL LOUDLY, NEVER EMPTY BY ACCIDENT. A missing path, a directory, invalid JSON,
an unrecognised shape and a malformed entry all raise, naming the file. So does
a file that holds no policies, unless the caller opts in with ``allow_empty``.
Cedar denies by default, so none of these was ever permissive, but each one used
to load nothing without a word, and a governor that silently holds no policy
denies every call for a reason nobody can see.
"""

from __future__ import annotations

import json
import os
import pathlib
from typing import Any, List

EXPECTED_SHAPE = (
    'a list of {"name", "code"} objects, {"policies": [...]}, '
    'or a single {"name", "code"} object'
)


def read_policy_file(
    path: "str | os.PathLike[str]", *, op: str, allow_empty: bool = False
) -> List[dict]:
    """Read ``path`` and return its policy entries, validated.

    Raises :class:`FileNotFoundError` for a missing path,
    :class:`IsADirectoryError` for a directory, and :class:`ValueError` for
    anything else that is not a policy file or (without ``allow_empty``) holds
    no policies. ``op`` prefixes every message (``load``, ``reload``, …)."""
    p = pathlib.Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{op}: no such policy file: {p}")
    if p.is_dir():
        raise IsADirectoryError(
            f"{op}: {p} is a directory, not a policy file. Load each policy file "
            f"in it by name."
        )
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{op}: {p} is not valid JSON: {exc}") from exc
    return policy_entries(data, str(p), op=op, allow_empty=allow_empty)


def policy_entries(data: Any, where: str, *, op: str, allow_empty: bool = False) -> List[dict]:
    """The policy entries of parsed policy-file ``data``, validated. ``where``
    names the source in every message."""
    if isinstance(data, list):
        entries = data
    elif isinstance(data, dict):
        has_policies = "policies" in data
        has_code = "code" in data
        if has_policies and has_code:
            raise ValueError(
                f'{op}: {where} has both "policies" and "code", so it is not clear '
                f"whether it is one policy or a set. Expected {EXPECTED_SHAPE}."
            )
        if has_policies:
            entries = data["policies"]
            if not isinstance(entries, list):
                raise ValueError(
                    f'{op}: {where}: "policies" must be a list of {{"name", "code"}} '
                    f"objects, not {_kind(entries)}."
                )
        elif has_code:
            entries = [data]
        else:
            hint = ""
            if "policyFile" in data or "policy_file" in data:
                hint = (
                    " It looks like a policy test suite that names its policies in "
                    "policyFile; load that file instead."
                )
            raise ValueError(
                f'{op}: {where} has neither "policies" nor "code", so it holds no '
                f"policy. Expected {EXPECTED_SHAPE}.{hint}"
            )
    else:
        raise ValueError(f"{op}: {where} is {_kind(data)}. Expected {EXPECTED_SHAPE}.")

    for index, entry in enumerate(entries):
        _check_entry(entry, index, where, op)

    if not entries and not allow_empty:
        raise ValueError(
            f"{op}: {where} defines no policies, so every governed call would be "
            f"denied. Expected {EXPECTED_SHAPE}. To load an empty set on purpose, "
            f"pass allow_empty=True."
        )
    return entries


def _check_entry(entry: Any, index: int, where: str, op: str) -> None:
    label = f"policy #{index + 1} in {where}"
    if not isinstance(entry, dict):
        raise ValueError(
            f'{op}: {label} is {_kind(entry)}, not a {{"name", "code"}} object.'
        )
    name = entry.get("name")
    if name is not None and not isinstance(name, str):
        raise ValueError(f'{op}: {label}: "name" must be a string, not {_kind(name)}.')
    if name:
        label = f'policy "{name}" in {where}'
    code = entry.get("code")
    if not isinstance(code, str) or not code.strip():
        raise ValueError(
            f'{op}: {label} has no Cedar "code" (a non-empty string is required).'
        )
    if "active" in entry and entry["active"] is not True:
        raise ValueError(
            f'{op}: {label} is marked "active": {json.dumps(entry["active"])}. Every '
            f"policy a governor loads is enforced, so an inactive policy cannot be "
            f'loaded; remove it from the file, or set "active": true.'
        )


def _kind(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "a boolean"
    if isinstance(value, (int, float)):
        return "a number"
    if isinstance(value, str):
        return "a string"
    if isinstance(value, list):
        return "a list"
    if isinstance(value, dict):
        return "an object"
    return type(value).__name__
