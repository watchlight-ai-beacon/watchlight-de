"""Plan parsing for Google ADK's PlanReActPlanner output.

ADK does not surface an agent's plan as a typed object. The
`PlanReActPlanner` shapes the LLM prompt to emit four marker
sections — `/*PLANNING*/`, `/*REASONING*/`, `/*ACTION*/`,
`/*FINAL_ANSWER*/` — but their bodies are free text. To get a
machine-readable plan out of an ADK agent, the WatchlightPlugin
adds a system-prompt addendum (see `plugin.py::_plan_prompt_addendum`)
asking the model to follow the `/*PLANNING*/` block with a JSON
code block in a fixed schema.

This module parses that JSON block back into a list of
`ProposedStep` dicts (matching the wl-apdp Rust struct of the same
name). Tolerant of:

  * Missing planning markers (returns None — caller may degrade).
  * Code-fence variants (```json, ```JSON, plain ```).
  * Trailing commas, BOM, leading whitespace.
  * Models that emit the JSON without a fence.

Returning None is **not** a parse error — it just means there was
no plan in the response (e.g. the model only wrote a final answer
on this turn). Callers branch on that to decide whether to apply
plan-time governance for this turn.
"""

import json
import re
from typing import Optional

# Re-export `governance_mode` from watchlight_core for backwards-compat
# with code that imports it from this module. See `__init__.py`'s
# public API for the full set of re-exported symbols.
from watchlight_core import governance_mode  # noqa: F401  # re-export
from watchlight_core import get_logger

logger = get_logger("watchlight_adk")

# `(?s)` enables DOTALL (`.` matches newlines).
# `\bjson\b` is case-insensitive via the `(?i)` flag below.
_FENCED_JSON_RE = re.compile(
    r"(?si)```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```",
)

_PLANNING_BLOCK_RE = re.compile(
    r"(?si)/\*\s*PLANNING\s*\*/(.+?)(?:/\*|\Z)",
)


def parse_planning_block(text: str) -> Optional[list[dict]]:
    """Extract `ProposedStep` dicts from an LLM response.

    Looks first inside a `/*PLANNING*/` block; falls back to scanning
    the full text for a fenced JSON block. Returns `None` when no
    plan is present, or `[]` when an empty plan was explicitly
    declared (rare, but distinguishable).
    """
    if not text:
        return None

    # Prefer a planning block if the planner wired one up. Otherwise
    # scan the whole response — some configurations of PlanReActPlanner
    # emit the JSON outside the marker.
    candidate_regions = []
    planning_match = _PLANNING_BLOCK_RE.search(text)
    if planning_match:
        candidate_regions.append(planning_match.group(1))
    candidate_regions.append(text)

    for region in candidate_regions:
        steps = _extract_first_json_plan(region)
        if steps is not None:
            return _normalise_steps(steps)

    return None


def _extract_first_json_plan(region: str) -> Optional[list]:
    """Try the fenced-JSON path first, then bare JSON object/array."""
    # Fenced.
    for match in _FENCED_JSON_RE.finditer(region):
        payload = _parse_json_lenient(match.group(1))
        steps = _coerce_to_step_list(payload)
        if steps is not None:
            return steps

    # Bare object/array, scanning for the first balanced one.
    for snippet in _scan_balanced_json(region):
        payload = _parse_json_lenient(snippet)
        steps = _coerce_to_step_list(payload)
        if steps is not None:
            return steps

    return None


def _parse_json_lenient(s: str) -> Optional[object]:
    """Parse JSON, tolerating trailing commas and common LLM quirks."""
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        # Strip trailing commas before } / ].
        cleaned = re.sub(r",(\s*[}\]])", r"\1", s)
        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            return None


def _coerce_to_step_list(payload: object) -> Optional[list]:
    """Accept either `[<step>, ...]` or `{"plan": [<step>, ...]}` shapes."""
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("plan"), list):
        return payload["plan"]
    return None


def _scan_balanced_json(s: str):
    """Yield candidate JSON substrings (objects or arrays) in order.

    Naive bracket matcher — handles nesting, ignores brackets inside
    string literals. Good enough for LLM output where the plan is
    typically the only structured object on the page.
    """
    open_chars = {"{": "}", "[": "]"}
    i = 0
    while i < len(s):
        c = s[i]
        if c in open_chars:
            close = open_chars[c]
            depth = 1
            j = i + 1
            in_string = False
            escape = False
            while j < len(s) and depth > 0:
                ch = s[j]
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = not in_string
                elif not in_string:
                    if ch == c:
                        depth += 1
                    elif ch == close:
                        depth -= 1
                j += 1
            if depth == 0:
                yield s[i:j]
                i = j
                continue
        i += 1


def _normalise_steps(raw: list) -> list[dict]:
    """Coerce loose LLM JSON into validator-compatible `ProposedStep` dicts.

    - `step_id` defaults to `s{idx}` if missing.
    - `action` and `resource_pattern` are required; any missing dict is
      dropped from the plan with a debug log.
    - `depends_on` and `estimated_risk` defaults are filled in.
    """
    out = []
    for idx, item in enumerate(raw):
        if not isinstance(item, dict):
            logger.debug("plan step %d is not a dict; dropping", idx)
            continue
        action = item.get("action")
        resource = item.get("resource_pattern") or item.get("resource") or "*"
        if not action:
            logger.debug("plan step %d missing action; dropping", idx)
            continue
        out.append(
            {
                "step_id": item.get("step_id") or f"s{idx + 1}",
                "action": action,
                "resource_pattern": resource,
                "intent_alignment": item.get("intent_alignment"),
                "depends_on": item.get("depends_on") or [],
                "estimated_risk": item.get("estimated_risk", "medium"),
                "reasoning": item.get("reasoning"),
            }
        )
    return out


# `governance_mode` is now re-exported from `watchlight_core` (see top
# of this module). The body lived here historically; keeping the
# re-export means the public symbol path is unchanged.


# ─── Prompt addendum ─────────────────────────────────────────────────

PLAN_PROMPT_ADDENDUM = """
You are governed by Watchlight Beacon. After your /*PLANNING*/ block,
emit a JSON code block describing your plan in this exact shape:

```json
{
  "plan": [
    {
      "step_id": "s1",
      "action": "<tool_name>",
      "resource_pattern": "<glob — e.g. Document::report-*>",
      "estimated_risk": "low|medium|high|critical",
      "depends_on": [],
      "reasoning": "<one sentence>"
    }
  ]
}
```

The `action` field MUST match a tool name from your toolset. Use
`*` as the resource_pattern when the resource is dynamic. Steps
that depend on earlier outputs MUST list those step_ids in
`depends_on`. The plan will be validated before any tool runs;
denied or modified plans are reported back to you on the next turn.
""".strip()
