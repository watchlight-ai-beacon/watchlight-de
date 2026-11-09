"""Plan-normalisation contract.

Every framework plugin coerces its native plan shape into APDP's
``ProposedStep[]`` wire format here. The contract surface is
deliberately narrow — two input shapes accepted, everything else
raises ``TypeError``. Silent acceptance of unknown shapes would mask
bugs at the framework boundary.
"""

from typing import Any, Dict, List

from .log import get_logger

logger = get_logger("watchlight_core.plan")


def normalize_plan(plan: Any) -> List[Dict[str, Any]]:
    """Coerce a framework-native plan into APDP ``ProposedStep[]`` shape.

    Accepts:

    - ``list[str]`` — canonical plan-and-execute output. Each string
      becomes one step with ``resource_pattern='*'`` and
      ``estimated_risk='medium'``.
    - ``list[dict]`` — already-typed steps; passed through after
      filling defaults (``step_id``, ``resource_pattern``,
      ``estimated_risk``, ``depends_on``).

    Rejects anything else with ``TypeError`` carrying a hint. Drops
    individual list items that are neither ``str`` nor ``dict``, and
    drops dict items missing ``action`` — both with a debug log so
    operators can inspect parser noise without it bubbling to errors.

    Output schema (per item):

    .. code-block:: python

        {
            "step_id": str,            # required, defaulted to s{i+1}
            "action": str,             # required; rejection if missing
            "resource_pattern": str,   # defaults to '*'
            "estimated_risk": str,     # defaults to 'medium'
            "depends_on": list[str],   # defaults to []
            "reasoning": str | None,   # passthrough
            "intent_alignment": str | None,  # passthrough on dict shape
        }
    """
    if not isinstance(plan, list):
        raise TypeError(
            f"plan must be list[str] or list[dict]; got {type(plan).__name__}. "
            f"For plan-and-execute frameworks, the canonical shape is a list "
            f"of action strings or a list of typed step dicts."
        )

    out: List[Dict[str, Any]] = []
    for i, item in enumerate(plan):
        if isinstance(item, str):
            out.append(
                {
                    "step_id": f"s{i + 1}",
                    "action": item.strip(),
                    "resource_pattern": "*",
                    "estimated_risk": "medium",
                    "depends_on": [],
                    "reasoning": None,
                }
            )
        elif isinstance(item, dict):
            action = item.get("action")
            if not action:
                logger.debug("plan step %d missing action; dropping", i)
                continue
            out.append(
                {
                    "step_id": item.get("step_id") or f"s{i + 1}",
                    "action": action,
                    "resource_pattern": item.get("resource_pattern")
                    or item.get("resource")
                    or "*",
                    "intent_alignment": item.get("intent_alignment"),
                    "depends_on": item.get("depends_on") or [],
                    "estimated_risk": item.get("estimated_risk", "medium"),
                    "reasoning": item.get("reasoning"),
                }
            )
        else:
            logger.debug(
                "plan step %d is %s (expected str or dict); dropping",
                i,
                type(item).__name__,
            )
    return out
