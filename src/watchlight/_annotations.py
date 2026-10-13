"""How a policy's ``@enforcement_effect`` annotation is checked at load.

Why the check exists
--------------------
``@enforcement_effect("<verb>")`` changes the VERDICT. On a ``permit``,
``require_approval`` turns an Allow into a NeedsApproval that a human has to
release. An effect value the engine did not implement used to be dropped. On a
``forbid`` that leaves a plain deny, which is the closed direction. On a
``permit`` it leaves a plain allow, which is the open one: a one-character typo
turned a human-in-the-loop gate into an unconditional permit. A misspelled
annotation NAME (``@enforcement_efect``) did the same, because Cedar accepts
any annotation name.

Who decides
-----------
The engine. Since ``watchlight-engine`` 0.2.3 the engine refuses such a policy
when it is added. It raises ``PolicyAnnotationError`` with a stable ``code``:

- ``UNRECOGNISED_ENFORCEMENT_EFFECT``: a value the engine does not implement
  (a typo, a case or whitespace variant, or an empty value);
- ``ENFORCEMENT_EFFECT_NAME_NEAR_MISS``: an annotation whose name is within two
  edits of ``enforcement_effect``, case folded, and not the exact name.

The SDK keeps no list of its own. It maps the engine's typed refusal to
:class:`PolicyError`, which names the policy and, for a file, its path. The
list of accepted effects lives in one place, the engine, so a new verb never
needs a change here.
"""

from __future__ import annotations

from typing import Any, Optional

#: The annotation whose value the engine turns into an enforcement effect.
ENFORCEMENT_EFFECT_ANNOTATION = "enforcement_effect"

#: ``PolicyError.code`` for an ``@enforcement_effect`` value the engine does
#: not implement.
UNRECOGNISED_ENFORCEMENT_EFFECT = "UNRECOGNISED_ENFORCEMENT_EFFECT"

#: ``PolicyError.code`` for an annotation name that is a near miss for
#: ``@enforcement_effect``.
ENFORCEMENT_EFFECT_NAME_NEAR_MISS = "ENFORCEMENT_EFFECT_NAME_NEAR_MISS"

#: Every ``PolicyError.code``, as the engine reports them.
POLICY_ERROR_CODES = (ENFORCEMENT_EFFECT_NAME_NEAR_MISS, UNRECOGNISED_ENFORCEMENT_EFFECT)

_ENGINE_PREFIX = "add_policy failed: "


class PolicyError(ValueError):
    """Raised at policy load by :meth:`~watchlight.Watchlight.allow`,
    :meth:`~watchlight.Watchlight.load` and :meth:`~watchlight.Watchlight.reload`
    when the engine refuses a policy for its ``@enforcement_effect``
    annotation: a value it does not implement, or an annotation name that is a
    near miss for ``enforcement_effect``.

    Nothing from the refused call is added: ``allow`` adds nothing, ``load``
    adds nothing from that file, and ``reload`` keeps the set it had.

    ``code`` is one of :data:`POLICY_ERROR_CODES`, ``policy`` names the policy,
    and ``source`` is the file it came from (``None`` inline).
    """

    def __init__(
        self, message: str, *, code: str, policy: str, source: Optional[str] = None
    ) -> None:
        super().__init__(message)
        self.code = code
        self.policy = policy
        self.source = source


def policy_error_from_engine(exc: Any, policy: str, source: Optional[str]) -> PolicyError:
    """Map the engine's ``PolicyAnnotationError`` to :class:`PolicyError`.

    The message names the policy as the developer did (the engine only knows
    its generated id) and keeps the engine's explanation, which is the same in
    every language because it comes from the same engine."""
    detail = str(exc)
    if detail.startswith(_ENGINE_PREFIX):
        detail = detail[len(_ENGINE_PREFIX) :]
    # "Policy <generated id> rejected: <why>" names an id the developer never
    # chose; keep only the reason.
    marker = " rejected: "
    if detail.startswith("Policy ") and marker in detail:
        detail = detail.split(marker, 1)[1]
    where = f" from {source}" if source else ""
    code = str(getattr(exc, "code", "") or "")
    return PolicyError(
        f'policy "{policy}"{where}: {detail}', code=code, policy=policy, source=source
    )
