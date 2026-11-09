"""AI application attribution — one client-side reader for ``application_id``.

Every plugin resolves the AI application a governed run belongs to from
three places, in this order: the per-run argument, the plugin
constructor, then the ``WATCHLIGHT_APPLICATION_ID`` environment variable.
All three go through :func:`resolve_application_id` so the rules are the
same everywhere:

- ``None``, an empty string and a whitespace-only string all mean
  *unset* — the field is not sent and the next fallback applies.
- Surrounding whitespace is trimmed (``"  <uuid> "`` → ``"<uuid>"``).
- Anything else must parse as a UUID; otherwise ``ValueError`` is
  raised at the call site (constructor or ``start_run``) before any
  session is opened.

This is a pure format check on the client. wl-apdp remains the
authority on whether the application exists and whether the agent is a
member of it; the check here only stops a typo from reaching the wire.
The id is explicit configuration, never inferred from prompts or names.
"""

from __future__ import annotations

import os
import uuid
from typing import Optional

APPLICATION_ID_ENV_VAR = "WATCHLIGHT_APPLICATION_ID"

_INVALID = "application_id must be a UUID"


def resolve_application_id(value: Optional[str]) -> Optional[str]:
    """Normalise an ``application_id`` value.

    Returns ``None`` for ``None`` / empty / whitespace-only input, the
    trimmed value when it parses as a UUID, and raises
    ``ValueError("application_id must be a UUID")`` otherwise.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(_INVALID)
    trimmed = value.strip()
    if not trimmed:
        return None
    try:
        uuid.UUID(trimmed)
    except (ValueError, AttributeError, TypeError):
        raise ValueError(_INVALID) from None
    return trimmed


def application_id_from_env() -> Optional[str]:
    """``WATCHLIGHT_APPLICATION_ID`` through :func:`resolve_application_id`.

    Unset / empty / whitespace ⇒ ``None``. A non-UUID value raises
    ``ValueError`` so a misconfigured deployment fails at plugin
    construction rather than on the first run.
    """
    return resolve_application_id(os.getenv(APPLICATION_ID_ENV_VAR))
