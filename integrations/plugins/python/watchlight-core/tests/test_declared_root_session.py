"""A declared root run on session open.

Pins the SDK side of the server's ``open_declared_root`` contract:

* ``create_session(declared_root=[...])`` sends
  ``declared_root: {"live_execution_ids": [...]}`` with the ids exactly as
  given; without it the body is unchanged.
* ``SessionInfo.declared_root`` is true only when the answer says
  ``declared_root: true`` (an older server ignores the field, and the
  caller then ends the session).
* ``403 declared_root_forbidden`` and ``422 declared_root_invalid`` raise
  :class:`DeclaredRootRefused` with that code.
* Backends that cannot open a declared root refuse it before anything is
  sent: the in-process engine and the connector.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, Dict, List, Optional

import httpx
import pytest

from watchlight_core import (
    ApdpClient,
    DeclaredRootRefused,
    GovernanceRefused,
    InProcessClient,
)
from watchlight_core.errors import (
    DECLARED_ROOT_FORBIDDEN,
    DECLARED_ROOT_INVALID,
    DECLARED_ROOT_UNSUPPORTED,
)

AGENT = "11111111-1111-4111-8111-111111111111"
LIVE = [f"exec_{uuid.uuid4()}", f"exec_{uuid.uuid4()}"]


class _Wire:
    """``POST /sessions`` answered with ``status`` and ``answer``."""

    def __init__(self, status: int = 200, answer: Optional[Dict[str, Any]] = None) -> None:
        self.status = status
        self.answer = answer
        self.bodies: List[Dict[str, Any]] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/sessions"
        self.bodies.append(json.loads(request.content))
        if self.answer is not None:
            return httpx.Response(self.status, json=self.answer)
        session_id = f"ses_{uuid.uuid4()}"
        return httpx.Response(
            200,
            json={
                "session": {"id": session_id, "agent_id": AGENT},
                "session_token": "sst_" + uuid.uuid4().hex,
                "execution_id": f"exec_{uuid.uuid4()}",
                "declared_root": True,
            },
        )


def _client(wire: _Wire) -> ApdpClient:
    apdp = ApdpClient("https://apdp.test")
    apdp._probed = True
    apdp._client = httpx.AsyncClient(
        base_url="https://apdp.test", transport=httpx.MockTransport(wire)
    )
    return apdp


@pytest.mark.asyncio
async def test_the_declaration_is_sent_with_the_ids_exactly_as_given() -> None:
    wire = _Wire()
    info = await _client(wire).create_session(agent_id=AGENT, declared_root=LIVE)
    assert wire.bodies[0]["declared_root"] == {"live_execution_ids": LIVE}
    assert info is not None and info.declared_root is True


@pytest.mark.asyncio
async def test_an_empty_declaration_is_still_sent() -> None:
    wire = _Wire()
    info = await _client(wire).create_session(agent_id=AGENT, declared_root=[])
    assert wire.bodies[0]["declared_root"] == {"live_execution_ids": []}
    assert info is not None and info.declared_root is True


@pytest.mark.asyncio
async def test_without_a_declaration_the_body_is_unchanged() -> None:
    wire = _Wire()
    info = await _client(wire).create_session(agent_id=AGENT)
    assert "declared_root" not in wire.bodies[0]
    # The answer's echo alone never marks an undeclared session declared...
    assert info is not None
    # ...the plugin only reads it when it declared one.


@pytest.mark.asyncio
async def test_an_answer_without_the_echo_is_not_a_declared_root() -> None:
    wire = _Wire(
        200,
        {
            "session": {"id": "ses_old", "agent_id": AGENT},
            "session_token": "sst_" + uuid.uuid4().hex,
            "execution_id": f"exec_{uuid.uuid4()}",
        },
    )
    info = await _client(wire).create_session(agent_id=AGENT, declared_root=LIVE)
    assert info is not None and info.declared_root is False


@pytest.mark.asyncio
@pytest.mark.parametrize("echo", ["true", 1, {"ok": True}, None])
async def test_only_a_literal_true_echo_counts(echo: Any) -> None:
    wire = _Wire(
        200,
        {
            "session": {"id": "ses_x", "agent_id": AGENT},
            "session_token": "sst_" + uuid.uuid4().hex,
            "execution_id": f"exec_{uuid.uuid4()}",
            "declared_root": echo,
        },
    )
    info = await _client(wire).create_session(agent_id=AGENT, declared_root=LIVE)
    assert info is not None and info.declared_root is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "code"),
    [(403, DECLARED_ROOT_FORBIDDEN), (422, DECLARED_ROOT_INVALID)],
)
async def test_a_refused_declaration_raises_its_code(status: int, code: str) -> None:
    for body in ({"error": code}, {"error": {"code": code, "message": "x"}}):
        wire = _Wire(status, body)
        with pytest.raises(DeclaredRootRefused) as exc:
            await _client(wire).create_session(agent_id=AGENT, declared_root=LIVE)
        assert exc.value.code == code
        assert exc.value.status_code == status
        # A refusal is never degraded: it is a GovernanceRefused.
        assert isinstance(exc.value, GovernanceRefused)


@pytest.mark.asyncio
async def test_an_untyped_422_is_an_unopened_session() -> None:
    wire = _Wire(422, {"error": "something_else"})
    assert await _client(wire).create_session(agent_id=AGENT, declared_root=LIVE) is None


@pytest.mark.asyncio
async def test_the_in_process_engine_refuses_a_declared_root() -> None:
    # Refused from the arguments alone, before the engine is touched.
    client = InProcessClient.__new__(InProcessClient)
    with pytest.raises(DeclaredRootRefused) as exc:
        await client.create_session(declared_root=[])
    assert exc.value.code == DECLARED_ROOT_UNSUPPORTED


@pytest.mark.asyncio
async def test_the_connector_refuses_a_declared_root_before_sending() -> None:
    from watchlight_core.sidecar_backend import SidecarBackend

    backend = SidecarBackend.__new__(SidecarBackend)
    with pytest.raises(DeclaredRootRefused) as exc:
        await backend.create_session(agent_id=AGENT, declared_root=[])
    assert exc.value.code == DECLARED_ROOT_UNSUPPORTED
