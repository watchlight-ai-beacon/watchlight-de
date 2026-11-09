"""``RemoteTrigger`` against the real Claude Code CLI.

With a stored claude.ai login (a credentials file, no API key and no
``CLAUDE_CODE_OAUTH_TOKEN``), Claude Code offers ``RemoteTrigger``, which
starts or schedules a session on Anthropic's cloud that these hooks never
see. ``governed_options`` never offers it (``disallowed_tools``), and a
call that still reaches ``PreToolUse`` is refused before any decision,
with a recorded Deny. Nothing leaves the machine: the model is a stand-in
on localhost (``_standin_api``) and every other request goes to a local
proxy that refuses it.
"""

from __future__ import annotations

import asyncio
import dataclasses
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

from watchlight_claude_agent import GovernanceBypassDetected, WatchlightClaudeAgentSDKPlugin
from watchlight_core_testing import MockApdpClient

ROOT_SLUG = "root-agent"
ROOT_UUID = "00000000-0000-0000-0000-000000000001"


class _RefusingProxy:
    """Records and refuses every proxied request."""

    def __init__(self) -> None:
        self.seen: List[str] = []
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def _refuse(self) -> None:
                proxy.seen.append(f"{self.command} {self.path}")
                self.send_response(403)
                self.send_header("content-length", "0")
                self.end_headers()

            do_CONNECT = do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _refuse  # noqa: N815

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def cloud_connects(self) -> int:
        return sum(1 for s in self.seen if s.startswith("CONNECT api.anthropic.com"))


async def _recorded(stream: Any, into: List[str]) -> Any:
    """``stream`` as it is, recording what the CLI sends before the
    plugin's watch sees it."""
    async for m in stream:
        into.append(repr(m))
        yield m


async def _run(
    tmp_path: Path,
    tool: Optional[str],
    tool_input: Optional[Dict[str, Any]] = None,
    *,
    drop_disallowed: bool = False,
) -> Dict[str, Any]:
    from ._standin_api import StandinMessagesApi
    from claude_agent_sdk import ClaudeAgentOptions, query
    from claude_agent_sdk.types import SystemMessage

    config = tmp_path / "config"
    work = tmp_path / "work"
    config.mkdir(parents=True)
    work.mkdir()
    # A stand-in stored login: what `claude login` leaves behind.
    (config / ".credentials.json").write_text(
        json.dumps(
            {
                "claudeAiOauth": {
                    "accessToken": "sk-ant-oat01-stand-in-not-a-token",
                    "refreshToken": "sk-ant-ort01-stand-in-not-a-token",
                    "expiresAt": int(time.time() * 1000) + 86_400_000,
                    "scopes": ["user:inference", "user:profile", "user:sessions:claude_code"],
                    "subscriptionType": "max",
                }
            }
        )
    )
    (config / ".credentials.json").chmod(0o600)
    api = StandinMessagesApi(tool or "NoToolCall", tool_input or {}, unoffered=tool is not None)
    proxy = _RefusingProxy()
    apdp = MockApdpClient(default_decision="Allow")
    apdp.known_agents[ROOT_SLUG] = ROOT_UUID
    plugin = WatchlightClaudeAgentSDKPlugin(apdp_url="http://localhost:8081", tenant_id="tenant-a")
    plugin.apdp = apdp
    root = await plugin.start_run(ROOT_SLUG)
    root._aentered = True
    env = {
        "ANTHROPIC_BASE_URL": api.url,
        # No API key and no OAuth token in the environment: the stored login.
        "ANTHROPIC_API_KEY": "",
        "CLAUDE_CONFIG_DIR": str(config),
        "HOME": str(tmp_path),
        "DISABLE_AUTOUPDATER": "1",
        "HTTPS_PROXY": proxy.url,
        "HTTP_PROXY": proxy.url,
        "https_proxy": proxy.url,
        "http_proxy": proxy.url,
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
    }
    host = ClaudeAgentOptions(
        cwd=str(work), env=env, model="claude-sonnet-4-5", max_turns=3, permission_mode="bypassPermissions"
    )
    init_tools: List[str] = []
    cli_messages: List[str] = []
    error: Optional[str] = None

    async def drain() -> None:
        opts = plugin.governed_options(root, host)
        if drop_disallowed:
            # A route the plugin cannot see: the options lose
            # disallowed_tools after the plugin composed them.
            opts = dataclasses.replace(opts, disallowed_tools=[])
        async for m in plugin.watch_messages(root, _recorded(query(prompt="run it", options=opts), cli_messages)):
            if isinstance(m, SystemMessage) and m.subtype == "init":
                init_tools.extend(m.data.get("tools") or [])

    try:
        await asyncio.wait_for(drain(), 120)
    except GovernanceBypassDetected:
        error = "GovernanceBypassDetected"
    except asyncio.TimeoutError:
        raise
    except Exception as exc:  # noqa: BLE001 - a refused call can end the session
        error = f"{type(exc).__name__}: {exc}"
    finally:
        api.close()
        proxy.close()
    return {
        "offered": "RemoteTrigger" in init_tools,
        "authorized": [c["resource"] for c in apdp.authorize_calls],
        "refused": [
            e
            for e in apdp.published_events
            if e.get("event_type") == "tool_call_observed" and (e.get("metadata") or {}).get("refusal_reason")
        ],
        "tool_results": "\n".join(api.tool_results()),
        "cli_messages": "\n".join(cli_messages),
        "cloud_connects": proxy.cloud_connects(),
        "error": error,
    }


_RUN = {"action": "run", "trigger_id": "trig_x"}


@pytest.mark.asyncio
async def test_cli_remote_trigger_is_never_offered_and_nothing_is_dispatched(tmp_path: Path) -> None:
    baseline = await _run(tmp_path / "b", None)
    out = await _run(tmp_path / "r", "RemoteTrigger", _RUN)
    assert out["offered"] is False
    assert [r for r in out["authorized"] if "RemoteTrigger" in r] == []
    assert out["cloud_connects"] <= baseline["cloud_connects"]


@pytest.mark.asyncio
async def test_cli_remote_trigger_offered_anyway_is_refused_with_a_recorded_deny(tmp_path: Path) -> None:
    baseline = await _run(tmp_path / "b", None)
    out = await _run(tmp_path / "r", "RemoteTrigger", _RUN, drop_disallowed=True)
    assert out["offered"] is True
    assert [r for r in out["authorized"] if "RemoteTrigger" in r] == []
    assert [(e["payload"]["decision"], e["metadata"]["refusal_reason"]) for e in out["refused"]] == [
        ("Deny", "remote_dispatch_refused")
    ]
    assert "does not start remote sessions" in out["tool_results"]
    # Zero remote sessions: the tool body never ran, so no trigger request
    # joined the CLI's own traffic.
    assert out["cloud_connects"] <= baseline["cloud_connects"]


@pytest.mark.asyncio
async def test_cli_a_remote_workflow_cannot_be_asked_for(tmp_path: Path) -> None:
    # Pin: Claude Code 2.1.310 compiles ``remote`` out of Workflow.
    # If a CLI release accepts it, this fails and the Workflow
    # classification is reviewed again.
    script = 'export const meta = { name: "p", description: "p", phases: [{ title: "p" }] }\nreturn 1\n'
    out = await _run(tmp_path / "w", "Workflow", {"script": script, "remote": True})
    assert [r for r in out["authorized"] if "Workflow" in r] == []
    # The CLI rejects the input before PreToolUse; the plugin then ends
    # the session on a tool result it did not decide (fail closed).
    assert "InputValidationError" in out["cli_messages"], out["cli_messages"][-800:]
    assert out["error"] == "GovernanceBypassDetected"

