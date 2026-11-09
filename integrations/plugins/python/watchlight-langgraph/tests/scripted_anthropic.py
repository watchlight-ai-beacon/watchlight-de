"""A real ``ChatAnthropic`` whose provider endpoint is a local HTTP server
that plays scripted answers (tests only).

In a governed run the plugin admits only chat model classes whose requests
go through a supported provider SDK, and refuses a tool-binding call of any
other class. So tests drive a real ``ChatAnthropic``: its request is
built and sent by the ``anthropic`` SDK, through the provider SDK gate, to
this server on 127.0.0.1, which answers each ``POST /v1/messages`` with the
next scripted answer as an Anthropic Messages response.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List

import pytest
from langchain_core.messages import AIMessage

langchain_anthropic = pytest.importorskip("langchain_anthropic")


def _as_messages_response(answer: AIMessage) -> Dict[str, Any]:
    content: List[Dict[str, Any]] = []
    if isinstance(answer.content, str) and answer.content:
        content.append({"type": "text", "text": answer.content})
    for call in answer.tool_calls:
        content.append(
            {
                "type": "tool_use",
                "id": call["id"],
                "name": call["name"],
                "input": call["args"],
            }
        )
    return {
        "id": "msg_scripted",
        "type": "message",
        "role": "assistant",
        "model": "claude-sonnet-5-5",
        "content": content or [{"type": "text", "text": ""}],
        "stop_reason": "tool_use" if answer.tool_calls else "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }


class ScriptedEndpoint:
    """The model's provider endpoint: answers in order, then the last one
    again. ``requests`` holds every request body it received."""

    def __init__(self, answers: List[AIMessage]) -> None:
        self.answers = list(answers)
        self.requests: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        endpoint = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - http.server API
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                with endpoint._lock:
                    endpoint.requests.append(json.loads(body or b"{}"))
                    answer = endpoint.answers[
                        min(len(endpoint.requests), len(endpoint.answers)) - 1
                    ]
                payload = json.dumps(_as_messages_response(answer)).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *args: Any) -> None:
                pass

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self._server.server_address[1]}"


def ScriptedChat(answers: List[AIMessage]) -> Any:  # noqa: N802 - reads like the model class it builds
    """A ``ChatAnthropic`` that plays ``answers`` from its own local endpoint."""
    endpoint = ScriptedEndpoint(answers)
    return langchain_anthropic.ChatAnthropic(
        model="claude-sonnet-5-5",
        api_key="not-a-key",
        base_url=endpoint.url,
        max_retries=0,
    )
