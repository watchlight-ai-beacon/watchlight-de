"""In-process stand-in for the Anthropic Messages API, for tests only.

The real Claude Code CLI is pointed at it with ``ANTHROPIC_BASE_URL``. It
records every request and, on the first main-loop turn (a request that
offers ``tool_name``), answers with one call to that tool; every other
request gets a plain text answer. No network is used.
"""

from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List


def _has_tool_result(body: Dict[str, Any]) -> bool:
    for message in body.get("messages") or []:
        content = message.get("content")
        if isinstance(content, list) and any(
            isinstance(block, dict) and block.get("type") == "tool_result" for block in content
        ):
            return True
    return False


class StandinMessagesApi:
    def __init__(
        self, tool_name: str, tool_input: Dict[str, Any], *, delay_s: float = 0.0, unoffered: bool = False
    ) -> None:
        """``delay_s`` holds the tool-call answer back, as a real model's
        latency does. ``unoffered`` asks for the tool on the first turn even
        when the request does not offer it (a deferred or withheld tool)."""
        self.requests: List[Dict[str, Any]] = []
        self.tool_name = tool_name
        self.tool_input = tool_input
        self.delay_s = delay_s
        self.unoffered = unoffered
        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:  # noqa: N802 - http.server's name
                self.send_response(404)
                self.end_headers()

            def do_POST(self) -> None:  # noqa: N802 - http.server's name
                raw = self.rfile.read(int(self.headers.get("content-length") or 0))
                try:
                    body = json.loads(raw or b"{}")
                except ValueError:
                    body = {}
                api.requests.append({"path": self.path, "body": body})
                if "count_tokens" in self.path:
                    self._json({"input_tokens": 10})
                    return
                if not self.path.startswith("/v1/messages"):
                    self.send_response(404)
                    self.end_headers()
                    return
                offered = [t.get("name") for t in body.get("tools") or []]
                asks = api.tool_name in offered or (api.unoffered and bool(offered))
                if asks and not _has_tool_result(body):
                    time.sleep(api.delay_s)
                    blocks = [{"type": "tool_use", "id": "toolu_test1", "name": api.tool_name, "input": api.tool_input}]
                    stop = "tool_use"
                else:
                    blocks = [{"type": "text", "text": "done"}]
                    stop = "end_turn"
                if body.get("stream"):
                    self._sse(body.get("model", "model"), blocks, stop)
                else:
                    self._json(
                        {
                            "id": "msg_1",
                            "type": "message",
                            "role": "assistant",
                            "model": body.get("model", "model"),
                            "content": blocks,
                            "stop_reason": stop,
                            "stop_sequence": None,
                            "usage": {"input_tokens": 1, "output_tokens": 1},
                        }
                    )

            def _json(self, obj: Dict[str, Any]) -> None:
                data = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def _sse(self, model: str, blocks: List[Dict[str, Any]], stop: str) -> None:
                self.send_response(200)
                self.send_header("content-type", "text/event-stream")
                self.end_headers()

                def event(name: str, data: Dict[str, Any]) -> None:
                    self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())

                usage = {"input_tokens": 1, "output_tokens": 1}
                event(
                    "message_start",
                    {
                        "type": "message_start",
                        "message": {
                            "id": "msg_1",
                            "type": "message",
                            "role": "assistant",
                            "model": model,
                            "content": [],
                            "stop_reason": None,
                            "stop_sequence": None,
                            "usage": usage,
                        },
                    },
                )
                for i, block in enumerate(blocks):
                    if block["type"] == "text":
                        start = {"type": "text", "text": ""}
                        delta = {"type": "text_delta", "text": block["text"]}
                    else:
                        start = {"type": "tool_use", "id": block["id"], "name": block["name"], "input": {}}
                        delta = {"type": "input_json_delta", "partial_json": json.dumps(block["input"])}
                    event("content_block_start", {"type": "content_block_start", "index": i, "content_block": start})
                    event("content_block_delta", {"type": "content_block_delta", "index": i, "delta": delta})
                    event("content_block_stop", {"type": "content_block_stop", "index": i})
                event(
                    "message_delta",
                    {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None}, "usage": {"output_tokens": 1}},
                )
                event("message_stop", {"type": "message_stop"})
                self.wfile.flush()

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"
        threading.Thread(target=self._server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    def tool_results(self) -> List[str]:
        """Every tool result the CLI sent back, as JSON text."""
        out = []
        for request in self.requests:
            for message in request["body"].get("messages") or []:
                if "tool_result" in json.dumps(message):
                    out.append(json.dumps(message))
        return out
