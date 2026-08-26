"""``watchlight`` command-line entry point.

Currently one command:

    watchlight dev        # a local dashboard for the in-process audit trail

``watchlight dev`` serves a tiny, dependency-free web page that tails the local
``.watchlight/audit.jsonl`` and shows every governance decision as it happens —
the ALLOWs, and (the point) the DENYs that stopped a tool **before** it ran. It
reads the same value-free audit the engine writes; no argument values, tokens,
or secrets are ever displayed because they are never in the trail.

It is deliberately minimal: the Developer-Edition dashboard shows *your one
process*. Fleet-wide lineage, signed tamper-evident audit, and drift→quarantine
live in the governed control plane (Enterprise).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


# --------------------------------------------------------------------------- #
# Reading the value-free audit trail
# --------------------------------------------------------------------------- #

def _read_events(audit_path: pathlib.Path, limit: int = 500) -> list[dict[str, Any]]:
    """Parse the audit JSONL into normalized decision records (newest last).

    Robust to both the `watchlight.govern` shape ({ts, agent, intent, resource,
    decision}) and the plugin/in-process shape — fields are looked up with
    fallbacks. Malformed lines are skipped. Never raises."""
    if not audit_path.exists():
        return []
    events: list[dict[str, Any]] = []
    try:
        lines = audit_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    for line in lines[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except (ValueError, TypeError):
            continue
        decision = str(raw.get("decision", "")).strip()
        events.append(
            {
                "ts": raw.get("ts") or raw.get("timestamp") or "",
                "agent": raw.get("agent") or raw.get("agent_id") or raw.get("principal") or "agent",
                "action": raw.get("intent") or raw.get("action") or "",
                "resource": raw.get("resource") or raw.get("tool") or "",
                "decision": decision,
                "allowed": decision.lower() in ("allow", "permit"),
            }
        )
    return events


def _summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    allowed = sum(1 for e in events if e["allowed"])
    denied = len(events) - allowed
    agents = sorted({e["agent"] for e in events if e["agent"]})
    return {"total": len(events), "allowed": allowed, "denied": denied, "agents": agents}


# --------------------------------------------------------------------------- #
# HTTP server
# --------------------------------------------------------------------------- #

def _make_handler(audit_path: pathlib.Path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_: Any) -> None:  # silence access logging
            pass

        def do_GET(self) -> None:  # noqa: N802 (http.server API)
            if self.path.startswith("/api/events"):
                events = _read_events(audit_path)
                body = json.dumps(
                    {"summary": _summary(events), "events": events, "audit_path": str(audit_path)}
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if self.path in ("/", "/index.html"):
                body = _PAGE.encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "text/html; charset=utf-8")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

    return Handler


def _cmd_dev(args: argparse.Namespace) -> int:
    audit_path = pathlib.Path(args.audit).expanduser()
    server = ThreadingHTTPServer((args.host, args.port), _make_handler(audit_path))
    url = f"http://{args.host}:{args.port}"
    print(f"watchlight dev — dashboard on {url}")
    print(f"  reading audit: {audit_path}")
    print("  run your governed agent in another terminal; decisions appear live.")
    print("  Ctrl-C to stop.")
    if not args.no_open:
        try:
            import webbrowser

            webbrowser.open(url)
        except Exception:  # pragma: no cover - best effort
            pass
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nwatchlight dev — stopped.")
    finally:
        server.server_close()
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="watchlight", description="Watchlight Developer Edition.")
    sub = parser.add_subparsers(dest="command")

    dev = sub.add_parser("dev", help="serve the local decision dashboard")
    dev.add_argument("--port", type=int, default=7000, help="port (default: 7000)")
    dev.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    dev.add_argument(
        "--audit",
        default=".watchlight/audit.jsonl",
        help="audit JSONL to tail (default: .watchlight/audit.jsonl)",
    )
    dev.add_argument("--no-open", action="store_true", help="do not open a browser")
    dev.set_defaults(func=_cmd_dev)

    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 0
    return int(args.func(args))


# --------------------------------------------------------------------------- #
# The dashboard page (self-contained: no external CSS/JS/fonts)
# --------------------------------------------------------------------------- #

_PAGE = """<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Watchlight · dev</title>
<style>
  :root {
    --bg:#0b0f17; --panel:#111827; --panel2:#0f1521; --border:rgba(148,163,184,.14);
    --text:#e5e7eb; --muted:#94a3b8; --amber:#fbbf24; --green:#34d399; --red:#f87171;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--text);
    font:14px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,sans-serif; }
  a { color:var(--amber); text-decoration:none; }
  header { display:flex; align-items:center; gap:12px; padding:18px 24px;
    border-bottom:1px solid var(--border); position:sticky; top:0; background:rgba(11,15,23,.85);
    backdrop-filter:blur(8px); z-index:2; }
  .logo { width:26px;height:26px;border-radius:7px;background:linear-gradient(135deg,var(--amber),#f59e0b);
    display:grid;place-items:center;color:#111;font-weight:800; }
  h1 { font-size:15px; margin:0; font-weight:700; letter-spacing:.2px; }
  .sub { color:var(--muted); font-size:12px; }
  .live { margin-left:auto; display:flex; align-items:center; gap:7px; color:var(--muted); font-size:12px; }
  .dot { width:8px;height:8px;border-radius:50%;background:var(--green); box-shadow:0 0 0 0 rgba(52,211,153,.5);
    animation:pulse 1.8s infinite; }
  @keyframes pulse { 0%{box-shadow:0 0 0 0 rgba(52,211,153,.45)} 70%{box-shadow:0 0 0 7px rgba(52,211,153,0)} 100%{box-shadow:0 0 0 0 rgba(52,211,153,0)} }
  main { max-width:1000px; margin:0 auto; padding:24px; }
  .cards { display:grid; grid-template-columns:repeat(4,1fr); gap:14px; }
  @media (max-width:640px){ .cards{ grid-template-columns:repeat(2,1fr);} }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:14px; padding:16px 18px; }
  .card .n { font-size:26px; font-weight:750; font-variant-numeric:tabular-nums; }
  .card .l { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.6px; margin-top:2px; }
  .card.deny .n { color:var(--red); } .card.allow .n { color:var(--green); }
  h2 { font-size:13px; text-transform:uppercase; letter-spacing:.7px; color:var(--muted); margin:26px 0 10px; }
  table { width:100%; border-collapse:collapse; }
  th,td { text-align:left; padding:10px 12px; border-bottom:1px solid var(--border); font-variant-numeric:tabular-nums; }
  th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.5px; }
  tr.deny td { background:rgba(248,113,113,.05); }
  .pill { display:inline-flex; align-items:center; gap:6px; font-weight:700; font-size:12px;
    padding:3px 9px; border-radius:999px; }
  .pill.allow { color:var(--green); background:rgba(52,211,153,.12); }
  .pill.deny { color:var(--red); background:rgba(248,113,113,.12); }
  .mono { font-family:ui-monospace,SFMono-Regular,Menlo,monospace; color:#cbd5e1; }
  .empty { text-align:center; color:var(--muted); padding:52px 20px; border:1px dashed var(--border); border-radius:14px; }
  .upsell { margin-top:30px; background:linear-gradient(180deg,rgba(251,191,36,.07),rgba(251,191,36,.02));
    border:1px solid rgba(251,191,36,.22); border-radius:16px; padding:20px 22px; }
  .upsell h3 { margin:0 0 6px; font-size:15px; }
  .upsell p { margin:0 0 12px; color:var(--muted); }
  .upsell ul { margin:0 0 14px; padding-left:18px; color:var(--muted); }
  .cta { display:inline-block; background:var(--amber); color:#111; font-weight:700; padding:9px 16px; border-radius:10px; }
  footer { text-align:center; color:var(--muted); font-size:12px; padding:24px; }
</style>
</head>
<body>
<header>
  <div class="logo">W</div>
  <div>
    <h1>Watchlight <span style="color:var(--amber)">·</span> dev</h1>
    <div class="sub" id="audit-path">in-process engine · value-free audit</div>
  </div>
  <div class="live"><span class="dot"></span> live</div>
</header>
<main>
  <div class="cards">
    <div class="card"><div class="n" id="c-total">0</div><div class="l">Decisions</div></div>
    <div class="card allow"><div class="n" id="c-allow">0</div><div class="l">Allowed</div></div>
    <div class="card deny"><div class="n" id="c-deny">0</div><div class="l">Denied before exec</div></div>
    <div class="card"><div class="n" id="c-agents">0</div><div class="l">Agents</div></div>
  </div>

  <h2>Decisions</h2>
  <div id="feed"></div>

  <div class="upsell">
    <h3>Governing more than one agent — or more than one environment?</h3>
    <p>The Developer Edition dashboard shows <em>this one process</em>. A fleet in production needs guarantees a single in-process engine structurally can't provide:</p>
    <ul>
      <li><b>Sub-agent scope attenuation &amp; delegation</b> — authority that can only narrow, validated end-to-end.</li>
      <li><b>Signed, tamper-evident audit &amp; lineage</b> — court-defensible, KMS-backed.</li>
      <li><b>Drift &amp; anomaly detection → automatic quarantine</b> — stop a misbehaving agent before its next action.</li>
      <li><b>Fleet-wide revocation</b> and one authority model across dev, staging, and prod.</li>
    </ul>
    <a class="cta" href="mailto:sales@watchlight.ai?subject=Watchlight%20Enterprise">Talk to us — sales@watchlight.ai →</a>
  </div>
</main>
<footer>Watchlight Developer Edition · the same engine you ship to production, in-process.</footer>

<script>
function esc(s){ return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }
function timefmt(ts){ if(!ts) return ''; const d=new Date(ts); return isNaN(d)? esc(ts) : d.toLocaleTimeString(); }
async function tick(){
  let data; try { data = await (await fetch('/api/events')).json(); } catch(e){ return; }
  const s = data.summary || {total:0,allowed:0,denied:0,agents:[]};
  document.getElementById('c-total').textContent = s.total;
  document.getElementById('c-allow').textContent = s.allowed;
  document.getElementById('c-deny').textContent  = s.denied;
  document.getElementById('c-agents').textContent = (s.agents||[]).length;
  if (data.audit_path) document.getElementById('audit-path').textContent = 'audit · ' + data.audit_path;
  const feed = document.getElementById('feed');
  const evs = (data.events||[]).slice().reverse();  // newest first
  if (!evs.length){ feed.innerHTML = '<div class="empty">No decisions yet.<br>Run your governed agent — every ALLOW and DENY appears here, live.</div>'; return; }
  let rows = '';
  for (const e of evs){
    const cls = e.allowed ? 'allow' : 'deny';
    const label = e.allowed ? 'ALLOW' : 'DENY';
    rows += `<tr class="${cls}"><td>${timefmt(e.ts)}</td><td class="mono">${esc(e.agent)}</td>`
         +  `<td class="mono">${esc(e.action)}</td><td class="mono">${esc(e.resource)}</td>`
         +  `<td><span class="pill ${cls}">${label}</span></td></tr>`;
  }
  feed.innerHTML = `<table><thead><tr><th>Time</th><th>Agent</th><th>Intent / action</th><th>Resource</th><th>Decision</th></tr></thead><tbody>${rows}</tbody></table>`;
}
tick(); setInterval(tick, 1500);
</script>
</body>
</html>"""


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
