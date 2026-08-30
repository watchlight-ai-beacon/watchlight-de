"""``watchlight`` command-line entry point.

Currently one command:

    watchlight dev        # a local dashboard for the in-process audit trail

``watchlight dev`` serves a dependency-free web page that tails the local
``.watchlight/audit.jsonl`` and shows every governance decision as it happens —
the ALLOWs and the DENYs that stopped a tool **before** it ran. It reads the
same value-free audit the engine writes; no argument values, tokens, or secrets
are ever displayed because they are never in the trail.

The dashboard shows a single process. Fleet-wide lineage, signed tamper-evident
audit, and drift→quarantine are provided by the Enterprise control plane.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


# --------------------------------------------------------------------------- #
# Reading the value-free audit trail
# --------------------------------------------------------------------------- #

def _tail_lines(audit_path: pathlib.Path, max_tail: int = 256 * 1024) -> list[str]:
    """Return the audit file's trailing lines, bounded to the last ``max_tail``
    bytes so each 1.5s poll stays cheap regardless of how large the trail grows.
    Never raises."""
    if not audit_path.exists():
        return []
    try:
        with audit_path.open("rb") as fh:
            fh.seek(0, 2)
            size = fh.tell()
            fh.seek(max(0, size - max_tail))
            data = fh.read()
    except OSError:
        return []
    lines = data.decode("utf-8", errors="replace").splitlines()
    if size > max_tail and lines:
        lines = lines[1:]  # drop the first, likely-partial, line
    return lines


def _read_events(audit_path: pathlib.Path, limit: int = 500) -> list[dict[str, Any]]:
    """Parse the audit JSONL into normalized decision records (newest last).

    Robust to both the `watchlight.govern` shape ({ts, agent, intent, resource,
    decision}) and the plugin/in-process shape — fields are looked up with
    fallbacks. Malformed lines are skipped. Never raises."""
    events: list[dict[str, Any]] = []
    for line in _tail_lines(audit_path)[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except (ValueError, TypeError):
            continue
        decision = str(raw.get("decision", "")).strip()
        # Normalize both shapes so either renders identically: the `govern`
        # decorator writes {ts, agent, intent, resource, decision:Allow/Deny};
        # the MCP PEP writes {timestamp, principal, mcp_method, tool, upstream,
        # decision:permit/deny, reason}.
        events.append(
            {
                "ts": raw.get("ts") or raw.get("timestamp") or "",
                "agent": raw.get("agent") or raw.get("agent_id") or raw.get("principal") or "agent",
                "action": raw.get("intent") or raw.get("action") or raw.get("mcp_method") or "",
                "resource": raw.get("resource") or raw.get("tool") or "",
                "decision": decision,
                "allowed": decision.lower() in ("allow", "permit"),
                "reason": str(raw.get("reason", "")).strip(),
                "via": str(raw.get("upstream", "")).strip(),
            }
        )
    return events


def _summary(events: list[dict[str, Any]]) -> dict[str, Any]:
    allowed = sum(1 for e in events if e["allowed"])
    denied = len(events) - allowed
    agents = sorted({e["agent"] for e in events if e["agent"]})
    return {"total": len(events), "allowed": allowed, "denied": denied, "agents": agents}


def _attenuation(audit_path: pathlib.Path, limit: int = 2000) -> list[dict[str, Any]]:
    """Extract sub-agent attenuation nodes for the tree view (newest-wins per
    node). Each node carries its id, parent, depth, and granted tools, so the
    console can reconstruct the exact tree — including the depth-5 ceiling, which
    arrives as a denied node whose reason points to Enterprise."""
    nodes: dict[str, dict[str, Any]] = {}
    for line in _tail_lines(audit_path)[-limit:]:
        line = line.strip()
        if not line:
            continue
        try:
            raw = json.loads(line)
        except (ValueError, TypeError):
            continue
        if raw.get("event") != "attenuation":
            continue
        nid = raw.get("node_id")
        if not nid:
            continue
        decision = str(raw.get("decision", "")).strip()
        reason = str(raw.get("reason", "")).strip()
        nodes[nid] = {
            "id": nid,
            "parent": raw.get("parent_id"),
            "depth": raw.get("depth", 0),
            "tools": raw.get("tools", []),
            "allowed": decision.lower() in ("allow", "permit"),
            "reason": reason,
            # The ceiling is the one denial whose reason points to Enterprise.
            "ceiling": (not decision.lower() in ("allow", "permit"))
            and "watchlight.ai" in reason,
        }
    return list(nodes.values())


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
                    {
                        "summary": _summary(events),
                        "events": events,
                        "attenuation": _attenuation(audit_path),
                        "audit_path": str(audit_path),
                    }
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
            if self.path in ("/favicon.svg", "/favicon.ico"):
                body = _FAVICON_SVG.encode("utf-8")
                self.send_response(200)
                self.send_header("content-type", "image/svg+xml")
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


# --------------------------------------------------------------------------- #
# `watchlight policy test` — run golden policy fixtures in CI
# --------------------------------------------------------------------------- #

def _color(enabled: bool):
    def wrap(code: str):
        return (lambda s: f"\x1b[{code}m{s}\x1b[0m") if enabled else (lambda s: s)
    return wrap("32"), wrap("31"), wrap("2")  # green, red, dim


def _print_report(file: str, report: dict) -> None:
    enabled = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    green, red, dim = _color(enabled)
    print(f"watchlight policy test — {file}\n")
    for r in report["results"]:
        name, expected, actual = r["name"], r["expected"], r["actual"]
        if r["ok"]:
            print(f"  {green('✓')} {name} {dim('→ ' + actual)}")
        else:
            why = dim(f"  ({r['reason']})") if r["reason"] else ""
            verdict = red(f"— expected {expected}, got {actual}")
            print(f"  {red('✗')} {name} {verdict}{why}")
    summary = f"{report['passed']} passed, {report['failed']} failed ({report['total']} total)"
    print("\n" + (red(summary) if report["failed"] else green(summary)))


def _cmd_policy_test(args: argparse.Namespace) -> int:
    # Imported here so `watchlight dev` never pays for loading the engine.
    from . import Watchlight
    from .policytest import load_test_suite

    file = pathlib.Path(args.suite)
    try:
        suite = load_test_suite(file)
    except Exception as exc:  # noqa: BLE001 - report and fail the CI step
        print(f"watchlight: could not read suite '{file}': {exc}", file=sys.stderr)
        return 2

    # Fresh, policy-free governor (fail-closed); load only what the suite declares.
    # No audit is written — `test()` uses the engine's decision core directly.
    gov = Watchlight(agent="policy-test")
    policy_file = suite.get("policy_file")
    if policy_file:
        gov.load(file.parent / policy_file)
    for policy in suite.get("policies") or []:
        gov.allow(policy["code"], policy.get("name"))

    tests = suite.get("tests") or []
    if not tests:
        print(f"watchlight: suite '{file}' has no tests", file=sys.stderr)
        return 2

    try:
        report = gov.test(tests)
    except ValueError as exc:  # malformed fixture (missing action/expect)
        print(f"watchlight: {exc}", file=sys.stderr)
        return 2
    _print_report(str(file), report)
    return 1 if report["failed"] else 0


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

    policy = sub.add_parser("policy", help="policy tooling")
    policy_sub = policy.add_subparsers(dest="policy_command")
    ptest = policy_sub.add_parser("test", help="run policy fixtures (exit 1 on failure)")
    ptest.add_argument("suite", help="suite JSON: {policyFile?|policies?, tests:[...]}")
    ptest.set_defaults(func=_cmd_policy_test)

    args = parser.parse_args(argv)
    if not getattr(args, "command", None) or not getattr(args, "func", None):
        parser.print_help()
        return 0
    return int(args.func(args))


# --------------------------------------------------------------------------- #
# The dashboard page (self-contained: no external CSS/JS/fonts)
# --------------------------------------------------------------------------- #

# The Watchlight beacon mark — the favicon used by the docs site.
# Embedded here so the dashboard tab shows the Watchlight icon next to its
# title with zero external requests (script-free, self-contained).
_FAVICON_SVG = """<svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 48 48">
  <defs>
    <radialGradient id="beacon" cx="50%" cy="45%" r="55%">
      <stop offset="0%" stop-color="#fde68a"/>
      <stop offset="45%" stop-color="#fbbf24"/>
      <stop offset="100%" stop-color="#d97706"/>
    </radialGradient>
    <linearGradient id="tile" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#111826"/>
      <stop offset="100%" stop-color="#0a0e17"/>
    </linearGradient>
  </defs>
  <rect width="48" height="48" rx="11" fill="url(#tile)"/>
  <rect x="0.75" y="0.75" width="46.5" height="46.5" rx="10.25" fill="none" stroke="#20293a" stroke-width="1.5"/>
  <path d="M7 24 C 14 12.5, 34 12.5, 41 24 C 34 35.5, 14 35.5, 7 24 Z"
        fill="none" stroke="#f59e0b" stroke-width="2.6" stroke-linejoin="round"/>
  <circle cx="24" cy="24" r="10.5" fill="#f59e0b" opacity="0.22"/>
  <circle cx="24" cy="24" r="6.6" fill="url(#beacon)"/>
  <circle cx="21.4" cy="21.4" r="1.7" fill="#fffaf0"/>
</svg>
"""

_PAGE = """<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Watchlight · dev</title>
<link rel="icon" type="image/svg+xml" href="/favicon.svg" />
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
  .enterprise { margin-top:30px; background:linear-gradient(180deg,rgba(251,191,36,.07),rgba(251,191,36,.02));
    border:1px solid rgba(251,191,36,.22); border-radius:16px; padding:20px 22px; }
  .enterprise h3 { margin:0 0 6px; font-size:15px; }
  .enterprise p { margin:0 0 12px; color:var(--muted); }
  .enterprise ul { margin:0 0 14px; padding-left:18px; color:var(--muted); }
  .cta { display:inline-block; background:var(--amber); color:#111; font-weight:700; padding:9px 16px; border-radius:10px; }
  footer { text-align:center; color:var(--muted); font-size:12px; padding:24px; }
  /* Attenuation tree */
  .attn-row { font:13px/1.6 ui-monospace,SFMono-Regular,Menlo,monospace; padding:2px 0; border-left:2px solid transparent; }
  .attn-row.allow   { border-left-color:var(--green); }
  .attn-row.deny    { border-left-color:var(--red); }
  .attn-row.ceiling { border-left-color:var(--amber); background:rgba(251,191,36,.06); }
  .attn-depth { color:var(--muted); }
  .attn-tools { color:var(--text); }
  .attn-reason { color:var(--amber); font-size:12px; padding:2px 0 10px; max-width:78ch; }
  #attn-section { margin-top:4px; }
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

  <div id="attn-section" style="display:none">
    <h2>Attenuation tree <span class="sub" style="font-weight:400">— authority narrowing per sub-agent (Developer-Edition ceiling: depth 5)</span></h2>
    <div id="attn"></div>
  </div>

  <h2>Decisions</h2>
  <div id="feed"></div>

  <div class="enterprise">
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
<footer>Watchlight Developer Edition · in-process governance.</footer>

<script>
function esc(s){ return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
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
  const path = esc(data.audit_path || '.watchlight/audit.jsonl');
  if (!evs.length){
    feed.innerHTML =
      `<div class="empty"><b>No decisions yet.</b> This console tails <span class="mono">${path}</span>.`
      + `<br><br>Feed it from either side — in another terminal, from this directory:`
      + `<br>&bull; a governed tool &mdash; <span class="mono">@govern.tool(...)</span> writes it automatically`
      + `<br>&bull; an MCP server &mdash; <span class="mono">serve(&hellip;, audit_path="${path}")</span>`
      + `<br><br>Every ALLOW and DENY streams in here, live.</div>`;
    return;
  }
  let rows = '';
  for (const e of evs){
    const cls = e.allowed ? 'allow' : 'deny';
    const label = e.allowed ? 'ALLOW' : 'DENY';
    const via = e.via ? ` <span style="color:var(--muted);font-size:11px">via ${esc(e.via)}</span>` : '';
    const reason = (!e.allowed && e.reason) ? `<div style="color:var(--muted);font-size:12px;margin-top:2px">${esc(e.reason)}</div>` : '';
    rows += `<tr class="${cls}"><td>${timefmt(e.ts)}</td><td class="mono">${esc(e.agent)}</td>`
         +  `<td class="mono">${esc(e.action)}</td><td class="mono">${esc(e.resource)}${via}${reason}</td>`
         +  `<td><span class="pill ${cls}">${label}</span></td></tr>`;
  }
  feed.innerHTML = `<table><thead><tr><th>Time</th><th>Agent</th><th>Intent / method</th><th>Resource</th><th>Decision</th></tr></thead><tbody>${rows}</tbody></table>`;
  renderAttn(data.attenuation);
}
function renderAttn(nodes){
  const box = document.getElementById('attn-section');
  if (!nodes || !nodes.length){ box.style.display='none'; return; }
  box.style.display='';
  const byId = {}, roots = [];
  nodes.forEach(n => { byId[n.id] = Object.assign({}, n, {children: []}); });
  nodes.forEach(n => { const nd = byId[n.id]; (n.parent && byId[n.parent] ? byId[n.parent].children : roots).push(nd); });
  let out = '';
  function walk(node){
    const cls = node.ceiling ? 'ceiling' : (node.allowed ? 'allow' : 'deny');
    const tools = (node.tools && node.tools.length) ? node.tools.join(', ') : '∅';
    const pad = 12 + (node.depth || 0) * 22;
    out += `<div class="attn-row ${cls}" style="padding-left:${pad}px">`
         + `<span class="attn-depth">depth ${node.depth}</span> · `
         + `<span class="attn-tools">[${esc(tools)}]</span>`
         + (node.ceiling ? ` <span class="pill deny">CEILING → Enterprise</span>`
                         : (node.allowed ? '' : ` <span class="pill deny">DENY</span>`))
         + `</div>`;
    if (node.ceiling && node.reason) out += `<div class="attn-reason" style="padding-left:${pad}px">${esc(node.reason)}</div>`;
    node.children.sort((a,b) => (a.depth||0) - (b.depth||0)).forEach(walk);
  }
  roots.sort((a,b) => (a.depth||0) - (b.depth||0)).forEach(walk);
  document.getElementById('attn').innerHTML = out;
}
tick(); setInterval(tick, 1500);
</script>
</body>
</html>"""


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
