"""Every Cedar policy in the plugin READMEs decides the run its README shows.

A README policy is an instruction: a reader copies it. On every backend the
principal of a governed call is the agent's id, ``Agent::"<agent uuid>"``:
``start_run`` resolves the slug first (``InProcessClient.resolve_agent`` derives
a UUID from it; wl-apdp returns the registry id). A policy that names the slug
as the id, ``principal == Agent::"research-agent"``, therefore never matches.
As a ``permit`` it allows nothing. As a ``forbid`` it forbids nothing, so the
example teaches a rule that silently does not apply.

An agent-scoped policy uses the agent's trusted attributes instead:
``principal.name`` (``InProcessClient`` registers the slug as the agent's name
with the engine, as wl-apdp reads the name from the registry record).

This test reads every Cedar statement in the Markdown under ``plugins/`` (a
``cedar`` block, a quoted policy in a code sample, or a ``"code"`` value in a
``json`` block) and decides it through a real ``BaseRunHandle`` over
``InProcessClient``, for the agent slug, action and resource its README uses:

- a ``permit`` must allow its scenario, deny each action in ``denied``, and deny
  the same call by another agent (``other_agent``), so an agent-scoped permit
  applies to the named agent ONLY;
- a ``forbid`` is loaded next to ``permit(principal, action, resource);`` and
  must deny its scenario, which proves the forbid itself matched.

A policy with no scenario below, or a scenario whose policy left its README,
fails here. CI builds the engine and sets ``WATCHLIGHT_REQUIRE_ENGINE``, so these
run there rather than skip (see ``conftest.py``).
"""

from __future__ import annotations

import contextlib
import io
import json
import pathlib
import re
import runpy
import uuid
from typing import Dict, List, Tuple

import pytest

pytest.importorskip("watchlight_engine")

from watchlight_core import InProcessClient  # noqa: E402
from watchlight_core.telemetry import GovernanceTelemetry  # noqa: E402
from watchlight_core_testing import stub_handle  # noqa: E402

PLUGINS = pathlib.Path(__file__).resolve().parents[2]

FENCE = re.compile(r"^(`{3,})([^\s`]*)[^\n]*\n(.*?)^\1[ \t]*$", re.S | re.M)
STATEMENT_START = re.compile(r"\b(?:permit|forbid)\s*\(")
QUOTED = re.compile(r"'((?:[^'\\\n]|\\.)*)'")
AGENT_LITERAL = re.compile(r'\bAgent::"([^"]*)"')
CATCH_ALL = "permit(principal, action, resource);"

#: The agent every scenario checks is denied what the named agent is allowed.
OTHER_AGENT = "some-other-agent"


def _read_by(slug: str) -> str:
    return (
        'permit(principal is Agent, action == Action::"read", resource) '
        f'when {{ principal.name == "{slug}" }};'
    )


READ_RESEARCH = _read_by("research-agent")

#: One scenario per README policy: the slug the README's run starts with, and
#: the action and resource its agent is governed on.
SCENARIOS: List[dict] = [
    {
        "file": "watchlight-core/README.md",
        "policy": READ_RESEARCH,
        "agent": "research-agent",
        "action": "read",
        "resource": "dataset",
        "denied": ["delete"],
    },
    {
        "file": "watchlight-core/README.md",
        "policy": (
            'permit(principal is Agent, action == Action::"read", resource) '
            'when { principal.name == "research-agent" };'
        ),
        "agent": "research-agent",
        "action": "read",
        "resource": "dataset",
        "denied": ["delete"],
    },
    {
        "file": "watchlight-adk/README.md",
        "policy": _read_by("agent-research-agent"),
        "agent": "agent-research-agent",
        "action": "read",
        "resource": "get_report",
        "denied": ["write", "execute"],
    },
    {
        "file": "watchlight-bedrock/README.md",
        "policy": READ_RESEARCH,
        "agent": "research-agent",
        "action": "read",
        "resource": "dataset",
        "denied": ["execute"],
    },
    {
        "file": "watchlight-bedrock/README.md",
        "policy": (
            'permit( principal is Agent, action == Action::"invoke_agent_version", '
            'resource == Resource::"bedrock://agent/AGENT12345/version/3" ) '
            'when { principal.name == "research-agent" };'
        ),
        "agent": "research-agent",
        "action": "invoke_agent_version",
        "resource": "bedrock://agent/AGENT12345/version/3",
        "denied": ["execute"],
    },
    {
        "file": "watchlight-claude-agent/README.md",
        "policy": (
            'permit(principal is Agent, action == Action::"execute", resource) '
            'when { principal.name == "research-agent" };'
        ),
        "agent": "research-agent",
        "action": "execute",
        "resource": "Read",
        "denied": ["read"],
    },
    {
        "file": "watchlight-deepagents/README.md",
        "policy": _read_by("research-orchestrator"),
        "agent": "research-orchestrator",
        "action": "read",
        "resource": "search",
        "denied": ["execute"],
    },
    {
        "file": "watchlight-langgraph/README.md",
        "policy": READ_RESEARCH,
        "agent": "research-agent",
        "action": "read",
        "resource": "dataset",
        "denied": ["delete"],
    },
    {
        "file": "watchlight-msaf/README.md",
        "policy": READ_RESEARCH,
        "agent": "research-agent",
        "action": "read",
        "resource": "dataset",
        "denied": ["delete"],
    },
    {
        "file": "watchlight-pydantic-ai/README.md",
        "policy": (
            'permit(principal is Agent, action == Action::"execute", '
            'resource == Resource::"web_search") '
            'when { principal.name == "research-agent" };'
        ),
        "agent": "research-agent",
        "action": "execute",
        "resource": "web_search",
        "denied": ["read"],
    },
    {
        "file": "watchlight-strands/README.md",
        "policy": (
            'permit(principal is Agent, action == Action::"execute", '
            'resource == Resource::"web_search") '
            'when { principal.name == "agent-writer" };'
        ),
        "agent": "agent-writer",
        "action": "execute",
        "resource": "web_search",
        "denied": ["read"],
    },
    {
        "file": "watchlight-strands/README.md",
        "policy": (
            'permit(principal is Agent, action == Action::"execute", '
            'resource == Resource::"researcher") '
            'when { principal.name == "agent-writer" };'
        ),
        "agent": "agent-writer",
        "action": "execute",
        "resource": "researcher",
        "denied": ["read"],
    },
]


# ── extraction ───────────────────────────────────────────────────────


def _normalize(statement: str) -> str:
    return " ".join(statement.split())


def _strip_comments(text: str) -> str:
    """Remove ``//`` comments, leaving any ``//`` inside a string."""
    out: List[str] = []
    in_string = False
    i = 0
    while i < len(text):
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < len(text):
                out.append(text[i + 1])
                i += 1
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
            out.append(ch)
        elif text.startswith("//", i):
            while i < len(text) and text[i] != "\n":
                i += 1
            continue
        else:
            out.append(ch)
        i += 1
    return "".join(out)


def _split_statements(cedar: str) -> List[str]:
    """Split Cedar text into statements on each ``;`` outside a string."""
    statements: List[str] = []
    current: List[str] = []
    in_string = False
    text = _strip_comments(cedar)
    i = 0
    while i < len(text):
        ch = text[i]
        current.append(ch)
        if in_string:
            if ch == "\\" and i + 1 < len(text):
                current.append(text[i + 1])
                i += 1
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch == ";":
            statements.append("".join(current))
            current = []
        i += 1
    tail = "".join(current).strip()
    assert not tail, f"Cedar text ends without a ';': {tail!r}"
    return [_normalize(s) for s in statements if s.strip()]


def _json_codes(value) -> List[str]:
    if isinstance(value, dict):
        found: List[str] = []
        for key, item in value.items():
            if key == "code" and isinstance(item, str):
                found.append(item)
            else:
                found.extend(_json_codes(item))
        return found
    if isinstance(value, list):
        return [code for item in value for code in _json_codes(item)]
    return []


def _fence_statements(lang: str, body: str) -> List[str]:
    if lang == "cedar":
        return _split_statements(body)
    if lang == "json":
        texts = _json_codes(json.loads(body))
    else:
        texts = [m.group(1) for m in QUOTED.finditer(body) if STATEMENT_START.search(m.group(1))]
    return [s for text in texts for s in _split_statements(text)]


def _markdown_files() -> List[pathlib.Path]:
    return sorted(
        p for p in PLUGINS.rglob("*.md")
        if not {"node_modules", ".venv", "dist", "build"} & set(p.relative_to(PLUGINS).parts)
    )


def extract() -> Dict[Tuple[str, str], int]:
    """``(file, statement) -> occurrences`` for every policy under ``plugins/``."""
    found: Dict[Tuple[str, str], int] = {}
    for path in _markdown_files():
        rel = path.relative_to(PLUGINS).as_posix()
        text = path.read_text(encoding="utf-8")
        for match in FENCE.finditer(text):
            lang, body = match.group(2).lower(), match.group(3)
            if not STATEMENT_START.search(body):
                continue
            statements = _fence_statements(lang, body)
            # Every `permit(` / `forbid(` in the block must have been read: a
            # policy in a shape this reader does not know would go unchecked.
            expected = len(
                STATEMENT_START.findall(_strip_comments(body) if lang == "cedar" else body)
            )
            line = text[: match.start()].count("\n") + 1
            assert len(statements) == expected, (
                f"{rel}:{line}: read {len(statements)} policy statements from a "
                f"`{lang}` block that has {expected}; teach this test the block's shape"
            )
            for statement in statements:
                found[(rel, statement)] = found.get((rel, statement), 0) + 1
    return found


# ── the checks ───────────────────────────────────────────────────────


def test_every_readme_policy_has_a_scenario():
    in_docs = set(extract())
    in_table = {(s["file"], _normalize(s["policy"])) for s in SCENARIOS}
    missing = sorted(in_docs - in_table)
    stale = sorted(in_table - in_docs)
    assert not missing, "README policies with no scenario in SCENARIOS:\n" + "\n".join(
        f"  {f}: {p}" for f, p in missing
    )
    assert not stale, "scenarios whose policy is no longer in its README:\n" + "\n".join(
        f"  {f}: {p}" for f, p in stale
    )


def test_no_readme_policy_names_an_agent_by_slug():
    """The principal is always the agent's id. A literal ``Agent::"<x>"`` is a
    UUID or a visible ``<placeholder>``; a policy names an agent by
    ``principal.name`` (or ``principal.slug``) instead."""
    offenders = []
    for (rel, statement) in extract():
        for literal in AGENT_LITERAL.findall(statement):
            if literal.startswith("<") and literal.endswith(">"):
                continue
            try:
                uuid.UUID(literal)
            except ValueError:
                offenders.append(f"{rel}: Agent::\"{literal}\" in {statement}")
    assert not offenders, (
        "a README policy names an agent by slug; the principal is the agent's id, "
        "Agent::\"<agent uuid>\":\n" + "\n".join(f"  {o}" for o in offenders)
    )


class _Plugin(GovernanceTelemetry):
    def __init__(self, backend: InProcessClient) -> None:
        super().__init__()
        self.apdp = backend
        self.tenant_id = None
        self.log_decisions = False


async def _authorize(
    policies: List[str], slug: str, action: str, resource: str, *, also: Tuple[str, ...] = ()
) -> bool:
    """One ``authorize_action`` through a real ``BaseRunHandle``, for the agent
    ``start_run(slug)`` resolves to: the principal is the RunHandle's own
    default, ``Agent::"<agent uuid>"``. The slugs in ``also`` are resolved
    first, so other agents are known to the engine too."""
    backend = InProcessClient(
        [{"name": f"p{i}", "code": code} for i, code in enumerate(policies)],
        audit_path=None,
    )
    for other in also:
        await backend.resolve_agent(other)
    agent = await backend.resolve_agent(slug)
    session = await backend.create_session(agent_id=agent["id"])
    handle = stub_handle(_Plugin(backend), agent_uuid=agent["id"], session_id=session.session_id)
    async with handle:
        return await handle.authorize_action(action, resource)


@pytest.mark.asyncio
@pytest.mark.parametrize("scenario", SCENARIOS, ids=[s["file"] for s in SCENARIOS])
async def test_readme_policy_decides_its_scenario(scenario):
    policy = _normalize(scenario["policy"])
    slug, action, resource = scenario["agent"], scenario["action"], scenario["resource"]
    if policy.startswith("forbid") or " forbid(" in policy:
        assert not await _authorize([CATCH_ALL, policy], slug, action, resource), (
            f"{scenario['file']}: the forbid does not match the run it documents, "
            f"so it forbids nothing: {policy}"
        )
        return
    assert await _authorize([policy], slug, action, resource), (
        f"{scenario['file']}: the permit does not allow the run it documents: {policy}"
    )
    for other in scenario.get("denied", []):
        assert not await _authorize([policy], slug, other, resource), (
            f"{scenario['file']}: the permit also allows {other!r}: {policy}"
        )
    # Agent-scoped: the same call by another agent is denied, whether or not
    # the named agent is known to the engine too.
    for also in ((), (slug,)):
        assert not await _authorize([policy], OTHER_AGENT, action, resource, also=also), (
            f"{scenario['file']}: the permit also allows another agent: {policy}"
        )


@pytest.mark.asyncio
async def test_a_slug_scoped_policy_never_matches_the_run():
    """Why the examples name the agent by attribute: the run's principal is
    the id, so the slug as an id allows nothing as a permit and forbids
    nothing as a forbid."""
    slug_permit = 'permit(principal == Agent::"research-agent", action == Action::"read", resource);'
    slug_forbid = 'forbid(principal == Agent::"research-agent", action == Action::"read", resource);'
    assert not await _authorize([slug_permit], "research-agent", "read", "dataset")
    assert await _authorize([CATCH_ALL, slug_forbid], "research-agent", "read", "dataset")


@pytest.mark.asyncio
@pytest.mark.parametrize("attribute", ["name", "slug"])
async def test_a_name_scoped_policy_applies_to_the_named_agent_only(attribute):
    """``principal.name`` / ``principal.slug`` is the slug ``start_run`` was
    given: a permit allows that agent and no other, and a forbid denies that
    agent and no other."""
    permit = f'permit(principal, action, resource) when {{ principal.{attribute} == "research-agent" }};'
    forbid = f'forbid(principal, action, resource) when {{ principal.{attribute} == "research-agent" }};'
    assert await _authorize([permit], "research-agent", "read", "dataset", also=(OTHER_AGENT,))
    assert not await _authorize([permit], OTHER_AGENT, "read", "dataset", also=("research-agent",))
    assert not await _authorize([CATCH_ALL, forbid], "research-agent", "read", "dataset")
    assert await _authorize([CATCH_ALL, forbid], OTHER_AGENT, "read", "dataset", also=("research-agent",))


@pytest.mark.asyncio
async def test_the_caller_cannot_name_the_agent_through_context():
    """A context key cannot set or change the trusted name."""
    permit = 'permit(principal, action, resource) when { principal.name == "research-agent" };'
    backend = InProcessClient([{"name": "p", "code": permit}], audit_path=None)
    await backend.resolve_agent("research-agent")
    other = await backend.resolve_agent(OTHER_AGENT)
    me = f'Agent::"{other["id"]}"'
    for context in ({"agent_name": "research-agent"}, {"name": "research-agent"},
                    {"agent_slug": "research-agent"}):
        result = await backend.authorize(me, "read", "dataset", context=context)
        assert result["decision"] == "Deny", context


def test_the_core_quickstart_prints_what_its_readme_says(tmp_path, monkeypatch):
    """The SDK README's quickstart runs, and prints the Allow / Deny it shows."""
    text = (PLUGINS / "watchlight-core" / "README.md").read_text(encoding="utf-8")
    start = text.index("## Quickstart")
    blocks = [m for m in FENCE.finditer(text, start)]
    code = next(m.group(3) for m in blocks if m.group(2) == "python")
    shown = next(m.group(3) for m in blocks if m.group(2) == "text")
    monkeypatch.chdir(tmp_path)  # the quickstart writes .watchlight/audit.jsonl
    script = tmp_path / "readme_quickstart.py"
    script.write_text(code, encoding="utf-8")
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        runpy.run_path(str(script), run_name="__readme__")
    assert out.getvalue().split() == shown.split()
