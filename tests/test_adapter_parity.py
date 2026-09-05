"""What a framework adapter can and cannot express, in the Python lane.

The TypeScript adapters (``governTool`` / ``governedHooks``) wrap a tool
themselves, so they carry every term ``tool()`` carries — see
``ts/test/adapter-parity.test.mjs``. The Python adapters are different in kind:
``watchlight.<framework>.governed_plugin`` builds a published framework plugin
and hands it the in-process engine. It is CONSTRUCTOR wiring. The governance
terms of a single call — the resource, Cedar ``context`` — belong to the
plugin's own run handle, and the acting subject is not expressible through a
plugin at all: every decision a plugin makes is attributed to the agent.

That distinction has to hold in the code and not only in prose, because the
failure it prevents is silent: a term a caller believes is reaching the
decision, and is not, is a policy that never matches and a tenancy rule that
denies for a reason no record explains. So the factory refuses those terms BY
NAME, and this file pins both halves — the refusal, and the ``tool()`` path
that does take them.
"""

from __future__ import annotations

import inspect
import json
import sys
import types

import pytest

pytest.importorskip("watchlight_engine")

from watchlight import Watchlight, principals  # noqa: E402
from watchlight.claude_agent import governed_plugin as claude_agent_plugin  # noqa: E402
from watchlight.langgraph import governed_plugin as langgraph_plugin  # noqa: E402
from watchlight.pydantic_ai import governed_plugin as pydantic_ai_plugin  # noqa: E402

# A tenancy rule whose verdict depends ENTIRELY on Cedar context.
TENANCY = (
    'permit(principal, action == Action::"read_ticket", resource) when { '
    "context has owner && context has caller && context.caller == context.owner };"
)

FACTORIES = {
    "langgraph": langgraph_plugin,
    "claude_agent": claude_agent_plugin,
    "pydantic_ai": pydantic_ai_plugin,
}

# The published plugin each factory builds, and its real constructor keywords.
PLUGINS = {
    "langgraph": ("watchlight_langgraph", "WatchlightLangGraphPlugin"),
    "claude_agent": ("watchlight_claude_agent", "WatchlightClaudeAgentSDKPlugin"),
    "pydantic_ai": ("watchlight_pydantic_ai", "WatchlightPydanticAIPlugin"),
}


def records(tmp_path):
    return [json.loads(line) for line in (tmp_path / "audit.jsonl").read_text().splitlines()]


@pytest.fixture
def stub_plugins(monkeypatch):
    """Stand in for the published plugin packages, with their real constructor
    keywords — the extras are not installed for the test run, and what is under
    test is what the factory forwards, not what the plugin does with it."""
    built = {}

    for framework, (module_name, class_name) in PLUGINS.items():

        class _Plugin:
            def __init__(
                self,
                apdp_url="http://localhost:8081",
                tenant_id=None,
                apdp_api_key=None,
                log_decisions=True,
                connect_proxy_url=None,
                governance=None,
                **rest,
            ):
                built[self.__class__.__framework__] = dict(
                    apdp_url=apdp_url,
                    tenant_id=tenant_id,
                    log_decisions=log_decisions,
                    governance=governance,
                    **rest,
                )

        _Plugin.__framework__ = framework
        _Plugin.__name__ = class_name
        module = types.ModuleType(module_name)
        setattr(module, class_name, _Plugin)
        monkeypatch.setitem(sys.modules, module_name, module)

    # Take the networked branch: it needs no compiled in-process client, and the
    # kwarg forwarding under test is the same on both branches.
    monkeypatch.setenv("WATCHLIGHT_APDP_URL", "https://apdp.example")
    return built


# ── what the factory cannot express, said by name ───────────────────────────


@pytest.mark.parametrize("framework", sorted(FACTORIES))
@pytest.mark.parametrize(
    "term, expected",
    [
        ("principal", "attributes every decision to the agent"),
        ("context", "per-call term"),
        ("resource", "per-call term"),
    ],
)
def test_a_per_call_term_is_refused_by_name(stub_plugins, framework, term, expected):
    with pytest.raises(TypeError) as excinfo:
        FACTORIES[framework](None, **{term: "anything"})
    message = str(excinfo.value)
    # Named, with somewhere to go — not an opaque "unexpected keyword argument"
    # from a plugin constructor the caller never wrote.
    assert f"`{term}`" in message
    assert expected in message
    assert "unexpected keyword argument" not in message


@pytest.mark.parametrize("framework", sorted(FACTORIES))
def test_the_refusal_happens_before_the_plugin_is_built(stub_plugins, framework):
    with pytest.raises(TypeError):
        FACTORIES[framework](None, tenant_id="acme", principal=principals.user("u1"))
    assert framework not in stub_plugins


@pytest.mark.parametrize("framework", sorted(FACTORIES))
def test_the_limit_is_in_the_docstring_an_integrator_reads(framework):
    doc = inspect.getdoc(FACTORIES[framework]) or ""
    assert "cannot express" in doc
    assert "authorize_action" in doc  # where context DOES go
    assert "Watchlight.tool" in doc  # where a named subject goes


# ── what it still forwards, unchanged ───────────────────────────────────────


@pytest.mark.parametrize("framework", sorted(FACTORIES))
def test_plugin_kwargs_are_forwarded_verbatim(stub_plugins, framework):
    FACTORIES[framework](None, tenant_id="acme", log_decisions=False)
    assert stub_plugins[framework]["tenant_id"] == "acme"
    assert stub_plugins[framework]["log_decisions"] is False


@pytest.mark.parametrize("framework", sorted(FACTORIES))
def test_the_factory_signature_is_unchanged(framework):
    params = list(inspect.signature(FACTORIES[framework]).parameters)
    assert params == ["policies", "audit_path", "plugin_kwargs"]


# ── what tool() expresses instead ───────────────────────────────────────────


def test_tool_satisfies_a_context_dependent_policy(tmp_path):
    """The path an integrator is pointed at when a policy needs context or a
    subject: the same tenancy rule, satisfied per call."""
    g = Watchlight(agent="tenancy-agent", audit_dir=str(tmp_path))
    g.allow(TENANCY, "same-tenant")

    @g.tool(
        "read_ticket",
        principal=lambda **kw: principals.user(kw["caller"]),
        context=lambda **kw: {"caller": kw["caller"], "owner": kw["owner"]},
    )
    def read_ticket(*, ticket, caller, owner):
        return f"ticket:{ticket}"

    assert read_ticket(ticket=1, caller="u1", owner="u1") == "ticket:1"

    from watchlight import Denied

    with pytest.raises(Denied):
        read_ticket(ticket=2, caller="u2", owner="u1")

    rows = records(tmp_path)
    # The subject reaches the decision AND the record — not the agent.
    assert [r["principal"] for r in rows] == ['User::"u1"', 'User::"u2"']
    assert [r["decision"] for r in rows] == ["Allow", "Deny"]
    # Value-free: the tenancy attributes are read, never written.
    assert "ticket:" not in (tmp_path / "audit.jsonl").read_text()


def test_without_context_the_same_policy_denies(tmp_path):
    """The failure this whole file exists for, in one assertion: the rule is
    unsatisfiable when nothing carries the context it reads."""
    g = Watchlight(agent="tenancy-agent", audit_dir=str(tmp_path))
    g.allow(TENANCY, "same-tenant")
    d = g.authorize(action="read_ticket", resource="tool/read_ticket")
    assert d["decision"] == "Deny"
    assert d["reason"] == "not authorized"
