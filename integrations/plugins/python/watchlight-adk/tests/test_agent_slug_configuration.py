"""The governed identity is CONFIGURED, never derived from ADK's
``agent.name``.

The defect these tests pin: ``before_agent_callback`` used to compute the
Watchlight slug from ``agent.name`` — first as ``agent.name.replace("_",
"-")``, then as that plus wl-registry's ``agent-`` prefixed spelling, as a
zero-configuration fallback.

A derived slug that 404s is a nuisance. A derived slug that RESOLVES is a
security defect: the run takes the resolved agent's UUID, passes its trust
check, opens a session as it, gets its tool allowlist, authorizes under
its Cedar policies and attributes its lineage — under an identity nobody
configured. Since wl-registry mints ``agent-<name>`` from an agent's name,
an unregistered ADK object named ``finance_bot`` derived
``agent-finance-bot`` and landed on whoever registered "finance bot"
first. Whoever writes ``LlmAgent(name=...)`` chose the governed identity.

The contract now, with no fallback and no opt-in switch to bring one back:

* the root agent authorizes under ``agent_slug``, and only when
  ``agent.name`` is the configured ``root_agent_name`` — the slug is bound
  to an identity, not to whichever agent opens an invocation;
* every other agent authorizes under its ``subagent_slugs[agent.name]``
  entry;
* an ADK agent with no mapping is REFUSED, and the refusal says
  *not configured* (a deployment error) rather than *not registered*;
* a plugin with no identity configured raises at CONSTRUCTION.
"""

from __future__ import annotations

import copy
from unittest.mock import AsyncMock

import pytest

import watchlight_adk
from watchlight_adk import WatchlightPlugin
from watchlight_adk.agent_slugs import configured_slug, normalize_subagent_slugs
from watchlight_adk.plugin import _NO_RUN_REFUSAL
from watchlight_core_testing import stub_session_info
from .conftest import stand_in_spawn

# These tests call the plugin's callbacks directly: a governed run is live.
pytestmark = pytest.mark.usefixtures("governed_run_live")

ROOT_NAME = "adk_orchestrator"
ROOT_SLUG = "agent-adk-orchestrator"
ROOT_UUID = "a0000000-0000-4000-8000-000000000001"

CHILD_NAME = "adk_researcher"
CHILD_SLUG = "agent-adk-researcher"
CHILD_UUID = "a0000000-0000-4000-8000-000000000002"


class _Agent:
    def __init__(self, name: str) -> None:
        self.name = name
        self.tools: list = []


class _Ctx:
    state: dict = {}


def _resolved(slug: str, uuid: str) -> dict:
    return {"id": uuid, "slug": slug, "name": slug, "trust_state": "trusted"}


def _plugin(**kwargs) -> WatchlightPlugin:
    """A plugin whose every network method is stubbed — these tests
    assert on the SLUG the plugin asks for, not on I/O."""
    kwargs.setdefault("agent_slug", ROOT_SLUG)
    kwargs.setdefault("root_agent_name", ROOT_NAME)
    p = WatchlightPlugin(apdp_url="https://apdp.test", log_decisions=False, **kwargs)
    p.apdp.resolve_agent = AsyncMock(return_value=None)
    p.apdp.check_agent_trust = AsyncMock(return_value={"trusted": True, "reason": ""})
    p.apdp.create_session = AsyncMock(
        return_value=stub_session_info(p.apdp, "ses_test", session_token="sst_test")
    )
    p.apdp.get_manifest = AsyncMock(return_value={"tool_allowlist": []})
    # A granted governed spawn, so a nested agent starts and the test can
    # read the identity it committed (a refused spawn never starts).
    p.apdp.spawn_subagent = AsyncMock(
        return_value=stand_in_spawn({
            "child_run_handle_id": "00000000-0000-4000-8000-0000000000c1",
            "granted_scope": {
                "allowed_tools": [],
                "allowed_resources": [],
                "allowed_intents": [],
                "max_depth": 1,
                "time_budget_seconds": 0,
            },
            "child_execution_id": "exec_child_test",
            "root_execution_id": "exec_root_test",
            "child_session_id": "ses_child_test",
            "child_session_token": "sst_child_test",
        })
    )
    p.lineage.connect = AsyncMock()
    p.lineage.emit_execution_started = AsyncMock()
    return p


def _slugs_asked(p: WatchlightPlugin) -> list:
    return [c.args[0] for c in p.apdp.resolve_agent.call_args_list]


# ─── The wire contract: which slug leaves the plugin ──────────────────


@pytest.mark.asyncio
async def test_root_agent_resolves_under_the_configured_slug():
    """The ROOT run asks for ``agent_slug`` — NOT ``agent.name``."""
    p = _plugin(subagent_slugs={CHILD_NAME: CHILD_SLUG})
    p.apdp.resolve_agent.return_value = _resolved(ROOT_SLUG, ROOT_UUID)

    result = await p.before_agent_callback(
        agent=_Agent(ROOT_NAME), callback_context=_Ctx()
    )

    assert result is None  # allowed to proceed
    assert _slugs_asked(p) == [ROOT_SLUG]
    assert p._current_agent_slug == ROOT_SLUG
    assert p._current_agent_id == ROOT_UUID


@pytest.mark.asyncio
async def test_subagent_resolves_under_its_configured_slug():
    """A nested ADK sub-agent transfer asks for its ``subagent_slugs``
    entry, under its own identity — not the root's, not its name's."""
    p = _plugin(subagent_slugs={CHILD_NAME: CHILD_SLUG})
    p.apdp.resolve_agent.return_value = _resolved(ROOT_SLUG, ROOT_UUID)
    await p.before_agent_callback(agent=_Agent(ROOT_NAME), callback_context=_Ctx())

    p.apdp.resolve_agent.return_value = _resolved(CHILD_SLUG, CHILD_UUID)
    await p.before_agent_callback(agent=_Agent(CHILD_NAME), callback_context=_Ctx())

    assert _slugs_asked(p) == [ROOT_SLUG, CHILD_SLUG]
    assert p._current_agent_slug == CHILD_SLUG
    assert p._current_agent_id == CHILD_UUID


@pytest.mark.asyncio
async def test_display_name_is_never_the_slug():
    """The regression itself: an ADK display name that differs from the
    registered slug must not reach ``/agents/resolve``."""
    p = _plugin()
    p.apdp.resolve_agent.return_value = _resolved(ROOT_SLUG, ROOT_UUID)

    await p.before_agent_callback(agent=_Agent(ROOT_NAME), callback_context=_Ctx())

    # ``agent.name.replace("_", "-")`` is "adk-orchestrator" — the slug the
    # old code asked for and wl-apdp 404s. It must never be on the wire.
    assert _slugs_asked(p) == [ROOT_SLUG]
    assert "adk-orchestrator" not in _slugs_asked(p)


# ─── Derivation is GONE, at every level of configuration ──────────────


def test_unconfigured_plugin_raises_at_construction():
    """The High this change closes.

    Before, a plugin given no identity derived candidates from
    ``agent.name``. An unregistered ADK object named ``finance_bot``
    derived ``agent-finance-bot``, which is exactly the slug wl-registry
    mints for a *registered* agent named "finance bot" — so the run
    executed under that agent's UUID, trust state, tool allowlist,
    policies and lineage attribution. It must be impossible to build such
    a plugin at all, and it must fail at CONSTRUCTION rather than at the
    first run.
    """
    with pytest.raises(ValueError) as excinfo:
        WatchlightPlugin(apdp_url="https://apdp.test")

    message = str(excinfo.value)
    assert "agent_slug" in message
    assert "root_agent_name" in message
    assert "subagent_slugs" in message


def test_subagent_slugs_alone_is_not_an_identity_for_the_root():
    """Mapping the children does not give the ROOT an identity."""
    with pytest.raises(ValueError):
        WatchlightPlugin(
            apdp_url="https://apdp.test", subagent_slugs={CHILD_NAME: CHILD_SLUG}
        )


def test_agent_slug_without_root_agent_name_raises():
    """A slug bound to no ADK name is bound to lifecycle POSITION —
    whichever agent opens an invocation would authorize as the root."""
    with pytest.raises(ValueError) as excinfo:
        WatchlightPlugin(apdp_url="https://apdp.test", agent_slug=ROOT_SLUG)

    assert "root_agent_name" in str(excinfo.value)


@pytest.mark.asyncio
async def test_no_resolve_is_ever_attempted_for_a_derived_name():
    """No configuration shape reaches ``/agents/resolve`` with a name.

    A plugin cannot be built unconfigured, and a CONFIGURED plugin asks
    for exactly one slug per agent: the configured one. There is no
    second candidate, so a "did you mean" retry can never land an
    unmapped agent on a registered identity that is not its own.
    """
    p = _plugin(subagent_slugs={CHILD_NAME: CHILD_SLUG})
    p.apdp.resolve_agent.return_value = None

    await p.before_agent_callback(agent=_Agent(ROOT_NAME), callback_context=_Ctx())
    await p.before_agent_callback(agent=_Agent("finance_bot"), callback_context=_Ctx())

    # One ask, for the configured root slug. Nothing derived from either
    # display name — not "adk-orchestrator", not "finance-bot", and
    # above all not wl-registry's own "agent-finance-bot" spelling.
    assert _slugs_asked(p) == [ROOT_SLUG]
    for asked in _slugs_asked(p):
        assert asked not in ("adk-orchestrator", "finance-bot", "agent-finance-bot")


def test_the_derivation_helper_is_gone_from_the_public_surface():
    """A removed fallback that is still importable grows a caller."""
    assert not hasattr(watchlight_adk, "derived_slug_candidates")
    assert not hasattr(watchlight_adk.agent_slugs, "derived_slug_candidates")
    assert "derived_slug_candidates" not in watchlight_adk.__all__


# ─── Fail closed on an unmapped agent ─────────────────────────────────


@pytest.mark.asyncio
async def test_unmapped_subagent_is_refused_as_not_configured(caplog):
    p = _plugin(subagent_slugs={CHILD_NAME: CHILD_SLUG})
    p.apdp.resolve_agent.return_value = _resolved(ROOT_SLUG, ROOT_UUID)
    await p.before_agent_callback(agent=_Agent(ROOT_NAME), callback_context=_Ctx())
    asked_before = len(_slugs_asked(p))

    with caplog.at_level("ERROR", logger="watchlight_adk"):
        result = await p.before_agent_callback(
            agent=_Agent("rogue_helper"), callback_context=_Ctx()
        )

    assert result is not None  # short-circuits the agent
    # Opaque-deny contract: the agent gets the fixed refusal, nothing else.
    assert result.parts[0].text == _NO_RUN_REFUSAL
    assert "rogue_helper" not in result.parts[0].text
    # The operator gets the DEPLOYMENT error in the log, told apart from a
    # missing registration.
    errors = [r.getMessage() for r in caplog.records if r.levelname == "ERROR"]
    assert any(
        "'rogue_helper' has no Watchlight slug configured" in m
        and "deployment configuration error" in m
        and "not registered" not in m
        for m in errors
    ), errors
    # Nothing was asked of the resolver — there was no identity to ask about.
    assert len(_slugs_asked(p)) == asked_before


@pytest.mark.asyncio
async def test_an_unmapped_agent_that_opens_a_run_does_not_get_the_root_slug():
    """``agent_slug`` belongs to ``root_agent_name``, not to "whoever
    started this invocation".

    An agent missing from ``subagent_slugs`` that becomes the root of an
    invocation — a second entrypoint, a re-entered tree, an agent added
    to the deployment without a mapping — must be refused, not silently
    authorized as the root.
    """
    p = _plugin(subagent_slugs={CHILD_NAME: CHILD_SLUG})
    p.apdp.resolve_agent.return_value = _resolved(ROOT_SLUG, ROOT_UUID)

    result = await p.before_agent_callback(
        agent=_Agent("some_other_entrypoint"), callback_context=_Ctx()
    )

    assert result is not None
    assert result.parts[0].text == _NO_RUN_REFUSAL
    assert _slugs_asked(p) == []
    assert not p._current_agent_id


@pytest.mark.asyncio
async def test_unmapped_agent_refusal_mutates_no_lifecycle_state():
    """Fail-closed ORDERING: a refused agent owns no state, anywhere.

    ADK skips ``after_agent_callback`` for an agent short-circuited from
    ``before_agent_callback``, so any frame pushed before the refusal
    would leak and desynchronise every later run in this plugin.

    This snapshots the plugin's WHOLE instance dict (minus the stubs,
    whose call lists grow by design) and the ADK agent's tool list, so
    that moving ``_reset_telemetry()`` or the synthetic-tool injection
    above the refusal fails here rather than in production.
    """
    p = _plugin(subagent_slugs={CHILD_NAME: CHILD_SLUG})
    p.apdp.resolve_agent.return_value = _resolved(ROOT_SLUG, ROOT_UUID)
    await p.before_agent_callback(agent=_Agent(ROOT_NAME), callback_context=_Ctx())

    rogue = _Agent("rogue_helper")
    before = (_plugin_state(p), list(rogue.tools))

    refusal = await p.before_agent_callback(agent=rogue, callback_context=_Ctx())

    assert refusal is not None
    assert (_plugin_state(p), list(rogue.tools)) == before


def _plugin_state(plugin: WatchlightPlugin) -> dict:
    """Every field the plugin owns, in a form that changes when it does.

    Scalars and containers are captured BY VALUE (deep-copied, so a later
    ``append`` to ``_lineage_stack`` or a rewritten ``last_manifest``
    shows up as a difference rather than as the same object). Everything
    else — the stubbed clients, whose mock call lists grow by design, and
    the per-run handles — is captured by identity, so re-creating one
    still registers.
    """
    state = {}
    for name, value in vars(plugin).items():
        if isinstance(value, (str, int, float, bool, type(None))):
            state[name] = value
        elif isinstance(value, (list, tuple, set, frozenset, dict)):
            state[name] = copy.deepcopy(value)
        else:
            state[name] = id(value)
    return state


@pytest.mark.asyncio
async def test_configured_slug_that_is_not_registered_says_not_registered():
    """The other half of the pair: a CONFIGURED slug that wl-apdp does
    not know is a registration gap, and reads as one."""
    p = _plugin()
    p.apdp.resolve_agent.return_value = None

    result = await p.before_agent_callback(
        agent=_Agent(ROOT_NAME), callback_context=_Ctx()
    )

    assert result is not None
    assert "not registered" in result.parts[0].text
    # Exactly the configured slug — no derived guesses behind the operator's back.
    assert _slugs_asked(p) == [ROOT_SLUG]


# ─── The pure lookup helpers ──────────────────────────────────────────


def test_configured_slug_precedence():
    kwargs = {
        "agent_slug": ROOT_SLUG,
        "root_agent_name": ROOT_NAME,
        "subagent_slugs": {CHILD_NAME: CHILD_SLUG},
    }
    assert configured_slug(ROOT_NAME, is_root=True, **kwargs) == ROOT_SLUG
    assert configured_slug(CHILD_NAME, is_root=False, **kwargs) == CHILD_SLUG
    # A non-root agent never inherits the root's slug — it is unmapped,
    # and the plugin refuses it.
    assert configured_slug("other", is_root=False, **kwargs) is None
    # Nor does an unmapped agent that happens to be the root of this
    # invocation: the slug is bound to ``root_agent_name``, not to the
    # lifecycle position.
    assert configured_slug("other", is_root=True, **kwargs) is None
    # The root's own name is not enough on a nested invocation.
    assert configured_slug(ROOT_NAME, is_root=False, **kwargs) is None
    # And a mapped sub-agent never opens a run as the root: its
    # authority only comes from a governed spawn under its parent.
    assert configured_slug(CHILD_NAME, is_root=True, **kwargs) is None
    # With no ``root_agent_name`` there is nothing for ``agent_slug`` to
    # be bound to, so it is never handed out.
    assert (
        configured_slug(
            ROOT_NAME,
            agent_slug=ROOT_SLUG,
            root_agent_name=None,
            subagent_slugs=None,
            is_root=True,
        )
        is None
    )
    # With nothing configured there is nothing to return, at any depth.
    assert (
        configured_slug(
            ROOT_NAME,
            agent_slug=None,
            root_agent_name=None,
            subagent_slugs=None,
            is_root=True,
        )
        is None
    )


def test_normalize_subagent_slugs_rejects_blanks():
    assert normalize_subagent_slugs(None) == {}
    assert normalize_subagent_slugs({CHILD_NAME: f" {CHILD_SLUG} "}) == {
        CHILD_NAME: CHILD_SLUG
    }
    with pytest.raises(ValueError):
        normalize_subagent_slugs({"": CHILD_SLUG})
    with pytest.raises(ValueError):
        normalize_subagent_slugs({CHILD_NAME: "  "})


def test_normalize_subagent_slugs_strips_keys_too():
    """A key with a leading space never matched ``agent.name``, and the
    operator was told to configure a mapping that is visibly already
    there."""
    assert normalize_subagent_slugs({f"  {CHILD_NAME} ": CHILD_SLUG}) == {
        CHILD_NAME: CHILD_SLUG
    }
    # Two keys that name the same ADK agent once stripped are a typo, not
    # a merge.
    with pytest.raises(ValueError, match="same ADK agent"):
        normalize_subagent_slugs({CHILD_NAME: CHILD_SLUG, f" {CHILD_NAME}": "agent-x"})


def test_normalize_subagent_slugs_rejects_two_agents_on_one_identity():
    """Attenuation and attribution are per-identity: two ADK agents
    sharing one governed identity make a sub-agent's scope
    indistinguishable from its sibling's."""
    with pytest.raises(ValueError, match="cannot share"):
        normalize_subagent_slugs({CHILD_NAME: CHILD_SLUG, "other": CHILD_SLUG})


def test_normalize_subagent_slugs_rejects_a_child_mapped_to_the_root():
    """A child running as the root makes the governed-spawn strict-subset
    check compare a scope to itself, so it can never attenuate."""
    with pytest.raises(ValueError, match="root"):
        normalize_subagent_slugs({CHILD_NAME: ROOT_SLUG}, agent_slug=ROOT_SLUG)
    # Whitespace does not get a child past it.
    with pytest.raises(ValueError, match="root"):
        normalize_subagent_slugs({CHILD_NAME: f" {ROOT_SLUG} "}, agent_slug=ROOT_SLUG)


def test_constructor_normalizes_configuration():
    p = WatchlightPlugin(
        apdp_url="https://apdp.test",
        agent_slug=f"  {ROOT_SLUG}  ",
        root_agent_name=f" {ROOT_NAME} ",
        subagent_slugs={f" {CHILD_NAME} ": f" {CHILD_SLUG} "},
    )
    assert p.agent_slug == ROOT_SLUG
    assert p.root_agent_name == ROOT_NAME
    assert p.subagent_slugs == {CHILD_NAME: CHILD_SLUG}


def test_constructor_rejects_a_child_mapped_to_the_root_slug():
    with pytest.raises(ValueError):
        WatchlightPlugin(
            apdp_url="https://apdp.test",
            agent_slug=ROOT_SLUG,
            root_agent_name=ROOT_NAME,
            subagent_slugs={CHILD_NAME: ROOT_SLUG},
        )
