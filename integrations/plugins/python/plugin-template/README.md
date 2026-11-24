# Watchlight Plugin Template

Forkable skeleton for building a Watchlight plugin for any AI agent
framework. Fill in the TODOs and run conformance — you ship a
governed plugin in under 30 minutes.

<!-- TODO: replace <Framework>/<Vendor> with your framework and its trademark owner (or "their respective owners" if unsure). -->
> **Independent third-party plugin.** This is an independent integration built by Watchlight AI. It is **not affiliated with, endorsed by, or sponsored by** <Vendor>. `<Framework>` and related names are trademarks of <Vendor or "their respective owners">, used here nominatively only to describe compatibility.

> **SDK reference**: [`watchlight-core`](../watchlight-core/README.md)

---

## What this is

A complete, working "hello-world" plugin that:

- Exports `WatchlightTemplatePlugin` — the plugin class your
  customer code instantiates.
- Exports `translate_template_event` — the framework-event →
  canonical-`ExecutionEvent` translator.
- Exports `state_from_template_plugin` — a one-liner adapter for
  the Watchlight Beacon dashboard's governance card.
- Includes one passing conformance test
  (`tests/test_conformance.py`).

You replace the placeholder identifiers (`template`, `Template`,
`my_framework`) with your framework's name, then wire your
framework's lifecycle callbacks into the four `TODO:` markers.

---

## Fork → fill → ship in 7 steps

```bash
# 1. Fork the template
cp -r plugin-template ~/my-framework-plugin
cd ~/my-framework-plugin

# 2. Rename the package directory
mv watchlight_template watchlight_myframework

# 3. Search-and-replace identifiers
#    template       → myframework
#    Template       → Myframework
find . -type f \( -name '*.py' -o -name '*.toml' -o -name '*.md' \) \
    -exec sed -i '' \
    -e 's/watchlight_template/watchlight_myframework/g' \
    -e 's/WatchlightTemplate/WatchlightMyframework/g' \
    -e 's/template\./myframework./g' \
    -e 's/translate_template_/translate_myframework_/g' \
    -e 's/state_from_template_/state_from_myframework_/g' \
    {} \;

# 4. Fill in the four TODOs in watchlight_myframework/plugin.py
#    and watchlight_myframework/traces.py
$EDITOR watchlight_myframework/plugin.py
$EDITOR watchlight_myframework/traces.py

# 5. Install in dev mode + run tests
pip install -e . -e ../watchlight-core[dev]
pytest

# 6. Run the conformance suite
python -m watchlight_core_testing.conformance watchlight_myframework

# 7. Build a wheel + ship to your customers
python -m build
# → dist/watchlight_myframework-0.1.0-py3-none-any.whl
```

---

## The four TODOs

You fill in four things. Everything else is provided by
`watchlight-agent-sdk`.

### TODO 1: `start_run()` — open a governed session for your agent

In `watchlight_template/plugin.py`. Resolves the agent slug to a
canonical UUID via the APDP registry, opens a session, returns a
`RunHandle`.

The session carries `application_id` — the AI application the run
belongs to — when one is set: per run on `start_run(...,
application_id=...)`, on the plugin constructor, or via
`WATCHLIGHT_APPLICATION_ID`. Keep all three going through
`watchlight_core.resolve_application_id` so empty / whitespace means
unset and a non-UUID is refused before any session opens; wl-apdp
stays the authority on membership.

### TODO 2: Lifecycle hooks → `handle.authorize_action()`

Wire your framework's "about-to-run-a-tool" callback to call
`await handle.authorize_action(action, resource)`. Deny → raise
`PermissionError` (or your framework's equivalent); allow → proceed.

Where this lives depends on the framework's lifecycle model — see
the four reference plugins for examples:

- **LangGraph** (explicit primitives): wire into your graph node's
  body — see `../watchlight-langgraph/watchlight_langgraph/`
- **Google ADK** (callbacks): register the plugin on a `Runner`
  — see `../watchlight-adk/watchlight_adk/plugin.py`
- **AWS Bedrock** (decorator): wrap your Lambda action handlers
  — see `../watchlight-bedrock/watchlight_bedrock/`
- **Pydantic AI** (Agent.run lifecycle): hook into the agent's
  event stream — see `../watchlight-pydantic-ai/`

### TODO 3: Event translator — `translate_template_event()`

In `watchlight_template/traces.py`. Pure function that maps one
framework callback dict to one canonical `ExecutionEvent` (or
`None` to drop). The conformance suite asserts the seven invariants
on the output.

### TODO 4: Optional — `plan_observed` emission

If your framework exposes a "plan" signal (the agent declared
intent to call N tools before calling them), emit a
`plan_observed` event. The wl-execution-graph plan-vs-act
correlator uses this to flag unplanned tool calls.

For frameworks without a plan signal, skip this — the SDK supports
plan-less plugins.

---

## Reading list

Before you start, skim:

1. [`watchlight-core`](../watchlight-core/README.md) — the SDK.
2. [`events_schema.py`](../watchlight-core/watchlight_core/events_schema.py) — the canonical `ExecutionEvent` shape.
3. One of the four reference plugins — pick the closest fit to
   your framework's lifecycle model.

---

## Testing

The template ships with one passing test
(`tests/test_conformance.py`). It uses
`watchlight_core_testing.MockApdpClient` so it runs without a real
APDP server. When you fork, it stays passing as long as the
synthetic lifecycle in `plugin.py` keeps emitting canonical events.

You'll add framework-specific tests on top — most plugins ship with
~30-50 tests covering callback translation, plan emission, and the
error paths.
