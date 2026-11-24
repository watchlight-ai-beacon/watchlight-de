"""The graph-state schema that carries the Watchlight run token.

Kept in its own module, imported lazily by ``middleware.py`` only when
the real LangChain ``AgentMiddleware`` base is in use, and written
WITHOUT ``from __future__ import annotations``: LangGraph resolves a
TypedDict's annotations with ``get_type_hints``, which needs the real
``Annotated`` / ``NotRequired`` objects in this module's globals.
"""

from typing import Annotated

from langchain.agents.middleware.types import AgentState, PrivateStateAttr
from typing_extensions import NotRequired


class WatchlightGovernanceState(AgentState):  # type: ignore[misc]
    """``AgentState`` plus the private ``wl_run_token`` key.

    ``PrivateStateAttr`` omits the key from the graph's input and output
    schema: a caller cannot inject a token through ``ainvoke`` input, a
    run's token never leaks in its result, and deepagents neither copies
    it into a sub-agent's state nor back out of it.
    """

    wl_run_token: NotRequired[Annotated[str, PrivateStateAttr]]
