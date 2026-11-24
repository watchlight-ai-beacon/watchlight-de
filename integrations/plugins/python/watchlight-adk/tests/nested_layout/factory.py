"""Where the application builds its agents: the only module that imports ADK."""

from typing import Any, Callable, List

from google.adk.agents import LlmAgent
from google.adk.runners import InMemoryRunner


def make_runner(model: Any, tools: List[Callable[..., Any]]) -> InMemoryRunner:
    agent = LlmAgent(name="inner", model=model, description="Inner.", tools=tools)
    return InMemoryRunner(agent=agent, app_name="nested")
