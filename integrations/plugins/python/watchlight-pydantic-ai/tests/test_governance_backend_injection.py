"""The Developer-Edition seam: ``governance=`` uses the supplied backend
verbatim (in-process ``InProcessClient``) instead of a networked ApdpClient.
"""
from watchlight_core import ApdpClient
from watchlight_core_testing import MockApdpClient
from watchlight_pydantic_ai import WatchlightPydanticAIPlugin


def test_governance_param_uses_supplied_backend():
    backend = MockApdpClient()
    plugin = WatchlightPydanticAIPlugin(governance=backend, auto_instrument=False)
    assert plugin.apdp is backend


def test_default_still_builds_networked_apdp_client():
    plugin = WatchlightPydanticAIPlugin(auto_instrument=False)
    assert isinstance(plugin.apdp, ApdpClient)
