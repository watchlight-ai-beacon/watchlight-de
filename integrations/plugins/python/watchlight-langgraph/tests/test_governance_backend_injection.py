"""The Developer-Edition seam: constructing the plugin with ``governance=``
uses the supplied GovernanceBackend verbatim (e.g. an in-process
``InProcessClient`` over the compiled watchlight-engine) instead of building a
networked ApdpClient. Same plugin, same agent code — only the backend differs.
"""
from watchlight_core import ApdpClient
from watchlight_core_testing import MockApdpClient
from watchlight_langgraph import WatchlightLangGraphPlugin


def test_governance_param_uses_supplied_backend():
    backend = MockApdpClient()
    plugin = WatchlightLangGraphPlugin(governance=backend)
    assert plugin.apdp is backend


def test_default_still_builds_networked_apdp_client():
    plugin = WatchlightLangGraphPlugin()
    assert isinstance(plugin.apdp, ApdpClient)
