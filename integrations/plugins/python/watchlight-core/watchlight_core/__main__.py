"""``python -m watchlight_core``: points at the conformance runner.

The conformance runner and the test doubles are in a separate,
test-only distribution, so they never ship in this SDK:

    pip install watchlight-agent-sdk-testing
    python -m watchlight_core_testing.conformance my_plugin_package
"""

from __future__ import annotations

import sys

if __name__ == "__main__":
    print(
        "The conformance runner is in watchlight-agent-sdk-testing: "
        "pip install watchlight-agent-sdk-testing, then run "
        "python -m watchlight_core_testing.conformance <plugin_package>",
        file=sys.stderr,
    )
    sys.exit(2)
