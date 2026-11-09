"""``python -m watchlight_core_testing`` runs the conformance runner.

    python -m watchlight_core_testing.conformance my_plugin_package
"""

from __future__ import annotations

from .conformance import _main

if __name__ == "__main__":
    raise SystemExit(_main())
