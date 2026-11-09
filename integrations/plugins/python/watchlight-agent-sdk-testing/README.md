# watchlight-agent-sdk-testing

Test doubles and the conformance runner for plugins built on
[`watchlight-agent-sdk`](../watchlight-core). For tests only: it depends
on the SDK, the SDK never depends on it, and none of it ships in the SDK.

```bash
pip install watchlight-agent-sdk-testing
```

```python
from watchlight_core_testing import MockApdpClient

apdp = MockApdpClient()              # denies every request
apdp.default_decision = "Allow"      # a test that needs allows says so
apdp.decisions[("execute", "fs.write")] = "Deny"
```

`MockApdpClient` denies by default. A test that needs an allow sets
`default_decision="Allow"` or a per-`(action, resource)` rule, so no test
passes because the double allowed by omission.

## Conformance

```bash
python -m watchlight_core_testing.conformance my_plugin_package
# or
watchlight-conformance my_plugin_package
```

## Moving from `watchlight_core_testing`

| Before | After |
|---|---|
| `from watchlight_core_testing import X` | `from watchlight_core_testing import X` |
| `from watchlight_core_testing.conformance import X` | `from watchlight_core_testing.conformance import X` |
| `python -m watchlight_core_testing.conformance` | `python -m watchlight_core_testing.conformance` |

A test that relied on the old allow default now sees denials. Set
`default_decision="Allow"` where the test means to allow.
