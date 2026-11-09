"""Keeps the Watchlight gate live for every Claude Code session.

The plugin's enforcement is a set of SDK hook callbacks. Claude Code's
minimal ("bare") mode skips them: ``--bare``, or ``CLAUDE_CODE_SIMPLE``
set in the CLI's environment or in a settings ``env``. In that mode no
``PreToolUse`` callback fires and every tool runs with no decision.

Two layers keep the gate live:

1. **Refuse every route around the gate** before the session starts. A
   Claude Code environment variable (``CLAUDE_*``, ``ANTHROPIC_*``,
   ``DISABLE_*``, ``ENABLE_*`` and a few internal prefixes) is refused
   unless it is on the allowlist in :mod:`.cli_surface`, wherever it is
   set: ``options.env``, this process's environment, or the ``env`` of any
   settings source the CLI reads (managed, user, project, local,
   ``options.settings``). That covers bare mode (``CLAUDE_CODE_SIMPLE``),
   safe mode, and redirected managed settings, and any variable a future
   Claude Code adds. ``extra_args`` flags are allowlisted the same way.
   The same sources must not set ``disableAllHooks``,
   ``allowManagedHooksOnly`` or ``allowManagedPermissionRulesOnly`` (the
   last drops the session's ``ask`` rule). A source that exists but
   cannot be read is refused.
2. **Prove the gate ran, per tool call.** The session's settings get a
   ``permissions.ask`` rule for every tool, so Claude Code asks the SDK's
   ``can_use_tool`` callback before any tool runs, whatever the permission
   mode or allow rules (an ``ask`` rule outranks both). The plugin's
   callback allows a call only when Watchlight's own ``PreToolUse`` gate
   allowed that tool-use id first. A session where the hooks do not run,
   by a route not covered above, is refused call by call. The permission
   callback runs in bare mode too.

   The forced ``ask`` must not widen what the session would run, so the
   callback also allows only a call the session's own configuration would
   have run without a prompt (:class:`SessionPermissions`, computed
   conservatively). Any other call goes to your own ``can_use_tool``, or
   is denied, as Claude Code denies a prompt in the SDK when no callback
   is set.

``permission_prompt_tool_name`` is refused too: it replaces the callback.

3. **Watch the session** (``governed_query`` / ``watch_messages``). Some
   managed settings cannot be read before the session starts: settings
   the server delivers at startup. Watchlight's ``UserPromptSubmit`` hook
   must have run for a session before Claude Code reports that session
   started, and every tool result must belong to a call the
   ``PreToolUse`` gate decided. Otherwise the session is ended, the run is
   terminated, and :class:`GovernanceBypassDetected` is raised. This
   **detects**; it does not prevent: Claude Code runs the model turn and
   its tools whether or not your code has read the messages, so tools may
   have run by the time the watcher sees the message. Layers 1 and 2 are
   the guarantee.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Tuple

from watchlight_core import GovernanceUnavailable

from .cli_surface import ALLOWED_ENV, ALLOWED_FLAGS, PROCESS_ONLY_ENV, is_governed_env_name

#: The environment variable that turns Claude Code's bare mode on.
BARE_MODE_ENV = "CLAUDE_CODE_SIMPLE"

#: The permission rule that makes Claude Code ask before every tool call.
ASK_EVERY_TOOL = "*"

#: The managed preferences domain Claude Code reads on macOS.
_MDM_DOMAIN = "com.anthropic.claudecode"


class UngovernableSession(GovernanceUnavailable):
    """The session's options would run Claude Code without the Watchlight
    gate; the session is refused before it starts."""


class GovernanceBypassDetected(GovernanceUnavailable):
    """A governed session showed a tool call Watchlight did not decide, or
    started without Watchlight's hooks; the session was ended and the run
    terminated."""


def _flag_name(key: Any) -> str:
    return str(key).strip().lstrip("-").split("=", 1)[0].strip().lower().replace("_", "-")


def _refuse(reason: str) -> None:
    raise UngovernableSession(
        f"Watchlight refused the Claude Code session: {reason}, which would run "
        "tools without the Watchlight gate."
    )


def _check_env(env: Optional[Mapping[Any, Any]], where: str, *, process: bool = False) -> None:
    """Refuse a Claude Code variable that is not on the allowlist
    (``cli_surface``). An empty value counts as unset."""
    for key, value in (env or {}).items():
        name = str(key)
        if value is None or str(value) == "" or not is_governed_env_name(name):
            continue
        upper = name.upper()
        if name == upper and (name in ALLOWED_ENV or (process and name in PROCESS_ONLY_ENV)):
            continue
        if upper == BARE_MODE_ENV:
            _refuse(f"{BARE_MODE_ENV} is set in {where} (Claude Code bare mode)")
        _refuse(f"{name} is set in {where} and is not a Claude Code variable Watchlight allows")


def _read_settings(value: str, where: str) -> Dict[str, Any]:
    """``options.settings`` as Claude Code reads it: inline JSON or a file
    path. Anything it cannot read is refused."""
    text = value.strip()
    if not (text.startswith("{") and text.endswith("}")):
        try:
            text = Path(text).read_text(encoding="utf-8")
        except OSError:
            _refuse(f"the settings file in {where} cannot be read")
    try:
        parsed = json.loads(text)
    except ValueError:
        _refuse(f"the settings in {where} are not valid JSON")
    if not isinstance(parsed, dict):
        _refuse(f"the settings in {where} are not a JSON object")
    return parsed


def _check_settings_env(settings: Mapping[str, Any], where: str) -> None:
    env = settings.get("env")
    if env is None:
        return
    if not isinstance(env, dict):
        _refuse(f"the env in {where} is not an object")
    _check_env(env, f"the env of {where}")


def _config_dir(env: Mapping[Any, Any]) -> Path:
    merged = {**os.environ, **{str(k): v for k, v in (env or {}).items() if v is not None}}
    config_dir = merged.get("CLAUDE_CONFIG_DIR")
    if config_dir:
        return Path(config_dir)
    home = merged.get("HOME") or str(Path.home())
    return Path(home) / ".claude"


def _user_settings_path(env: Mapping[Any, Any]) -> Path:
    return _config_dir(env) / "settings.json"


#: Settings keys that take a layer away when any source sets them: the
#: first two switch hooks off or limit them to managed ones, the third
#: drops every permission rule that is not managed (the session's ``ask``
#: rule with it). Claude Code reads them from every source.
_REFUSED_KEYS = ("disableAllHooks", "allowManagedHooksOnly", "allowManagedPermissionRulesOnly")


def _check_settings(settings: Mapping[str, Any], where: str) -> None:
    _check_settings_env(settings, where)
    for key in _REFUSED_KEYS:
        if settings.get(key) not in (None, False):
            _refuse(f"{key} is set in {where}")


def _managed_dir() -> Path:
    """Where Claude Code reads its managed settings file and drop-ins."""
    if sys.platform == "darwin":
        return Path("/Library/Application Support/ClaudeCode")
    if sys.platform == "win32":
        return Path("C:\\Program Files\\ClaudeCode")
    return Path("/etc/claude-code")


#: Under WSL, Claude Code also reads the Windows managed settings folder and
#: the Windows policy registry keys (through ``reg.exe``).
_WSL_MANAGED_DIR = Path("/mnt/c/Program Files/ClaudeCode")
_WSL_REG_EXE = "/mnt/c/Windows/System32/reg.exe"


def _managed_dirs() -> List[Path]:
    dirs = [_managed_dir()]
    if sys.platform.startswith("linux") and os.path.exists(_WSL_REG_EXE):
        dirs.append(_WSL_MANAGED_DIR)
    return dirs


def _managed_files() -> List[Path]:
    """The managed settings file and its ``managed-settings.d`` drop-ins,
    as Claude Code lists them: ``*.json`` not starting with a dot, sorted.
    A drop-in directory that exists but cannot be listed is refused."""
    files: List[Path] = []
    for base in _managed_dirs():
        files.append(base / "managed-settings.json")
        drop_ins = base / "managed-settings.d"
        try:
            names = sorted(
                entry.name
                for entry in os.scandir(drop_ins)
                if entry.name.endswith(".json") and not entry.name.startswith(".")
            )
        except (FileNotFoundError, NotADirectoryError):
            names = []
        except OSError:
            _refuse(f"the managed settings directory {drop_ins} cannot be read")
        files.extend(drop_ins / name for name in names)
    return files


def _mdm_plist_paths() -> List[str]:
    """The macOS managed preferences Claude Code reads: the user's, then
    the device's."""
    paths = []
    try:
        # The real user, as Claude Code's os.userInfo() reads it; USER and
        # LOGNAME can be set to anything.
        import pwd

        user = pwd.getpwuid(os.getuid()).pw_name
        paths.append(f"/Library/Managed Preferences/{user}/{_MDM_DOMAIN}.plist")
    except Exception:  # noqa: BLE001 - no user name: the device profile still applies
        pass
    paths.append(f"/Library/Managed Preferences/{_MDM_DOMAIN}.plist")
    return paths


def _mdm_settings() -> List[Tuple[str, Dict[str, Any]]]:
    """Managed settings from an MDM profile (macOS) or the policy registry
    keys (Windows). One that exists but cannot be read is refused."""
    out: List[Tuple[str, Dict[str, Any]]] = []
    if sys.platform == "darwin":
        for path in _mdm_plist_paths():
            if not os.path.lexists(path):
                continue
            try:
                done = subprocess.run(
                    ["/usr/bin/plutil", "-convert", "json", "-o", "-", "--", path],
                    capture_output=True,
                    timeout=5,
                    check=True,
                )
                parsed = json.loads(done.stdout)
            except Exception:  # noqa: BLE001 - unreadable: refuse
                _refuse(f"the managed preferences {path} cannot be read")
            if not isinstance(parsed, dict):
                _refuse(f"the managed preferences {path} are not a dictionary")
            out.append((path, parsed))
    elif sys.platform == "win32":  # pragma: no cover - Windows only
        import winreg

        for hive, name in ((winreg.HKEY_LOCAL_MACHINE, "HKLM"), (winreg.HKEY_CURRENT_USER, "HKCU")):
            where = f"{name}\\SOFTWARE\\Policies\\ClaudeCode"
            try:
                with winreg.OpenKey(hive, r"SOFTWARE\Policies\ClaudeCode") as key:
                    value, _ = winreg.QueryValueEx(key, "Settings")
            except FileNotFoundError:
                continue
            except OSError:
                _refuse(f"the policy key {where} cannot be read")
            try:
                parsed = json.loads(value) if isinstance(value, str) else None
            except ValueError:
                parsed = None
            if not isinstance(parsed, dict):
                _refuse(f"the policy key {where} is not a JSON object")
            out.append((where, parsed))
    elif sys.platform.startswith("linux") and os.path.exists(_WSL_REG_EXE):
        for where in ("HKLM\\SOFTWARE\\Policies\\ClaudeCode", "HKCU\\SOFTWARE\\Policies\\ClaudeCode"):
            parsed = _wsl_policy_value(where)
            if parsed is not None:
                out.append((where, parsed))
    return out


def _wsl_policy_value(where: str) -> Optional[Dict[str, Any]]:
    """The ``Settings`` value of a Windows policy key read from WSL, as
    Claude Code reads it (``reg.exe query <key> /v Settings``); ``None``
    when the value does not exist. Anything else unreadable is refused."""
    try:
        done = subprocess.run(
            [_WSL_REG_EXE, "query", where, "/v", "Settings"], capture_output=True, timeout=5
        )
    except Exception:  # noqa: BLE001 - unreadable: refuse
        _refuse(f"the policy key {where} cannot be read")
    if done.returncode != 0:
        # reg.exe exits 1 when the key or value does not exist.
        if done.returncode == 1:
            return None
        _refuse(f"the policy key {where} cannot be read")
    text = done.stdout.decode("utf-8", "replace")
    for line in text.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) == 3 and parts[0] == "Settings" and parts[1] == "REG_SZ":
            try:
                parsed = json.loads(parts[2])
            except ValueError:
                parsed = None
            if not isinstance(parsed, dict):
                _refuse(f"the policy key {where} is not a JSON object")
            return parsed
    _refuse(f"the policy key {where} cannot be read")
    return None


def _project_files(cwd: Any) -> List[Path]:
    """Project and local settings files Claude Code may read: the working
    directory's and every parent's ``settings.json`` and
    ``settings.local.json`` in its ``.claude`` directory (a superset of what
    it loads)."""
    start = Path(str(cwd)) if cwd else Path.cwd()
    out = []
    for directory in [start, *start.parents]:
        out.append(directory / ".claude" / "settings.json")
        out.append(directory / ".claude" / "settings.local.json")
    return out


def _read_file_source(path: Path) -> Optional[Dict[str, Any]]:
    """A settings file Claude Code would read, or ``None`` when absent. One
    that exists but cannot be read or parsed is refused."""
    try:
        if not os.path.lexists(path):
            return None
    except OSError:
        _refuse(f"the settings file {path} cannot be read")
    return _read_settings(str(path), str(path))


@dataclass
class CheckedSettings:
    """What :func:`check_session_options` read: ``flag`` is
    ``options.settings`` parsed (``{}`` when unset); ``sources`` is every
    settings document the session will load, the flag first, for the
    permission rules they carry."""

    flag: Dict[str, Any]
    sources: List[Dict[str, Any]] = field(default_factory=list)


def check_session_options(
    *,
    extra_args: Optional[Mapping[Any, Any]],
    env: Optional[Mapping[Any, Any]],
    settings: Optional[str],
    setting_sources: Any,
    permission_prompt_tool_name: Optional[str],
    cwd: Any = None,
    cli_path: Any = None,
) -> CheckedSettings:
    """Refuse every known route to bare mode, and options or settings that
    would take either layer away. Reads every settings source the session
    loads: managed (file, drop-ins, MDM profile or policy registry, and the
    cached server-managed settings), user, project, local and
    ``options.settings``."""
    if cli_path is not None:
        # Another program in place of the bundled Claude Code could drop
        # Watchlight's hooks from the initialize request it receives.
        _refuse("cli_path runs a program in place of the Claude Code the SDK bundles")
    for key, value in (extra_args or {}).items():
        name = _flag_name(key)
        if name == "bare":
            _refuse("extra_args passes --bare (Claude Code bare mode)")
        if str(key) not in ALLOWED_FLAGS or value is not None:
            _refuse(f"extra_args passes --{name}, which is not a Claude Code flag Watchlight allows")
    if permission_prompt_tool_name:
        _refuse("permission_prompt_tool_name replaces the permission callback")
    _check_env(env, "options.env")
    _check_env(os.environ, "this process's environment", process=True)
    checked = CheckedSettings(flag={})
    if settings is not None:
        checked.flag = _read_settings(settings, "options.settings")
        _check_settings(checked.flag, "options.settings")
    checked.sources.append(checked.flag)

    sources = None if setting_sources is None else {str(s) for s in setting_sources}
    files: List[Path] = list(_managed_files())
    files.append(_config_dir(env or {}) / "remote-settings.json")
    if sources is None or "user" in sources:
        files.append(_user_settings_path(env or {}))
    if sources is None or sources & {"project", "local"}:
        files.extend(_project_files(cwd))
    for path in files:
        parsed = _read_file_source(path)
        if parsed is not None:
            _check_settings(parsed, str(path))
            checked.sources.append(parsed)
    for where, parsed in _mdm_settings():
        _check_settings(parsed, where)
        checked.sources.append(parsed)
    return checked


def with_ask_every_tool(settings: Dict[str, Any]) -> str:
    """``settings`` as inline JSON, with a ``permissions.ask`` rule for
    every tool added."""
    out = dict(settings)
    permissions = out.get("permissions")
    if permissions is None:
        permissions = {}
    if not isinstance(permissions, dict):
        _refuse("the permissions in options.settings are not an object")
    permissions = dict(permissions)
    ask = permissions.get("ask")
    if ask is None:
        ask = []
    if not isinstance(ask, list):
        _refuse("permissions.ask in options.settings is not a list")
    if ASK_EVERY_TOOL not in ask:
        ask = [*ask, ASK_EVERY_TOOL]
    permissions["ask"] = ask
    out["permissions"] = permissions
    return json.dumps(out)




# ── what the session's own configuration would run without a prompt ──
#
# Layer 2 sends every tool call to the permission callback, so the callback
# must not allow more than Claude Code would have run on its own: a
# Watchlight allow never widens the session's configuration. The answer is
# computed conservatively from the options Watchlight governs; anything it
# cannot be sure of counts as "would have prompted".

#: Claude Code's read-only file tools (its ``Read`` permission group, plus
#: notebook reads).
READ_ONLY_TOOLS = frozenset({"Read", "Grep", "Glob", "NotebookRead"})
#: Claude Code's file edit tools (its ``Edit`` permission group).
EDIT_TOOLS = frozenset({"Edit", "Write", "NotebookEdit"})
#: A permission rule naming the group covers every tool in it.
_RULE_GROUPS = {"Read": frozenset({"Read", "Grep", "Glob"}), "Edit": EDIT_TOOLS}
_KNOWN_MODES = frozenset({"default", "acceptEdits", "plan", "bypassPermissions"})
_PATH_KEYS = ("file_path", "notebook_path", "path")


def _rule_covers(rule: Any, tool_name: str) -> bool:
    """An allow or ask rule that names ``tool_name`` as a whole tool. A rule
    with content (``Bash(ls *)``) covers only some calls and never counts as
    an allow; :func:`_rule_mentions` treats it as an ask."""
    if not isinstance(rule, str):
        return False
    rule = rule.strip()
    if rule == tool_name or tool_name in _RULE_GROUPS.get(rule, ()):
        return True
    if rule.startswith("mcp__") and tool_name.startswith("mcp__"):
        server = rule[:-3] if rule.endswith("__*") else rule
        return server.count("__") == 1 and tool_name.startswith(server + "__")
    return False


def _rule_mentions(rule: Any, tool_name: str) -> bool:
    """A rule that names ``tool_name``, with or without content."""
    if not isinstance(rule, str):
        return True
    base = rule.strip().split("(", 1)[0].strip()
    return _rule_covers(base, tool_name)


class SessionPermissions:
    """What the session's own configuration would run without a prompt.

    Built from the options ``governed_options`` checked. The permission mode
    of each call is the one Claude Code reports in that call's ``PreToolUse``
    input, so a mode changed during the session is honoured; when it
    reports none, the options' mode applies.
    """

    def __init__(
        self,
        *,
        permission_mode: Any,
        allowed_tools: Any,
        sources: List[Mapping[str, Any]],
        cwd: Any,
        add_dirs: Any,
    ) -> None:
        """``sources`` are the settings documents the session loads
        (:attr:`CheckedSettings.sources`). Their allow and ask rules all
        count; a rule list that cannot be read makes every call count as
        prompted."""
        self.rules_readable = True
        self.allow_rules: List[Any] = list(allowed_tools or [])
        self.ask_rules: List[Any] = []
        modes = []
        for settings in sources:
            permissions = settings.get("permissions")
            if permissions is None:
                continue
            if not isinstance(permissions, dict):
                self.rules_readable = False
                continue
            allow = permissions.get("allow") or []
            ask = permissions.get("ask") or []
            if not isinstance(allow, list) or not isinstance(ask, list):
                self.rules_readable = False
                continue
            self.allow_rules.extend(allow)
            self.ask_rules.extend(rule for rule in ask if rule != ASK_EVERY_TOOL)
            if permissions.get("defaultMode") is not None:
                modes.append(permissions["defaultMode"])
        # With no mode in the options, any mode a settings source names
        # must agree, else nothing counts as unprompted.
        if permission_mode is not None:
            self.default_mode = permission_mode
        elif not modes:
            self.default_mode = "default"
        else:
            self.default_mode = modes[0] if len(set(map(str, modes))) == 1 else None
        self.cwd = str(cwd) if cwd else None
        self.add_dirs = [str(d) for d in (add_dirs or [])]

    def _inside_workspace(self, tool_input: Any, cwd: Optional[str]) -> bool:
        roots = [r for r in [cwd or self.cwd, *self.add_dirs] if r]
        if not roots:
            return False
        real_roots = [os.path.realpath(r) for r in roots]
        paths = []
        if isinstance(tool_input, dict):
            for key in _PATH_KEYS:
                value = tool_input.get(key)
                if value is not None:
                    if not isinstance(value, str) or not value:
                        return False
                    paths.append(value)
            pattern = tool_input.get("pattern")
            if isinstance(pattern, str) and pattern.startswith(("/", "~")):
                fixed = pattern.split("*", 1)[0].split("?", 1)[0].split("[", 1)[0]
                paths.append(fixed or "/")
        elif tool_input is not None:
            return False
        for path in paths:
            full = os.path.realpath(os.path.join(cwd or self.cwd or "/", os.path.expanduser(path)))
            if not any(full == r or full.startswith(r.rstrip(os.sep) + os.sep) for r in real_roots):
                return False
        return True

    def would_run_unprompted(
        self, tool_name: str, tool_input: Any, mode: Any = None, cwd: Optional[str] = None
    ) -> bool:
        mode = mode if mode is not None else self.default_mode
        if mode not in _KNOWN_MODES or not self.rules_readable:
            return False
        if mode == "bypassPermissions":
            return True
        if any(_rule_mentions(rule, tool_name) for rule in self.ask_rules):
            return False
        read_only = tool_name in READ_ONLY_TOOLS and self._inside_workspace(tool_input, cwd)
        if mode == "plan":
            return read_only
        allowed = any(_rule_covers(rule, tool_name) for rule in self.allow_rules)
        if mode == "acceptEdits" and tool_name in EDIT_TOOLS and self._inside_workspace(tool_input, cwd):
            return True
        return allowed or read_only


__all__ = [
    "ASK_EVERY_TOOL",
    "BARE_MODE_ENV",
    "CheckedSettings",
    "EDIT_TOOLS",
    "GovernanceBypassDetected",
    "READ_ONLY_TOOLS",
    "SessionPermissions",
    "UngovernableSession",
    "check_session_options",
    "with_ask_every_tool",
]
