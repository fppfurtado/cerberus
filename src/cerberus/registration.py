"""Whether the Claude Code hook is registered for every event and tool it serves (Spec v1.3, PR13).

Reads the two settings scopes that apply to every session of the user: the user settings
(``settings.json`` in ``$CLAUDE_CONFIG_DIR``, ``~/.claude`` when unset) and the managed settings file.
Project, local and plugin settings are not read (a stated residual). Matcher rules follow the Claude
Code hooks reference (https://code.claude.com/docs/en/hooks, read 2026-11-19).
"""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path

from cerberus.hook import SEGMENT_SPLIT, program_words

REQUIRED = (
    ("PreToolUse", "Bash"),
    ("PreToolUse", "Read"),
    ("PreToolUse", "Edit"),
    ("PreToolUse", "Write"),
    ("PreToolUse", "NotebookEdit"),
    ("PreToolUse", "Grep"),
    ("PostToolUseFailure", "Bash"),
)
MANAGED_SETTINGS = (
    Path("/etc/claude-code/managed-settings.json"),
    Path("/Library/Application Support/ClaudeCode/managed-settings.json"),
)
_EXACT_LIST = re.compile(r"^[A-Za-z0-9_\-, |]+$")


def user_settings() -> Path:
    base = os.environ.get("CLAUDE_CONFIG_DIR") or str(Path.home() / ".claude")
    return Path(base).expanduser() / "settings.json"


def _read(path: Path) -> tuple[dict | None, str | None]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None, None
    except (OSError, ValueError) as exc:
        return None, f"{path}: unreadable ({type(exc).__name__})"
    return (data, None) if isinstance(data, dict) else (None, f"{path}: not a JSON object")


def matcher_selects(matcher: object, tool: str) -> bool:
    if matcher is None or matcher == "" or matcher == "*":
        return True
    if not isinstance(matcher, str):
        return False
    if _EXACT_LIST.match(matcher):
        return tool in {m.strip() for m in re.split(r"[|,]", matcher) if m.strip()}
    try:
        return re.search(matcher, tool) is not None
    except re.error:
        return False


def runs_hook(command: object) -> bool:
    """True when a segment of ``command`` runs ``cerberus hook claude-code`` (Spec v1.4)."""
    if not isinstance(command, str):
        return False
    for segment in SEGMENT_SPLIT.split(command):
        words = program_words(segment)
        if words[:1] and Path(words[0]).name == "cerberus" and words[1:] == ["hook", "claude-code"]:
            if _executable(words[0]):
                return True
    return False


def _executable(program: str) -> bool:
    """The named program exists and is executable: a guarded registration whose binary is gone runs
    `exit 0`, so the hook never runs (Spec v1.4)."""
    if "/" in program:
        path = Path(os.path.expandvars(program)).expanduser()
        return path.is_file() and os.access(path, os.X_OK)
    return shutil.which(program) is not None


def _registered(settings: dict) -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    hooks = settings.get("hooks")
    if not isinstance(hooks, dict):
        return found
    for event, tool in REQUIRED:
        groups = hooks.get(event)
        if not isinstance(groups, list):
            continue
        for group in groups:
            if not isinstance(group, dict) or not matcher_selects(group.get("matcher"), tool):
                continue
            entries = group.get("hooks")
            if isinstance(entries, list) and any(
                isinstance(h, dict) and h.get("type", "command") == "command" and runs_hook(h.get("command"))
                for h in entries
            ):
                found.add((event, tool))
    return found


def report() -> dict[str, object]:
    problems: list[str] = []
    user, err = _read(user_settings())
    if err:
        problems.append(err)
    managed: dict | None = None
    for path in MANAGED_SETTINGS:
        managed, err = _read(path)
        if err:
            problems.append(err)
        if managed is not None:
            break

    from_managed = _registered(managed) if managed else set()
    from_user = _registered(user) if user else set()
    managed_only = bool(managed and managed.get("allowManagedHooksOnly") is True)
    if managed_only and from_user - from_managed:
        problems.append("managed settings allow only managed hooks; the user-settings registration does not run")
        from_user = set()
    for scope, data in (("user", user), ("managed", managed)):
        if data and data.get("disableAllHooks") is True:
            problems.append(f"{scope} settings set disableAllHooks")

    registered = from_user | from_managed
    pairs = {f"{event}:{tool}": (event, tool) in registered for event, tool in REQUIRED}
    missing = [k for k, ok in pairs.items() if not ok]
    if missing:
        problems.append("not registered for " + ", ".join(missing))
    return {"ok": not problems, "registered": pairs, "problems": problems}
