"""`cerberus hook claude-code` — keep direct database clients off declared connections.

Reads one Claude Code hook event on stdin (shapes from the Claude Code hooks reference,
https://code.claude.com/docs/en/hooks, read 2026-11-15 and 2026-11-19):

- ``PreToolUse`` for ``Bash``: deny a command that names a declared connection's host or one of its
  ``hook_match`` strings unless that part of the command is itself a ``cerberus`` invocation; the
  reason names the connection and the command to use instead. Also deny a command that names a
  protected path (below), a ``cerberus`` invocation included.
- ``PreToolUse`` for the file tools (``Read`` / ``Edit`` / ``Write`` / ``MultiEdit`` /
  ``NotebookEdit``): deny a path that is a protected file or lies under a protected directory.
- ``PreToolUse`` for ``Grep``: deny a search path (the event's ``cwd`` when the input names none) that
  is protected, or that contains a protected path.
- ``PostToolUseFailure`` for ``Bash``: when the error shows an authentication failure naming a declared
  host (a script file holding the host, which the pre-tool match cannot see), add the same pointer as
  context.

Protected paths (Spec v1.3): each connection's password file and ``deny_paths`` entries, plus the
default password file path always. A missing, unreadable or non-TOML connections file leaves only the
default path protected; a TOML file with an invalid declaration still protects every string the hook
can read from it. Anything the rules above do not select passes untouched.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
from dataclasses import dataclass
from pathlib import Path

from cerberus import config
from cerberus.refusal import Refusal

_SEGMENT_SPLIT = re.compile(r"&&|\|\||[;|\n&]")
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_AUTH_FAILURE = re.compile(
    r"password authentication failed|no password supplied|fe_sendauth|authentication failed",
    re.IGNORECASE,
)
_FILE_TOOLS = {"Read", "Edit", "Write", "MultiEdit", "NotebookEdit"}
# Where a spelled path counts as named (Spec v1.3, Hook): start, whitespace, a quote, `=`, `:`, `(` or a
# shell operator before it; end, whitespace, a quote, `/`, `)` or a shell operator after it.
_BEFORE = r"(?:^|(?<=[\s'\"=:(;&|<>`]))"
_AFTER = r"(?=$|[\s'\"/);&|<>`])"

_CREDENTIAL = "this path holds a cerberus credential; it is read only by cerberus or its own tool"


@dataclass(frozen=True)
class _Target:
    """A declared connection as the hook sees it: what names it in a command, and the pointer."""

    name: str
    matches: tuple[str, ...]
    pointer: str


def _pointer(name: str, cls: str | None) -> str:
    if cls not in config.CLASSES:
        return (f"{name!r} is a declared cerberus connection, but the connections file is invalid, so no "
                "cerberus command works until it is fixed (`cerberus doctor` names the error); a direct "
                "database client may not reach it.")
    if cls == "writable":
        use = f"cerberus run-script {name} <file>"
    else:
        use = f'cerberus query {name} "<sql>"'
    return (f"{name!r} is a declared cerberus connection; a direct database client may not reach "
            f"it. Use: {use}")


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [v for v in value if isinstance(v, str) and v]
    return []


def _load() -> tuple[list[_Target], list[Path]]:
    """The connections to route and the paths to protect, from whatever the hook can read."""
    protected = [config.default_passfile()]
    try:
        connections = config.load_all()
    except (Refusal, OSError):
        return _load_leniently(protected)
    targets = []
    for c in connections.values():
        targets.append(_Target(c.name, tuple(m for m in (c.host, *c.hook_match) if m),
                               _pointer(c.name, c.cls)))
        protected.append(c.passfile)
        protected.extend(c.deny_paths)
    return targets, protected


def _load_leniently(protected: list[Path]) -> tuple[list[_Target], list[Path]]:
    """An invalid declaration still protects every string it shows (Spec v1.3)."""
    try:
        raw = config.load_raw_connections()
    except (Refusal, OSError):
        return [], protected
    targets = []
    for name, body in raw.items():
        if not isinstance(body, dict):
            continue
        matches = tuple(_strings(body.get("host")) + _strings(body.get("hook_match")))
        if matches:
            targets.append(_Target(str(name), matches, _pointer(str(name), None)))
        protected.extend(Path(p).expanduser() for p in _strings(body.get("passfile"))
                         if config.is_anchored(p))
        protected.extend(Path(p).expanduser() for p in _strings(body.get("deny_paths"))
                         if config.is_anchored(p))
    return targets, protected


def _resolved(paths: list[Path]) -> set[Path]:
    out = set()
    for p in paths:
        out.add(Path(os.path.abspath(p)))
        out.add(p.resolve())
    return out


def _within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _event_path(raw: str, cwd: str | None) -> Path:
    path = Path(raw).expanduser()
    if not path.is_absolute() and cwd:
        path = Path(cwd) / path
    return path.resolve()


def _spellings(path: Path) -> set[str]:
    """The ways a command may write ``path``: as is, resolved, and through ``~``/``$HOME``/XDG."""
    forms = {str(path), os.path.abspath(path), str(path.resolve())}
    home = str(Path.home())
    xdg = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    out = set(forms)
    for form in forms:
        for base, names in ((home, ("~", "$HOME", "${HOME}")),
                            (xdg, ("$XDG_CONFIG_HOME", "${XDG_CONFIG_HOME}"))):
            if form == base:
                out.update(names)
            elif form.startswith(base.rstrip("/") + "/"):
                rest = form[len(base.rstrip("/")) + 1:]
                out.update(f"{n}/{rest}" for n in names)
    return {s for s in out if s}


def _names(command: str, spelling: str) -> bool:
    return re.search(_BEFORE + re.escape(spelling) + _AFTER, command) is not None


def _names_protected_path(command: str, protected: list[Path]) -> bool:
    for path in protected:
        if any(_names(command, s) for s in _spellings(path)):
            return True
        parent, name = path.parent, path.name
        if name and re.search(r"(?:^|(?<=[\s'\"=:(;&|<>`/]))" + re.escape(name) + _AFTER, command):
            if any(_names(command, s) for s in _spellings(parent)):
                return True
    return False


def program_words(command: str) -> list[str]:
    """The command's words from its program on: environment assignments, ``env``, ``command``,
    ``exec`` and ``uv run`` dropped. Shared with ``doctor``'s registration check, so the two read a
    ``cerberus`` invocation the same way."""
    try:
        words = shlex.split(command)
    except ValueError:
        words = command.split()
    while words and (_ASSIGNMENT.match(words[0]) or words[0] in ("env", "command", "exec")):
        words = words[1:]
    if words[:2] == ["uv", "run"]:
        words = words[2:]
    return words


def _is_cerberus(segment: str) -> bool:
    words = program_words(segment)
    return bool(words) and Path(words[0]).name == "cerberus"


def _bash_denial(command: str, targets: list[_Target]) -> str | None:
    for segment in _SEGMENT_SPLIT.split(command):
        for target in targets:
            if any(m in segment for m in target.matches) and not _is_cerberus(segment):
                return target.pointer
    return None


def _deny(reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def decide(event: dict) -> dict | None:
    """The hook's answer for one event, or None to answer nothing."""
    targets, protected = _load()
    name = event.get("hook_event_name")
    tool = event.get("tool_name")
    tool_input = event.get("tool_input") or {}
    cwd = event.get("cwd") if isinstance(event.get("cwd"), str) else None

    if name == "PreToolUse" and tool == "Bash":
        command = str(tool_input.get("command", ""))
        if _names_protected_path(command, protected):
            return _deny(_CREDENTIAL + "; this command names it")
        reason = _bash_denial(command, targets)
        return _deny(reason) if reason else None

    if name == "PreToolUse" and tool in _FILE_TOOLS:
        raw = tool_input.get("file_path") or tool_input.get("notebook_path")
        if isinstance(raw, str) and raw:
            path = _event_path(raw, cwd)
            if any(_within(path, p) for p in _resolved(protected)):
                return _deny(_CREDENTIAL)
        return None

    if name == "PreToolUse" and tool == "Grep":
        raw = tool_input.get("path")
        raw = raw if isinstance(raw, str) and raw else cwd
        if raw:
            search = _event_path(raw, cwd)
            if any(_within(search, p) or _within(p, search) for p in _resolved(protected)):
                return _deny(_CREDENTIAL + "; this search would read it — search a narrower path")
        return None

    if name == "PostToolUseFailure" and tool == "Bash":
        error = str(event.get("error", ""))
        if _AUTH_FAILURE.search(error):
            for target in targets:
                if any(m in error for m in target.matches):
                    return {"hookSpecificOutput": {"hookEventName": "PostToolUseFailure",
                                                   "additionalContext": target.pointer}}
    return None


def main(stdin=None) -> int:
    stream = stdin or sys.stdin
    try:
        event = json.load(stream)
    except (ValueError, OSError):
        return 0
    answer = decide(event) if isinstance(event, dict) else None
    if answer is not None:
        print(json.dumps(answer))
    return 0
