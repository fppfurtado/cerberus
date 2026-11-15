"""`cerberus hook claude-code` — keep direct database clients off declared connections.

Reads one Claude Code hook event on stdin (shapes from the Claude Code hooks reference,
https://code.claude.com/docs/en/hooks, read 2026-11-15):

- ``PreToolUse`` for ``Bash``: deny a command that names a declared connection's host or one of its
  ``hook_match`` strings unless that part of the command is itself a ``cerberus`` invocation; the
  reason names the connection and the command to use instead.
- ``PreToolUse`` for ``Read`` / ``Edit`` / ``Write``: deny a path that resolves to a credential file.
- ``PostToolUseFailure`` for ``Bash``: when the error shows an authentication failure naming a declared
  host (a script file holding the host, which the pre-tool match cannot see), add the same pointer as
  context.

Anything that names no declared connection passes untouched. A missing or unreadable connections file
blocks nothing.
"""

from __future__ import annotations

import json
import re
import shlex
import sys
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


def _pointer(conn: config.Connection) -> str:
    if conn.cls == "writable":
        use = f"cerberus run-script {conn.name} <file>"
    else:
        use = f'cerberus query {conn.name} "<sql>"'
    return (f"{conn.name!r} is a declared cerberus connection; a direct database client may not reach "
            f"it. Use: {use}")


def _is_cerberus(segment: str) -> bool:
    try:
        words = shlex.split(segment)
    except ValueError:
        words = segment.split()
    while words and (_ASSIGNMENT.match(words[0]) or words[0] in ("env", "command", "exec")):
        words = words[1:]
    if words[:2] == ["uv", "run"]:
        words = words[2:]
    return bool(words) and Path(words[0]).name == "cerberus"


def _matches(conn: config.Connection) -> list[str]:
    return [m for m in (conn.host, *conn.hook_match) if m]


def _bash_denial(command: str, connections: dict[str, config.Connection]) -> str | None:
    for segment in _SEGMENT_SPLIT.split(command):
        for conn in connections.values():
            if any(m in segment for m in _matches(conn)) and not _is_cerberus(segment):
                return _pointer(conn)
    return None


def _credential_files(connections: dict[str, config.Connection]) -> set[Path]:
    return {c.passfile.expanduser().resolve() for c in connections.values()}


def _deny(reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def decide(event: dict) -> dict | None:
    """The hook's answer for one event, or None to answer nothing."""
    try:
        connections = config.load_all()
    except (Refusal, OSError):
        return None
    if not connections:
        return None
    name = event.get("hook_event_name")
    tool = event.get("tool_name")
    tool_input = event.get("tool_input") or {}

    if name == "PreToolUse" and tool == "Bash":
        reason = _bash_denial(str(tool_input.get("command", "")), connections)
        return _deny(reason) if reason else None

    if name == "PreToolUse" and tool in _FILE_TOOLS:
        path = tool_input.get("file_path") or tool_input.get("notebook_path")
        if path and Path(path).expanduser().resolve() in _credential_files(connections):
            return _deny("this is a cerberus credential file; it is read only by cerberus itself")
        return None

    if name == "PostToolUseFailure" and tool == "Bash":
        error = str(event.get("error", ""))
        if _AUTH_FAILURE.search(error):
            for conn in connections.values():
                if any(m in error for m in _matches(conn)):
                    return {"hookSpecificOutput": {"hookEventName": "PostToolUseFailure",
                                                   "additionalContext": _pointer(conn)}}
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
