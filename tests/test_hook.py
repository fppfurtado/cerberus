"""SP-T9: `cerberus hook claude-code`, replaying recorded event payloads.

Payload shapes follow the Claude Code hooks reference (https://code.claude.com/docs/en/hooks, read
2026-11-15): PreToolUse carries ``tool_name`` / ``tool_input`` (``command`` for Bash, ``file_path``
for Read/Edit/Write); PostToolUseFailure carries the same plus ``error``. A deny is
``hookSpecificOutput.permissionDecision = "deny"`` on exit 0; context on a failure is
``hookSpecificOutput.additionalContext``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

CERBERUS = str(Path(sys.executable).parent / "cerberus")
HOST = "db-replica.example.invalid"
WRITABLE_HOST = "db-scratch.example.invalid"
COMMON = {
    "session_id": "abc123",
    "transcript_path": "/home/user/.claude/projects/x/transcript.jsonl",
    "cwd": "/home/user/project",
    "permission_mode": "default",
    "tool_use_id": "toolu_01ABC123",
}


def pre_bash(command: str) -> dict:
    return {**COMMON, "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command, "description": "x", "timeout": 120000,
                           "run_in_background": False}}


def pre_file(tool: str, path: str) -> dict:
    return {**COMMON, "hook_event_name": "PreToolUse", "tool_name": tool,
            "tool_input": {"file_path": path}}


def failed_bash(command: str, error: str) -> dict:
    return {**COMMON, "hook_event_name": "PostToolUseFailure", "tool_name": "Bash",
            "tool_input": {"command": command}, "error": error}


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "home"
    cfg = home / ".config" / "cerberus"
    cfg.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    (cfg / "connections.toml").write_text(f"""
[connection.replica]
host = "{HOST}"
port = 5432
dbname = "inventory"
user = "reader"
class = "server-enforced"
hook_match = ["inventory-replica-alias"]
deny_paths = ["~/tools/wrapper.env", "~/edge"]

[connection.scratch]
host = "{WRITABLE_HOST}"
port = 5432
dbname = "inventory_test"
user = "writer"
class = "writable"
""")
    (cfg / "pgpass").write_text("x:5432:*:reader:pw\n")
    (home / "tools").mkdir()
    (home / "tools" / "wrapper.env").write_text("PW=x\n")
    (home / "edge").mkdir()
    (home / "edge" / "cred").write_text("x\n")
    return home


def hook(event: dict | str) -> tuple[int, dict | None]:
    payload = event if isinstance(event, str) else json.dumps(event)
    proc = subprocess.run([CERBERUS, "hook", "claude-code"], input=payload, env=dict(os.environ),
                          capture_output=True, text=True, timeout=30)
    return proc.returncode, (json.loads(proc.stdout) if proc.stdout.strip() else None)


def denial(answer: dict | None) -> str:
    assert answer is not None
    out = answer["hookSpecificOutput"]
    assert out["hookEventName"] == "PreToolUse" and out["permissionDecision"] == "deny"
    return out["permissionDecisionReason"]


@pytest.mark.parametrize(
    "command",
    [
        f"psql -h {HOST} -d inventory -c 'select 1'",
        f"PGPASSWORD=x psql 'host={HOST} dbname=inventory'",
        f"python3 -c \"import psycopg; psycopg.connect(host='{HOST}')\"",
        f"cerberus query replica 'select 1'; psql -h {HOST}",
        "psql service=inventory-replica-alias",
    ],
)
def test_a_direct_client_aimed_at_a_read_connection_is_denied_with_query_pointer(home, command) -> None:
    code, answer = hook(pre_bash(command))
    assert code == 0
    reason = denial(answer)
    assert "'replica'" in reason and "cerberus query replica" in reason


def test_a_direct_client_aimed_at_a_writable_connection_points_to_run_script(home) -> None:
    reason = denial(hook(pre_bash(f"psql -h {WRITABLE_HOST} -f change.sql"))[1])
    assert "cerberus run-script scratch" in reason


@pytest.mark.parametrize(
    "command",
    [
        f"cerberus query replica 'select 1 /* {HOST} */'",
        f"uv run cerberus query replica 'select 1 /* {HOST} */'",
    ],
)
def test_a_cerberus_invocation_naming_the_host_passes(home, command) -> None:
    assert hook(pre_bash(command)) == (0, None)


def test_a_non_cerberus_segment_naming_the_host_is_denied_even_after_a_cerberus_one(home) -> None:
    denial(hook(pre_bash(f"cerberus connections | grep {HOST}"))[1])


@pytest.mark.parametrize("command", ["ls -la", "psql -h other-db.example.invalid -c 'select 1'", "git status"])
def test_a_command_naming_no_declared_connection_gets_no_answer(home, command) -> None:
    assert hook(pre_bash(command)) == (0, None)


@pytest.mark.parametrize("tool", ["Read", "Edit", "Write"])
def test_reading_or_editing_the_credential_file_is_denied(home, tool) -> None:
    reason = denial(hook(pre_file(tool, str(home / ".config" / "cerberus" / "pgpass")))[1])
    assert "credential" in reason


def test_reading_another_file_gets_no_answer(home) -> None:
    assert hook(pre_file("Read", str(home / "notes.txt"))) == (0, None)


def test_a_failed_script_file_with_an_auth_failure_on_a_declared_host_gets_the_pointer(home) -> None:
    error = (f'Exit code 2\npsycopg.OperationalError: connection to server at "{HOST}" (10.0.0.5), '
             'port 5432 failed: fe_sendauth: no password supplied')
    code, answer = hook(failed_bash("python3 report.py", error))
    assert code == 0
    out = answer["hookSpecificOutput"]
    assert out["hookEventName"] == "PostToolUseFailure"
    assert "cerberus query replica" in out["additionalContext"]


def test_a_failure_without_a_declared_host_gets_no_answer(home) -> None:
    error = 'Exit code 2\nconnection to server at "other.example.invalid" failed: password authentication failed'
    assert hook(failed_bash("python3 report.py", error)) == (0, None)


def test_a_missing_connections_file_blocks_nothing(home) -> None:
    (home / ".config" / "cerberus" / "connections.toml").unlink()
    assert hook(pre_bash(f"psql -h {HOST}")) == (0, None)


def test_a_connections_file_that_is_not_toml_blocks_no_host(home) -> None:
    (home / ".config" / "cerberus" / "connections.toml").write_text("not [valid toml")
    assert hook(pre_bash(f"psql -h {HOST}")) == (0, None)


def test_malformed_input_blocks_nothing(home) -> None:
    assert hook("not json") == (0, None)


# --- Spec v1.3: protected paths -------------------------------------------------------------------


def pre_grep(path: str | None, cwd: str | None = None) -> dict:
    tool_input = {"pattern": "password"}
    if path is not None:
        tool_input["path"] = path
    event = {**COMMON, "hook_event_name": "PreToolUse", "tool_name": "Grep", "tool_input": tool_input}
    if cwd is not None:
        event["cwd"] = cwd
    return event


@pytest.mark.parametrize("command", [
    "cat ~/.config/cerberus/pgpass",
    "cat $HOME/.config/cerberus/pgpass",
    "cat ${HOME}/.config/cerberus/pgpass",
    "cat \"$XDG_CONFIG_HOME/cerberus/pgpass\"",
    "cat ${XDG_CONFIG_HOME}/cerberus/pgpass",
    "cd ~/.config/cerberus && cat pgpass",
    "cd ~/.config/cerberus; head -1 ./pgpass",
    "source ~/tools/wrapper.env",
    "grep -r x ~/edge",
    "ls ~/edge/",
    "cat ~/edge/cred",
    "cerberus run-script scratch ~/tools/wrapper.env",
])
def test_a_shell_command_naming_a_protected_path_is_denied(home, command) -> None:
    assert "credential" in denial(hook(pre_bash(command))[1])


def test_the_absolute_spelling_is_denied(home) -> None:
    denial(hook(pre_bash(f"cat {home}/.config/cerberus/pgpass"))[1])


@pytest.mark.parametrize("command", [
    "cat ~/tools/wrapper.envrc",
    "ls ~/.config/cerberus",
    "cat ~/.config/cerberus/connections.toml",
    "ls ~/edges",
    "echo pgpass",
])
def test_a_shell_command_sharing_only_a_prefix_or_a_word_passes(home, command) -> None:
    assert hook(pre_bash(command)) == (0, None)


@pytest.mark.parametrize("tool", ["Read", "Edit", "Write", "MultiEdit"])
def test_file_tools_on_a_deny_path_file_are_denied(home, tool) -> None:
    denial(hook(pre_file(tool, str(home / "tools" / "wrapper.env")))[1])


def test_a_file_under_a_protected_directory_is_denied(home) -> None:
    denial(hook(pre_file("Read", str(home / "edge" / "cred")))[1])


def test_a_relative_path_resolves_against_the_event_cwd(home) -> None:
    event = {**pre_file("Read", "pgpass"), "cwd": str(home / ".config" / "cerberus")}
    denial(hook(event)[1])


def test_a_symlink_to_a_protected_file_is_denied(home) -> None:
    link = home / "innocent.txt"
    link.symlink_to(home / "tools" / "wrapper.env")
    denial(hook(pre_file("Read", str(link)))[1])


@pytest.mark.parametrize("which", ["config_dir", "home", "file", "deny_dir"])
def test_grep_over_or_into_a_protected_path_is_denied(home, which) -> None:
    path = {"config_dir": home / ".config" / "cerberus", "home": home,
            "file": home / ".config" / "cerberus" / "pgpass", "deny_dir": home / "edge"}[which]
    assert "narrower" in denial(hook(pre_grep(str(path)))[1])


def test_grep_without_a_path_uses_the_event_cwd(home) -> None:
    denial(hook(pre_grep(None, cwd=str(home)))[1])


def test_grep_over_a_directory_without_protected_paths_passes(home) -> None:
    (home / "project").mkdir()
    assert hook(pre_grep(str(home / "project"))) == (0, None)
    assert hook(pre_grep(None, cwd=str(home / "project"))) == (0, None)


# --- Spec v1.3: a broken connections file ---------------------------------------------------------


def test_a_missing_connections_file_still_protects_the_default_password_file(home) -> None:
    (home / ".config" / "cerberus" / "connections.toml").unlink()
    denial(hook(pre_file("Read", str(home / ".config" / "cerberus" / "pgpass")))[1])
    denial(hook(pre_bash("cat ~/.config/cerberus/pgpass"))[1])


def test_a_connections_file_that_is_not_toml_still_protects_the_default_password_file(home) -> None:
    (home / ".config" / "cerberus" / "connections.toml").write_text("not [valid toml")
    denial(hook(pre_file("Read", str(home / ".config" / "cerberus" / "pgpass")))[1])


def test_an_invalid_declaration_still_protects_what_it_shows(home) -> None:
    (home / ".config" / "cerberus" / "connections.toml").write_text(f"""
[connection.replica]
host = "{HOST}"
port = "not-a-number"
hook_match = ["inventory-replica-alias", 7]
deny_paths = ["~/tools/wrapper.env", "relative/ignored"]
""")
    reason = denial(hook(pre_bash(f"psql -h {HOST}"))[1])
    assert "'replica'" in reason and "invalid" in reason and "cerberus query" not in reason
    denial(hook(pre_bash("psql service=inventory-replica-alias"))[1])
    denial(hook(pre_file("Read", str(home / "tools" / "wrapper.env")))[1])
    assert hook(pre_bash("ls")) == (0, None)


def test_a_relative_deny_path_makes_the_declaration_invalid(home) -> None:
    from cerberus import config
    from cerberus.refusal import Refusal

    (home / ".config" / "cerberus" / "connections.toml").write_text(f"""
[connection.replica]
host = "{HOST}"
port = 5432
dbname = "inventory"
user = "reader"
class = "server-enforced"
deny_paths = ["tools/wrapper.env"]
""")
    with pytest.raises(Refusal) as exc:
        config.load_all()
    assert exc.value.rule == "config.invalid" and "deny_paths" in exc.value.detail


def test_grep_with_a_relative_path_resolves_against_the_event_cwd(home) -> None:
    denial(hook(pre_grep("pgpass", cwd=str(home / ".config" / "cerberus")))[1])
    (home / "project").mkdir()
    assert hook(pre_grep("src", cwd=str(home / "project"))) == (0, None)


def test_an_invalid_declaration_still_adds_the_pointer_on_a_failed_command(home) -> None:
    (home / ".config" / "cerberus" / "connections.toml").write_text(f"""
[connection.replica]
host = "{HOST}"
port = "not-a-number"
""")
    error = f'connection to server at "{HOST}" failed: fe_sendauth: no password supplied'
    out = hook(failed_bash("python3 report.py", error))[1]["hookSpecificOutput"]
    assert "'replica'" in out["additionalContext"] and "invalid" in out["additionalContext"]
