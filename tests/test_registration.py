"""Spec v1.3 (SP-T2): `doctor` reports whether the hook is registered for every event and tool it serves."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from cerberus import registration

COMMAND = {"type": "command", "command": "cerberus hook claude-code"}
ALL_PRE = "Bash|Read|Edit|Write|NotebookEdit|Grep"


@pytest.fixture
def claude_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    d = tmp_path / "claude"
    d.mkdir()
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(d))
    monkeypatch.setattr(registration, "MANAGED_SETTINGS", (tmp_path / "managed-settings.json",))
    return d


def write(path: Path, settings: dict) -> None:
    path.write_text(json.dumps(settings))


def settings(pre_matcher: object = ALL_PRE, command: dict = COMMAND, **extra: object) -> dict:
    pre = {"hooks": [command]}
    if pre_matcher is not None:
        pre["matcher"] = pre_matcher
    return {"hooks": {"PreToolUse": [pre],
                      "PostToolUseFailure": [{"matcher": "Bash", "hooks": [command]}]}, **extra}


def test_every_pair_registered_is_ok(claude_dir: Path) -> None:
    write(claude_dir / "settings.json", settings())
    report = registration.report()
    assert report["ok"] is True, report
    assert all(report["registered"].values())


def test_a_matcher_without_grep_is_not_ok_and_names_the_pair(claude_dir: Path) -> None:
    write(claude_dir / "settings.json", settings("Bash|Read|Edit|Write|NotebookEdit"))
    report = registration.report()
    assert report["ok"] is False
    assert report["registered"]["PreToolUse:Grep"] is False
    assert any("PreToolUse:Grep" in p for p in report["problems"])


@pytest.mark.parametrize("matcher", ["^(Bash|Read|Edit|Write|NotebookEdit|Grep)$", ".*", "*", "", None])
def test_regex_omitted_and_match_all_matchers_select_every_tool(claude_dir: Path, matcher) -> None:
    write(claude_dir / "settings.json", settings(matcher))
    assert registration.report()["ok"] is True


def test_an_exact_list_does_not_match_by_substring(claude_dir: Path) -> None:
    # "Edit" in an exact list must not select NotebookEdit (only a regex is unanchored).
    write(claude_dir / "settings.json", settings("Bash, Read, Edit, Write, Grep"))
    report = registration.report()
    assert report["registered"]["PreToolUse:NotebookEdit"] is False
    assert report["registered"]["PreToolUse:Edit"] is True


@pytest.fixture
def binary(tmp_path: Path) -> Path:
    """An executable named cerberus at an absolute path, as the deployment installs it."""
    path = tmp_path / "bin" / "cerberus"
    path.parent.mkdir()
    path.write_text("#!/bin/sh\n")
    path.chmod(0o755)
    return path


@pytest.mark.parametrize("template", [
    "uv run cerberus hook claude-code",
    "{bin} hook claude-code",
    "env FOO=1 cerberus hook claude-code",
    # the deployment's guarded form, verbatim from the dotfiles settings template (Spec v1.4)
    'test -x "{bin}" || exit 0; exec "{bin}" hook claude-code',
])
def test_command_forms_that_run_the_hook_are_recognized(claude_dir: Path, binary: Path, template: str) -> None:
    command = template.format(bin=binary)
    write(claude_dir / "settings.json", settings(command={"type": "command", "command": command}))
    assert registration.report()["ok"] is True


@pytest.mark.parametrize("template", [
    "cerberus doctor",
    "echo cerberus hook claude-code",
    "cerberus hook",
    "cerberus query x hook claude-code",
    'test -x "{bin}" || exit 0; exec "{bin}" doctor',
    # the guarded form whose binary is gone runs `exit 0`: the hook never runs (Spec v1.4)
    'test -x "{missing}" || exit 0; exec "{missing}" hook claude-code',
])
def test_other_commands_do_not_count(claude_dir: Path, binary: Path, template: str) -> None:
    command = template.format(bin=binary, missing=binary.parent / "gone" / "cerberus")
    write(claude_dir / "settings.json", settings(command={"type": "command", "command": command}))
    assert registration.report()["ok"] is False


def test_a_non_executable_binary_does_not_count(claude_dir: Path, binary: Path) -> None:
    binary.chmod(0o644)
    command = f'test -x "{binary}" || exit 0; exec "{binary}" hook claude-code'
    write(claude_dir / "settings.json", settings(command={"type": "command", "command": command}))
    assert registration.report()["ok"] is False


def test_disable_all_hooks_is_not_ok(claude_dir: Path) -> None:
    write(claude_dir / "settings.json", settings(disableAllHooks=True))
    report = registration.report()
    assert report["ok"] is False
    assert any("disableAllHooks" in p for p in report["problems"])


def test_managed_only_hooks_void_a_user_registration(claude_dir: Path, tmp_path: Path) -> None:
    write(claude_dir / "settings.json", settings())
    write(tmp_path / "managed-settings.json", {"allowManagedHooksOnly": True})
    assert registration.report()["ok"] is False


def test_a_managed_registration_counts(claude_dir: Path, tmp_path: Path) -> None:
    write(tmp_path / "managed-settings.json", settings(allowManagedHooksOnly=True))
    assert registration.report()["ok"] is True


def test_no_settings_at_all_is_not_ok(claude_dir: Path) -> None:
    report = registration.report()
    assert report["ok"] is False
    assert not any(report["registered"].values())


def test_unparseable_settings_are_reported(claude_dir: Path) -> None:
    (claude_dir / "settings.json").write_text("{not json")
    report = registration.report()
    assert report["ok"] is False
    assert any("unreadable" in p for p in report["problems"])


def test_disable_all_hooks_in_managed_settings_is_not_ok(claude_dir: Path, tmp_path: Path) -> None:
    write(claude_dir / "settings.json", settings())
    write(tmp_path / "managed-settings.json", {"disableAllHooks": True})
    report = registration.report()
    assert report["ok"] is False
    assert any("managed settings set disableAllHooks" in p for p in report["problems"])


def test_disable_all_hooks_false_is_ok(claude_dir: Path) -> None:
    write(claude_dir / "settings.json", settings(disableAllHooks=False))
    assert registration.report()["ok"] is True
