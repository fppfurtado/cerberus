"""SP-T12: the release's version and the README's refusal table, kept in step with the code."""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

import cerberus
from cerberus.cli import main

ROOT = Path(__file__).resolve().parent.parent
# Every dotted lower-case literal in the package is a refusal rule unless it is one of these.
RULE = re.compile(r"""["']([a-z][a-z0-9_]*\.[a-z0-9_-]+)["']""")
NOT_RULES = {"connections.toml", "settings.json", "commits.jsonl", "managed-settings.json",
             "policy.columns", "policy.deny_relations", "policy.allow_functions"}  # config keys


def test_version_is_single_sourced():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    assert "version" not in project and "version" in project["dynamic"]
    assert cerberus.__version__ == "0.1.0"


def test_changelog_has_an_entry_for_the_version():
    assert f"## [{cerberus.__version__}]" in (ROOT / "CHANGELOG.md").read_text()


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as exit_:
        main(["--version"])
    assert exit_.value.code == 0
    assert capsys.readouterr().out.strip() == f"cerberus {cerberus.__version__}"


def test_readme_lists_every_refusal_rule_and_no_other():
    in_code = {m for f in (ROOT / "src" / "cerberus").rglob("*.py") for m in RULE.findall(f.read_text())
               if m not in NOT_RULES and not m.startswith("pg_catalog.")}
    rows = [r for r in (ROOT / "README.md").read_text().splitlines() if re.match(r"^\|[^|]*\| `", r)]
    table = [re.match(r"^\|[^|]*\| `([^`]+)` \|", r).group(1) for r in rows]
    assert len(table) == len(set(table)), "a rule is listed twice"
    assert set(table) == in_code
