"""SP-T7: `cerberus query` and `cerberus connections`, run as the installed command."""

from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from cerberus.custody import inside_working_tree
from conftest import MARKER, READER_PASSWORD, Cluster

CERBERUS = str(Path(sys.executable).parent / "cerberus")


def run(args: list[str], cwd: Path) -> tuple[int, str]:
    proc = subprocess.run([CERBERUS, *args], cwd=cwd, env=dict(os.environ),
                          capture_output=True, text=True, timeout=60)
    return proc.returncode, proc.stdout


@pytest.fixture
def outside(tmp_path: Path) -> Path:
    d = tmp_path / "anywhere"
    d.mkdir()
    assert not inside_working_tree(d)
    return d


@pytest.fixture
def declared(schema: Cluster, declare):
    r = dataclasses.replace(schema.standby, user="reader", password=READER_PASSWORD)
    declare("replica", r, "server-enforced",
            'timeout_ms = 2000\n[connection.replica.policy.columns]\n"app.vault" = ["id", "label"]\n')
    declare("scratchdb", schema.primary, "writable")


def test_query_prints_the_result_with_rows_and_guarantee_and_exits_0(declared, outside: Path) -> None:
    code, out = run(["query", "replica", "SELECT id, label FROM app.vault"], outside)
    assert code == 0, out
    result = json.loads(out)
    assert result["rows"] == [[1, "first"]]
    assert result["columns"] == ["id", "label"]
    assert result["guarantee"] == {"class": "server-enforced", "basis": "pg_is_in_recovery"}
    assert result["resolved"][0]["schema"] == "app"
    assert result["connection"] == "replica"


def test_a_refusal_prints_the_refusal_object_and_exits_3(declared, outside: Path) -> None:
    code, out = run(["query", "replica", "SELECT secret FROM app.vault"], outside)
    assert code == 3
    refusal = json.loads(out)
    assert refusal["refused"] is True
    assert refusal["rule"] == "policy.column-not-listed"
    assert refusal["guarantee"]["class"] == "server-enforced"
    assert MARKER not in out


def test_query_on_a_writable_connection_refuses_and_names_run_script(declared, outside: Path) -> None:
    code, out = run(["query", "scratchdb", "SELECT 1"], outside)
    assert code == 3
    refusal = json.loads(out)
    assert refusal["rule"] == "connection.writable"
    assert "run-script" in refusal["detail"]


def test_connections_lists_name_class_and_bound_and_no_host_or_credential(
    declared, outside: Path, schema: Cluster
) -> None:
    code, out = run(["connections"], outside)
    assert code == 0
    assert json.loads(out) == [
        {"name": "replica", "class": "server-enforced", "timeout_ms": 2000},
        {"name": "scratchdb", "class": "writable", "timeout_ms": 30000},
    ]
    for leak in (schema.primary.host, READER_PASSWORD, schema.primary.password):
        assert leak not in out


def test_table_format_for_a_person(declared, outside: Path) -> None:
    code, out = run(["query", "replica", "SELECT id, label FROM app.vault", "--format", "table"], outside)
    assert code == 0
    assert "first" in out and "server-enforced" in out


def test_a_server_error_shows_its_first_line_unless_verbose(declared, outside: Path) -> None:
    code, out = run(["query", "replica", "SELECT label::int FROM app.vault"], outside)
    assert code == 3
    refusal = json.loads(out)
    assert refusal["rule"] == "server.error"
    assert refusal["detail"].startswith("22P02:")
    assert "\n" not in refusal["detail"]
