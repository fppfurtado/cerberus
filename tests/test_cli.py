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
    assert "Traceback" not in proc.stderr, proc.stderr  # Spec v1.5: no command prints a traceback
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


# --- Spec v1.5: a script file is decoded as declared; a failure is a named refusal, never a traceback ---

LEGACY_SCRIPT = "-- Município: a comment in the vendor's legacy encoding\nselect 1 as one;\n"


def test_a_script_not_in_utf8_is_refused_by_name_and_points_to_encoding(declared, outside: Path) -> None:
    path = outside / "vendor.sql"
    path.write_bytes(LEGACY_SCRIPT.encode("cp1252"))
    code, out = run(["run-script", "scratchdb", str(path)], cwd=outside)
    assert code == 3, out
    refusal = json.loads(out)
    assert refusal["rule"] == "script.encoding" and "--encoding" in refusal["detail"]
    assert "Traceback" not in out


def test_encoding_option_runs_a_legacy_script_rolled_back(declared, outside: Path) -> None:
    path = outside / "vendor.sql"
    path.write_bytes(LEGACY_SCRIPT.encode("cp1252"))
    code, out = run(["run-script", "scratchdb", str(path), "--encoding", "cp1252"], cwd=outside)
    assert code == 0, out
    result = json.loads(out)
    assert result["committed"] is False
    assert result["statements"][0]["rows"] == [[1]]


def test_a_utf8_script_with_a_byte_order_mark_runs(declared, outside: Path) -> None:
    path = outside / "bom.sql"
    path.write_bytes(LEGACY_SCRIPT.encode("utf-8-sig"))
    code, out = run(["run-script", "scratchdb", str(path)], cwd=outside)
    assert code == 0, out


@pytest.mark.parametrize("args,rule", [
    (["--encoding", "no-such-encoding"], "script.encoding"),
    ([], "script.unreadable"),
])
def test_bad_encoding_name_and_missing_file_are_named_refusals(declared, outside: Path, args, rule) -> None:
    path = outside / ("vendor.sql" if args else "missing.sql")
    if args:
        path.write_text("select 1;")
    code, out = run(["run-script", "scratchdb", str(path), *args], cwd=outside)
    assert code == 3, out
    refusal = json.loads(out)
    assert refusal["rule"] == rule
    if rule == "script.encoding":
        assert "--encoding" in refusal["detail"]


@pytest.mark.parametrize("handler,argv", [
    ("_connections", ["connections"]),
    ("_query", ["query", "x", "select 1"]),
    ("_run_script", ["run-script", "x", "f.sql"]),
    ("_doctor", ["doctor"]),
])
def test_an_unexpected_failure_is_a_refusal_naming_only_the_exception_class(
    monkeypatch, capsys, handler, argv
) -> None:
    from cerberus import cli

    def boom(_args):
        raise ValueError("a message that could quote secret-value-123")

    monkeypatch.setattr(cli, handler, boom)
    code = cli.main(argv)
    captured = capsys.readouterr()
    assert code == 3
    refusal = json.loads(captured.out)
    assert refusal["rule"] == "internal.error" and "ValueError" in refusal["detail"]
    assert "secret-value-123" not in captured.out + captured.err
    assert "Traceback" not in captured.err


def test_the_hook_keeps_its_own_contract_on_an_unexpected_failure(monkeypatch) -> None:
    from cerberus import cli

    def boom(_args):
        raise ValueError("x")

    monkeypatch.setattr(cli, "_hook", boom)
    with pytest.raises(ValueError):
        cli.main(["hook", "claude-code"])


def test_utf8_named_explicitly_still_drops_a_byte_order_mark(declared, outside: Path) -> None:
    path = outside / "bom.sql"
    path.write_bytes(LEGACY_SCRIPT.encode("utf-8-sig"))
    code, out = run(["run-script", "scratchdb", str(path), "--encoding", "UTF8"], cwd=outside)
    assert code == 0, out


def test_a_character_the_client_encoding_cannot_carry_is_a_named_refusal(
    preconditions: Cluster, declare, tmp_path: Path, capsys
) -> None:
    from cerberus import cli

    server = dataclasses.replace(preconditions.primary, dbname="latin1db")
    declare("l", server, "client-requested", 'client_encoding = "LATIN1"')
    declare("lw", server, "writable", 'client_encoding = "LATIN1"')
    assert cli.main(["query", "l", "select 'it’s' as q"]) == 3
    refusal = json.loads(capsys.readouterr().out)
    assert refusal["rule"] == "encoding.unrepresentable" and "LATIN" in refusal["detail"].upper()
    script = tmp_path / "vendor.sql"
    script.write_bytes("-- it’s the vendor's\nselect 'it’s' as q;\n".encode("cp1252"))
    assert cli.main(["run-script", "lw", str(script), "--encoding", "cp1252"]) == 3
    out = capsys.readouterr().out
    assert json.loads(out)["rule"] == "encoding.unrepresentable" and "’" not in out
