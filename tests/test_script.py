"""SP-T8: `cerberus run-script` — rollback-only scripts on a writable connection."""

from __future__ import annotations

import hashlib
import json
import os
import pty
import select
import subprocess
import sys
import time
from pathlib import Path

import psycopg
import pytest

from cerberus.refusal import Refusal
from cerberus.script import run_script
from conftest import MARKER, Cluster

CERBERUS = str(Path(sys.executable).parent / "cerberus")

WRITABLE_POLICY = """
[connection.w.policy]
allow_functions = ["app.commit_inside"]

[connection.w.policy.columns]
"app.vault" = ["id", "label"]
"""


@pytest.fixture(scope="module")
def ledger(preconditions: Cluster) -> Cluster:
    with psycopg.connect(preconditions.primary.conninfo(), autocommit=True) as db:
        db.execute("CREATE TABLE IF NOT EXISTS app.ledger (id int PRIMARY KEY, amount int)")
        db.execute("TRUNCATE app.ledger")
        db.execute("INSERT INTO app.ledger VALUES (1, 10), (2, 20)")
        db.execute(
            "CREATE OR REPLACE PROCEDURE app.commit_inside() LANGUAGE plpgsql AS "
            "$$ BEGIN INSERT INTO app.ledger VALUES (99, 0); COMMIT; END $$"
        )
    return preconditions


def ledger_rows(cluster: Cluster) -> list[tuple]:
    with psycopg.connect(cluster.primary.conninfo()) as db:
        return db.execute("SELECT id, amount FROM app.ledger ORDER BY id").fetchall()


@pytest.fixture
def writable(ledger: Cluster, declare):
    return declare("w", ledger.primary, "writable", 'search_path = ["app"]\n' + WRITABLE_POLICY)


def test_an_update_with_its_verification_select_returns_outputs_and_commits_nothing(
    writable, ledger: Cluster
) -> None:
    before = ledger_rows(ledger)
    result = run_script(writable, "UPDATE ledger SET amount = amount + 1;\n"
                                  "SELECT id, amount FROM ledger ORDER BY id;")
    assert result["committed"] is False
    first, second = result["statements"]
    assert first["command"] == "UPDATE 2"
    assert second["rows"] == [[1, 11], [2, 21]]
    assert ledger_rows(ledger) == before


@pytest.mark.parametrize(
    "script",
    [
        "UPDATE app.vault SET label = 'x' RETURNING secret",
        "UPDATE ledger SET amount = 0; SELECT secret FROM app.vault",
        "DELETE FROM ledger WHERE id = 1 RETURNING (SELECT max(secret) FROM app.vault)",
    ],
)
def test_returned_rows_reaching_a_restricted_column_are_refused_and_rolled_back(
    writable, ledger: Cluster, script: str
) -> None:
    before = ledger_rows(ledger)
    with pytest.raises(Refusal) as refused:
        run_script(writable, script)
    assert refused.value.rule.startswith("policy.")
    assert MARKER not in json.dumps(refused.value.as_dict())
    assert ledger_rows(ledger) == before


def test_a_data_modifying_statement_without_returned_rows_may_touch_a_flagged_table(writable) -> None:
    result = run_script(writable, "UPDATE app.vault SET secret = 'rewritten' WHERE id = 1")
    assert result["statements"] == [{"statement": 1, "command": "UPDATE 1"}]


def test_bound_encoding_and_search_path_apply_to_every_statement(writable, ledger: Cluster, declare) -> None:
    result = run_script(writable, "SELECT current_setting('client_encoding'), "
                                  "current_setting('statement_timeout');\nSELECT count(*) FROM ledger;")
    assert result["statements"][0]["rows"] == [["UTF8", "30s"]]
    assert result["statements"][1]["rows"] == [[2]]

    bounded = declare("wb", ledger.primary, "writable", "timeout_ms = 500")
    before = ledger_rows(ledger)
    with pytest.raises(Refusal) as refused:
        run_script(bounded, "UPDATE app.ledger SET amount = 0;\n"
                            "SELECT count(*) FROM app.big a, app.big b;")
    assert refused.value.rule == "limit.timeout"
    assert ledger_rows(ledger) == before


@pytest.mark.parametrize(
    "script, rule",
    [
        ("BEGIN; UPDATE app.ledger SET amount = 0; COMMIT;", "script.transaction-control"),
        ("UPDATE app.ledger SET amount = 0; COMMIT; UPDATE app.ledger SET amount = 1;",
         "script.transaction-control"),
        ("END", "script.transaction-control"),
        ("PREPARE TRANSACTION 'x'", "script.transaction-control"),
        ("VACUUM app.ledger", "script.not-undone"),
        ("CREATE DATABASE nope", "script.not-undone"),
        ("CREATE INDEX CONCURRENTLY ix ON app.ledger (amount)", "script.not-undone"),
        ("ALTER SYSTEM SET work_mem = '1MB'", "script.not-undone"),
        ("COPY app.ledger TO PROGRAM 'true'", "script.not-undone"),
        ("SELECT pg_sleep(1)", "function.denied"),
        ("SELECT set_config('statement_timeout', '0', true)", "function.denied"),
        ("UPDATE app.ledger SET amount = 0;\n\\gexec", "script.meta-command"),
    ],
)
def test_a_forbidden_statement_is_refused_before_connecting(
    ledger: Cluster, declare, script: str, rule: str
) -> None:
    unreachable = declare("w", ledger.primary, "writable")
    unreachable = type(unreachable)(**{**unreachable.__dict__, "port": 1})  # connecting would fail
    with pytest.raises(Refusal) as refused:
        run_script(unreachable, script)
    assert refused.value.rule == rule
    assert "statement" in refused.value.detail or "line" in refused.value.detail


def test_a_procedure_that_commits_inside_returns_the_server_error_and_commits_nothing(
    writable, ledger: Cluster
) -> None:
    before = ledger_rows(ledger)
    with pytest.raises(Refusal) as refused:
        run_script(writable, "CALL app.commit_inside()")
    assert refused.value.rule == "server.error"
    assert "2D000" in refused.value.detail  # invalid_transaction_termination
    assert ledger_rows(ledger) == before


def test_run_script_refuses_a_connection_that_is_not_writable(ledger: Cluster, declare) -> None:
    conn = declare("r", ledger.primary, "client-requested")
    with pytest.raises(Refusal) as refused:
        run_script(conn, "SELECT 1")
    assert refused.value.rule == "connection.not-writable"


# --- --commit ---------------------------------------------------------------------------------------


def script_file(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "change.sql"
    path.write_text(text)
    return path


def test_commit_without_a_terminal_is_refused(writable, ledger: Cluster, tmp_path: Path) -> None:
    before = ledger_rows(ledger)
    path = script_file(tmp_path, "UPDATE app.ledger SET amount = 0;")
    proc = subprocess.run([CERBERUS, "run-script", "w", str(path), "--commit"], env=dict(os.environ),
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 3
    assert json.loads(proc.stdout)["rule"] == "commit.no-terminal"
    assert ledger_rows(ledger) == before


def run_on_terminal(args: list[str], typed: str) -> tuple[int, str]:
    master, slave = pty.openpty()
    proc = subprocess.Popen(args, stdin=slave, stdout=subprocess.PIPE, stderr=slave,
                            env=dict(os.environ), text=True)
    os.close(slave)
    deadline = time.monotonic() + 30
    prompt = b""
    while b"COMMIT" not in prompt and time.monotonic() < deadline:
        ready, _, _ = select.select([master], [], [], 0.5)
        if ready:
            try:
                prompt += os.read(master, 1024)
            except OSError:  # the child closed the terminal (EIO)
                break
    os.write(master, typed.encode() + b"\n")
    out, _ = proc.communicate(timeout=60)
    os.close(master)
    return proc.returncode, out


def test_commit_confirmed_on_a_terminal_commits_and_records_the_authorization(
    writable, ledger: Cluster, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    path = script_file(tmp_path, "UPDATE app.ledger SET amount = 777 WHERE id = 2;")

    code, out = run_on_terminal([CERBERUS, "run-script", "w", str(path), "--commit"], typed="wrong")
    assert code == 3 and json.loads(out)["rule"] == "commit.not-confirmed"
    assert (2, 777) not in ledger_rows(ledger)

    code, out = run_on_terminal([CERBERUS, "run-script", "w", str(path), "--commit"], typed="w")
    assert code == 0, out
    assert json.loads(out)["committed"] is True
    assert (2, 777) in ledger_rows(ledger)
    [record] = [json.loads(line) for line in (state / "cerberus" / "commits.jsonl").read_text().splitlines()]
    assert record["connection"] == "w" and record["statements"] == 1
    assert len(record["script_sha256"]) == 64 and "time" in record
    assert record["script_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()  # `sha256sum <file>`
    assert record["encoding"] == "utf-8"


def test_the_commit_record_hashes_the_file_bytes_and_names_its_encoding(
    writable, ledger: Cluster, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    path = tmp_path / "vendor.sql"
    path.write_bytes("-- Município\nUPDATE app.ledger SET amount = 778 WHERE id = 2;\n".encode("cp1252"))
    code, out = run_on_terminal([CERBERUS, "run-script", "w", str(path), "--commit", "--encoding", "cp1252"],
                                typed="w")
    assert code == 0, out
    [record] = [json.loads(line) for line in (state / "cerberus" / "commits.jsonl").read_text().splitlines()]
    assert record["script_sha256"] == hashlib.sha256(path.read_bytes()).hexdigest()
    assert record["encoding"] == "cp1252"
