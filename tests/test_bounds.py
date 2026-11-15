"""SP-T6: load bound and correctness preconditions."""

from __future__ import annotations

import dataclasses
import os
import subprocess
import sys
import time
import uuid

import psycopg
import pytest

from cerberus.read import run_query
from cerberus.refusal import Refusal
from conftest import READER_PASSWORD, Cluster

HEAVY = "SELECT count(*) FROM app.big a, app.big b /* {marker} */"


def reader(server):
    return dataclasses.replace(server, user="reader", password=READER_PASSWORD)


def backends_running(cluster: Cluster, marker: str) -> list[tuple]:
    with psycopg.connect(cluster.primary.conninfo(), autocommit=True) as db:
        return db.execute(
            "SELECT pid, backend_type, state FROM pg_stat_activity "
            "WHERE query LIKE %s AND pid <> pg_backend_pid() AND query NOT LIKE '%%pg_stat_activity%%'",
            (f"%{marker}%",),
        ).fetchall()


def test_the_heavy_query_is_planned_with_parallel_workers(preconditions: Cluster) -> None:
    with psycopg.connect(reader(preconditions.primary).conninfo()) as db:
        plan = "\n".join(r[0] for r in db.execute("EXPLAIN " + HEAVY.format(marker="x")).fetchall())
    assert "Workers Planned" in plan


def test_a_query_past_its_bound_is_cancelled_with_its_parallel_workers(
    preconditions: Cluster, declare
) -> None:
    bound_ms = 1000
    conn = declare("p", reader(preconditions.primary), "client-requested", f"timeout_ms = {bound_ms}")
    marker = f"bound_{uuid.uuid4().hex}"
    start = time.monotonic()
    with pytest.raises(Refusal) as refused:
        run_query(conn, HEAVY.format(marker=marker))
    assert refused.value.rule == "limit.timeout"
    deadline = start + bound_ms / 1000 + 5
    while backends_running(preconditions, marker) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert backends_running(preconditions, marker) == []


def test_the_bound_is_set_on_the_server(preconditions: Cluster, declare) -> None:
    conn = declare("p", reader(preconditions.primary), "client-requested", "timeout_ms = 1500")
    result = run_query(conn, "SELECT current_setting('statement_timeout'), current_setting('lock_timeout')")
    assert result["rows"] == [["1500ms", "1500ms"]]


@pytest.mark.parametrize(
    "sql, rule",
    [
        ("SET statement_timeout = 0", "statement.not-select"),
        ("SET LOCAL statement_timeout = 0", "statement.not-select"),
        ("SELECT set_config('statement_timeout', '0', true)", "function.denied"),
        ("SELECT set_config('statement' || '_timeout', '0', true)", "function.denied"),
        ("SELECT set_config('lock_timeout', '0', true)", "function.denied"),
    ],
)
def test_query_text_cannot_change_the_bound(preconditions: Cluster, declare, sql: str, rule: str) -> None:
    conn = declare("p", reader(preconditions.primary), "client-requested")
    with pytest.raises(Refusal) as refused:
        run_query(conn, sql)
    assert refused.value.rule == rule


def test_killing_cerberus_mid_query_leaves_no_backend_past_the_bound(
    preconditions: Cluster, declare
) -> None:
    bound_ms = 3000
    declare("p", reader(preconditions.primary), "client-requested", f"timeout_ms = {bound_ms}")
    marker = f"kill_{uuid.uuid4().hex}"
    script = (
        "import sys\nfrom cerberus import config\nfrom cerberus.read import run_query\n"
        "run_query(config.load('p'), sys.argv[1])\n"
    )
    proc = subprocess.Popen([sys.executable, "-c", script, HEAVY.format(marker=marker)],
                            env=dict(os.environ), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        seen_at = None
        wait_until = time.monotonic() + 15
        while time.monotonic() < wait_until:
            if backends_running(preconditions, marker):
                seen_at = time.monotonic()
                break
            time.sleep(0.05)
        assert seen_at is not None, "the query never reached the server"
        proc.kill()
        proc.wait(timeout=5)
        deadline = seen_at + bound_ms / 1000 + 5
        while backends_running(preconditions, marker) and time.monotonic() < deadline:
            time.sleep(0.1)
        assert backends_running(preconditions, marker) == []
    finally:
        if proc.poll() is None:
            proc.kill()


@pytest.mark.parametrize("declared", ["LATIN1", "UTF8"])
def test_the_declared_client_encoding_applies_with_nothing_set_by_the_caller(
    preconditions: Cluster, declare, monkeypatch: pytest.MonkeyPatch, declared: str
) -> None:
    server = dataclasses.replace(preconditions.primary, dbname="latin1db")
    conn = declare("l", server, "client-requested", f'client_encoding = "{declared}"')
    monkeypatch.setenv("PGCLIENTENCODING", "SQL_ASCII")  # a caller setting that must not apply
    result = run_query(
        conn,
        "SELECT current_setting('client_encoding'), "
        "(SELECT count(*) FROM words WHERE w = 'ação'), (SELECT length(w) FROM words WHERE w LIKE 'a_ão')",
    )
    assert result["rows"] == [[declared, 1, 4]]


def test_an_unqualified_name_reports_the_schema_it_resolved_to(preconditions: Cluster, declare) -> None:
    a = declare("a", dataclasses.replace(preconditions.primary, dbname="db_a"), "client-requested",
                'search_path = ["sa"]')
    b = declare("b", dataclasses.replace(preconditions.primary, dbname="db_b"), "client-requested",
                'search_path = ["sb"]')
    for conn, expected in ((a, "sa"), (b, "sb")):
        result = run_query(conn, "SELECT x FROM t")
        assert result["rows"] == [[1]]
        assert result["resolved"] == [{"named": "t", "schema": expected, "relation": "t", "kind": "table"}]
