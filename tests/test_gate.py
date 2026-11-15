"""SP-T4: statement gate and function/operator allowlist.

The hostile-input cases marked "pgguard-mcp" are ported from pgguard-mcp 0.1.0
(tests/policy.attacks.test.ts; MIT, Copyright (c) 2026 Gilang Pratama), adapted to this schema.
"""

from __future__ import annotations

import time

import psycopg
import pytest

from cerberus.read import run_query
from cerberus.refusal import Refusal
from conftest import MARKER, Cluster

CLASSES = [("standby", "server-enforced"), ("primary", "client-requested")]


@pytest.fixture(params=CLASSES, ids=[c for _, c in CLASSES])
def read_conn(request, schema: Cluster, declare):
    role, cls = request.param
    server = getattr(schema, role)
    return declare(role, server, cls)


def refused(conn, sql: str) -> Refusal:
    with pytest.raises(Refusal) as info:
        run_query(conn, sql)
    return info.value


def assert_refused(conn, sql: str, *rules: str) -> Refusal:
    r = refused(conn, sql)
    assert r.rule in rules, f"{sql!r}: got {r.rule}: {r.detail}"
    assert r.guarantee is not None and r.guarantee["class"] == conn.cls
    assert MARKER not in r.detail
    return r


# --- statement kinds --------------------------------------------------------------------------------

NOT_SELECT = [  # pgguard-mcp "DML and DDL", "procedural statements", COPY ... TO PROGRAM
    "INSERT INTO app.scratch VALUES (1)",
    "UPDATE app.scratch SET i = 0",
    "DELETE FROM app.scratch",
    "TRUNCATE app.scratch",
    "DROP TABLE app.scratch",
    "ALTER TABLE app.scratch ADD COLUMN backdoor text",
    "CREATE TABLE pwned (id int)",
    "GRANT SELECT ON app.vault TO public",
    "COPY (SELECT * FROM app.scratch) TO PROGRAM 'true'",
    "DO $$ BEGIN RAISE NOTICE 'x'; END $$",
    "CALL some_proc()",
    "REFRESH MATERIALIZED VIEW mv",
    "SET default_transaction_read_only = off",
    "SET statement_timeout = 0",
    "EXPLAIN ANALYZE SELECT 1",
    "VACUUM app.scratch",
]


@pytest.mark.parametrize("sql", NOT_SELECT)
def test_statements_other_than_select_are_refused(read_conn, sql: str) -> None:
    assert_refused(read_conn, sql, "statement.not-select")


@pytest.mark.parametrize(
    "sql, rule",
    [  # pgguard-mcp "smuggling through SELECT shape"
        ("SELECT * INTO new_table FROM app.scratch", "statement.select-into"),
        ("WITH x AS (INSERT INTO app.scratch VALUES (9) RETURNING *) SELECT * FROM x",
         "statement.data-modifying-cte"),
        ("WITH x AS (DELETE FROM app.scratch RETURNING *) SELECT 1", "statement.data-modifying-cte"),
        ("SELECT 1; DROP TABLE app.scratch", "statement.multiple"),
        ("SELECT 1; --\nDROP TABLE app.scratch", "statement.multiple"),
        ("SELECT * FROM app.scratch FOR UPDATE", "statement.locking-clause"),
        ("SELECT * FROM app.scratch FOR SHARE", "statement.locking-clause"),
        ("SELECT * FROM (SELECT * FROM app.scratch FOR UPDATE) s", "statement.locking-clause"),
        ("SELECT i FROM app.scratch UNION SELECT i FROM app.scratch FOR KEY SHARE",
         "statement.locking-clause"),
    ],
)
def test_select_shapes_that_write_or_lock_are_refused(read_conn, sql: str, rule: str) -> None:
    assert_refused(read_conn, sql, rule)


def test_a_second_statement_hidden_by_a_comment_is_refused(read_conn) -> None:
    assert_refused(read_conn, "SELECT 1 --\nDROP TABLE app.scratch", "statement.multiple",
                   "statement.parse-error")


# --- W1, W2, W5: refused through cerberus, succeed through a direct client -------------------------

W1 = "CREATE TEMP TABLE probe_w1 (i int)"
W2 = "SELECT 1; COMMIT; CREATE TEMP TABLE probe_w2 (i int)"
W5 = "ANALYZE app.scratch"


def last_analyze(cluster: Cluster):
    with psycopg.connect(cluster.primary.conninfo(), autocommit=True) as conn:
        conn.execute("SELECT pg_stat_clear_snapshot()")
        return conn.execute(
            "SELECT last_analyze FROM pg_stat_user_tables WHERE relid = 'app.scratch'::regclass"
        ).fetchone()[0]


@pytest.mark.parametrize("sql", [W1, W2, W5], ids=["W1", "W2", "W5"])
def test_w1_w2_w5_are_refused_on_every_read_class(read_conn, schema: Cluster, sql: str) -> None:
    before = last_analyze(schema)
    assert_refused(read_conn, sql, "statement.not-select", "statement.multiple")
    assert last_analyze(schema) == before


@pytest.mark.parametrize("sql", [W1, W2, W5], ids=["W1", "W2", "W5"])
def test_w1_w2_w5_succeed_through_a_direct_client_on_the_primary(schema: Cluster, sql: str) -> None:
    before = last_analyze(schema)
    with psycopg.connect(schema.primary.conninfo(), autocommit=True) as conn:
        conn.execute(sql)
    if sql == W5:
        deadline = time.monotonic() + 10
        while last_analyze(schema) == before and time.monotonic() < deadline:
            time.sleep(0.2)
        assert last_analyze(schema) != before


# --- functions and operators ------------------------------------------------------------------------

DENIED = [  # pgguard-mcp "system catalogs and functions", plus the Spec's named cases
    "SELECT pg_read_file('/etc/passwd')",
    "SELECT * FROM pg_read_file('/etc/passwd')",
    "SELECT * FROM dblink('host=x dbname=y', 'SELECT 1') AS t(a int)",
    "SELECT pg_sleep(60)",
    "SELECT set_config('log_statement', 'all', false)",
    "SELECT set_config('statement' || '_timeout', '0', false)",
    "SELECT pg_catalog.set_config('statement_timeout', '0', false)",
    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity",
    "SELECT lo_import('/etc/passwd')",
    "SELECT nextval('s')",
    "SELECT setval('s', 1)",
    "SELECT currval('s')",
    f"SELECT query_to_xml('SELECT secret FROM app.vault', true, false, '')",
    "SELECT table_to_xml('app.vault', true, false, '')",
    "SELECT schema_to_xml('app', true, true, '')",
    "SELECT database_to_xml(true, true, '')",
    "SELECT * FROM ts_stat('SELECT to_tsvector(secret) FROM app.vault')",
    "SELECT ts_rewrite('a'::tsquery, 'SELECT ''a''::tsquery, ''b''::tsquery')",
    "SELECT pg_advisory_lock(1)",
    "SELECT pg_reload_conf()",
    "SELECT dblink_exec('x', 'DROP TABLE app.scratch')",
]


@pytest.mark.parametrize("sql", DENIED)
def test_denylisted_functions_are_refused(read_conn, sql: str) -> None:
    assert_refused(read_conn, sql, "function.denied")


def test_a_database_defined_function_is_refused_unless_allowed(schema: Cluster, declare) -> None:
    conn = declare("p", schema.primary, "client-requested")
    r = refused(conn, "SELECT app.dump_secret()")
    assert r.rule == "function.not-allowed"
    assert MARKER not in r.detail


def test_a_database_defined_function_listed_in_allow_functions_passes(schema: Cluster, declare) -> None:
    conn = declare(
        "p", schema.primary, "client-requested",
        '[connection.p.policy]\nallow_functions = ["app.dump_secret"]\n',
    )
    result = run_query(conn, "SELECT app.dump_secret()")
    assert result["rows"] == [[MARKER]]


@pytest.mark.parametrize("sql", ["SELECT 1 OPERATOR(app.===) 1", "SELECT 1 === 1"])
def test_a_user_defined_operator_is_refused(read_conn, sql: str) -> None:
    assert_refused(read_conn, sql, "operator.not-allowed")


def test_a_function_unknown_to_the_catalog_is_refused(read_conn) -> None:
    assert_refused(read_conn, "SELECT no_such_function(1)", "function.unknown")


# --- the gate is not a reject-everything filter -----------------------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT 1",
        "SELECT count(*) FROM app.scratch",
        "SELECT lower('A'), now() IS NOT NULL, coalesce(NULL, 1)",
        "SELECT i FROM app.scratch WHERE i BETWEEN 1 AND 3 AND i IN (1, 2) ORDER BY i",
        "WITH c AS (SELECT i FROM app.scratch) SELECT max(i) FROM c",
        "SELECT i FROM app.scratch WHERE i::text LIKE '1%' LIMIT 1",
        "WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 3) SELECT n FROM r",
    ],
)
def test_plain_reads_pass(read_conn, sql: str) -> None:
    result = run_query(read_conn, sql)
    assert result["guarantee"]["class"] == read_conn.cls
    assert result["row_count"] >= 1
