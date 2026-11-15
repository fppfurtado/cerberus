"""SP-T5: read-surface policy. One test per form; each asserts the planted marker is absent."""

from __future__ import annotations

import dataclasses
import json

import psycopg
import pytest

from cerberus.read import run_query
from cerberus.refusal import Refusal
from conftest import MARKER, READER_PASSWORD, Cluster

CLASSES = [("standby", "server-enforced"), ("primary", "client-requested")]

POLICY = """
[connection.{name}.policy]
deny_relations = ["app.hidden"]
allow_functions = ["app.vault_rows"]

[connection.{name}.policy.columns]
"app.vault" = ["id", "label"]
"app.pvault" = ["id", "label"]
"app.ivault" = ["id", "label"]
"app.grow" = ["id", "label"]
"""


def reader(server):
    return dataclasses.replace(server, user="reader", password=READER_PASSWORD)


@pytest.fixture(params=CLASSES, ids=[c for _, c in CLASSES])
def conn(request, schema: Cluster, declare):
    role, cls = request.param
    return declare(role, reader(getattr(schema, role)), cls, POLICY.format(name=role))


@pytest.fixture
def primary_conn(schema: Cluster, declare):
    return declare("primary", reader(schema.primary), "client-requested", POLICY.format(name="primary"))


def refusal_of(conn, sql: str) -> Refusal:
    with pytest.raises(Refusal) as info:
        result = run_query(conn, sql)
        pytest.fail(f"not refused; output carried the marker: {MARKER in json.dumps(result, default=str)}")
    r = info.value
    assert MARKER not in json.dumps(r.as_dict(), default=str)
    return r


FORMS = {
    "select-star": ("SELECT * FROM app.vault", "policy.star"),
    "explicit-column": ("SELECT secret FROM app.vault", "policy.column-not-listed"),
    "alias": ("SELECT secret AS x FROM app.vault", "policy.column-not-listed"),
    "expression": ("SELECT secret || '' FROM app.vault", "policy.column-not-listed"),
    "whole-row": ("SELECT t FROM app.vault t", "policy.whole-row"),
    "whole-row-row_to_json": ("SELECT row_to_json(t) FROM app.vault t", "policy.whole-row"),
    "whole-row-cast": ("SELECT t::text FROM app.vault t", "policy.whole-row"),
    "whole-row-by-table-name": ("SELECT row_to_json(vault) FROM app.vault", "policy.whole-row"),
    "whole-row-field-selection": ("SELECT (t).secret FROM app.vault t", "policy.whole-row"),
    "qualified-star": ("SELECT t.* FROM app.vault t", "policy.star"),
    "subquery": ("SELECT x FROM (SELECT secret AS x FROM app.vault) s", "policy.column-not-listed"),
    "cte": ("WITH c AS (SELECT secret AS x FROM app.vault) SELECT x FROM c", "policy.column-not-listed"),
    "view": ("SELECT secret FROM app.v_vault", "policy.reached-through-view"),
    "aggregate": ("SELECT max(secret) FROM app.vault", "policy.column-not-listed"),
    "union-branch": ("SELECT label FROM app.vault UNION SELECT secret FROM app.vault",
                     "policy.column-not-listed"),
    "using-join": ("SELECT id FROM app.vault JOIN app.vault v2 USING (id)", "policy.natural-or-using-join"),
    "natural-join": ("SELECT id FROM app.vault NATURAL JOIN app.other", "policy.natural-or-using-join"),
    "unqualified-search-path": ("SELECT secret FROM vault", "policy.column-not-listed"),
    "filter-only": ("SELECT id FROM app.vault WHERE secret LIKE 'P%'", "policy.column-not-listed"),
    "order-only": ("SELECT id FROM app.vault ORDER BY secret", "policy.column-not-listed"),
    "alias-column-list": ("SELECT c FROM app.vault AS t(a, b, c)", "policy.alias-column-list"),
    "view-renames-column": ("SELECT harmless FROM app.v_rename", "policy.reached-through-view"),
    "view-renames-column-joined-with-table": (
        "SELECT r.harmless FROM app.v_rename r JOIN app.vault v ON v.id = r.id",
        "policy.reached-through-view",
    ),
    "view-calls-function": ("SELECT x FROM app.v_fn", "policy.view-function-not-allowed"),
    "materialized-view": ("SELECT secret FROM app.mv_vault", "policy.reached-through-view"),
    "partition-by-own-name": ("SELECT secret FROM app.pvault_p1", "policy.column-not-listed"),
    "partition-star": ("SELECT * FROM app.pvault_p1", "policy.star"),
    "inheritance-child-by-own-name": ("SELECT secret FROM app.ivault_c", "policy.column-not-listed"),
    "sql-as-text-function": (
        "SELECT query_to_xml('SELECT secret FROM app.vault', true, false, '')", "function.denied",
    ),
    "inlined-function-seen-only-in-plan": ("SELECT id FROM app.vault_rows()", "policy.reached-indirectly"),
    "correlated-subquery": (
        "SELECT o.id FROM app.other o WHERE EXISTS "
        "(SELECT 1 FROM app.vault v WHERE v.secret = o.secret)",
        "policy.column-not-listed",
    ),
    "denied-relation": ("SELECT id FROM app.hidden", "policy.relation-denied"),
}


@pytest.mark.parametrize("form", list(FORMS))
def test_no_value_of_a_non_listed_column_in_any_form(conn, form: str) -> None:
    sql, rule = FORMS[form]
    r = refusal_of(conn, sql)
    assert r.rule == rule, f"{form}: {r.rule}: {r.detail}"
    assert r.guarantee is not None


def test_the_name_rule_refuses_a_same_named_column_of_another_table_and_says_so(conn) -> None:
    r = refusal_of(conn, "SELECT o.secret FROM app.other o JOIN app.vault v ON v.id = o.id")
    assert r.rule == "policy.column-not-listed"
    assert "same-named column of another table" in r.detail


# --- what passes ----------------------------------------------------------------------------------


def direct_rows(server, sql: str) -> list[list]:
    with psycopg.connect(server.conninfo()) as db:
        return [list(r) for r in db.execute(sql).fetchall()]


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT i FROM app.scratch ORDER BY i LIMIT 5",
        "SELECT id, secret FROM app.other",  # a same-named column on an unflagged table, alone
    ],
)
def test_a_query_touching_no_flagged_object_returns_what_a_direct_client_returns(
    conn, schema: Cluster, sql: str
) -> None:
    role = "standby" if conn.cls == "server-enforced" else "primary"
    result = run_query(conn, sql)
    assert result["rows"] == direct_rows(reader(getattr(schema, role)), sql)


@pytest.mark.parametrize(
    "sql, expected",
    [
        ("SELECT id, label FROM app.vault", [[1, "first"]]),
        ("SELECT count(*) FROM app.vault", [[1]]),
        ("SELECT id, label FROM app.pvault", [[1, "first"]]),
        ("SELECT id, label FROM vault", [[1, "first"]]),
        ("SELECT v.id FROM app.vault v JOIN app.other o ON o.id = v.id", [[1]]),
    ],
)
def test_listed_columns_of_a_flagged_table_are_returned(conn, sql: str, expected) -> None:
    result = run_query(conn, sql)
    assert result["rows"] == expected
    assert MARKER not in json.dumps(result, default=str)


def test_a_column_added_later_is_denied_until_listed(primary_conn, schema: Cluster) -> None:
    with psycopg.connect(schema.primary.conninfo(), autocommit=True) as db:
        db.execute("ALTER TABLE app.grow ADD COLUMN IF NOT EXISTS added text")
    assert refusal_of(primary_conn, "SELECT added FROM app.grow").rule == "policy.column-not-listed"
    assert run_query(primary_conn, "SELECT id, label FROM app.grow")["rows"] == []


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT * FROM pg_stats",
        "SELECT * FROM pg_catalog.pg_statistic",
        "SELECT * FROM pg_stats_ext",
        "SELECT * FROM pg_authid",
        "SELECT * FROM pg_shadow",
    ],
)
def test_statistics_and_credential_catalogs_are_refused(conn, sql: str) -> None:
    assert refusal_of(conn, sql).rule == "policy.relation-denied"


def test_the_result_names_the_resolved_relations(conn) -> None:
    result = run_query(conn, "SELECT id FROM vault")
    assert result["resolved"] == [
        {"named": "vault", "schema": "app", "relation": "vault", "kind": "table"}
    ]
