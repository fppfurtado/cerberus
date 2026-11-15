"""Regression tests for the breaks the review of the first build confirmed (B1–B8).

Each form here returned a restricted value, or defeated a guard rule, before its fix.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from cerberus.read import run_query
from cerberus.refusal import Refusal
from conftest import MARKER, READER_PASSWORD, Cluster

POLICY = """
[connection.{name}.policy]
deny_relations = ["app.hidden"]
allow_functions = ["app.vault_rows"]

[connection.{name}.policy.columns]
"app.vault" = ["id", "label"]
"app.pvault" = ["id", "label"]
"app.ivault" = ["id", "label"]
"""


def reader(server):
    return dataclasses.replace(server, user="reader", password=READER_PASSWORD)


@pytest.fixture
def standby(schema: Cluster, declare):
    return declare("standby", reader(schema.standby), "server-enforced", POLICY.format(name="standby"))


def refused(fn, *args, **kwargs) -> Refusal:
    with pytest.raises(Refusal) as info:
        out = fn(*args, **kwargs)
        pytest.fail(f"not refused; marker in output: {MARKER in json.dumps(out, default=str)}")
    assert MARKER not in json.dumps(info.value.as_dict(), default=str)
    return info.value


# --- B1: a CTE name elsewhere in the query no longer hides a view of that name ---------------------

CTE_SHADOW = {
    "matview": "SELECT secret FROM mv_vault WHERE EXISTS (WITH mv_vault AS (SELECT 1) SELECT 1 FROM mv_vault)",
    "view-calls-function": "SELECT x FROM v_fn WHERE EXISTS (WITH v_fn AS (SELECT 1) SELECT 1 FROM v_fn)",
    "view": "SELECT secret FROM v_vault WHERE EXISTS (WITH v_vault AS (SELECT 1) SELECT 1 FROM v_vault)",
    "table": "SELECT secret FROM vault WHERE EXISTS (WITH vault AS (SELECT 1) SELECT 1 FROM vault)",
}


@pytest.mark.parametrize("form", list(CTE_SHADOW))
def test_b1_a_cte_name_does_not_hide_a_relation_of_that_name(standby, form: str) -> None:
    assert refused(run_query, standby, CTE_SHADOW[form]).rule.startswith("policy.")


def test_b1_a_cte_with_its_own_name_still_reads(standby) -> None:
    result = run_query(standby, "WITH c AS (SELECT id FROM app.vault) SELECT id FROM c")
    assert result["rows"] == [[1]]


# --- B2: a JOIN's alias over a restricted table ------------------------------------------------------

JOIN_ALIAS = {
    "whole-row": ("SELECT j FROM (app.vault v JOIN app.scratch s ON s.i = v.id) AS j", "policy.whole-row"),
    "row_to_json": ("SELECT row_to_json(j) FROM (app.vault v JOIN app.scratch s ON s.i = v.id) AS j",
                    "policy.whole-row"),
    "column-list": ("SELECT j.c FROM (app.vault CROSS JOIN app.scratch) AS j(a, b, c, d) LIMIT 1",
                    "policy.alias-column-list"),
    "nested": ("SELECT k FROM ((app.vault v JOIN app.scratch s ON s.i = v.id) JOIN app.other o "
               "ON o.id = v.id) AS k", "policy.whole-row"),
}


@pytest.mark.parametrize("form", list(JOIN_ALIAS))
def test_b2_a_join_alias_over_a_restricted_table_is_refused(standby, form: str) -> None:
    sql, rule = JOIN_ALIAS[form]
    assert refused(run_query, standby, sql).rule == rule


def test_b2_listed_columns_through_a_join_alias_still_read(standby) -> None:
    result = run_query(standby, "SELECT j.id FROM (app.vault v JOIN app.scratch s ON s.i = v.id) AS j")
    assert result["rows"] == [[1]]


# --- B3: a policy key that names nothing refuses the connection --------------------------------------


@pytest.mark.parametrize(
    "policy",
    [
        '[connection.standby.policy.columns]\n"app.Vault" = ["id", "label"]\n',
        '[connection.standby.policy.columns]\n"app.vualt" = ["id", "label"]\n',
        '[connection.standby.policy]\ndeny_relations = ["app.Hidden"]\n',
    ],
    ids=["columns-case-mismatch", "columns-typo", "deny-case-mismatch"],
)
def test_b3_an_unresolved_policy_key_refuses_every_query(schema: Cluster, declare, policy: str) -> None:
    conn = declare("standby", reader(schema.standby), "server-enforced", policy)
    for sql in ("SELECT secret FROM app.vault", "SELECT id FROM app.hidden", "SELECT 1"):
        assert refused(run_query, conn, sql).rule == "policy.key-unresolved"


# --- B8: a user-defined operator wherever the query names one ---------------------------------------


@pytest.mark.parametrize(
    "sql",
    [
        "SELECT id FROM app.vault WHERE id OPERATOR(app.===) ANY (SELECT 1)",
        "SELECT id FROM app.vault WHERE id OPERATOR(app.===) ALL (SELECT 1)",
        "SELECT id FROM app.vault ORDER BY id USING OPERATOR(app.===)",
    ],
    ids=["any-subquery", "all-subquery", "order-by-using"],
)
def test_b8_a_user_defined_operator_is_refused_in_sublinks_and_order_by(standby, sql: str) -> None:
    assert refused(run_query, standby, sql).rule == "operator.not-allowed"


def test_b8_built_in_operators_in_sublinks_and_order_by_still_pass(standby) -> None:
    result = run_query(standby, "SELECT id FROM app.vault WHERE id = ANY (SELECT 1) ORDER BY id USING <")
    assert result["rows"] == [[1]]


# --- B4–B7 and server-error text in run-script ------------------------------------------------------

from cerberus.script import run_script  # noqa: E402

WPOLICY = '[connection.w.policy.columns]\n"app.vault" = ["id", "label"]\n'


@pytest.fixture
def writable(schema: Cluster, declare):
    return declare("w", schema.primary, "writable",
                   'timeout_ms = 1500\nsearch_path = ["app"]\n' + WPOLICY)


@pytest.mark.parametrize(
    "script",
    [
        "PREPARE p AS SELECT secret FROM app.vault;\nEXECUTE p;",  # B4
        "DECLARE c CURSOR FOR SELECT secret FROM app.vault;\nFETCH ALL FROM c;",  # B4
        "COPY app.vault TO STDOUT",  # B4 neighbour: COPY … TO returns rows
        "DO $$BEGIN RAISE EXCEPTION '%', (SELECT secret FROM app.vault LIMIT 1); END$$;",  # B5
        "DO $$BEGIN PERFORM set_config('statement_timeout','0',true); END$$;",  # B5
        "SET statement_timeout = 0;\nSELECT current_setting('statement_timeout');",  # B6
        "SET LOCAL search_path = public;\nSELECT current_setting('search_path');",  # B6
        "RESET ALL;",  # B6 neighbour
        "SET ROLE reader;",  # B6 neighbour
    ],
    ids=["prepare-execute", "declare-fetch", "copy-to-stdout", "do-raise", "do-set-config",
         "set-timeout", "set-local-search-path", "reset-all", "set-role"],
)
def test_b4_b5_b6_statements_that_escape_the_checks_are_refused_before_connecting(
    writable, script: str
) -> None:
    unreachable = type(writable)(**{**writable.__dict__, "port": 1})
    assert refused(run_script, unreachable, script).rule == "script.statement-not-allowed"


def test_b7_a_script_with_non_ascii_text_runs_the_statements_that_were_checked(writable) -> None:
    result = run_script(writable, "SELECT 'ação' AS a;\nSELECT label FROM vault;")
    assert result["statements"][0]["rows"] == [["ação"]]
    assert result["statements"][1]["rows"] == [["first"]]


def test_a_server_error_in_a_script_does_not_quote_a_restricted_value(writable) -> None:
    r = refused(run_script, writable, "UPDATE app.vault SET id = secret::int")
    assert r.rule == "server.error"
    assert "22P02" in r.detail and "InvalidTextRepresentation" in r.detail


def test_show_and_explain_rows_still_return_in_a_script(writable) -> None:
    result = run_script(writable, "SHOW client_encoding;\nEXPLAIN SELECT id FROM app.vault;")
    assert result["statements"][0]["rows"] == [["UTF8"]]
    assert result["statements"][1]["rows"]
