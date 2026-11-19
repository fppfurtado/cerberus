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


def test_a_server_error_in_a_script_shows_the_condition_not_the_message(writable) -> None:
    # Reading a restricted column to force an error is refused by the policy first (Spec v1.1) ...
    assert refused(run_script, writable, "UPDATE app.vault SET id = secret::int").rule == \
        "policy.column-not-listed"
    # ... and an error that does reach the server shows its condition, not its message or detail.
    r = refused(run_script, writable, "INSERT INTO app.vault (id, label, secret) VALUES (1, 'x', 'y')")
    assert r.rule == "server.error"
    assert "23505" in r.detail and "UniqueViolation" in r.detail
    assert "already exists" not in r.detail and "duplicate key" not in r.detail


def test_show_and_explain_rows_still_return_in_a_script(writable) -> None:
    result = run_script(writable, "SHOW client_encoding;\nEXPLAIN SELECT id FROM app.vault;")
    assert result["statements"][0]["rows"] == [["UTF8"]]
    assert result["statements"][1]["rows"]


def test_rows_from_a_statement_the_policy_did_not_check_stop_the_script(schema: Cluster, declare) -> None:
    import psycopg

    with psycopg.connect(schema.primary.conninfo(), autocommit=True) as db:
        db.execute("CREATE OR REPLACE PROCEDURE app.out_proc(OUT x text) LANGUAGE plpgsql "
                   "AS $$ BEGIN x := 'from-a-procedure'; END $$")
    conn = declare("w", schema.primary, "writable",
                   '[connection.w.policy]\nallow_functions = ["app.out_proc"]\n')
    r = refused(run_script, conn, "CALL app.out_proc(NULL)")
    assert r.rule == "script.unchecked-rows"
    assert "from-a-procedure" not in r.detail


# --- Spec v1.1: no script expression may read a restricted column ------------------------------------

MOVES = {
    "create-table-as": "CREATE TABLE app.copy1 AS SELECT secret AS s FROM app.vault;\nSELECT s FROM app.copy1;",
    "insert-select": "INSERT INTO app.other SELECT id, secret FROM app.vault;\nSELECT secret FROM app.other;",
    "update-listed-from-hidden": "UPDATE app.vault SET label = secret;\nSELECT label FROM app.vault;",
    "update-from-join": "UPDATE app.other o SET secret = v.secret FROM app.vault v WHERE v.id = o.id;\n"
                        "SELECT secret FROM app.other;",
    "create-view": "CREATE VIEW app.vcopy AS SELECT secret AS s FROM app.vault;",
    "on-conflict-reads-stored": "INSERT INTO app.vault VALUES (1, 'x', 'y') ON CONFLICT (id) DO UPDATE "
                                "SET label = vault.secret;",
}


@pytest.mark.parametrize("form", list(MOVES))
def test_v11_a_script_statement_may_not_read_a_restricted_column(writable, form: str) -> None:
    assert refused(run_script, writable, MOVES[form]).rule.startswith("policy.")


def test_v11_writing_a_restricted_column_still_passes(writable) -> None:
    result = run_script(writable, "UPDATE app.vault SET secret = 'rewritten' WHERE id = 1;\n"
                                  "INSERT INTO app.vault (id, label, secret) VALUES (5, 'five', 'new');")
    assert [s["command"] for s in result["statements"]] == ["UPDATE 1", "INSERT 0 1"]


def test_v11_an_upsert_that_writes_its_own_value_passes(writable) -> None:
    result = run_script(writable, "INSERT INTO app.vault (id, label, secret) VALUES (1, 'x', 'mine') "
                                  "ON CONFLICT (id) DO UPDATE SET secret = EXCLUDED.secret, label = EXCLUDED.label;")
    assert result["statements"][0]["command"] == "INSERT 0 1"


# --- B9: a column rename on a flagged table; B10: code a script defines -----------------------------

RENAME_AND_CODE = {
    "rename-swap": ("ALTER TABLE app.vault RENAME COLUMN label TO label_old;\n"
                    "ALTER TABLE app.vault RENAME COLUMN secret TO label;\nSELECT label FROM app.vault;",
                    "policy.reshapes-flagged-relation"),
    "rename-restricted-column": ("ALTER TABLE vault RENAME COLUMN secret TO s2;", "policy.reshapes-flagged-relation"),
    "trigger-copy": ("CREATE FUNCTION app.t_copy() RETURNS trigger LANGUAGE plpgsql AS $f$ BEGIN "
                     "NEW.label := NEW.secret; RETURN NEW; END $f$;\n"
                     "CREATE TRIGGER t_copy BEFORE UPDATE ON app.vault FOR EACH ROW EXECUTE FUNCTION app.t_copy();\n"
                     "UPDATE app.vault SET id = id;\nSELECT label FROM app.vault;",
                     "script.statement-not-allowed"),
    "procedure": ("CREATE PROCEDURE app.p() LANGUAGE sql AS $$ UPDATE app.vault SET label = secret $$;",
                  "script.statement-not-allowed"),
    "rule": ("CREATE RULE r AS ON UPDATE TO app.other DO ALSO NOTIFY c;", "script.statement-not-allowed"),
}


@pytest.mark.parametrize("form", list(RENAME_AND_CODE))
def test_b9_b10_renames_on_flagged_tables_and_script_defined_code_are_refused(writable, form: str) -> None:
    script, rule = RENAME_AND_CODE[form]
    assert refused(run_script, writable, script).rule == rule


def test_b9_renaming_a_column_of_an_unflagged_table_passes(writable) -> None:
    result = run_script(writable, "ALTER TABLE app.other RENAME COLUMN secret TO note;")
    assert result["statements"][0]["command"] == "ALTER TABLE"


# --- B11: reshaping a flagged relation; B12: `excluded` as an alias inside a subquery ---------------

RESHAPE_POLICY = ('[connection.r.policy.columns]\n"app.vault" = ["id", "label"]\n'
                  '"app.pvault" = ["id", "label"]\n"app.ivault" = ["id", "label"]\n')


@pytest.fixture
def reshaper(schema: Cluster, declare):
    return declare("r", schema.primary, "writable", 'search_path = ["app"]\n' + RESHAPE_POLICY)


@pytest.mark.parametrize(
    "script",
    [
        "ALTER TABLE app.pvault DETACH PARTITION app.pvault_p1;\nSELECT secret FROM app.pvault_p1;",
        "ALTER TABLE app.ivault_c NO INHERIT app.ivault;\nSELECT secret FROM app.ivault_c;",
        "ALTER TABLE app.vault ALTER COLUMN secret TYPE text;",
        "ALTER TABLE app.vault DROP COLUMN label;",
        "ALTER TABLE app.vault SET SCHEMA public;",
        "ALTER TABLE app.vault RENAME TO vault2;",
    ],
    ids=["detach-partition", "no-inherit", "alter-column", "drop-column", "set-schema", "rename-table"],
)
def test_b11_a_script_may_not_reshape_a_flagged_relation(reshaper, script: str) -> None:
    assert refused(run_script, reshaper, script).rule == "policy.reshapes-flagged-relation"


def test_b11_reshaping_an_unflagged_relation_passes(reshaper) -> None:
    result = run_script(reshaper, "ALTER TABLE app.other ADD COLUMN note text;")
    assert result["statements"][0]["command"] == "ALTER TABLE"


@pytest.mark.parametrize(
    "script",
    [
        "INSERT INTO app.vault VALUES (1,'x','y') ON CONFLICT (id) DO UPDATE "
        "SET label = (SELECT excluded.secret FROM app.vault AS excluded LIMIT 1);\nSELECT label FROM app.vault;",
        "INSERT INTO app.vault VALUES (1,'x','y') ON CONFLICT (id) DO UPDATE SET label = 'z' "
        "WHERE EXISTS (SELECT 1 FROM app.vault AS excluded WHERE excluded.secret LIKE 'P%');",
    ],
    ids=["subquery-set", "subquery-where-oracle"],
)
def test_b12_excluded_as_an_alias_inside_a_subquery_is_a_stored_read(writable, script: str) -> None:
    assert refused(run_script, writable, script).rule == "policy.column-not-listed"


# --- Final-review gaps (#4): cases that already behave right, pinned as regressions ---------------

@pytest.mark.parametrize(
    "script",
    [
        "ALTER TABLE app.pvault_p1 RENAME COLUMN secret TO label2;",
        "ALTER TABLE app.ivault_c RENAME COLUMN secret TO label2;",
    ],
    ids=["partition-directly", "inheritance-child-directly"],
)
def test_reshaping_a_flagged_child_directly_is_refused(reshaper, script: str) -> None:
    assert refused(run_script, reshaper, script).rule == "policy.reshapes-flagged-relation"


def test_renaming_the_schema_of_a_flagged_table_is_caught_at_the_next_statement(reshaper) -> None:
    script = "ALTER SCHEMA app RENAME TO app2;\nSELECT secret FROM app2.vault;"
    refusal = refused(run_script, reshaper, script)
    assert refusal.rule == "policy.key-unresolved"
    assert "statement 2" in refusal.detail


def test_a_subquery_reading_the_outer_excluded_row_is_over_blocked(writable) -> None:
    # Deliberate (Spec v1.2; recorded in D12): the EXCLUDED exemption holds at the ON CONFLICT clause's own level only,
    # so a subquery that reads the outer proposed row is refused although it reads no stored value.
    script = ("INSERT INTO app.vault VALUES (1,'x','y') ON CONFLICT (id) DO UPDATE "
              "SET label = (SELECT excluded.secret);")
    assert refused(run_script, writable, script).rule == "policy.column-not-listed"
