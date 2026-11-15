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
