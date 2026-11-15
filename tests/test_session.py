"""SP-T3: guarded session and write guarantee; the CB01 sensor."""

from __future__ import annotations

import ast
import uuid
from pathlib import Path

import psycopg
import pytest

from cerberus import config
from cerberus.refusal import Refusal
from cerberus.session import ReadSession
from conftest import Cluster, Server, server_log

SRC = Path(__file__).resolve().parents[1] / "src" / "cerberus"
GUARDED_MODULE = "session.py"


def test_read_session_runs_in_a_read_only_transaction(declare, cluster: Cluster) -> None:
    conn = declare("p", cluster.primary, "client-requested")
    with ReadSession(conn) as s:
        assert s.execute("SELECT current_setting('transaction_read_only')").fetchone()[0] == "on"
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            s.execute("CREATE TABLE should_not_exist (x int)")


def test_standby_gives_server_enforced(declare, cluster: Cluster) -> None:
    conn = declare("s", cluster.standby, "server-enforced")
    with ReadSession(conn) as s:
        assert s.guarantee == {"class": "server-enforced", "basis": "pg_is_in_recovery"}


def test_primary_gives_client_requested(declare, cluster: Cluster) -> None:
    conn = declare("p", cluster.primary, "client-requested")
    with ReadSession(conn) as s:
        assert s.guarantee == {"class": "client-requested", "basis": "transaction_read_only"}


def test_a_stronger_guarantee_than_declared_is_reported(declare, cluster: Cluster) -> None:
    conn = declare("s", cluster.standby, "client-requested")
    with ReadSession(conn) as s:
        assert s.guarantee["class"] == "server-enforced"


def test_refusals_after_the_guarantee_carry_it(declare, cluster: Cluster) -> None:
    conn = declare("s", cluster.standby, "server-enforced")
    with ReadSession(conn) as s:
        refusal = s.refuse("example.rule", "detail")
    assert refusal.as_dict()["guarantee"] == {"class": "server-enforced", "basis": "pg_is_in_recovery"}


def test_a_refusal_before_the_guarantee_says_none_was_established(declare, cluster: Cluster) -> None:
    conn = declare("p", cluster.primary, "client-requested")
    broken = config.Connection(**{**conn.__dict__, "port": 1})
    with pytest.raises(Refusal) as refused:
        with ReadSession(broken):
            pass
    assert refused.value.rule == "connection.failed"
    assert refused.value.as_dict()["guarantee"] is None


def test_declared_server_enforced_on_a_primary_is_refused_before_the_query(
    declare, cluster: Cluster
) -> None:
    conn = declare("p", cluster.primary, "server-enforced")
    marker = f"cerberus_marker_{uuid.uuid4().hex}"
    with pytest.raises(Refusal) as refused:
        with ReadSession(conn) as s:
            s.execute(f"SELECT '{marker}'")
    assert refused.value.rule == "guarantee.weaker-than-declared"
    assert refused.value.guarantee == {"class": "client-requested", "basis": "transaction_read_only"}
    log = server_log(cluster.primary)
    assert "pg_is_in_recovery" in log  # positive control: the guarantee probes are logged
    assert marker not in log


def test_libpq_environment_does_not_redirect_or_reconfigure_the_session(
    declare, cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    conn = declare("p", cluster.primary, "client-requested")
    monkeypatch.setenv("PGHOSTADDR", "192.0.2.1")  # TEST-NET-1: unreachable if used
    monkeypatch.setenv("PGOPTIONS", "-c search_path=planted_by_env")
    monkeypatch.setenv("PGSERVICE", "planted_service")
    with ReadSession(conn) as s:
        assert "planted_by_env" not in s.execute("SHOW search_path").fetchone()[0]


# --- CB01: no driver connect outside the guarded-session module -----------------------------------


def connect_calls(source: str) -> list[int]:
    """Line numbers of calls to anything named ``connect``, and of any import of a ``connect`` from
    the driver (which an alias would hide). Conservative and name-based."""
    lines = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "psycopg":
            if any(alias.name == "connect" for alias in node.names):
                lines.append(node.lineno)
        if isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name == "connect":
                lines.append(node.lineno)
    return lines


def test_cb01_sensor_detects_a_connect_call() -> None:
    assert connect_calls("import psycopg\npsycopg.connect('')\n") == [2]
    assert connect_calls("from psycopg import connect as c\nc('')\n") == [1]
    assert connect_calls("from psycopg import Connection\nConnection.connect('')\n") == [2]


def test_cb01_no_driver_connect_outside_the_guarded_session_module() -> None:
    offenders = {
        path.name: lines
        for path in SRC.rglob("*.py")
        if path.name != GUARDED_MODULE and (lines := connect_calls(path.read_text()))
    }
    assert offenders == {}, f"driver connect outside {GUARDED_MODULE}: {offenders}"
    assert connect_calls((SRC / GUARDED_MODULE).read_text()), "sensor sees the guarded module's connect"
