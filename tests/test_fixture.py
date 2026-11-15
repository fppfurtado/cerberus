"""SP-T1: the suite runs against its own synthetic primary and standby, and nothing else."""

from __future__ import annotations

import os
import time

import psycopg

from conftest import _LIBPQ_ENV, Cluster


def test_no_libpq_environment_reaches_the_suite() -> None:
    leaked = [name for name in _LIBPQ_ENV if name in os.environ]
    assert leaked == []


def test_servers_are_local_to_the_fixture(cluster: Cluster) -> None:
    assert cluster.primary.host == "127.0.0.1"
    assert cluster.standby.host == "127.0.0.1"
    assert cluster.primary.port != cluster.standby.port


def test_primary_is_not_in_recovery(cluster: Cluster) -> None:
    with psycopg.connect(cluster.primary.conninfo()) as conn:
        assert conn.execute("SELECT pg_is_in_recovery()").fetchone()[0] is False


def test_standby_is_in_recovery_and_streams_from_the_primary(cluster: Cluster) -> None:
    with psycopg.connect(cluster.standby.conninfo()) as conn:
        assert conn.execute("SELECT pg_is_in_recovery()").fetchone()[0] is True

    marker = f"m{time.time_ns()}"
    with psycopg.connect(cluster.primary.conninfo(), autocommit=True) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS fixture_probe (v text)")
        conn.execute("INSERT INTO fixture_probe VALUES (%s)", (marker,))

    deadline = time.monotonic() + 30
    seen = False
    while time.monotonic() < deadline and not seen:
        with psycopg.connect(cluster.standby.conninfo()) as conn:
            exists = conn.execute("SELECT to_regclass('public.fixture_probe')").fetchone()[0]
            if exists is not None:
                seen = conn.execute(
                    "SELECT count(*) FROM fixture_probe WHERE v = %s", (marker,)
                ).fetchone()[0] == 1
        if not seen:
            time.sleep(0.5)
    assert seen, "the standby did not receive a row written on the primary"
