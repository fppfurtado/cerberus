"""Test fixtures: a synthetic PostgreSQL primary and a streaming standby, started in containers.

The suite never talks to any database but these two. libpq environment variables are removed before
any test runs, so nothing falls back to a database named by the developer's or the runner's
environment, and both servers listen only on 127.0.0.1 ports the fixture publishes.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
import uuid
from dataclasses import dataclass

import psycopg
import pytest

IMAGE = os.environ.get("CERBERUS_TEST_PG_IMAGE", "postgres:16")
SUPERUSER = "postgres"
PASSWORD = "synthetic-test-only"
DBNAME = "postgres"
READY_TIMEOUT_S = 120

# libpq reads these; none may leak into the suite (no access to any other database).
_LIBPQ_ENV = (
    "PGHOST", "PGHOSTADDR", "PGPORT", "PGDATABASE", "PGUSER", "PGPASSWORD", "PGPASSFILE",
    "PGSERVICE", "PGSERVICEFILE", "PGOPTIONS", "PGSSLMODE", "PGTARGETSESSIONATTRS",
)


def pytest_configure(config: pytest.Config) -> None:
    for name in _LIBPQ_ENV:
        os.environ.pop(name, None)


@dataclass(frozen=True)
class Server:
    """One synthetic server: connection parameters for a test."""

    role: str  # "primary" or "standby"
    host: str
    port: int
    container: str
    user: str = SUPERUSER
    password: str = PASSWORD
    dbname: str = DBNAME

    def conninfo(self, **overrides: str) -> str:
        params = {
            "host": self.host, "port": str(self.port), "user": self.user,
            "password": self.password, "dbname": self.dbname,
        }
        params.update(overrides)
        return " ".join(f"{k}={v}" for k, v in params.items())


@dataclass(frozen=True)
class Cluster:
    primary: Server
    standby: Server


def server_log(server: Server) -> str:
    """The server's log so far (the primary logs every statement)."""
    result = subprocess.run(["docker", "logs", server.container], capture_output=True, text=True)
    return result.stdout + result.stderr


def _docker(*args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["docker", *args], capture_output=True, text=True, check=False,
    )
    if check and result.returncode != 0:
        raise RuntimeError(f"docker {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def _published_port(container: str) -> int:
    out = _docker("port", container, "5432/tcp")
    # e.g. "127.0.0.1:49153"
    return int(out.splitlines()[0].rsplit(":", 1)[1])


def _wait_ready(server: Server, *, standby: bool) -> None:
    deadline = time.monotonic() + READY_TIMEOUT_S
    last: Exception | None = None
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(server.conninfo(), connect_timeout=2) as conn:
                in_recovery = conn.execute("SELECT pg_is_in_recovery()").fetchone()[0]
                if in_recovery == standby:
                    return
        except psycopg.Error as exc:
            last = exc
        time.sleep(1)
    raise RuntimeError(f"{server.role} not ready after {READY_TIMEOUT_S}s: {last}")


@pytest.fixture(scope="session")
def cluster() -> Cluster:
    if shutil.which("docker") is None:
        pytest.fail("the suite needs docker to start its synthetic PostgreSQL primary and standby")

    tag = uuid.uuid4().hex[:8]
    network = f"cerberus-test-{tag}"
    primary_name = f"cerberus-primary-{tag}"
    standby_name = f"cerberus-standby-{tag}"
    started: list[str] = []
    _docker("network", "create", network)
    try:
        _docker(
            "run", "-d", "--name", primary_name, "--network", network,
            "-p", "127.0.0.1::5432",
            "-e", f"POSTGRES_PASSWORD={PASSWORD}",
            "-e", "POSTGRES_HOST_AUTH_METHOD=scram-sha-256",
            "-e", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
            IMAGE,
            "-c", "wal_level=replica", "-c", "max_wal_senders=5", "-c", "hot_standby=on",
            "-c", "log_statement=all",
        )
        started.append(primary_name)
        primary = Server("primary", "127.0.0.1", _published_port(primary_name), primary_name)
        _wait_ready(primary, standby=False)
        # Allow streaming replication from the private test network.
        _docker(
            "exec", primary_name, "bash", "-c",
            "echo 'host replication all all scram-sha-256' >> \"$PGDATA/pg_hba.conf\"",
        )
        with psycopg.connect(primary.conninfo(), autocommit=True) as conn:
            conn.execute("SELECT pg_reload_conf()")

        standby_script = (
            "set -e; D=/var/lib/postgresql/data/standby; "
            "until PGPASSWORD=\"$PRIMARY_PASSWORD\" gosu postgres pg_basebackup "
            f"-h {primary_name} -U {SUPERUSER} -D \"$D\" -R -X stream; "
            "do rm -rf \"$D\"; sleep 1; done; "
            "exec gosu postgres postgres -D \"$D\" -c hot_standby=on"
        )
        _docker(
            "run", "-d", "--name", standby_name, "--network", network,
            "-p", "127.0.0.1::5432",
            "-e", f"PRIMARY_PASSWORD={PASSWORD}",
            "--entrypoint", "bash", IMAGE, "-c", standby_script,
        )
        started.append(standby_name)
        standby = Server("standby", "127.0.0.1", _published_port(standby_name), standby_name)
        _wait_ready(standby, standby=True)
        yield Cluster(primary=primary, standby=standby)
    finally:
        for name in reversed(started):
            _docker("rm", "-f", "-v", name, check=False)
        _docker("network", "rm", network, check=False)


MARKER = "PLANTED-MARKER-4f1c"
READER_PASSWORD = "reader-synthetic"

_SCHEMA_SQL = f"""
CREATE SCHEMA IF NOT EXISTS app;
CREATE TABLE IF NOT EXISTS app.vault (id int PRIMARY KEY, label text, secret text);
INSERT INTO app.vault VALUES (1, 'first', '{MARKER}') ON CONFLICT DO NOTHING;
CREATE OR REPLACE FUNCTION app.dump_secret() RETURNS text LANGUAGE sql
    AS 'SELECT secret FROM app.vault LIMIT 1';
CREATE OR REPLACE FUNCTION app.int_eq(int, int) RETURNS bool LANGUAGE sql IMMUTABLE
    AS 'SELECT $1 = $2';
DO $$ BEGIN
    CREATE OPERATOR app.=== (LEFTARG = int, RIGHTARG = int, FUNCTION = app.int_eq);
EXCEPTION WHEN duplicate_function THEN NULL; END $$;
CREATE TABLE IF NOT EXISTS app.scratch (i int);
INSERT INTO app.scratch SELECT generate_series(1, 100);
CREATE TABLE app.grow (id int, label text);
CREATE TABLE app.other (id int, secret text);
INSERT INTO app.other VALUES (1, 'harmless-other');
CREATE TABLE app.hidden (id int);
CREATE VIEW app.v_vault AS SELECT id, secret FROM app.vault;
CREATE VIEW app.v_rename AS SELECT id, secret AS harmless FROM app.vault;
CREATE VIEW app.v_fn AS SELECT app.dump_secret() AS x;
CREATE MATERIALIZED VIEW app.mv_vault AS SELECT id, secret FROM app.vault;
CREATE TABLE app.pvault (id int, label text, secret text) PARTITION BY RANGE (id);
CREATE TABLE app.pvault_p1 PARTITION OF app.pvault FOR VALUES FROM (0) TO (100);
INSERT INTO app.pvault VALUES (1, 'first', '{MARKER}');
CREATE TABLE app.ivault (id int, label text, secret text);
CREATE TABLE app.ivault_c () INHERITS (app.ivault);
INSERT INTO app.ivault_c VALUES (1, 'first', '{MARKER}');
CREATE FUNCTION app.vault_rows() RETURNS SETOF app.vault LANGUAGE sql STABLE
    AS 'SELECT * FROM app.vault';
CREATE ROLE reader LOGIN PASSWORD '{READER_PASSWORD}';
ALTER ROLE reader SET search_path = app, public;
GRANT USAGE ON SCHEMA app TO reader;
GRANT SELECT ON ALL TABLES IN SCHEMA app TO reader;
CREATE TABLE IF NOT EXISTS app.schema_ready (ok bool);
"""


@pytest.fixture(scope="session")
def schema(cluster: Cluster) -> Cluster:
    """A synthetic schema on the primary, replicated to the standby before tests use it."""
    with psycopg.connect(cluster.primary.conninfo(), autocommit=True) as conn:
        conn.execute(_SCHEMA_SQL)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        with psycopg.connect(cluster.standby.conninfo()) as conn:
            if conn.execute("SELECT to_regclass('app.schema_ready')").fetchone()[0] is not None:
                return cluster
        time.sleep(0.5)
    raise RuntimeError("the synthetic schema did not reach the standby")


@pytest.fixture
def declare(tmp_path, monkeypatch: pytest.MonkeyPatch):
    """Declare synthetic servers in an isolated private config; returns the loaded declaration.

    ``declare(name, server, cls, extra="")`` — ``extra`` is TOML appended to the connection's table
    (sub-tables such as ``[connection.NAME.policy]`` included).
    """
    from cerberus import config

    home = tmp_path / "home"
    cfg = home / ".config" / "cerberus"
    cfg.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    blocks: list[str] = []
    lines: list[str] = []

    def _declare(name: str, server: Server, cls: str, extra: str = ""):
        blocks.append(
            f'[connection.{name}]\nhost = "{server.host}"\nport = {server.port}\n'
            f'dbname = "{server.dbname}"\nuser = "{server.user}"\nclass = "{cls}"\n{extra}\n'
        )
        lines.append(f"{server.host}:{server.port}:{server.dbname}:{server.user}:{server.password}")
        (cfg / "connections.toml").write_text("\n".join(blocks))
        passfile = cfg / "pgpass"
        passfile.write_text("\n".join(lines) + "\n")
        passfile.chmod(0o600)
        return config.load(name)

    return _declare
