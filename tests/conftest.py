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
        )
        started.append(primary_name)
        primary = Server("primary", "127.0.0.1", _published_port(primary_name))
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
        standby = Server("standby", "127.0.0.1", _published_port(standby_name))
        _wait_ready(standby, standby=True)
        yield Cluster(primary=primary, standby=standby)
    finally:
        for name in reversed(started):
            _docker("rm", "-f", "-v", name, check=False)
        _docker("network", "rm", network, check=False)
