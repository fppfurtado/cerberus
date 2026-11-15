"""The guarded session: the one module that opens a database connection (Spec invariant CB01).

A read session opens the connection, starts ``BEGIN TRANSACTION READ ONLY`` and establishes the write
guarantee against the server before anything of the caller's is sent. The transaction is always
rolled back on exit.
"""

from __future__ import annotations

import os
from typing import Any

import psycopg
from psycopg.types.string import TextLoader

from cerberus.config import Connection
from cerberus.custody import driver_credentials
from cerberus.refusal import Refusal

SERVER_ENFORCED = "server-enforced"
CLIENT_REQUESTED = "client-requested"
_STRENGTH = {CLIENT_REQUESTED: 1, SERVER_ENFORCED: 2}

# libpq fills unset parameters from these (PGHOSTADDR could send the connection to another server;
# PGOPTIONS or PGSERVICE could change its settings; PGPASSWORD would be a credential source). cerberus
# runs one invocation per process, so it removes them before connecting.
_LIBPQ_ENV_PREFIX = "PG"
# Explicit values for the parameters that matter most, as a second line.
_NEUTRAL = {"hostaddr": "", "options": "", "target_session_attrs": "any"}


def _clear_libpq_environment() -> None:
    for name in [n for n in os.environ if n.startswith(_LIBPQ_ENV_PREFIX)]:
        del os.environ[name]


def open_connection(conn: Connection) -> psycopg.Connection:
    """Open ``conn`` with credentials taken only from its custody password file."""
    _clear_libpq_environment()
    params: dict[str, Any] = {
        "host": conn.host,
        "port": conn.port,
        "dbname": conn.dbname,
        "user": conn.user,
        "client_encoding": conn.client_encoding,
        **_NEUTRAL,
        **driver_credentials(conn),
    }
    try:
        db = psycopg.connect(**params, autocommit=True)
    except psycopg.OperationalError as exc:
        text = str(exc).strip()
        first_line = text.splitlines()[0] if text else type(exc).__name__
        raise Refusal("connection.failed", f"connection {conn.name!r}: {first_line}") from None
    # psycopg's JSON loader decodes as UTF-8 whatever the client encoding is; load JSON as text,
    # which is decoded in the connection's encoding.
    for json_type in ("json", "jsonb"):
        db.adapters.register_loader(json_type, TextLoader)
    return db


def apply_bounds_and_preconditions(db: psycopg.Connection, conn: Connection) -> None:
    """Inside the open transaction: the server-side time bound, and the declared search path."""
    db.execute("SELECT pg_catalog.set_config('statement_timeout', %s, true)", (f"{conn.timeout_ms}ms",))
    db.execute("SELECT pg_catalog.set_config('lock_timeout', %s, true)", (f"{conn.timeout_ms}ms",))
    if conn.search_path is not None:
        quoted = [db.execute("SELECT pg_catalog.quote_ident(%s)", (s,)).fetchone()[0]
                  for s in conn.search_path]
        db.execute("SELECT pg_catalog.set_config('search_path', %s, true)", (", ".join(quoted),))


def establish_guarantee(db: psycopg.Connection) -> dict[str, str]:
    """Read the guarantee the server actually gives inside the current read-only transaction."""
    in_recovery = db.execute("SELECT pg_is_in_recovery()").fetchone()[0]
    if in_recovery:
        return {"class": SERVER_ENFORCED, "basis": "pg_is_in_recovery"}
    read_only = db.execute("SELECT current_setting('transaction_read_only')").fetchone()[0]
    if read_only == "on":
        return {"class": CLIENT_REQUESTED, "basis": "transaction_read_only"}
    return {"class": "none", "basis": "transaction_read_only is off"}


class ReadSession:
    """``with ReadSession(conn) as s:`` — a guarded read-only transaction on a declared connection."""

    def __init__(self, conn: Connection) -> None:
        self.conn = conn
        self.db: psycopg.Connection | None = None
        self.guarantee: dict[str, str] | None = None

    def __enter__(self) -> "ReadSession":
        self.db = open_connection(self.conn)
        try:
            self.db.execute("BEGIN TRANSACTION READ ONLY")
            apply_bounds_and_preconditions(self.db, self.conn)
            self.guarantee = establish_guarantee(self.db)
            established = _STRENGTH.get(self.guarantee["class"], 0)
            declared = _STRENGTH.get(self.conn.cls, 0)
            if established < declared or established == 0:
                raise self.refuse(
                    "guarantee.weaker-than-declared",
                    f"connection {self.conn.name!r} is declared {self.conn.cls} but the server gives "
                    f"{self.guarantee['class']}; no statement of the query was sent",
                )
        except BaseException:
            self._close()
            raise
        return self

    def __exit__(self, *exc: object) -> None:
        self._close()

    def _close(self) -> None:
        if self.db is not None:
            try:
                if not self.db.closed:
                    self.db.execute("ROLLBACK")
            except psycopg.Error:
                pass
            finally:
                self.db.close()
                self.db = None

    def refuse(self, rule: str, detail: str) -> Refusal:
        """A refusal issued after the guarantee was established carries it."""
        return Refusal(rule, detail, guarantee=self.guarantee)

    def execute(self, sql: str, params: Any = None) -> psycopg.Cursor:
        assert self.db is not None, "session is not open"
        return self.db.execute(sql, params)
