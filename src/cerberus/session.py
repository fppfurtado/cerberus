"""The guarded session: the one module that opens a database connection (Spec invariant CB01)."""

from __future__ import annotations

import psycopg

from cerberus.config import Connection
from cerberus.custody import driver_credentials
from cerberus.refusal import Refusal


def open_connection(conn: Connection) -> psycopg.Connection:
    """Open ``conn`` with credentials taken only from its custody password file."""
    params = {
        "host": conn.host,
        "port": conn.port,
        "dbname": conn.dbname,
        "user": conn.user,
        **driver_credentials(conn),
    }
    try:
        return psycopg.connect(**params)
    except psycopg.OperationalError as exc:
        first_line = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
        raise Refusal("connection.failed", f"connection {conn.name!r}: {first_line}") from None
