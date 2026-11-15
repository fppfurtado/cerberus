"""The read path: guarded session, statement gate, function check, read-surface policy, execution."""

from __future__ import annotations

import time

import psycopg

from cerberus import gate
from cerberus.config import Connection
from cerberus.policy import SurfaceCheck
from cerberus.refusal import Refusal
from cerberus.session import ReadSession


def _server_error(exc: psycopg.Error, verbose: bool) -> Refusal:
    """A server error as a refusal: SQLSTATE and the first line, unless verbose (a message line can
    quote a value)."""
    text = str(exc).strip()
    shown = text if verbose else (text.splitlines()[0] if text else type(exc).__name__)
    return Refusal("server.error", f"{exc.sqlstate or 'unknown'}: {shown}")


def run_query(conn: Connection, sql: str, *, verbose_errors: bool = False) -> dict[str, object]:
    if conn.cls == "writable":
        raise Refusal(
            "connection.writable",
            f"connection {conn.name!r} is writable; use `cerberus run-script {conn.name} <file>`",
        )
    started = time.monotonic()
    with ReadSession(conn) as session:
        def lookup(q: str, params):
            return session.execute(q, params).fetchall()

        try:
            parsed = gate.check_statement(sql)
            gate.check_functions(parsed, lookup, conn.allow_functions)
            resolved = SurfaceCheck(conn, lookup).check(parsed)
            cursor = session.execute(sql)
            columns = [c.name for c in cursor.description or ()]
            rows = [list(r) for r in cursor.fetchall()] if cursor.description else []
        except Refusal as refusal:
            raise session.refuse(refusal.rule, refusal.detail) from None
        except psycopg.errors.QueryCanceled:
            raise session.refuse(
                "limit.timeout",
                f"the query ran past this connection's bound of {conn.timeout_ms} ms and was "
                "cancelled on the server",
            ) from None
        except psycopg.Error as exc:
            error = _server_error(exc, verbose_errors)
            raise session.refuse(error.rule, error.detail) from None
        return {
            "connection": conn.name,
            "guarantee": session.guarantee,
            "resolved": resolved,
            "columns": columns,
            "rows": rows,
            "row_count": len(rows),
            "elapsed_ms": round((time.monotonic() - started) * 1000),
        }
