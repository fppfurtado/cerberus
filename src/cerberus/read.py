"""The read path: guarded session, statement gate, function check, read-surface policy, execution."""

from __future__ import annotations

import psycopg

from cerberus import gate
from cerberus.config import Connection
from cerberus.policy import SurfaceCheck
from cerberus.refusal import Refusal
from cerberus.session import ReadSession


def _server_error(exc: psycopg.Error) -> Refusal:
    text = str(exc).strip()
    first_line = text.splitlines()[0] if text else type(exc).__name__
    return Refusal("server.error", f"{exc.sqlstate or 'unknown'}: {first_line}")


def run_query(conn: Connection, sql: str) -> dict[str, object]:
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
        except psycopg.Error as exc:
            error = _server_error(exc)
            raise session.refuse(error.rule, error.detail) from None
        return {
            "connection": conn.name,
            "guarantee": session.guarantee,
            "resolved": resolved,
            "columns": columns,
            "rows": rows,
            "row_count": len(rows),
        }
