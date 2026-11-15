"""The read path: guarded session, statement gate, function check, execution."""

from __future__ import annotations

from cerberus import gate
from cerberus.config import Connection
from cerberus.refusal import Refusal
from cerberus.session import ReadSession


def run_query(conn: Connection, sql: str) -> dict[str, object]:
    with ReadSession(conn) as session:
        try:
            parsed = gate.check_statement(sql)
            gate.check_functions(
                parsed,
                lambda q, params: session.execute(q, params).fetchall(),
                conn.allow_functions,
            )
        except Refusal as refusal:
            raise session.refuse(refusal.rule, refusal.detail) from None
        cursor = session.execute(sql)
        columns = [c.name for c in cursor.description or ()]
        rows = [list(r) for r in cursor.fetchall()] if cursor.description else []
        return {
            "connection": conn.name,
            "guarantee": session.guarantee,
            "columns": columns,
            "rows": rows,
            "row_count": len(rows),
        }
