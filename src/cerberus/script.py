"""Rollback-only scripts on a writable connection (``cerberus run-script``).

The whole script is checked before connecting: no transaction control (``SAVEPOINT`` and ``ROLLBACK TO``
excepted), nothing a rollback does not undo or that cannot run inside a transaction, no denylisted
function, no client meta-command. The statements then run in one explicit transaction, each under the
connection's bound, encoding and search path and the function rule; a statement that returns rows
passes the read-surface policy first. The transaction is always rolled back, unless a person confirms
a commit for this one run on an interactive terminal.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import pglast
import psycopg
from pglast import ast
from pglast.enums import TransactionStmtKind
from pglast.visitors import Visitor

from cerberus import gate
from cerberus.config import Connection
from cerberus.policy import SurfaceCheck
from cerberus.refusal import Refusal
from cerberus.session import WriteSession

_ALLOWED_TRANSACTION_KINDS = {TransactionStmtKind.TRANS_STMT_SAVEPOINT,
                              TransactionStmtKind.TRANS_STMT_ROLLBACK_TO}
# Statements whose effect escapes the checks: rows the read-surface policy never sees (B4), code the
# function rule never reads (B5), settings that override the connection's bound and search path (B6).
_REFUSED_KINDS = {
    ast.PrepareStmt: "PREPARE / EXECUTE return rows the read-surface policy does not see",
    ast.ExecuteStmt: "PREPARE / EXECUTE return rows the read-surface policy does not see",
    ast.DeclareCursorStmt: "a cursor returns rows the read-surface policy does not see",
    ast.FetchStmt: "a cursor returns rows the read-surface policy does not see",
    ast.DoStmt: "a DO block's body is code the function rule does not read",
    ast.VariableSetStmt: "SET / RESET would override the connection's bound, search path or role",
    ast.LoadStmt: "LOAD loads a library into the server process",
}
# Statements whose rows may be returned without passing the read-surface policy.
_ROWS_WITHOUT_POLICY = (ast.VariableShowStmt, ast.ExplainStmt)

_NOT_UNDONE = {
    ast.VacuumStmt: "VACUUM",
    ast.CreatedbStmt: "CREATE DATABASE",
    ast.DropdbStmt: "DROP DATABASE",
    ast.AlterSystemStmt: "ALTER SYSTEM",
    ast.CreateTableSpaceStmt: "CREATE TABLESPACE",
    ast.DropTableSpaceStmt: "DROP TABLESPACE",
    ast.CheckPointStmt: "CHECKPOINT",
    ast.DiscardStmt: "DISCARD",
}


@dataclass
class Statement:
    index: int
    text: str
    tree: ast.Node


def _first_line(text: str) -> str:
    return text.strip().splitlines()[0][:120] if text.strip() else ""


class _Functions(Visitor):
    def __init__(self) -> None:
        self.names: list[gate.Name] = []

    def visit_FuncCall(self, ancestors, node: ast.FuncCall) -> None:
        self.names.append(gate._qualified(node.funcname, len(node.args or ())))


def parse_script(script: str) -> list[Statement]:
    """Check the whole script before any connection; refuse naming the offending statement."""
    for number, line in enumerate(script.splitlines(), start=1):
        if line.lstrip().startswith("\\"):
            raise Refusal("script.meta-command",
                          f"line {number} is a client meta-command ({_first_line(line)}); not SQL")
    try:
        raw = pglast.parse_sql(script)
    except pglast.parser.ParseError as exc:
        raise Refusal("script.parse-error", f"the script does not parse: {exc}") from None
    statements = []
    for index, stmt in enumerate(raw, start=1):
        # pglast's statement offsets count characters (measured), so slice the string itself.
        start = stmt.stmt_location or 0
        end = start + stmt.stmt_len if stmt.stmt_len else len(script)
        text = script[start:end].strip()
        tree = stmt.stmt
        label = f"statement {index} ({_first_line(text)})"
        if isinstance(tree, ast.TransactionStmt) and tree.kind not in _ALLOWED_TRANSACTION_KINDS:
            raise Refusal("script.transaction-control",
                          f"{label} controls the transaction; cerberus owns it (SAVEPOINT and ROLLBACK "
                          "TO are allowed)")
        for kind, why in _REFUSED_KINDS.items():
            if isinstance(tree, kind):
                raise Refusal("script.statement-not-allowed", f"{label}: {why}")
        if isinstance(tree, ast.CopyStmt) and not tree.is_from and not tree.is_program:
            raise Refusal("script.statement-not-allowed",
                          f"{label}: COPY … TO returns rows the read-surface policy does not see")
        if isinstance(tree, ast.VacuumStmt) and not tree.is_vacuumcmd:
            raise Refusal("script.not-undone",
                          f"{label}: ANALYZE updates statistics counters a rollback does not undo")
        for kind, name in _NOT_UNDONE.items():
            if isinstance(tree, kind):
                raise Refusal("script.not-undone", f"{label}: {name} is not undone by a rollback")
        if isinstance(tree, ast.IndexStmt) and tree.concurrent:
            raise Refusal("script.not-undone",
                          f"{label}: CREATE INDEX CONCURRENTLY cannot run in a transaction")
        if isinstance(tree, ast.ReindexStmt) and any(
            getattr(p, "defname", None) == "concurrently" for p in (tree.params or ())
        ):
            raise Refusal("script.not-undone",
                          f"{label}: REINDEX CONCURRENTLY cannot run in a transaction")
        if isinstance(tree, ast.CopyStmt) and tree.is_program:
            raise Refusal("script.not-undone",
                          f"{label}: COPY … PROGRAM runs a program, which a rollback does not undo")
        functions = _Functions()
        functions(tree)
        for fn in functions.names:
            if gate.is_denied(fn):
                raise Refusal("function.denied", f"{label} calls the denylisted function {fn}()")
        statements.append(Statement(index, text, tree))
    if not statements:
        raise Refusal("script.empty", "the script holds no statement")
    return statements


def _returns_rows(tree: ast.Node) -> bool:
    if isinstance(tree, ast.SelectStmt):
        return True
    if isinstance(tree, (ast.InsertStmt, ast.UpdateStmt, ast.DeleteStmt, ast.MergeStmt)):
        clause = tree.returningClause  # PostgreSQL 18 grammar: RETURNING lives in a clause node
        return bool(clause and clause.exprs)
    return False


def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base).expanduser() / "cerberus"


def _record_commit(conn: Connection, script: str, count: int) -> None:
    directory = state_dir()
    directory.mkdir(parents=True, exist_ok=True)
    record = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "connection": conn.name,
        "script_sha256": hashlib.sha256(script.encode("utf-8")).hexdigest(),
        "statements": count,
    }
    with (directory / "commits.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")


Confirm = Callable[[Connection], bool]


def run_script(conn: Connection, script: str, *, commit: bool = False,
               confirm: Confirm | None = None, verbose_errors: bool = False) -> dict[str, object]:
    if conn.cls != "writable":
        raise Refusal("connection.not-writable",
                      f"connection {conn.name!r} is {conn.cls}; run-script needs a writable connection")
    statements = parse_script(script)
    if commit and confirm is None:
        raise Refusal("commit.no-terminal",
                      "--commit needs an interactive terminal on stdin; a person runs a commit")
    outputs: list[dict[str, object]] = []
    with WriteSession(conn) as session:
        def lookup(q: str, params):
            return session.execute(q, params).fetchall()

        for stmt in statements:
            try:
                collector = gate._Collector()  # functions and operators; shape rules are read-only
                collector(stmt.tree)
                parsed = gate.ParsedQuery(stmt.text, stmt.tree, collector.functions, collector.operators)
                gate.check_functions(parsed, lookup, conn.allow_functions)
                if _returns_rows(stmt.tree):
                    SurfaceCheck(conn, lookup).check(parsed)
                cursor = session.execute(stmt.text)
            except Refusal as refusal:
                raise Refusal(refusal.rule, f"statement {stmt.index}: {refusal.detail}; the script "
                              "was rolled back") from None
            except psycopg.errors.QueryCanceled:
                raise Refusal("limit.timeout",
                              f"statement {stmt.index} ran past this connection's bound of "
                              f"{conn.timeout_ms} ms; the script was rolled back") from None
            except psycopg.Error as exc:
                # A statement may touch a restricted column without returning it, and the first line
                # of a server error can quote that value: show the condition, not the message.
                text = str(exc).strip()
                shown = text if verbose_errors else type(exc).__name__
                raise Refusal("server.error",
                              f"statement {stmt.index}: {exc.sqlstate or 'unknown'}: {shown}; the "
                              "script was rolled back") from None
            if (cursor.description and not _returns_rows(stmt.tree)
                    and not isinstance(stmt.tree, _ROWS_WITHOUT_POLICY)):
                raise Refusal("script.unchecked-rows",
                              f"statement {stmt.index} returned rows the read-surface policy did not "
                              "check; the script was rolled back")
            output: dict[str, object] = {"statement": stmt.index, "command": cursor.statusmessage}
            if cursor.description:
                output["columns"] = [c.name for c in cursor.description]
                output["rows"] = [list(r) for r in cursor.fetchall()]
            outputs.append(output)
        committed = False
        if commit:
            if not confirm(conn):
                raise Refusal("commit.not-confirmed",
                              "the confirmation did not match the connection name; rolled back")
            session.commit_on_exit()
            committed = True
    if committed:
        _record_commit(conn, script, len(statements))
    return {"connection": conn.name, "committed": committed, "statements": outputs}
