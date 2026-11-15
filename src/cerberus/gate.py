"""Statement gate (read path step 4) and function/operator allowlist (step 5).

The statement is parsed with PostgreSQL's own grammar (pglast). Exactly one plain ``SELECT`` passes:
no ``SELECT INTO``, no locking clause, no data-modifying CTE. Every function and operator the query
names is then checked against the live catalog: a name counts as built-in only when every catalog
entry of that name lives in ``pg_catalog``; anything else is refused unless the connection allows it.
Built-ins pass unless on the denylist below.

The denylist starts from the default list of pgguard-mcp 0.1.0 (MIT, Copyright (c) 2026 Gilang
Pratama, https://github.com/Azzaraell/pgguard-mcp, ``src/policy/schema.ts``) and adds the families the
Spec names (SQL-as-text functions, file and large-object readers, session-state setters, sequence
movers, backend signals, advisory locks, sleeps) plus server-administration functions.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import pglast
from pglast import ast
from pglast.enums import A_Expr_Kind
from pglast.visitors import Visitor

from cerberus.refusal import Refusal

DENIED_FUNCTIONS = frozenset({
    # ported from pgguard-mcp's DEFAULT_DENY_FUNCTIONS
    "pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
    "dblink", "dblink_connect", "lo_import", "lo_export",
    "pg_sleep", "pg_terminate_backend", "pg_cancel_backend", "set_config",
    "nextval", "setval", "currval", "lastval",
    "query_to_xml", "query_to_xmlschema", "query_to_xml_and_xmlschema",
    "table_to_xml", "table_to_xmlschema", "table_to_xml_and_xmlschema",
    "schema_to_xml", "schema_to_xmlschema", "schema_to_xml_and_xmlschema",
    "database_to_xml", "database_to_xmlschema", "database_to_xml_and_xmlschema",
    # SQL given as text, or a cursor read by name
    "cursor_to_xml", "cursor_to_xmlschema", "ts_stat",
    "dblink_connect_u", "dblink_exec", "dblink_open", "dblink_fetch", "dblink_send_query",
    "dblink_get_result",
    # files
    "pg_ls_logdir", "pg_ls_waldir", "pg_ls_tmpdir", "pg_ls_archive_statusdir",
    "pg_ls_logicalsnapdir", "pg_ls_logicalmapdir", "pg_ls_replslotdir",
    # large objects (lo_* also by prefix)
    "loread", "lowrite",
    # sleeps, signals, server administration
    "pg_sleep_for", "pg_sleep_until", "pg_reload_conf", "pg_rotate_logfile",
    "pg_log_backend_memory_contexts", "pg_notify", "pg_switch_wal", "pg_promote",
    "pg_drop_replication_slot",
})
DENIED_PREFIXES = (
    "lo_", "pg_advisory_", "pg_try_advisory_", "pg_stat_reset", "pg_wal_replay_", "pg_backup_",
    "pg_create_", "pg_replication_origin_", "pg_logical_",
)
# ts_rewrite(query, text) runs its second argument as SQL; the three-argument form does not.
_SQL_TEXT_BY_ARITY = {"ts_rewrite": 2}

_NOT_OPERATOR_KINDS = {
    A_Expr_Kind.AEXPR_BETWEEN, A_Expr_Kind.AEXPR_NOT_BETWEEN,
    A_Expr_Kind.AEXPR_BETWEEN_SYM, A_Expr_Kind.AEXPR_NOT_BETWEEN_SYM,
}


@dataclass(frozen=True)
class Name:
    schema: str | None
    name: str
    arity: int = 0

    def __str__(self) -> str:
        return f"{self.schema}.{self.name}" if self.schema else self.name


@dataclass
class ParsedQuery:
    sql: str
    tree: ast.Node
    functions: list[Name] = field(default_factory=list)
    operators: list[Name] = field(default_factory=list)


def _qualified(parts: tuple, arity: int = 0) -> Name:
    names = [p.sval for p in parts]
    return Name(names[-2] if len(names) > 1 else None, names[-1], arity)


class _Collector(Visitor):
    def __init__(self) -> None:
        self.functions: list[Name] = []
        self.operators: list[Name] = []
        self.problem: tuple[str, str] | None = None

    def visit_SelectStmt(self, ancestors, node: ast.SelectStmt) -> None:
        if node.intoClause is not None:
            self.problem = self.problem or ("statement.select-into", "SELECT INTO creates a table")
        if node.lockingClause:
            self.problem = self.problem or (
                "statement.locking-clause", "a locking clause (FOR UPDATE / FOR SHARE) takes row locks"
            )

    def visit_CommonTableExpr(self, ancestors, node: ast.CommonTableExpr) -> None:
        if not isinstance(node.ctequery, ast.SelectStmt):
            kind = type(node.ctequery).__name__
            self.problem = self.problem or (
                "statement.data-modifying-cte", f"the CTE {node.ctename!r} is a {kind}, not a SELECT"
            )

    def visit_FuncCall(self, ancestors, node: ast.FuncCall) -> None:
        self.functions.append(_qualified(node.funcname, len(node.args or ())))

    def visit_A_Expr(self, ancestors, node: ast.A_Expr) -> None:
        if node.kind not in _NOT_OPERATOR_KINDS and node.name:
            self.operators.append(_qualified(node.name))


def check_statement(sql: str) -> ParsedQuery:
    """Step 4: accept exactly one plain SELECT, or refuse naming the rule."""
    try:
        statements = pglast.parse_sql(sql)
    except pglast.parser.ParseError as exc:
        raise Refusal("statement.parse-error", f"the statement does not parse: {exc}") from None
    if len(statements) != 1:
        raise Refusal(
            "statement.multiple", f"exactly one statement is accepted; got {len(statements)}"
        )
    tree = statements[0].stmt
    if not isinstance(tree, ast.SelectStmt):
        raise Refusal(
            "statement.not-select",
            f"only a plain SELECT is accepted; got {type(tree).__name__}",
        )
    collector = _Collector()
    collector(tree)
    if collector.problem:
        raise Refusal(*collector.problem)
    return ParsedQuery(sql, tree, collector.functions, collector.operators)


def is_denied(fn: Name) -> bool:
    if fn.name in DENIED_FUNCTIONS or fn.name.startswith(DENIED_PREFIXES):
        return True
    return _SQL_TEXT_BY_ARITY.get(fn.name) == fn.arity


Lookup = Callable[[str, tuple], list[tuple]]

_FUNCTION_SCHEMAS = (
    "SELECT n.nspname FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n "
    "ON n.oid = p.pronamespace WHERE p.proname = %s AND (%s::text IS NULL OR n.nspname = %s)"
)
_OPERATOR_SCHEMAS = (
    "SELECT n.nspname FROM pg_catalog.pg_operator o JOIN pg_catalog.pg_namespace n "
    "ON n.oid = o.oprnamespace WHERE o.oprname = %s AND (%s::text IS NULL OR n.nspname = %s)"
)


def check_functions(parsed: ParsedQuery, lookup: Lookup, allow_functions: frozenset[str]) -> None:
    """Step 5: every function and operator against the catalog and the connection's allowlist."""
    for fn in parsed.functions:
        if is_denied(fn):
            raise Refusal(
                "function.denied",
                f"function {fn}() is on the denylist: it can execute SQL given as text, read files, "
                "change session state, move a sequence, signal a backend, take a lock or sleep",
            )
        schemas = {row[0] for row in lookup(_FUNCTION_SCHEMAS, (fn.name, fn.schema, fn.schema))}
        if not schemas:
            raise Refusal("function.unknown", f"no function named {fn} in the catalog")
        outside = {s for s in schemas if s != "pg_catalog"}
        not_allowed = sorted(f"{s}.{fn.name}" for s in outside if f"{s}.{fn.name}" not in allow_functions)
        if not_allowed:
            raise Refusal(
                "function.not-allowed",
                f"function {fn}() has catalog entries outside pg_catalog ({', '.join(not_allowed)}) that "
                "are not in this connection's allow_functions",
            )
    for op in parsed.operators:
        schemas = {row[0] for row in lookup(_OPERATOR_SCHEMAS, (op.name, op.schema, op.schema))}
        if not schemas:
            raise Refusal("operator.unknown", f"no operator named {op} in the catalog")
        if any(s != "pg_catalog" for s in schemas):
            raise Refusal(
                "operator.not-allowed", f"operator {op} has catalog entries outside pg_catalog"
            )
