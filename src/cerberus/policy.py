"""Read-surface policy: what a query reaches (read path step 6) and the rules over it (step 7).

What the query reaches comes from three server sources, because no single one is complete:
(i) each relation the query names, resolved under the connection's search path; (ii) the dependency
closure of every named view or materialized view, read from the catalog (``pg_rewrite`` /
``pg_depend``), recursively, with the function rule applied to every function in it; (iii) every
relation the query's plan scans (``EXPLAIN (VERBOSE, FORMAT JSON)``, which does not execute it).

A table under ``policy.columns`` exposes only its listed columns; a relation under
``policy.deny_relations`` exposes nothing. A flagged table's partitions and inheritance children are
flagged with it. The rules (Spec, Interfaces — Read-surface policy):
(a) a flagged relation reached other than by being named directly is refused, even when the same
    query also names it directly;
(b) a column-restricted table named directly may not meet ``*``, a whole-row reference, a
    ``NATURAL``/``USING`` join, or an alias column list;
(c) a column reference that has the name of a non-listed column of a flagged table the query names
    is refused (name-based and conservative).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable

from pglast import ast
from pglast.visitors import Visitor

from cerberus.config import Connection
from cerberus.gate import Name, ParsedQuery, is_denied
from cerberus.refusal import Refusal

Lookup = Callable[[str, tuple], list[tuple]]

# Statistics relations that expose column samples, and credential catalogs.
BUILTIN_DENY_RELATIONS = frozenset({
    "pg_catalog.pg_statistic", "pg_catalog.pg_stats", "pg_catalog.pg_statistic_ext",
    "pg_catalog.pg_statistic_ext_data", "pg_catalog.pg_stats_ext", "pg_catalog.pg_stats_ext_exprs",
    "pg_catalog.pg_authid", "pg_catalog.pg_shadow", "pg_catalog.pg_user_mapping",
    "pg_catalog.pg_user_mappings",
})

_KINDS = {"r": "table", "p": "partitioned table", "v": "view", "m": "materialized view",
          "f": "foreign table", "c": "composite type", "S": "sequence"}


@dataclass(frozen=True)
class Relation:
    oid: int
    schema: str
    name: str
    kind: str

    @property
    def qualified(self) -> str:
        return f"{self.schema}.{self.name}"


@dataclass(frozen=True)
class NamedRef:
    """A relation as the query names it, with the alias it is referred to by."""

    schema: str | None
    name: str
    alias: str | None
    alias_columns: bool


class _Refs(Visitor):
    def __init__(self) -> None:
        self.ranges: list[NamedRef] = []
        self.range_nodes: list[ast.RangeVar] = []
        self.column_refs: list[tuple] = []
        self.natural_or_using: list[ast.JoinExpr] = []
        self.aliased_joins: list[ast.JoinExpr] = []

    def visit_RangeVar(self, ancestors, node: ast.RangeVar) -> None:
        alias = node.alias.aliasname if node.alias else None
        has_cols = bool(node.alias and node.alias.colnames)
        self.ranges.append(NamedRef(node.schemaname, node.relname, alias, has_cols))
        self.range_nodes.append(node)

    def visit_ColumnRef(self, ancestors, node: ast.ColumnRef) -> None:
        self.column_refs.append(tuple(node.fields))

    def visit_JoinExpr(self, ancestors, node: ast.JoinExpr) -> None:
        if node.isNatural or node.usingClause:
            self.natural_or_using.append(node)
        if node.alias is not None:
            self.aliased_joins.append(node)


def _subtree_ranges(node) -> list[ast.RangeVar]:
    found: list[ast.RangeVar] = []

    class _V(Visitor):
        def visit_RangeVar(self, ancestors, n):
            found.append(n)

    _V()(node)
    return found


_RESOLVE = (
    "SELECT c.oid, n.nspname, c.relname, c.relkind FROM pg_catalog.pg_class c "
    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
    "WHERE c.oid = pg_catalog.to_regclass(%s)"
)
_BY_NAME = (
    "SELECT c.oid, n.nspname, c.relname, c.relkind FROM pg_catalog.pg_class c "
    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = %s AND c.relname = %s"
)
_QUOTE = "SELECT pg_catalog.quote_ident(%s)"
_VIEW_DEPS = (
    "SELECT DISTINCT d.refclassid = 'pg_catalog.pg_class'::regclass, d.refobjid "
    "FROM pg_catalog.pg_rewrite r JOIN pg_catalog.pg_depend d "
    "ON d.classid = 'pg_catalog.pg_rewrite'::regclass AND d.objid = r.oid "
    "WHERE r.ev_class = %s AND d.refobjid <> %s "
    "AND d.refclassid IN ('pg_catalog.pg_class'::regclass, 'pg_catalog.pg_proc'::regclass)"
)
_BY_OID = (
    "SELECT c.oid, n.nspname, c.relname, c.relkind FROM pg_catalog.pg_class c "
    "JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = %s"
)
_PROC = (
    "SELECT n.nspname, p.proname FROM pg_catalog.pg_proc p "
    "JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace WHERE p.oid = %s"
)
_DESCENDANTS = (
    "WITH RECURSIVE d(oid) AS (SELECT inhrelid FROM pg_catalog.pg_inherits WHERE inhparent = %s "
    "UNION SELECT i.inhrelid FROM pg_catalog.pg_inherits i JOIN d ON i.inhparent = d.oid) "
    "SELECT oid FROM d"
)
_COLUMNS = (
    "SELECT attname FROM pg_catalog.pg_attribute WHERE attrelid = %s AND attnum > 0 "
    "AND NOT attisdropped"
)


def _row_to_relation(row: tuple) -> Relation:
    return Relation(row[0], row[1], row[2], _KINDS.get(row[3], row[3]))


class SurfaceCheck:
    def __init__(self, conn: Connection, lookup: Lookup) -> None:
        self.conn = conn
        self.lookup = lookup
        self.denied = BUILTIN_DENY_RELATIONS | conn.deny_relations
        # oid -> the policy key (schema.table) that flags it; columns: key -> listed columns.
        self.flag_of: dict[int, str] = {}
        self._load_flags()

    def _one(self, sql: str, params: tuple) -> tuple | None:
        rows = self.lookup(sql, params)
        return rows[0] if rows else None

    def _load_flags(self) -> None:
        for key in sorted(self.denied | set(self.conn.columns)):
            schema, _, name = key.partition(".")
            row = self._one(_BY_NAME, (schema, name))
            if row is None:
                if key in BUILTIN_DENY_RELATIONS:
                    continue  # a catalog relation this server version does not have
                # A key that names nothing (a typo, a case mismatch) would leave the table it meant
                # fully readable: refuse the connection until the declaration is fixed.
                raise Refusal(
                    "policy.key-unresolved",
                    f"the policy of connection {self.conn.name!r} names {key}, which is not a relation "
                    "on this server (names are exact: unquoted identifiers are lower case); fix the "
                    "declaration",
                )
            self.flag_of[row[0]] = key
            for (child,) in self.lookup(_DESCENDANTS, (row[0],)):
                self.flag_of.setdefault(child, key)

    # -- step 6 ------------------------------------------------------------------------------------

    def _resolve(self, ref: NamedRef) -> Relation | None:
        parts = [ref.schema, ref.name] if ref.schema else [ref.name]
        quoted = ".".join(self._one(_QUOTE, (p,))[0] for p in parts)
        row = self._one(_RESOLVE, (quoted,))
        return _row_to_relation(row) if row else None

    def _closure(self, view: Relation, seen: set[int]) -> list[Relation]:
        reached: list[Relation] = []
        for is_rel, oid in self.lookup(_VIEW_DEPS, (view.oid, view.oid)):
            if is_rel:
                if oid in seen:
                    continue
                seen.add(oid)
                row = self._one(_BY_OID, (oid,))
                if row is None:
                    continue
                rel = _row_to_relation(row)
                reached.append(rel)
                if rel.kind in ("view", "materialized view"):
                    reached.extend(self._closure(rel, seen))
            else:
                schema, name = self._one(_PROC, (oid,))
                self._check_closure_function(view, Name(schema, name))
        return reached

    def _check_closure_function(self, view: Relation, fn: Name) -> None:
        if is_denied(fn):
            raise Refusal(
                "policy.view-function-denied",
                f"view {view.qualified} calls the denylisted function {fn}()",
            )
        if fn.schema != "pg_catalog" and str(fn) not in self.conn.allow_functions:
            raise Refusal(
                "policy.view-function-not-allowed",
                f"view {view.qualified} calls {fn}(), which is defined outside pg_catalog and not in "
                "this connection's allow_functions",
            )

    def _plan_relations(self, sql: str) -> set[tuple[str, str]]:
        plan = self.lookup("EXPLAIN (VERBOSE, FORMAT JSON) " + sql, None)[0][0]
        if isinstance(plan, str):
            plan = json.loads(plan)
        found: set[tuple[str, str]] = set()

        def walk(node) -> None:
            if isinstance(node, dict):
                if "Relation Name" in node:
                    found.add((node.get("Schema"), node["Relation Name"]))
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(plan)
        return found

    # -- steps 6 and 7 -----------------------------------------------------------------------------

    def check(self, parsed: ParsedQuery) -> list[dict[str, str]]:
        refs = _Refs()
        refs(parsed.tree)

        named: list[tuple[NamedRef, Relation, ast.RangeVar]] = []
        # Every name goes through the catalog, CTE names included: CTE scope is per query level, so
        # skipping a name because some CTE somewhere carries it let a view of that name go unchecked.
        # A CTE that shares a real relation's name gets that relation's checks (conservative).
        for ref, node in zip(refs.ranges, refs.range_nodes):
            rel = self._resolve(ref)
            if rel is not None:
                named.append((ref, rel, node))

        named_keys = {self.flag_of[rel.oid] for _, rel, _ in named if rel.oid in self.flag_of}

        # every relation flagged-or-denied that is named, at all
        for _, rel, _ in named:
            if rel.qualified in self.denied or self.flag_of.get(rel.oid) in self.denied:
                raise Refusal(
                    "policy.relation-denied", f"{rel.qualified} is not readable on this connection"
                )

        # (a) through view closures — even when the query also names the reached table directly,
        # so the closure's visited set starts empty, never with the named relations.
        seen: set[int] = set()
        for _, rel, _ in named:
            if rel.kind in ("view", "materialized view"):
                for reached in self._closure(rel, seen):
                    key = self.flag_of.get(reached.oid)
                    if reached.qualified in self.denied or key is not None:
                        raise Refusal(
                            "policy.reached-through-view",
                            f"{rel.qualified} reads {key or reached.qualified}, which this connection "
                            "restricts; query the table directly with its listed columns",
                        )

        # (b) and (c) on column-restricted tables named directly (static, before the plan)
        restricted = [(ref, rel, node) for ref, rel, node in named
                      if self.flag_of.get(rel.oid) in self.conn.columns]
        if restricted:
            self._check_columns(refs, restricted)

        # (a) through the plan
        for schema, name in self._plan_relations(parsed.sql):
            row = self._one(_BY_NAME, (schema, name))
            if row is None:
                continue
            key = self.flag_of.get(row[0])
            qualified = f"{schema}.{name}"
            if qualified in self.denied:
                raise Refusal("policy.relation-denied", f"{qualified} is not readable on this connection")
            if key is not None and key not in named_keys:
                raise Refusal(
                    "policy.reached-indirectly",
                    f"the query's plan reads {key}, which this connection restricts, without naming "
                    "it; query the table directly with its listed columns",
                )

        return [
            {"named": ".".join(filter(None, [ref.schema, ref.name])), "schema": rel.schema,
             "relation": rel.name, "kind": rel.kind}
            for ref, rel, _ in named
        ]

    def _check_columns(self, refs: _Refs, restricted) -> None:
        handles: dict[str, str] = {}  # alias or relation name -> policy key
        hidden: dict[str, str] = {}  # non-listed column name -> policy key
        restricted_nodes = []
        for ref, rel, node in restricted:
            key = self.flag_of[rel.oid]
            restricted_nodes.append(node)
            if ref.alias_columns:
                raise Refusal(
                    "policy.alias-column-list",
                    f"an alias column list on {key} can rename a restricted column; drop the list",
                )
            handles[ref.alias or ref.name] = key
            if not ref.alias:
                handles[rel.name] = key
            listed = self.conn.columns[key]
            for (col,) in self.lookup(_COLUMNS, (rel.oid,)):
                if col not in listed:
                    hidden.setdefault(col, key)

        # A JOIN's alias covers every column of the tables under it: a whole-row reference to it, or
        # an alias column list on it, reaches the restricted columns like the table's own alias would.
        for join in refs.aliased_joins:
            under = [n for n in _subtree_ranges(join) if n in restricted_nodes]
            if not under:
                continue
            key = next(self.flag_of[rel.oid] for _, rel, node in restricted if node in under)
            if join.alias.colnames:
                raise Refusal(
                    "policy.alias-column-list",
                    f"an alias column list on a join over {key} can rename a restricted column; drop "
                    "the list",
                )
            handles[join.alias.aliasname] = key

        for join in refs.natural_or_using:
            if any(n in restricted_nodes for n in _subtree_ranges(join)):
                raise Refusal(
                    "policy.natural-or-using-join",
                    "a NATURAL or USING join over a column-restricted table can expose its columns; "
                    "join with ON and name the listed columns",
                )

        for fields in refs.column_refs:
            if any(isinstance(f, ast.A_Star) for f in fields):
                raise Refusal(
                    "policy.star",
                    "* on a query that names a column-restricted table; name the listed columns",
                )
            names = [f.sval for f in fields if isinstance(f, ast.String)]
            last = names[-1] if names else None
            if last in handles and last not in self.conn.columns[handles[last]]:
                raise Refusal(
                    "policy.whole-row",
                    f"{'.'.join(names)!r} is a whole-row reference to {handles[last]}; name the "
                    "listed columns",
                )
            if names and names[-1] in hidden:
                key = hidden[names[-1]]
                raise Refusal(
                    "policy.column-not-listed",
                    f"column {names[-1]!r} of {key} is not readable on this connection (the rule is "
                    "by name: a same-named column of another table in this query is refused too)",
                )
