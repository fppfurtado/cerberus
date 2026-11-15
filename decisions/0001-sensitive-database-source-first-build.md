# 0001 — Build decisions for the first build of `sensitive-database-source`

- Date: 2026-11-15
- Context: the build of `specs/sensitive-database-source.spec.md` (v1, fppfurtado/iris#34), tasks SP-T1 to
  SP-T9, and the fixes of its review. These are the choices the frozen Spec left open, resolved while building. They bind the code; a Spec
  amendment may supersede them.

## D1 — A function or operator with no catalog entry is refused

The Spec checks every function and operator "against the catalog and the allowlist" and calls a name
built-in "only when every catalog entry of that name lives in `pg_catalog`". A name with no catalog entry
at all is neither: the gate refuses it (`function.unknown`, `operator.unknown`) rather than letting the
server fail on it. Default deny, consistent with the rest of the rule; the cost is a refusal where the
server would have answered "does not exist".

## D2 — Every libpq environment variable is removed before connecting

libpq fills unset parameters from `PG*` variables: `PGHOSTADDR` can send the connection to another server,
`PGOPTIONS`/`PGSERVICE` can change its settings, `PGPASSWORD`/`PGPASSFILE` are credential sources.
Explicit empty parameters do not work for all of them (`service=""` makes libpq look up a service named
""), so `open_connection` deletes every `PG*` variable from the process environment first. cerberus runs
one invocation per process, so nothing else in the process relies on them. Explicit `password=""`,
`passfile=<custody>`, `hostaddr=""`, `options=""` stay as a second line.

## D3 — The static column rules run before the plan

Rules (b) and (c) of the read-surface policy need only the parse tree and the catalog, rule (a) needs
`EXPLAIN`. The static rules run first, so a query they refuse never reaches the planner (which evaluates
some functions at plan time, Spec Risks), and the refusal names the policy rule instead of a planner error.

## D4 — `run-script` also refuses `RELEASE SAVEPOINT` and `ANALYZE`

The Spec allows `SAVEPOINT` and `ROLLBACK TO` among transaction-control statements; `RELEASE` is not
named, so it is refused with the rest. `ANALYZE` parses as the same node as `VACUUM` and its statistics
counters survive a rollback, so it is refused as "not undone" under its own name.

## D5 — JSON is loaded as text on cerberus connections

psycopg's JSON loader decodes the bytes as UTF-8 whatever the client encoding is, so reading the plan
(`EXPLAIN (FORMAT JSON)`) on a LATIN1 connection failed. `json` and `jsonb` are loaded as text, which
psycopg decodes in the connection's encoding; cerberus parses the plan itself, and a JSON column in a result
arrives as its text.

## D6 — The denylist goes beyond the Spec's minimum

Added to the Spec's families and the ported pgguard-mcp list: `cursor_to_xml*`, the `pg_ls_*dir`
readers, `pg_reload_conf`, `pg_rotate_logfile`, `pg_log_backend_memory_contexts`, `pg_notify`,
`pg_switch_wal`, `pg_promote`, `pg_drop_replication_slot`, and the prefixes `pg_stat_reset`,
`pg_wal_replay_`, `pg_backup_`, `pg_create_`, `pg_replication_origin_`, `pg_logical_`. `ts_rewrite` is
denied only in its two-argument form, the one that runs SQL text.

## D7 — The hook reads a command as segments

A shell command is split on `;`, `&&`, `||`, `|`, `&` and newlines. A segment that names a declared
connection's host or `hook_match` string is allowed only when it is itself a cerberus invocation (after
leading `VAR=value`, `env`, `command`, `exec`, or `uv run`). So `cerberus connections | grep <host>` is
denied: its second segment is not cerberus.

## D8 — `doctor` exits 1 when the report is not clean

`doctor` prints its report as JSON and exits 0 only when every password file is present, outside a working
tree and private (no group/other bits), no declared connection is still in `~/.pgpass`, and no
`~/.pgpass` entry shares a password in custody. Exit 3 stays reserved for refusals.

## D9 — Every named relation is resolved, CTE names included (review fix B1)

CTE scope is per query level; skipping any name some CTE carried let a view of that name go unchecked.
Every name goes through the catalog; a CTE that shares a real relation's name gets that relation's
checks. Over-refusal for such a CTE, not a leak.

## D10 — `run-script` refuses statements that escape the checks (review fixes B4–B6)

`PREPARE`/`EXECUTE`, `DECLARE`/`FETCH`, `COPY … TO`, `DO`, `SET`/`RESET`/`SET ROLE` and `LOAD` are refused
before connecting. As a second line, a statement that returns rows the read-surface policy did not check
(other than `SHOW` and `EXPLAIN`) stops the script, rolled back.

## D11 — A server error in a script shows the condition, not the message (amended into Spec v1.1)

The Spec (Cross-cutting) truncates a server error to "its SQLSTATE and first line". Measured: a script
statement that touches a restricted column without returning it (`UPDATE … SET id = secret::int`) fails
with a first line that quotes the value. The Spec's own invariant is that a refusal never contains a row
value, so in scripts a server error shows the SQLSTATE and the condition name only; `--verbose-errors`
shows the full text. The read path keeps the Spec's form: a query there that names a non-listed column is
refused before it runs. Amended into the Spec as v1.1 (Cross-cutting, "Errors never echo data"), by the
operator's delegation of the decision (2026-11-15).

## D12 — No expression in a script may read a restricted column (Spec v1.1)

The Spec v1 checked only the statements of a script that return rows, and stated as a residual "what a
data-modifying statement moves between columns". Measured: `CREATE TABLE … AS SELECT <restricted>` then a
read of the copy returned the value within one script, and `UPDATE … SET <listed> = <restricted>` does the
same through a listed column. The read-surface check now runs on every statement of a script (its plan
source only where `EXPLAIN` can take the statement). A restricted column may still be written, as a `SET`
or `INSERT` target, which is not a column reference; any expression reading one is refused — including in
an `EXPLAIN` or a filter (`EXCLUDED.<column>` in `ON CONFLICT` is the statement's own proposed row
and passes). Reshaping a flagged relation (any `ALTER TABLE`, rename or `SET SCHEMA` naming one: a column rename, a
detached partition, dropped inheritance) and code the script defines (functions, procedures, triggers,
rules, event triggers) are refused too: each moved the value without an expression reading it (review
B9–B11). Inside `ON CONFLICT`, only `EXCLUDED.<column>` at the clause's own level is the proposed row; in a
subquery `excluded` can alias a stored table (B12). Cost: a script that copies a restricted column on
purpose is refused; it is a job for a person with a direct client, not for the agent's carrier. The
residual left is code the statements do not name (a trigger or rule in the database, an allowlisted
function's body). Decided by the operator's delegation (2026-11-15); amended into the Spec as v1.1.

## Consequence recorded — every `information_schema` view is refused

Those views call `information_schema._pg_*` functions, which live outside `pg_catalog`, so the closure's
function rule refuses them. Over-refusal, not a leak; revisit if a session needs them.
