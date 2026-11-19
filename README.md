# cerberus

A guard between AI agents and confidential PostgreSQL databases.

**Version 0.1.0.** The contract is [`specs/sensitive-database-source.spec.md`](specs/sensitive-database-source.spec.md)
(v1.5); where this README and the Spec differ, the Spec wins. Changes: [`CHANGELOG.md`](CHANGELOG.md).

## What it is

One program that is the only holder of the database credential and the only path an agent's SQL takes
to a declared connection. It:

- refuses every write on a read connection, and states with each result and each refusal which write
  guarantee actually held (enforced by the server, or only requested by the client);
- keeps declared-sensitive tables and columns out of results, refusing every query shape it has been
  tested against that would reveal them (the known gaps are under [Residual risks](#residual-risks));
- bounds the time a query may run, on the server;
- applies each connection's encoding and schema search path without the caller setting them;
- runs a script on a writable test database only inside a transaction that is rolled back, unless a person
  authorizes a commit for that one run.

## What it is not

Not a wire-protocol proxy, not a query interpreter, and not a boundary against an agent that sets out to
defeat it: the agent runs as the same operating-system user. Its threat model is a careless agent. The
known gaps are listed under [Residual risks](#residual-risks).

## Install

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/).

```
uv tool install git+https://github.com/fppfurtado/cerberus@v0.1.0
cerberus --version
```

## Configuration

Everything cerberus reads lives in the private configuration directory, `$XDG_CONFIG_HOME/cerberus/`
(`~/.config/cerberus/` when the variable is unset). Nothing is read from the current directory or from a
repository.

### `connections.toml`

One `[connection.NAME]` table per declared connection:

```toml
[connection.reports]
host = "db.example.internal"     # required
port = 5432                      # required
dbname = "app"                   # required
user = "reader"                  # required
class = "server-enforced"        # required: "server-enforced", "client-requested" or "writable"
timeout_ms = 30000               # optional; default 30000; the server-side bound per statement
client_encoding = "UTF8"         # optional; default UTF8
search_path = ["app", "public"]  # optional; absent = the role's default
passfile = "~/.config/cerberus/pgpass"  # optional; default: pgpass in the configuration directory
hook_match = ["reports-db"]      # optional; extra strings that identify this connection in a command
deny_paths = ["~/.config/other-tool/credentials"]  # optional; other holders of this password

[connection.reports.policy]
deny_relations = ["app.audit_secret"]   # never readable, in any form
allow_functions = ["app.normalize"]     # functions defined outside pg_catalog that may be called

[connection.reports.policy.columns]
"app.customer" = ["id", "name", "city"] # ONLY these columns of this table are readable
```

- **`class`** is the guarantee you require. `server-enforced`: the server must refuse writes (a standby,
  `pg_is_in_recovery()`); a connection declared so that turns out to be a primary is refused before any
  statement of the query is sent. `client-requested`: a read-only transaction on a primary; a standby
  reports the stronger class. `writable`: a test database, used only through `run-script`.
- **`passfile`** and every **`deny_paths`** entry must be absolute or start with `~/` (`~otheruser/` is
  refused). A `deny_paths` entry
  is a file, or a directory whose every file counts.
- **Policy names are exact**: `schema.table`, unquoted identifiers in lower case. A name that is not a
  relation on the server is refused (`policy.key-unresolved`). A table under `policy.columns` exposes only
  its listed columns; a column added to it later stays unreadable until listed. Partitions and inheritance
  children of a flagged table are flagged with it.

### Password file

The password file is in libpq's `.pgpass` format, mode `0600`, outside every git working tree (cerberus
refuses a connection whose password file resolves inside one). cerberus passes it to the driver
explicitly and never reads `~/.pgpass`, `PGPASSWORD` or a prompt; it also clears every `PG*` environment
variable before connecting.

## Commands

Exit status: `0` success, `1` a `doctor` report that is not clean, `2` a usage error (bad arguments),
`3` a refusal. The hook always exits `0`; its answer is in its output.

### `cerberus query <connection> <sql> [--format json|table] [--verbose-errors]`

Runs exactly one plain `SELECT` on a read connection (`server-enforced` or `client-requested`), in a
read-only transaction under the connection's time bound, after the statement gate and the read-surface
policy pass. It prints:

```json
{"connection": "reports",
 "guarantee": {"class": "server-enforced", "basis": "pg_is_in_recovery"},
 "resolved": [{"named": "customer", "schema": "app", "relation": "customer", "kind": "table"}],
 "columns": ["id", "name"], "rows": [[1, "…"]], "row_count": 1, "elapsed_ms": 12}
```

`resolved` names the schema each relation resolved to under the search path. `--format table` prints the
rows for a person. A server error shows its SQLSTATE and first line; `--verbose-errors` shows the full
message, which can quote a value.

### `cerberus run-script <connection> <file> [--encoding NAME] [--commit] [--verbose-errors]`

Runs a script on a `writable` connection inside one transaction and **always rolls it back**. It prints
each statement's output (its command tag, and its rows when it returns any) and `"committed": false`.

- The file is read as UTF-8 (a byte-order mark dropped) unless `--encoding` names its encoding; scripts
  saved by Windows editors are usually `cp1252`. A single-byte encoding decodes any file, so a wrong name is
  not caught.
- The whole script is parsed before connecting. Transaction control (`SAVEPOINT` and `ROLLBACK TO` are
  allowed), statements a rollback does not undo, code the checks cannot read (functions, procedures,
  triggers, rules, `DO`), statements that return rows the policy does not see (`COPY … TO`, prepared
  statements, cursors), `SET`/`RESET`, denylisted functions and client meta-commands (`\…`) are refused
  then.
- On every statement: the connection's encoding, search path and time bound; the function rule; the
  read-surface policy. No expression may read a non-listed column of a flagged table; a statement may still
  write one (as a `SET` or `INSERT` target). A script may not reshape a flagged relation.
- A server error shows its SQLSTATE and condition name, not its message: in a script, a statement may
  write a restricted column, and the message can quote that value. `--verbose-errors` shows the full
  message.
- **`--commit`** commits instead, only after the connection's name is typed on an interactive terminal;
  with no terminal on stdin it is refused. An agent's shell has no terminal, so a person runs the commit.
  Each commit first appends one record to `$XDG_STATE_HOME/cerberus/commits.jsonl`
  (`~/.local/state/cerberus/` by default): time, connection, the SHA-256 of the file's bytes (it matches
  `sha256sum`), the encoding and the statement count. If the record cannot be written, the script is rolled
  back.

### `cerberus connections`

Lists the declared connections — name, class and time bound — with no host or credential.

### `cerberus doctor`

Checks custody and deployment without printing a secret, and exits `1` when anything is not clean:

- each password file: its location and mode (not clean when missing, inside a git working tree, or
  readable by group or others);
- declared connections that still have an entry in `~/.pgpass`, and `~/.pgpass` entries whose password
  equals one in custody (only the entry's host is printed);
- each `deny_paths` entry (not clean when missing, inside a git working tree, or a file readable by group
  or others);
- the hook's registration, in the user settings (`$CLAUDE_CONFIG_DIR/settings.json`, `~/.claude` when
  unset) and the managed settings file: whether a registered command runs `cerberus hook claude-code` under a
  matcher that selects each tool below; not clean when a pair is missing, when either scope sets
  `disableAllHooks: true`, or when managed settings set `allowManagedHooksOnly: true` while the hook is
  registered in user settings.

### `cerberus hook claude-code`

A Claude Code hook: it reads the event on stdin and
answers only when one of its rules applies.

- **Shell (`Bash`)**: denies a command that is not a `cerberus` invocation and names a declared
  connection's host or `hook_match` string, pointing to `cerberus query` (or `run-script` for a
  `writable` connection). It also denies any command, a `cerberus` one included, that names a protected
  path.
- **File tools (`Read`, `Edit`, `Write`, `NotebookEdit`)**: denies a protected file or a path under a
  protected directory.
- **`Grep`**: denies a search whose path (the working directory when it names none) is protected or
  contains a protected path. Search a narrower path.
- **Failed shell command (`PostToolUseFailure`)**: when the output shows an authentication failure naming
  a declared host — a script file that holds the host, which the pre-tool match cannot see — adds the
  same pointer as context.

The protected paths are each connection's password file and `deny_paths` entries, plus the default
password file path. With a connections file that is missing or not TOML, only the default password file
path stays protected; with one that parses but holds an invalid declaration, the hook still denies on every
host, `hook_match` string and path it can read.

Register it for the pre-tool event on `Bash|Read|Edit|Write|NotebookEdit|Grep` and the failed-tool event on
`Bash`, in user settings (`~/.claude/settings.json`):

```json
{
  "hooks": {
    "PreToolUse": [{"matcher": "Bash|Read|Edit|Write|NotebookEdit|Grep",
                    "hooks": [{"type": "command", "command": "cerberus hook claude-code"}]}],
    "PostToolUseFailure": [{"matcher": "Bash",
                            "hooks": [{"type": "command", "command": "cerberus hook claude-code"}]}]
  }
}
```

A guarded form that stays quiet when the binary is absent also counts for `doctor`:
`test -x <bin> || exit 0; exec <bin> hook claude-code`.

## Refusals

A refusal is printed as `{"refused": true, "rule": "<rule>", "detail": "<what and how to proceed>",
"guarantee": {…}}` with exit status `3`. It never contains a row value. `guarantee` is present on every
refusal issued after the guarantee was established; before that it is `null` and the detail says why.

| Group | Rule | Refused when |
|---|---|---|
| Configuration | `config.missing` | there is no `connections.toml` |
| | `config.invalid` | the file is not TOML, or a declaration is malformed |
| | `config.unknown-connection` | no connection has the given name |
| Custody | `custody.passfile-in-working-tree` | the password file resolves inside a git working tree |
| Connection | `connection.failed` | the server cannot be reached or rejects the login |
| | `connection.writable` | `query` is given a `writable` connection (use `run-script`) |
| | `connection.not-writable` | `run-script` is given a read connection |
| Guarantee | `guarantee.weaker-than-declared` | a `server-enforced` connection turns out to be a primary |
| Statement (`query`) | `statement.parse-error` | the SQL does not parse |
| | `statement.multiple` | more than one statement |
| | `statement.not-select` | anything other than a `SELECT` |
| | `statement.select-into` | `SELECT INTO` |
| | `statement.locking-clause` | `FOR UPDATE` / `FOR SHARE` |
| | `statement.data-modifying-cte` | a CTE that writes |
| Functions and operators | `function.denied` | a built-in on the denylist: runs SQL given as text, reads files or large objects, sets session state, moves a sequence, signals a backend, takes an advisory lock or sleeps |
| | `function.not-allowed` | a function defined outside `pg_catalog` and not in `allow_functions` |
| | `function.unknown` | a function the catalog does not have |
| | `operator.not-allowed` | an operator defined outside `pg_catalog` |
| | `operator.unknown` | an operator the catalog does not have |
| Read-surface policy | `policy.relation-denied` | a relation under `deny_relations`, or a built-in one (column statistics, credential catalogs) |
| | `policy.reached-through-view` | a view or materialized view reads a flagged relation, even when the query also names it |
| | `policy.reached-indirectly` | the query's plan reads a flagged relation it does not name |
| | `policy.view-function-denied` | a named view's definition calls a denylisted function |
| | `policy.view-function-not-allowed` | a named view's definition calls a non-allowlisted function |
| | `policy.star` | `*` in a query that names a column-restricted table |
| | `policy.whole-row` | a whole-row reference to a column-restricted table (`t`, `row_to_json(t)`, `t::text`) |
| | `policy.natural-or-using-join` | a `NATURAL` or `USING` join over a column-restricted table |
| | `policy.alias-column-list` | an alias column list (`AS t(a, b)`) on a column-restricted table or a join over it |
| | `policy.column-not-listed` | a column reference with the name of a non-listed column (by name: a same-named column of another table in the query is refused too) |
| | `policy.key-unresolved` | the policy names a relation that is not on the server |
| | `policy.reshapes-flagged-relation` | a script alters, renames or moves a flagged relation |
| Bounds and encoding | `limit.timeout` | a statement ran past the connection's bound; it was cancelled on the server (a lock wait past the bound is reported as `server.error`, SQLSTATE 55P03) |
| | `encoding.unrepresentable` | the text sent holds a character the client encoding lacks (its index is named, not the character) |
| Scripts | `script.unreadable` | the file cannot be read |
| | `script.encoding` | the file does not decode, or `--encoding` names an unknown or non-text encoding |
| | `script.empty` | the script holds no statement |
| | `script.parse-error` | the script does not parse |
| | `script.meta-command` | a line starting with `\` |
| | `script.transaction-control` | `BEGIN`, `COMMIT`, `ROLLBACK`, `PREPARE TRANSACTION`, … |
| | `script.not-undone` | `VACUUM`, `ANALYZE`, `CREATE`/`DROP DATABASE`, `CREATE`/`DROP TABLESPACE`, `ALTER SYSTEM`, `CHECKPOINT`, `DISCARD`, `CREATE INDEX`/`REINDEX CONCURRENTLY`, `COPY … PROGRAM` |
| | `script.statement-not-allowed` | `COPY … TO`, `PREPARE`/`EXECUTE`, cursors, `DO`, `CREATE FUNCTION`/`PROCEDURE`/`TRIGGER`/`RULE`/`EVENT TRIGGER`, `SET`/`RESET`, `LOAD` |
| | `script.unchecked-rows` | a statement returned rows the policy did not check |
| | `commit.no-terminal` | `--commit` with no interactive terminal on stdin |
| | `commit.not-confirmed` | the typed confirmation did not match the connection name |
| Errors | `server.error` | the server rejected the statement: SQLSTATE and first line (`query`) or condition name (`run-script`); the full message only with `--verbose-errors` |
| | `internal.error` | an unexpected failure; only the exception's class is named |

## Residual risks

What cerberus does not stop, stated in full in the Spec's Cross-cutting section:

- **Read-surface policy.** No server-side backstop exists for it. A built-in function the denylist misses;
  a relation reached through a path none of the three sources (the names, the view closure, the plan)
  shows, such as a function inside an allowlisted function; an implicit cast or a user-defined type's
  output function; a comparison the server resolves through a user-defined type's operator class
  (`BETWEEN`, simple `CASE`, `GREATEST`/`LEAST`, implicit sort, equality and partition operators, array,
  record and range operations); side channels through timing or error text.
- **Parser and server grammar.** The parser follows PostgreSQL 18's grammar; a statement only it accepts
  fails on an older server instead of at the gate. Text both grammars parse differently was not searched for.
- **Scripts.** Sequence values a rolled-back script consumed stay consumed. Code a script does not name — a
  trigger or rule already in the database, or an allowlisted function's body — can move a value into a
  readable column.
- **Custody.** The level is "not reachable by accident": an agent that deliberately reads the password file
  or disables the hook is outside the threat model. A holder of a custody password that no declaration
  lists is not protected.
- **Hook.** Its shell rules are text matching. A command reaches a protected path unrefused through a glob,
  a variable built at run time, a relative path from another directory, a recursive search over an ancestor
  directory, a script file, an un-normalized path, a quoted base apart from the rest, a path glued to an
  option or prefix, or a symlink named in the command. A short host or `hook_match` string matches as a
  substring and can deny unrelated commands. Tools other than those listed (an MCP or IDE server's) are not
  checked.
- **`doctor`'s registration check** does not read project, local or plugin settings, so a directory whose
  project settings disable hooks runs without the hook while `doctor` reports clean. It reads matchers with
  Python's regular expressions, reads a command lexically (a segment that would not run still counts), and
  resolves the binary in its own environment, not the harness's.
- **Error output.** `--verbose-errors` prints the server's full message, which can quote a value. An
  interrupt (Ctrl-C) prints Python's traceback (frames, not values); a failure while printing a refusal
  is not caught; the hook's output belongs to the harness and is not turned into a refusal.

## Development

Requires Python 3.12+, [uv](https://docs.astral.sh/uv/) and Docker.

```
uv sync
uv run pytest
```

The suite starts its own synthetic PostgreSQL primary and streaming standby in containers, bound to
`127.0.0.1`, and removes them at the end. It clears libpq environment variables first, so no test reaches
any other database. CI runs it on PostgreSQL 15 and 16.

## Provenance

The problem and the requirements come from the `sensitive-database-source` Brief and PRD in
[fppfurtado/iris](https://github.com/fppfurtado/iris) (`briefs/`, `prds/`); tracker item fppfurtado/iris#34.
The design decisions of the first build are in [`decisions/`](decisions/).

License: MIT.
