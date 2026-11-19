# Spec: cerberus — the outside-iris carrier for sensitive database sources (first build)

- Frozen at: 2026-11-15
- Spec version: v1.3
- Source: PRD `sensitive-database-source` v4 (frozen 2026-11-15; v4 adds this carrier to the candidate
  list and changes nothing else; lives in the iris repository,
  `prds/sensitive-database-source.PRD.md`), projected from Brief `sensitive-database-source` v3 (same
  repository, `briefs/`). Tracker item: fppfurtado/iris#34.
- Status: frozen after approval on 2026-11-15 (operator "Congelar v1 (Recomendado)" to "Congelo como v1?",
  which listed the reads below and the two recorded narrowings, PR13 and PR4)
- Independent read: ran — throughline:blind-critic, lenses J5/J6/J3/J1 + conformance vs the iris `AGENTS.md`
  and `docs/domain.md` BR01–BR07 (2026-11-15); 10 findings (3 High), all acted on in this text: the
  read-surface rule rebuilt on three server sources after four unlisted forms were measured to leak; the
  guarantee carried on refusals; `run-script` given the read path's guards; the candidate set amended at
  the PRD; W1/W2/W5 moved to the gate task; deploy split from replay; two over-stated measurements
  corrected. Conformance clean. The fixes were not re-read (one read, no re-pass): the read-surface rule as
  a whole first runs in SP-T3 and SP-T5. Validated text: no record
- Amendments: v1 → v1.1 (2026-11-15), from the build's review (fppfurtado/cerberus#2). (1) Rollback-only
  scripts: no expression of any statement may read a non-listed column of a flagged table (a statement may
  still write one, as a `SET` or `INSERT` target); v1 checked only statements that return rows, and a
  `CREATE TABLE … AS SELECT <restricted>` followed by a read of the copy returned the value in one script
  (measured on the fixture); reshaping a flagged relation (a column rename, a detached partition, dropped
  inheritance) and code the script defines (functions, procedures, triggers, rules) are refused for the same
  reason (each measured to move the value; event triggers are refused by extension, not measured). The
  residual in Deliberate exclusions narrows accordingly and joins the M5 list. (2) Cross-cutting,
  errors: in scripts a server error shows its SQLSTATE and condition name only; v1's "SQLSTATE and first line"
  quoted a restricted value (`UPDATE … SET id = secret::int`, measured). Approval: the operator delegated the
  decision ("Delego as três decisões", 2026-11-15); decided by the agent with the reasoning stated in the
  session and in `decisions/0001` D11–D12.
  v1.1 → v1.2 (2026-11-19), from the build's ledger and the final review (fppfurtado/cerberus#5, #4).
  (1) The M5 residual list gains two residuals found in the first build and left out of v1.1: a comparison
  the server resolves through a user-defined type's operator class (the class of the `BETWEEN` case #5
  named; its review found `CASE`, `GREATEST`/`LEAST`, implicit sort, equality and partition operators, and
  built-in array, record and range operations in it), and
  the grammar-version gap between the parser and the server. (2) Choices: the `pglast` claim "the gate and the server cannot disagree" is qualified to the
  grammar version, and the `psycopg` claim "encodes per the connection's client encoding" is qualified to
  exclude its JSON loader (fppfurtado/cerberus#7, reported upstream as psycopg/psycopg#1504). (3) Records:
  the v1.1 entry above now names event triggers, as the body and D12 already did, marked as refused by
  extension, not measured; the body states the `EXCLUDED` exemption's scope, until now in D12 only, and
  D12 records the over-block it costs. No rule of the gate changes; the code is untouched. Approval: the
  operator's merge of the pull request that carries this text.
  v1.2 → v1.3 (2026-11-19), from SP-T10's deployment and its review (fppfurtado/cerberus#6, #9, #10).
  (1) Hook: what it protects is now a set of paths, not one file: each connection's password file, the
  other holders of that connection's password the declaration lists (`deny_paths`), and the default
  password file path whatever the declaration says. The file-tool deny covers `Grep` (v1.2 let `Grep` read
  the password file: tested), including a search over a directory that contains a protected path; and a
  shell command that names a protected path is denied (v1.2 let `cat <password file>` through). (2) Hook on
  a broken connections file: v1.2 went silent on any `config.invalid`; v1.3 keeps what it can read. (3)
  `doctor`'s "whether the hook is registered", listed since v1 and never specified or built, is specified,
  and `doctor` reports the declared other holders (#9). A `passfile` must now be absolute or start with
  `~` (valid in v1.2 when relative; the deployment declares none).
  (4) Deployment text: SP-T10 as executed — the `uv tool` channel's home, the Bitwarden items, the scope of
  the in-tree credential copies and the holders outside the trees (Tech choices, SP-T10, Deliberate
  exclusions). (5) Facts measured at SP-T10 on the case study enter Risks; no Assumption changes. (6)
  SP-T11 gains step (0) — the deployment brought to v1.3, the operator's yes on the residuals v1.3 adds,
  the suite on PostgreSQL 15 — and asserts the two log-history primaries' guarantee in (b). Approval: the
  operator's merge of the pull request that carries this text.
- Branch taken (PRD v3 "Branches on J5 test 1"): test 1 ended without an answering verdict (attempt 1
  INCONCLUSIVE, attempt 2 HELD, attempt 3 designed and not funded; iris#34 comment of 2026-11-13) and no
  further test-1 budget is recorded, so the first build (PR1–PR6, PR8a, PR9–PR11, PR13) is entirely outside
  iris. PR7 and PR8b are not in this build (PRD Scope; carried by fppfurtado/iris#73).
- Home (operator, 2026-11-15): a new public repository, `cerberus`. This Spec is that repository's first
  contract and lives in its `specs/`.
- Private inputs (gitignored, never in a public repository, PR11): the M1 replay instantiation
  (`m1-private-instantiation.md`) and the probe scripts and outputs (`spec-first-build-probes/`), both in
  the iris session dossiers of 2026-11-15.

## Design

### Architecture

**What is built.** One small Python program, `cerberus`, that is the only holder of the database
credentials and the only path an agent's SQL takes to a declared connection. It has three entry points:

- `cerberus query <connection> <sql>` — the read carrier (PR2–PR6, PR8a).
- `cerberus run-script <connection> <file>` — the rollback-only write carrier for `writable` connections
  (PR10).
- `cerberus hook claude-code` — reads a pre-tool event on stdin and refuses a direct database client aimed
  at a declared connection, pointing to the two commands above (PR9).

plus `cerberus connections` (list declared connections, no secrets) and `cerberus doctor` (custody and
deployment checks, PR13).

**Read path, per query.** Each step refuses with a named rule; nothing later runs after a refusal.

1. Load the connection's declaration; check credential custody (PR13).
2. Open the connection with the declared client encoding and search path; `BEGIN TRANSACTION READ ONLY`;
   `SET LOCAL statement_timeout` (and `lock_timeout`) to the connection's bound.
3. Establish the write guarantee against the server (below). Refuse if weaker than declared. From here on,
   every result AND every refusal carries the guarantee (PRD M2).
4. Parse the SQL with the real PostgreSQL grammar. Accept exactly one statement, a plain `SELECT` (no
   `SELECT INTO`, no locking clause, no data-modifying CTE). Collect the relations, functions, operators,
   column references and alias column lists it names. The read-only transaction alone is not the write
   guard: measured 2026-11-15, it refuses a temporary-table create but allows `ANALYZE`.
5. Check functions and operators against the catalog and the allowlist (below).
6. Resolve what the query reaches, from three server sources: (i) each named relation, resolved under the
   search path; (ii) the dependency closure of every named view or materialized view — the relations and
   functions its definition uses, recursively, read from the catalog; (iii) every relation the query's plan
   scans (`EXPLAIN (VERBOSE, FORMAT JSON)`, which does not execute it). A flagged table's partitions and
   inheritance children are flagged with it.
7. Apply the read-surface policy to that set and to the query's column references.
8. Execute; return rows with the guarantee and the resolved relations; `ROLLBACK`.

**Why the server is in the path (measured, 2026-11-15, PostgreSQL 16, synthetic data; private probes
dossier).** Result-column origin (the wire protocol's table/column ids) marks a flagged column only for direct
forms; it is empty for an expression, a whole-row cast, `row_to_json`, an aggregate and a `UNION`, and names
the view, not the table, for a view (15 forms probed; every one returned the flagged value). The plan showed
the flagged table in 19 of the 21 rows probed (the other two: SQL passed as text to a function, and a query
on an unrelated table), including behind a view, a CTE and a subquery; an unqualified name resolved through
the search path was shown separately (2 queries). The plan alone still misses, each measured to return the
flagged value: a materialized view (the plan names only the materialized view), a view whose definition
calls a function that reads the table (the plan names nothing), and a function that runs SQL given as text
(`query_to_xml`, `ts_stat`). The catalog closure showed the table behind the materialized view and the
function behind the view. Parse analysis alone (what the best existing server does) cannot resolve a view
or a search path without the server. No single source is complete; the design uses the three together plus
the function rule, and the residual is stated (Cross-cutting).

**Arrangement — options, decision, consequences.**
- **Chosen: one process-per-invocation CLI that holds the credential (a statement-level carrier on the data
  path).** It serves every PR of this branch with one component, needs no daemon, and is reachable from any
  session and directory once installed (PR8a).
- A PostgreSQL wire-protocol proxy (the PRD's P: every client, `psql` included, goes through the guard).
  Not chosen for this build. The one existing open-source proxy with a parsed column policy leaked the
  flagged column in 4 forms when run (table below) — a flaw of that project, not of the class. A wire front
  over this build's own guard was not built or measured; it is set aside on cost alone, and that cost is an
  estimate with no measurement behind it (a wire front must implement start-up and authentication, the simple
  and extended query protocols, COPY and cancel requests). Its one advantage — covering a direct client by
  interception — is served here by credential custody plus the hook (the PRD's C4 row keeps both). Reopen if
  a session list shows clients the hook cannot see (Assumptions).
- A daemon under a separate OS user holding the credential (a real OS boundary for PR13). Declined by the
  operator for this build (2026-11-15): the PRD's threat model is a careless agent, and the daemon roughly
  doubles the build. Armed in Deliberate exclusions.
- An MCP server. Not required by any PR on this branch (PR8b is SUPPORTED-only); the CLI already gives reach.
- Adopting an existing server and wrapping it. Weighed in Tech choices; lost.

**Candidate set.** PRD v3 chose "among P, A1 and A3" and gives P a property this carrier does not have
(a proxy "covers every client, `psql` included"). The chosen carrier is the guard the PRD called G, built
outside iris. PRD v4 (2026-11-15) adds it to the candidate list as S, a standalone statement-level carrier
outside iris; this Spec is frozen against v4.

### Data model

**Connection declaration** — one private file, `connections.toml` in the configuration directory
(`$XDG_CONFIG_HOME/cerberus/`, `~/.config/cerberus/` when the variable is unset; PR1; the instance lives
only here):

```toml
[connection.NAME]
host = "…"; port = 5432; dbname = "…"; user = "…"
class = "server-enforced"        # or "client-requested" or "writable"
timeout_ms = 30000               # default when absent: 30000
client_encoding = "UTF8"         # default when absent: UTF8
search_path = ["…", "…"]         # optional; absent = the role's default
passfile = "~/.config/cerberus/pgpass"   # example; the default is pgpass in the configuration directory;
                                         # libpq format; absolute or ~ (v1.3)
hook_match = ["…"]               # optional extra strings that identify this connection in a command
deny_paths = ["…"]               # optional other holders of this connection's password (v1.3): a file,
                                 # or a directory whose every file counts

[connection.NAME.policy]
deny_relations = ["schema.table", …]                 # whole relation never readable
allow_functions = ["schema.function", …]             # non-built-in functions allowed

[connection.NAME.policy.columns]
"schema.table" = ["col_a", "col_b"]                  # ONLY these columns of this table are readable
```

**Result** (JSON by default; `--format table` for a person):

```json
{"connection": "NAME",
 "guarantee": {"class": "server-enforced", "basis": "pg_is_in_recovery"},
 "resolved": [{"named": "t", "schema": "s", "relation": "t", "kind": "table"}],
 "columns": ["…"], "rows": [["…"]], "row_count": 0, "elapsed_ms": 0}
```

**Refusal**: `{"refused": true, "rule": "<rule id>", "detail": "<what and how to proceed>", "guarantee":
{…}}`, exit status 3. A refusal never contains a row value. `guarantee` is present on every refusal issued
after step 3 of the read path; a refusal before it (custody, an unreachable server, a connection weaker
than declared) says why none was established.

**Commit authorization record** (PR10(b)): one line appended to `~/.local/state/cerberus/commits.jsonl` —
timestamp, connection, script SHA-256, statement count.

### Interfaces / contracts

- **Write guarantee (PR2).** Inside the read-only transaction and before the query, cerberus runs
  `pg_is_in_recovery()` and reads `transaction_read_only`. In recovery → `server-enforced` (a standby
  refuses writes whatever the role does). Not in recovery, transaction read-only → `client-requested`. A
  connection declared `server-enforced` that establishes `client-requested` is refused before the query's
  statement is sent. The standby branch is not yet measured (the probes ran on a primary); SP-T3 tests it
  on a real standby. A connection declared `client-requested` that establishes `server-enforced` reports the
  stronger class. "Server-enforced by privileges on a primary" is not recognized in this build (it reports
  `client-requested`).
- **Function and operator allowlist (PR4, PRD R1).** Checked on the open connection (step 5). A function
  or operator defined outside `pg_catalog` is refused unless it is in the connection's `allow_functions`
  (default deny — the property the best existing server lacks: measured, its list let a database-defined
  function return the flagged column). A name counts as built-in only when every catalog entry of that name
  lives in `pg_catalog`. Built-in functions pass unless on the built-in denylist — a list, so a built-in
  that executes SQL text and is missing from it would pass; that residual is stated at M5. The denylist is
  at minimum: everything that executes SQL given as text (the `*_to_xml*` family, `ts_stat`, `ts_rewrite`
  with a query argument, `dblink*`), file and large-object readers (`pg_read_file`, `pg_ls_dir`, `lo_*`, …),
  session-state setters (`set_config`), sequence movers (`nextval`, `setval`), backend signals
  (`pg_cancel_backend`, `pg_terminate_backend`), advisory locks and `pg_sleep*`. The starting list is ported
  from the hostile-input suite of `pgguard-mcp` (MIT) with attribution. The same rule applies to every
  function in the dependency closure of a named view.
- **Read-surface policy (PR4).** Deny by default on a flagged table: a table under `policy.columns` exposes
  only its listed columns; a relation under `deny_relations` exposes nothing. With "reached" meaning the set
  of step 6, a query is refused when:
  (a) a flagged relation is reached other than by being named directly in the query — through a view, a
  materialized view, or the plan — including when the same query also names it directly;
  (b) a flagged table is named directly and the query uses `*`, a whole-row reference, a `NATURAL`/`USING`
  join over it, or an alias column list on it (`AS t(a, b, …)`, measured to rename the flagged column);
  (c) any column reference in the query has the name of a non-listed column of a flagged table it names
  (name-based and conservative: a same-named column of another table in the same query is refused too, with
  a message saying so).
  The non-listed columns are computed from the live catalog, so a column added later is denied until
  listed. Statistics relations that expose column samples (`pg_stats`, `pg_statistic`, extended statistics)
  and credential catalogs are in a built-in `deny_relations` list.
- **Rollback-only scripts (PR10).** `run-script` accepts only a `writable` connection. It parses the whole
  script first and refuses, before connecting: any transaction-control statement (`BEGIN`, `COMMIT`, `END`,
  `ROLLBACK`, `PREPARE TRANSACTION`, …; `SAVEPOINT` and `ROLLBACK TO` are allowed), any statement that cannot
  run inside a transaction or whose effect a rollback does not undo (`VACUUM`, `CREATE DATABASE`,
  `CREATE INDEX CONCURRENTLY`, `ALTER SYSTEM`, `COPY … PROGRAM`), denylisted functions, and client
  meta-commands (lines starting with `\`). It then runs the statements in one explicit transaction, returns
  each statement's output (rows or command tag) and always issues `ROLLBACK`. Measured 2026-11-15: a
  procedure that commits internally fails inside the explicit transaction (`invalid transaction
  termination`) and leaves no row. The script path carries the same guards as the read path where they
  apply: the connection's encoding and search path; the time bound on every statement; the function rule on
  every statement; and steps 6–7 of the read path on every statement that names a flagged relation (the
  plan source where the statement can be explained) — a statement in which any expression reads a
  non-listed column, or that returns rows reaching a flagged relation outside the policy, is refused and the
  script stops (rolled back). A statement may write a restricted column (as a `SET` or `INSERT` target, or
  from the statement's own proposed row, `EXCLUDED.<column>` at the `ON CONFLICT` clause's own level — a
  subquery inside it that reads a restricted column through `excluded` is refused, an over-block kept on
  purpose, D12): what it may not
  do is read a stored one. For
  the same reason a script may not reshape a flagged relation — no `ALTER TABLE`, rename or `SET SCHEMA`
  naming one, which covers renaming its columns (the policy lists columns by name) and detaching a
  partition or dropping inheritance (the policy flags children through the tree) — and may not define code
  the checks do not read (`CREATE FUNCTION`/`PROCEDURE`/`TRIGGER`/`RULE`/`EVENT TRIGGER`, `DO`), so no value
  moves to a readable place (v1.1). `--commit` replaces the final `ROLLBACK` with `COMMIT` only after a
  confirmation typed on an interactive terminal (the connection name); with no terminal on stdin it is
  refused. An agent's shell has no terminal, so the operator runs a commit himself.
- **Hook (PR9).** `cerberus hook claude-code` reads the harness's pre-tool event. For a shell command it
  denies when the command is not itself a `cerberus` invocation and its text contains a declared connection's
  host or one of its `hook_match` strings. The denial names the connection and the command to use instead
  (`query` for read classes, `run-script` for `writable`). An event that none of the hook's rules here
  selects (the deny rules, and the failed-tool context below) gets no answer.
  **Protected paths (v1.3).** The set is: each declared connection's password file and each entry of its
  `deny_paths` (the other holders of that connection's password: a file, or a directory, every file under
  which counts), plus the default password file path always (`pgpass` in the configuration directory,
  `$XDG_CONFIG_HOME/cerberus/`, or `~/.config/cerberus/` when the variable is unset in the hook's
  process). A `passfile` or `deny_paths` entry must be absolute or start with `~`, else the declaration is
  `config.invalid`. The connections file is not protected: it holds no password, and `cerberus
  connections` already shows what of it an agent needs (#6's wider option, the whole directory, is
  narrowed for that reason). A file tool (`Read`, `Edit`, `Write`, `NotebookEdit`, and `MultiEdit` for a
  harness version that still has it) is denied on a path that is a protected file or lies under a
  protected directory. A content search (`Grep`) is denied when its search path — the event's working
  directory when it names none — is protected as above or contains a protected path; whether the search
  tool would skip a hidden or ignored file is not relied on. The cost is stated: a `Grep` with no path in a
  session whose working directory is the home directory is denied, and so is one whose `glob` would have
  excluded the protected file; the denial says to search a narrower path. Paths are compared resolved,
  symlinks followed; a relative path in an event resolves against the event's working directory. A
  filename search (`Glob`) reads no content and is not checked. A path denial, in any tool, says the path
  holds a cerberus credential and is read only by cerberus or its own tool.
  A shell command is denied when any part of it — a `cerberus` invocation included, since `cerberus` never
  takes a password holder as an argument — names a protected path in one of these spellings: as declared,
  resolved, with the home directory written `~`, `$HOME` or `${HOME}`, or with the configuration base
  written `$XDG_CONFIG_HOME` or `${XDG_CONFIG_HOME}`. A spelling counts as named where it starts the
  command or follows whitespace, a quote, `=`, `:`, `(`, a backtick or a shell operator, and where it ends
  the command or is followed by whitespace, a quote, `/`, `)`, a backtick or a shell operator — so a
  protected directory named with a path below it counts, and a protected `/x/.env` does not match
  `/x/.envrc`. A command is also denied when it names, the same way, a protected path's parent directory
  and, anywhere in it, the protected path's last component at the same boundaries or after a `/` (so
  `cd <dir> && cat <file>` and `cat ./<file>` count). That rule over-blocks a command that names the
  directory and merely uses the word, such as `ls ~ && echo <name>`; for a holder directly under the home
  directory with a common name, that is any command that names a path under the home directory, in any
  listed spelling, and contains the name. Like the host match,
  this is text matching at the careless-agent level, not a boundary; the escapes known are listed in
  Cross-cutting.
  **A broken connections file (v1.3).** A missing or unreadable file, or one that is not TOML, leaves only
  the default password file path protected. A file that parses as TOML but holds an invalid declaration
  (every `cerberus` command that reads it then refuses with `config.invalid`, `doctor` naming the error)
  still protects what it shows: from each `[connection.NAME]` table the hook takes every non-empty string
  it finds under `host` and `hook_match`, and every absolute or `~` string under `passfile` and
  `deny_paths`, ignoring other values. A shell denial on such a host names the connection and says the
  connections file is invalid, so no `cerberus` command works until it is fixed and `cerberus doctor`
  names the error; it points to no command. As in a valid file, a short host or `hook_match` string
  matches as a substring, so it may deny many commands; the hook errs toward denying.
  Refusal with a pointer was
  chosen over rewriting the command into a cerberus call (PRD R4's routing option): a direct client's flags
  and scripts do not translate losslessly. A direct client the pre-tool match cannot see (a script file that
  holds the host) fails at the server for lack of a credential; for that case the hook also handles the
  harness's failed-tool event: when a failed command's output shows an authentication failure naming a
  declared host, it adds the same pointer as context. Whether the harness lets a hook add context on a
  failed tool is read from its reference at SP-T9; if it does not, that case is refused without a pointer
  and the narrowing is recorded then (amendment).
- **Credential custody (PR13).** cerberus passes an explicit password file to the driver and never reads
  `~/.pgpass`, `PGPASSWORD` or a prompt. It refuses a connection whose password file resolves (symlinks
  followed) to a path inside a git working tree, naming the path class, not the path. `cerberus doctor`
  reports, without printing a secret: the password file's mode and location; any declared connection that
  still has an entry in `~/.pgpass`; any `~/.pgpass` entry whose password equals one in custody (compared in
  memory; only the entry's host is printed); whether the hook is registered. For each `deny_paths` entry
  (v1.3, #9) it also reports whether it exists, whether it sits inside a git working tree, and, for a file,
  whether it is readable by group or others; any of the three makes the report not clean (a missing entry
  is a mistyped or stale declaration, which protects nothing while the real holder stays readable).
  The registration check (v1.3) reads the two settings scopes that apply to every session of the user: the
  user settings (`settings.json` in `$CLAUDE_CONFIG_DIR`, `~/.claude` when unset), where the deployment
  registers the hook, and the managed settings file (`/etc/claude-code/managed-settings.json` on Linux,
  `/Library/Application Support/ClaudeCode/managed-settings.json` on macOS). For each event and tool the
  hook serves — the pre-tool event for `Bash`, `Read`, `Edit`, `Write`, `NotebookEdit` and `Grep`, and the
  failed-tool event for `Bash` (`MultiEdit` is not required: the current harness reference lists no such
  tool) — it reports whether a registered command runs the hook under a matcher that selects that tool. A
  command runs the hook when its first program word, after environment assignments, `env` and `uv run`, is
  named `cerberus` and the words `hook claude-code` follow. Matchers are read by the rules of the Claude
  Code hooks reference (read 2026-11-19): omitted, empty or `*` matches all; one made only of letters,
  digits, `_`, `-`, spaces, `,` and `|` is a list of exact names; anything else is an unanchored
  JavaScript regular expression, evaluated here with Python's `re.search` (a pattern Python cannot compile
  counts as selecting nothing; the two dialects agree on the alternations and anchors matchers use, and
  any other difference is a stated residual). Not clean: a missing pair; `disableAllHooks: true` in either
  scope; or managed settings with `allowManagedHooksOnly: true` while the registration is in user settings.
  Not read, so not reported (Cross-cutting): project and local settings, which apply per directory, and
  plugin hooks.

### Tech choices

- **Own build in Python over adopting an existing carrier.** Each candidate was read in source and the two
  strongest were run against a synthetic PostgreSQL 16 on 2026-11-15 (containers; same 27–33 cases; outputs
  in the private probes dossier). Each disqualifier is marked intrinsic or swappable.

  | Candidate (PRD class) | Measured / read | Disqualifier — intrinsic? |
  |---|---|---|
  | `pgguard-mcp` 0.1.0 (A1: best existing server; TypeScript, MIT, one push on 2026-07-29, 0 stars) | RAN. Refused all 7 write and setting cases and 19 of the 20 flagged-column forms in its run; timeout cancelled on the server. Not run against the forms added after the blind read (alias column list, materialized view, partition). LEAKED through a database-defined function (it denies functions by list; an unlisted one passes). Refused an unqualified table name outside `public`. | Database-defined functions pass unless listed: swappable only by patching (a list entry fixes one function, not the default). No guarantee field (PR2), no search path (PR6(b) fails as measured), no rollback-only mode (PR10), one database per process, no CLI: each needs a fork in a language outside the operator's stack, or a wrapper as large as the guard. Not intrinsic to the approach — which this build reuses — but to adopting this project. |
  | AgentIAM `d463a9c` (P: wire proxy; Go, Apache-2.0, 2 stars) | RAN. LEAKED the flagged column through a whole-row select, a whole-row cast, a view and a database function (4 of 27 cases). It accepted `set_config` written with a computed name, but a later heavy query on the same client session was still cancelled at the bound. No read-only transaction (read). | Swappable only by patching its masking engine; its own security notes list the view leak as unresolved. |
  | `crystaldba/postgres-mcp` `15c8e33` (A1 of the S4 probe) | Probed 2026-11-12 (S4): refuses writes; no column policy, no guarantee, two modes only. Re-read 2026-11-15: unchanged since 2026-08; not installable as published (pins parser versions no longer on PyPI). | No column policy: intrinsic to the project as shipped. |
  | hoop sidecar, dbveil, DBHub, pii-safe-db-mcp (A1/P) | Read, not run. Column rules keyed on the result's column label or on value patterns (hoop, dbveil), none at all (DBHub), or on result-column origin (pii-safe-db-mcp). | Label and origin keys miss the forms measured above (alias, expression, whole row, view): intrinsic to the keying. NOT RUN — a reading of source and READMEs, not a measurement. |
  | A3 alone (a harness hook on the direct client) | PRD probes 2026-11-12: client-injected settings are undone by an in-SQL `SET`; wrapping a script in `BEGIN … ROLLBACK` is defeated by an inner `COMMIT`. A post-tool output replacement works but sees only formatted text. | For PR3/PR5/PR10: intrinsic to a client-requested setting. For PR4: it would need this same query analysis, covers one harness, and where harness telemetry is on, the original output is captured first (PRD R5). Kept only as the router/refusal of PR9. |

  Per job (PRD M4; RAN = executed 2026-11-15 or in the S4 probe of 2026-11-12, READ = source read only):

  | Job | crystaldba (A1) | pgguard-mcp (A1) | A2 native controls | A3 hook alone | AgentIAM (P) | Verdict |
  |---|---|---|---|---|---|---|
  | J1 refuse writes | pass (RAN) | pass (RAN) | infeasible (operator, 2026-11-12) | fail: undone by `SET` (RAN) | pass on the cases run, no read-only transaction (RAN) | built on the parser + read-only-transaction approach both passing servers use |
  | J1 report / refuse weaker | fail (READ) | fail (READ) | infeasible | fail: no connection concept | fail (READ) | built; no candidate has it |
  | J2 sensitive objects | fail: none (RAN+READ) | 19 of 20 forms, leaks by database function (RAN) | infeasible | needs the same analysis; one harness (RAN for the replacement itself) | fail: 4 leaks (RAN) | built: deny by reference + server plan + function allowlist |
  | J3 load bound | pass, fixed 30 s (RAN) | pass, configurable (RAN) | infeasible | fail: undone by `SET` (RAN) | pass on the cases run; accepts a computed `set_config` name (RAN) | built on the server-side timeout both passing servers use |
  | J4 preconditions | encoding pass, schema inconclusive (RAN) | encoding pass, unqualified name outside `public` refused (RAN) | infeasible | pass for defaults (PRD) | not configurable (READ) | built: declared per connection, resolution reported |
  | J7 rollback-only | fail: two modes (READ) | fail: no write path (READ) | infeasible | fail: inner `COMMIT` (RAN) | fail (READ) | built: parse, one transaction, always roll back |

  The guard is written on the approach, not vendored from `crystaldba/postgres-mcp`: its guard is tied to a
  parser pin that no longer installs (PRD R2), and the column policy and plan check have no counterpart
  there to vendor.

  Total cost of the own build: one small package and its tests, in the stack the operator already runs
  (Python, uv). What it reuses: the PostgreSQL grammar through `pglast`; `pgguard-mcp`'s deny-by-reference
  design and its hostile-input cases as test corpus.
- **`pglast` (the PostgreSQL parser as a library) over `sqlglot`.** `pglast` is PostgreSQL's own grammar, so
  the gate and the server agree on what a statement is, within one grammar version (v1.2: `pglast` 8.8
  parses the PostgreSQL 18 grammar and older servers run older ones; a statement only the newer grammar
  accepts passes the gate's parse and fails on the server as `server.error`; text both grammars accept
  but parse differently was not searched for, and no task plans that search; both stated at M5); `sqlglot` is an independent grammar whose
  authors of a sibling project document edge-case disagreement. Retrieved 2026-11-15: `pglast` 8.8
  (2026-11-13, PostgreSQL 18 grammar) on PyPI. Pin an exact version (PRD R2: an upstream project broke on an
  unpinned-then-vanished parser release).
- **`psycopg` 3 (binary) as the driver.** It encodes per the connection's client encoding (the recorded
  false zero came from a terminal/encoding mismatch in the direct client, S4 E1) and exposes the server's
  cancel and timeout errors. Retrieved 2026-11-15: 3.3.9. One exception, measured in SP-T6 (v1.2): its
  `json`/`jsonb` loader decodes as UTF-8 whatever the client encoding is, so cerberus loads both types as
  text (fppfurtado/cerberus#7, reported upstream as psycopg/psycopg#1504).
- **Server `statement_timeout` as the bound (PR5), not a client timer.** Measured 2026-11-12 (S4): killing a
  client leaves its backend and parallel worker running. A server-side bound holds even if cerberus dies.
- **No pooling, one connection per invocation.** The job is keyed, occasional lookups (Brief F7). Connection
  setup cost is paid per query; revisit only on evidence.
- **Deployment through the operator's existing env-stack homes** (dotfiles `CLAUDE.md`, sections "Secrets via
  Bitwarden" and "Repos relacionados", read 2026-11-15): the connections file and the password file are
  rendered by chezmoi from Bitwarden items of the work account as `private_` templates under the
  operator's work context; the hook is registered through the dotfiles settings template; the tool is
  installed through the `uv tool` channel; the repository enters the `mr` inventory. As deployed (SP-T10,
  2026-11-19, v1.3): the `uv tool` channel lives in the dotfiles repository, not the loadout, so the whole
  deployment landed in dotfiles; the connections file joins two items, because one Notes field holds at
  most 10000 encrypted characters and the policy repeats per connection; the password file is rendered
  from one item, except that the personal role's password is taken from an existing item the operator
  already keeps current, so the vault holds no second copy of it (holders outside the vault: Deliberate
  exclusions).

### Cross-cutting

- **Custody of instance data (PR11).** Code, tests, fixtures, docs and commit messages name no instance.
  Tests run against a synthetic database started by the test fixture. The private identifier list stays
  outside the repository; the M3 grep is an operator-present task.
- **Errors never echo data.** A refusal or a database error returns the rule and the server's error class,
  never a row value. On the read path a server error is truncated to its SQLSTATE and first line (a query
  there that names a non-listed column is refused before it runs); in a script, where a statement may write
  a restricted column, it shows its SQLSTATE and condition name only (v1.1). `--verbose-errors` shows the
  full text.
- **Residual risks stated to the operator at M5 (PRD R1).** No server-side backstop exists for PR4. Known
  residuals of this design: a built-in function that this Spec's denylist misses; a relation reached only
  through a path none of the three sources shows (for example a function inside an allowlisted function); an implicit cast or a
  user-defined type's output function; a comparison the server resolves through a user-defined type's
  operator class, which may run a user-defined operator the allowlist never sees — where the query names
  no operator (`BETWEEN` in its four kinds, whose keyword the parser records instead of an operator, so the
  gate does not check it; simple `CASE`; `GREATEST`/`LEAST`; the sort and equality operators of `ORDER BY`
  without `USING`, `DISTINCT`, `GROUP BY`, window `PARTITION BY`, set operations and `USING`/`NATURAL`
  joins), and where a built-in array, record or range operation compares the elements of such a type
  (v1.2); the grammar-version gap: a statement only
  the parser's newer grammar accepts fails on the server instead of at the gate, and text both grammars
  accept but parse differently was not searched for (v1.2); side channels through timing or
  error text; sequence values consumed
  by a rolled-back script; on a `writable` connection, code a script's statements do not name — a trigger
  or rule already defined in the database, or an allowlisted function's body — moving a value into a
  readable column (v1.1). The custody level is "not reachable by accident": an agent that deliberately
  reads the credential file or disables the hook is outside this build's threat model (PRD Assumptions).
  The hook's path match is text matching (v1.3). A shell command reaches a protected path unrefused through
  a glob, a variable assembled at run time, a relative path from any directory other than the file's own
  (`cd ~ && cat .config/…`), a recursive search over an ancestor directory (`grep -r x ~`), or a script
  file; a path written un-normalized (`~/.config/./cerberus/pgpass`, `//`, `..`); a base written in quotes
  apart from the rest (`"$HOME"/.config/…`); a path glued to an option or
  prefix the boundaries do not list (`-f/path`, `@/path`, `file:///path`); a symlink to the holder named in
  the command (the shell rule matches text; only the file tools and `Grep` resolve links). A holder of a
  custody password that no declaration lists is not protected at all. A tool outside
  the listed ones that reads files (an MCP or IDE server's) is not checked. A connections file that is
  missing, unreadable or not valid TOML leaves only the default password file path protected (every
  `cerberus` command that reads it refuses then, and `doctor` names the error). `doctor`'s registration check does
  not see project, local or plugin settings, so a directory whose project settings disable hooks runs
  without the hook while `doctor` reports clean; and it reads a matcher's JavaScript regular expression
  with Python's engine, so a pattern using a construct the two read differently may be misreported.

### Durable invariants

- **CB01:** every statement cerberus sends to a declared connection is sent by one module (the guarded
  session), after the gate for its entry point has passed; no other module opens a database connection.
  (carrier: sensor: a test in the suite fails when a driver `connect` call appears outside the guarded-session
  module — run at every change by CI.)

## Task plan

- SP-T1: Create the `cerberus` repository (public, MIT, Python ≥ 3.12, `uv`, `pglast` and `psycopg` pinned
  exactly), with CI running the test suite against a synthetic PostgreSQL primary and standby started by the
  fixture, the throughline operational floor in `AGENTS.md`, a `catalog-info.yaml` descriptor, this Spec
  under `specs/`, and a README stating what the tool is and is not — implements PR11 — acceptance (EARS):
  "WHEN CI runs on a clean checkout, the system SHALL start a synthetic primary and standby, run the suite
  and pass with no network access to any other database"; "the repository SHALL contain no host, database,
  schema, table or column name of a real instance" (checked at SP-T11) — depends on: — (operator acts: create
  the GitHub repository; choose the constellation cluster for the descriptor)
- SP-T2: Connection declarations and credential custody — implements PR1, PR13 — acceptance (EARS): "WHEN a
  declared connection is requested, the system SHALL read host, database, role, class, bound, encoding and
  search path from the private connections file and nothing from the repository"; "IF a connection's
  password file resolves to a path inside a git working tree, THEN the system SHALL refuse the connection
  and name the path class, not the path"; "the system SHALL NOT read `~/.pgpass`, `PGPASSWORD` or a prompt
  for a declared connection" (test: with a valid `~/.pgpass` entry and no custody entry, the connection
  fails for lack of a credential); "WHEN `cerberus doctor` runs, the system SHALL report each declared
  connection still present in `~/.pgpass` and each `~/.pgpass` entry sharing a password in custody, printing
  no secret"; "WHEN `cerberus doctor` runs, the system SHALL report, for each event and tool the hook
  serves, whether the user or managed settings register `cerberus hook claude-code` under a matcher that
  selects it, and SHALL NOT report clean while one is missing or while those settings disable it" (v1.3;
  tests: settings with every pair; one missing `Grep`; a regex matcher; an omitted matcher; a command
  through `uv run`; `disableAllHooks`; managed-only hooks; no settings at all); "WHEN a `deny_paths`
  entry is missing, sits inside a git working tree, or is a file readable by group or others, `cerberus
  doctor` SHALL NOT report clean"; "IF a `passfile` or `deny_paths` entry is neither absolute nor starts with
  `~`, THEN the system SHALL refuse the declaration as `config.invalid`" (v1.3) — depends on: SP-T1
- SP-T3: Guarded session and write guarantee — implements PR2 — acceptance (EARS): "the system SHALL
  open every read connection in a read-only transaction and return a guarantee field established on that
  connection, on results and on refusals issued after it"; "WHEN the server is a standby, the guarantee SHALL
  be `server-enforced`; WHEN it is a primary, `client-requested`" (integration, against the fixture's standby
  and primary); "IF a connection declared `server-enforced` establishes `client-requested`, THEN the system
  SHALL refuse and send none of the query's statements" (integration: the primary declared
  `server-enforced`; the server log shows no user statement); "IF a driver `connect` call exists outside the
  guarded-session module, THEN the suite SHALL fail" (CB01) — depends on: SP-T2
- SP-T4: Statement gate and function/operator allowlist — implements PR3, PR4 — acceptance (EARS): "the
  system SHALL accept exactly one plain `SELECT` and refuse every other statement kind, multi-statement
  input, `SELECT INTO`, a locking clause and a data-modifying CTE, naming the rule and the guarantee"; "the
  system SHALL refuse a temporary-table create, `SELECT 1; COMMIT; <write>`, and `ANALYZE` on a scratch
  table on every read connection class, while the same statement through a direct client succeeds on the
  primary" (W1, W2, W5; last-analyze time unchanged); "IF a query calls a
  function or operator that is denylisted, or that has a catalog entry outside `pg_catalog` and is not in the
  connection's `allow_functions`, THEN the system SHALL refuse it" (integration: a database-defined function
  that returns a flagged column is refused; the same function listed in `allow_functions` passes;
  `query_to_xml`, `ts_stat`, `set_config` written as a concatenated name, and `dblink` are refused; a
  user-defined operator is refused); the ported
  hostile-input cases are part of the suite, each asserting the refusal and its rule — depends on: SP-T3
- SP-T5: Read-surface policy — implements PR4 — acceptance (EARS): "WHEN a column of a table is not listed
  for that table, the system SHALL return no value of it in any of these forms: `SELECT *`, the explicit
  column, an alias, an expression over it, a whole-row reference (`t`, `row_to_json(t)`, `t::text`), a
  subquery, a CTE, a view over the table, an aggregate, a `UNION` branch, a `USING`/`NATURAL` join, an
  unqualified name resolved through the search path, a filter-only or order-only use, an alias column list,
  a view that renames the column (alone, and joined with the table named directly), a view whose definition
  calls a function that reads the table, a materialized view over the table, a partition or inheritance
  child queried by its own name, and a function that runs SQL given as text — each refused with the policy
  named" (integration, one test per form, asserting a
  planted marker value is absent from the whole output); "WHEN a query touches no flagged object, the system
  SHALL return the same rows as a direct client"; "WHEN a query reads only listed columns of a flagged table
  (including `count(*)`), the system SHALL return them"; "WHEN a column is added to a flagged table and not
  listed, the system SHALL deny it"; "the system SHALL refuse the statistics relations that expose column
  samples" — depends on: SP-T4
- SP-T6: Load bound and correctness preconditions — implements PR5, PR6 — acceptance (EARS): "WHEN a query
  runs past its connection's bound, the system SHALL return a timeout refusal and, within 5 s of the bound,
  no backend of that query, parallel workers included, SHALL remain on the server" (integration: a query
  planned with parallel workers on the fixture; `pg_stat_activity` checked); "IF the query text tries to
  change the bound (`SET`, `set_config`), THEN the system SHALL refuse it"; "WHEN the cerberus process is
  killed mid-query, the backend SHALL be gone within 5 s of the bound"; "the system SHALL apply the declared
  client encoding with nothing set by the caller" (integration: a LATIN1 fixture database; an accented
  literal counts correctly); "WHEN an unqualified relation name is queried, the result SHALL name the schema
  it resolved to, on two fixture databases that hold the table in different schemas" — depends on: SP-T3
- SP-T7: `cerberus query` and `cerberus connections` — implements PR8a — acceptance (EARS): "WHEN `cerberus
  query <connection> <sql>` runs from a directory outside every repository, the system SHALL print the
  result object with rows and guarantee field and exit 0; a refusal SHALL print the refusal object and exit
  3"; "IF the connection is `writable`, THEN `query` SHALL refuse and name `run-script`"; `connections` lists
  name, class and bound and no host credential — depends on: SP-T5, SP-T6
- SP-T8: `cerberus run-script` — implements PR10, PR4, PR5, PR6 — acceptance (EARS): "WHEN a script with an UPDATE and an
  embedded verification SELECT runs on a `writable` connection, the system SHALL return each statement's
  output and leave no committed change" (integration: a read before and after is equal); "WHEN a statement
  of the script returns rows (a `SELECT` or a `RETURNING` clause) that reach a flagged relation outside the
  policy, the system SHALL refuse it, return no value of it and roll back"; "IF any expression of a script
  statement reads a non-listed column of a flagged table (a `CREATE TABLE … AS`, an `INSERT … SELECT`, an
  `UPDATE … SET <listed> = <non-listed>`), THEN the system SHALL refuse it and roll back, while a statement
  that only writes the restricted column passes" (v1.1); "the system SHALL apply the
  connection's time bound, encoding and search path to every statement of the script" (integration: a
  statement past the bound is cancelled and the script rolled back); "IF the script
  contains a transaction-control statement, a statement a rollback does not undo, a denylisted function or a
  client meta-command, THEN the system SHALL refuse before connecting, naming the statement"; "WHEN a called
  procedure commits internally, the system SHALL return the server's error and leave no committed change";
  "IF `--commit` is given and stdin is not an interactive terminal, THEN the system SHALL refuse"; "WHEN
  `--commit` is confirmed on a terminal by typing the connection name, the system SHALL commit and append one
  authorization record (time, connection, script hash)"; "IF the connection is not `writable`, THEN
  `run-script` SHALL refuse" — depends on: SP-T3, SP-T4
- SP-T9: `cerberus hook claude-code` — implements PR9 — acceptance (EARS; v1.3 states the whole list, v1.2's
  "names no declared connection … answer nothing" and "missing or unreadable … block nothing" clauses are
  replaced): "WHEN a recorded pre-tool event carries a shell command that names a declared connection's
  host or `hook_match` string and is not a `cerberus` invocation — the direct command-line client, or an
  inline script that names the host — the system SHALL answer deny with the connection's name and the
  command to use (`query`, or `run-script` for `writable`)"; "WHEN a shell command names a protected path
  in any listed spelling at the stated boundaries, or names a protected path's parent directory and its
  last component, the system SHALL answer deny, a `cerberus` invocation included"; "WHEN a file-tool event
  targets a protected file, or a path under a protected directory (a relative path resolved against the
  event's working directory), the system SHALL answer deny"; "WHEN a `Grep` event's search path (or,
  absent, the event's working directory) is protected or contains a protected path, the system SHALL
  answer deny"; "WHEN a failed-tool event's output shows an authentication failure naming a declared host
  (the case of a script FILE that holds the host, which the pre-tool match cannot see), the system SHALL
  add the pointer as context"; "IF the connections file is missing, unreadable or not TOML, THEN the hook
  SHALL exit 0 and its only denial SHALL be of the default password file path"; "IF the connections file
  parses but holds an invalid declaration, THEN the hook SHALL still deny on every string it can read as
  stated, a host denial saying the file is invalid"; "WHEN an event matches none of the clauses above (a
  command naming no declared connection and no protected path; a `Grep` over a directory that holds no
  protected path; a path that only shares a protected path's prefix, such as `/x/.envrc` for `/x/.env`),
  the system SHALL answer nothing and exit 0" (persisted tests replay recorded event payloads, at least one
  per clause; the payload shapes, and whether a failed-tool hook may add context, are recorded from the
  harness's hooks reference at build time) — depends on: SP-T2
- SP-T10: Deploy on the operator's machine — implements PR1, PR9, PR13; verifies PRD M5 — acceptance:
  (a) dotfiles: the connections file and the password file are rendered from Bitwarden items of the work
  account as `private_` templates in the work context, registered in the secrets registry; the hook is
  registered in the settings template; `cerberus` enters the `mr` inventory and the `uv tool` channel (both
  homed in dotfiles, v1.3) — each landed by a pull request in its repository; (b) the declared connections'
  entries leave `~/.pgpass`; every working tree on the machine is scanned by the value of each custody
  password (not only the path Brief F11 recorded: worktree tooling copies a value without its path, v1.3),
  and each copy found leaves the trees before first use — moved outside with its consumer re-pointed where
  a consumer still needs it, deleted otherwise — until a re-scan finds none; `cerberus doctor` reports
  clean; (c) M5: the operator accepts the
  declared read-surface policy and the residuals of Cross-cutting — a recorded yes; (d) the operator's manual
  for the commands he runs by hand (`run-script --commit`, `doctor`) is written in the dotfiles manuals home
  — depends on: SP-T7, SP-T8, SP-T9 (operator acts: Bitwarden items; the `~/.pgpass` edit; M5).
  Executed 2026-11-19 against v1.2 (fppfurtado/dotfiles#313; M5 recorded on fppfurtado/iris#34): (a) one
  dotfiles pull request, no loadout one; (b) the scan found four gitignored files inside working trees
  holding a custody password, plus fourteen copies in session worktrees that a `.worktreeinclude` had made;
  all left the trees and the re-scan finds none (#10 does not record which were moved and which deleted,
  nor whether the copy Brief F11 recorded is one of the four; Deliberate exclusions states that the
  recorded one is kept, moved, for the local application stack); `doctor` reported clean under v1.2's checks. v1.3's `doctor` checks more,
  so the deployment is brought to it before SP-T11 (SP-T11(0)).
- SP-T11: Replay M1 on the case study, operator present, VPN up — verifies PRD M1, M2, M3 and the live
  halves of PR8a, PR9, PR11 — acceptance: (0) before the replay (v1.3): the deployment runs this build's
  hook and `doctor` — the installed tool updated, every known other holder of a custody password listed in
  its connection's `deny_paths` (the personal role's two holders, and the writable role's copy kept by the
  local application stack), `Grep` added to the hook's matcher, each landed in dotfiles by a pull
  request — and `cerberus doctor` reports clean under v1.3's checks; the residuals v1.3 adds to
  Cross-cutting are accepted by the operator, a recorded yes on fppfurtado/iris#34 (M5's form); and the
  suite passes on a PostgreSQL 15 fixture, the case study's major version; (a) M1: every row of the private replay set that belongs to this
  build (RP-J1, RP-J2, RP-J3, RP-J4a, RP-J4b, RP-J7) passes, the two statements marked RECOVER recovered
  first; (b) M2: every write attempt in the replay fails with its guarantee stated; each production read
  replica reports `server-enforced` and the homologation read connection reports `client-requested`
  (PR2(c)); the two log-history primaries report `client-requested` (v1.3); (c) PR9 in the live harness, fresh session: the direct command-line client aimed at a declared
  connection is refused with the pointer; a script file using a client library aimed at a declared
  connection fails to authenticate and the pointer is shown; a client aimed at an undeclared database is
  unaffected; (d) PR8a: one query from a directory outside every repository in a fresh session returns rows
  and guarantee; (e) M3: the private identifier list greps to zero hits over the `cerberus` repository,
  commit messages included — depends on: SP-T10
- SP-T12: Release 0.1.0 — implements PR8a — acceptance: the package's version manifest and changelog entry
  are set to 0.1.0, and the README documents every command, the connections file, the refusal rules and the
  residual risks — depends on: SP-T11

## Coverage check (every in-scope PR* -> ≥1 task)
- PR1 -> SP-T2, SP-T10
- PR2 -> SP-T3, SP-T11
- PR3 -> SP-T4
- PR4 -> SP-T4, SP-T5, SP-T8
- PR5 -> SP-T6, SP-T8
- PR6 -> SP-T6, SP-T8
- PR8a -> SP-T7, SP-T11, SP-T12
- PR9 -> SP-T9, SP-T10, SP-T11
- PR10 -> SP-T8
- PR11 -> SP-T1, SP-T11
- PR13 -> SP-T2, SP-T10
- PR7, PR8b -> not in this build by the PRD's own branch rule (Deliberate exclusions).
- No task without a PR*.

## Deliberate exclusions (from the PRD)
- PR7 (object-keyed knowledge) and PR8b (iris CLI/MCP surfaces) — not narrowed by this Spec: PRD v3 puts
  them outside the first build on this branch, armed on fppfurtado/iris#73 (open, checked 2026-11-15). The
  RP-J5 rows of M1 follow them.
- PRD "J1–J4 can sit in iris (G) or in a local proxy (P), which iris then queries through for J5 when J5 is
  built" — carried as a property, not built: `cerberus query` returns JSON a later iris adapter can call. No
  iris-facing interface is designed here.
- A credential boundary enforced by the operating system (a daemon under a separate user) — value affirmed,
  deferred by the operator's choice of custody level for this build (2026-11-15).
Trigger-source: fppfurtado/iris#73 · the case-study harness memory or session journal — fires when (outside) a recorded failure shows an agent reading the credential file or bypassing the hook to reach a declared connection
- PR13 "reachable only by the chosen carriers" — CARRIED-NARROWED, by the operator's decision of 2026-11-15:
  the credential is kept where no other client looks (outside `~/.pgpass`, outside every working tree, mode
  0600) and the hook refuses reads of it, but the agent runs as the same OS user and could read it on
  purpose. The OS-level form is the armed deferral above. A second holder also remains for the writable
  role: the local application stack that already uses that credential keeps its own copy, moved outside the
  working tree (SP-T10(b)). Found at SP-T10 (v1.3): the personal role's password has further holders
  outside every working tree — an operator wrapper's environment file and another tool's credential file,
  each read by its own tool. They stay (each serves its tool). SP-T10's deployment keeps an agent's shell
  off them by listing them, and the wrapper's name, as `hook_match` strings, which the file tools ignore.
  Owed after this build, in dotfiles, before SP-T11 (SP-T11(0)): list these holders, and the writable
  role's copy above, in their connections' `deny_paths` as well (the `hook_match` strings stay: a raw substring also catches the wrapper's bare
  name, which no path rule sees), and add `Grep` to the hook's matcher; until then the file tools and
  content search still reach them.
- PR4 "A query that touches no flagged object returns unchanged" — CARRIED-NARROWED: a query that calls a
  function or operator defined outside `pg_catalog` and not allowlisted, or that reads a statistics or
  credential catalog relation, is refused even when it touches no flagged object. Why: PRD R1's own
  mitigation (an allowlist of functions) and the measured leak through a database function and through
  SQL-as-text functions; without it PR4's last form cannot hold.
- The read-surface policy on a `writable` connection covers every expression a script's statements read
  (v1.1). What remains outside it — a residual stated at M5 — is code the statements do not name: a trigger
  or rule already defined in the database, and the body of an allowlisted function, either of which may move
  a value into a readable column.
- PRD R7 "adds a second repository to the effort" — WIDER here, declared: the code lives in `cerberus`, and
  deployment (SP-T10) lands small changes in the operator's dotfiles repository (v1.3: the loadout needed
  none) and re-points one credential file in a work repository.
- PRD open questions on J5's knowledge home, object identity and the judging of the RP-J5 rows — not
  answered here: they belong to the J5 build (fppfurtado/iris#73).
- One Spec, not one per carrier: on this branch there is no iris carrier.
- An MCP surface for cerberus — no PR on this branch requires it; a boundary, not a deferral.
- Database engines other than PostgreSQL — PRD NR1, armed there on fppfurtado/iris#11.

## Risks / unknowns
- The guarantee's standby branch and the full read-surface rule are designed from measured parts but were
  not run as a whole before this Spec; SP-T3 and SP-T5 are their first execution, one test per form.
- The plan-based relation check depends on `EXPLAIN (VERBOSE, FORMAT JSON)` naming every scanned relation.
  Measured on PostgreSQL 16 only; the case study's server versions are not recorded — SP-T11(a) runs the
  RP-J2 forms on the real replicas, and the fixture matrix adds any older major version found there.
  Recorded at SP-T10 (2026-11-19, fppfurtado/cerberus#10; v1.3): the case study's servers are PostgreSQL
  15 with LATIN1 encoding, so the suite runs on a PostgreSQL 15 fixture at SP-T11(0).
- Observed at SP-T10 (2026-11-19, v1.3; source fppfurtado/cerberus#10): the two log-history databases are
  primaries, so their connections are declared `client-requested`, not replicas (SP-T11(b) asserts it); the
  tables and columns the policy names were found identical on the production replicas, the homologation
  database and the test database, per #10's "the policy tables are identical" (whether row content was compared
  is not recorded); one query took 4–7 s over the VPN, attributed to connection setup plus the catalog
  closure, with no sample count or split of the two recorded — the Assumption on one connection per
  invocation stands until SP-T11 measures a session's query loop.
- Planning a query evaluates some functions at plan time. Mitigation: the function allowlist runs before
  `EXPLAIN`, inside the read-only transaction and the time bound.
- The name-based column rule refuses a harmless same-named column of another table in the same query. Cost:
  a false refusal with a message; revisit if it recurs in use.
- The two RECOVER statements of the private replay set (RP-J4a's regex, RP-J4b's table) are not in the notes
  read; if they cannot be recovered from the 2026-11-10/11 sessions, those rows are replayed (SP-T11) with the
  stand-ins the instantiation names, and the substitution is recorded.
- The harness's hook payload shape is read from its reference at build time (SP-T9), not fixed here.
- Moving the credential that lives inside a working tree changes how a local application stack finds it;
  SP-T10(b) re-points that consumer in the same step. That consumer (a local application stack) keeps
  using the writable role's credential from its new location: a second holder, recorded in Deliberate
  exclusions.

## Assumptions & invalidators
- The agent is careless, not adversarial (PRD Assumptions) — invalidated if a recorded failure shows a
  deliberate or injected evasion; then the OS-level boundary above is no longer deferrable.
- Every session that queries these databases runs in Claude Code, through its shell tool — invalidated if a
  session list shows a case-study query from another harness or tool; the hook then needs that surface, or
  the wire-proxy arrangement is reopened.
- A standby is the only server-enforced class the case study has (Brief F1) — invalidated if a declared
  connection is a primary whose role provably cannot write; the guarantee rule then needs a privilege-based
  branch.
- "Refuse the query and run no statement on it" (PR2(b)) is read as: none of the QUERY's statements is sent;
  the two system probes that establish the guarantee do run. Stated in the approved text, not separately
  confirmed — invalidated if the operator reads it as no statement at all on the connection.
- One connection per invocation is fast enough for keyed lookups — invalidated if a session's query loop is
  measurably slowed by connection setup.

## Open questions
- Whether `cerberus` later grows a wire-protocol front or an MCP surface — deferred: no PR on this branch
  needs either; the invalidators above name what would reopen it.
- The constellation cluster of the new repository — the operator's call at SP-T1.
- Row-count limits on results — not required by the PRD (J3 is a time bound "at minimum"); left out;
  revisit if result size becomes a problem in use.
