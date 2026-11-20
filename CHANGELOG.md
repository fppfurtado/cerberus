# Changelog

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow
[Semantic Versioning](https://semver.org/). The contract each version builds is
[`specs/sensitive-database-source.spec.md`](specs/sensitive-database-source.spec.md).

## [0.1.0] - 2026-11-19

The first release: the first build of the `sensitive-database-source` Spec (v1.5), deployed and replayed
on its case study (fppfurtado/iris#34).

### Added

- `cerberus query`: one guarded `SELECT` on a read connection, in a read-only transaction, with the write
  guarantee established on the server (`server-enforced` on a standby, `client-requested` on a primary)
  and stated on every result and refusal; a connection weaker than declared is refused before any
  statement of the query is sent.
- Statement gate on PostgreSQL's own grammar (`pglast`), and a function and operator allowlist: built-ins
  pass unless denylisted; anything defined outside `pg_catalog` needs `allow_functions`.
- Read-surface policy: `deny_relations` and per-table column lists, applied to what the query names, to
  the dependency closure of every view it names and to the relations its plan scans.
- Server-side time bound (`statement_timeout`, `lock_timeout`), and the declared client encoding and search
  path, per connection.
- `cerberus run-script`: a script on a `writable` connection, always rolled back; `--commit` only after a
  confirmation typed on a terminal, recorded in `commits.jsonl` before the commit; `--encoding` for
  scripts not in UTF-8.
- `cerberus connections` and `cerberus doctor` (credential custody, other holders of a custody password,
  the hook's registration).
- `cerberus hook claude-code`: refuses a direct database client aimed at a declared connection, and an
  agent's file read, search or shell command that names a holder of a connection's password.
- `cerberus --version`.

### Known residual risks

Listed in the README and, in full, in the Spec's Cross-cutting section.

[0.1.0]: https://github.com/fppfurtado/cerberus/releases/tag/v0.1.0
