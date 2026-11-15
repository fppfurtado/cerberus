# cerberus

A guard between AI agents and confidential PostgreSQL databases.

**Status: in development.** The first contract is frozen in
[`specs/sensitive-database-source.spec.md`](specs/sensitive-database-source.spec.md). The repository
scaffold and its test fixture exist; the commands below are not built yet.

## What it is

One program that is the only holder of the database credential and the only path an agent's SQL takes
to a declared connection. It will:

- refuse every write on a read connection, and state with each result which write guarantee actually held
  (enforced by the server, or only requested by the client);
- keep declared-sensitive tables and columns out of results, whatever shape the query takes;
- bound the time a query may run, on the server;
- apply each connection's encoding and schema search path without the caller setting them;
- run a script on a writable test database only inside a transaction that is rolled back, unless a person
  authorizes a commit for that one run.

Planned commands: `cerberus query`, `cerberus run-script`, `cerberus connections`, `cerberus doctor`, and
`cerberus hook claude-code` (a pre-tool hook that refuses a direct database client aimed at a declared
connection).

## What it is not

Not a wire-protocol proxy, not a query interpreter, and not a boundary against an agent that sets out to
defeat it: the agent runs as the same operating-system user. The residual risks are listed in the Spec.

## Development

Requires Python 3.12+, [uv](https://docs.astral.sh/uv/) and Docker.

```
uv sync
uv run pytest
```

The suite starts its own synthetic PostgreSQL primary and streaming standby in containers, bound to
`127.0.0.1`, and removes them at the end. It clears libpq environment variables first, so no test reaches
any other database.

## Provenance

The problem and the requirements come from the `sensitive-database-source` Brief and PRD in
[fppfurtado/iris](https://github.com/fppfurtado/iris) (`briefs/`, `prds/`); tracker item fppfurtado/iris#34.

License: MIT.
