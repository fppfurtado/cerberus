# cerberus

A guard between AI agents and confidential PostgreSQL databases.

**Status: specified, not built.** The first contract is frozen in
[`specs/sensitive-database-source.spec.md`](specs/sensitive-database-source.spec.md); no code exists yet.

What it will do, in one program that is the only holder of the database credential:

- refuse every write on a read connection, and state with each result which write guarantee actually held
  (enforced by the server, or only requested by the client);
- keep declared-sensitive tables and columns out of results, whatever shape the query takes;
- bound the time a query may run, on the server;
- apply each connection's encoding and schema search path without the caller setting them;
- run a script on a writable test database only inside a transaction that is rolled back, unless a person
  authorizes a commit for that one run.

What it is not: a wire-protocol proxy, a query interpreter, or a boundary against an agent that sets out to
defeat it. The residual risks are listed in the Spec.

The problem and the requirements come from the `sensitive-database-source` Brief and PRD in
[fppfurtado/iris](https://github.com/fppfurtado/iris) (`briefs/`, `prds/`); tracker item fppfurtado/iris#34.

License: MIT.
