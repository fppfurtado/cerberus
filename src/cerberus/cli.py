"""Command-line entry point.

Exit status: 0 success, 1 a check that did not come back clean (``doctor``), 3 a refusal.
"""

from __future__ import annotations

import argparse
import json
import sys

from cerberus import config, custody
from cerberus.read import run_query
from cerberus.script import run_script
from cerberus.refusal import Refusal

EXIT_REFUSED = 3


def _json(obj: object) -> str:
    return json.dumps(obj, indent=2, default=str, ensure_ascii=False)


def _table(result: dict) -> str:
    columns = [str(c) for c in result["columns"]]
    rows = [["" if v is None else str(v) for v in row] for row in result["rows"]]
    widths = [max([len(c)] + [len(r[i]) for r in rows]) for i, c in enumerate(columns)]
    line = lambda cells: " | ".join(c.ljust(w) for c, w in zip(cells, widths))  # noqa: E731
    out = [line(columns), "-+-".join("-" * w for w in widths), *map(line, rows)]
    g = result["guarantee"]
    out.append(f"({result['row_count']} rows; guarantee: {g['class']} by {g['basis']})")
    return "\n".join(out)


def _query(args: argparse.Namespace) -> int:
    result = run_query(config.load(args.connection), args.sql, verbose_errors=args.verbose_errors)
    print(_table(result) if args.format == "table" else _json(result))
    return 0


def _confirm_on_terminal(conn: config.Connection) -> bool:
    print(f"Type the connection name ({conn.name}) to COMMIT this script: ", end="", file=sys.stderr,
          flush=True)
    return sys.stdin.readline().strip() == conn.name


def read_script(path: str, encoding: str | None) -> str:
    """The script's text, decoded as declared (Spec v1.5): UTF-8 by default (a byte-order mark
    dropped), else ``--encoding``. A file that cannot be read or decoded is a named refusal."""
    try:
        data = open(path, "rb").read()
    except OSError as exc:
        raise Refusal("script.unreadable",
                      f"cannot read the script file ({type(exc).__name__})") from None
    name = encoding or "utf-8-sig"
    try:
        return data.decode(name)
    except LookupError:
        raise Refusal("script.encoding", f"unknown encoding {encoding!r}") from None
    except UnicodeDecodeError as exc:
        shown = encoding or "UTF-8"
        raise Refusal(
            "script.encoding",
            f"the script is not valid {shown} (byte {exc.start}); pass --encoding <name> "
            "(for example latin1 or cp1252) to read it in its own encoding, or convert it to UTF-8",
        ) from None


def _run_script(args: argparse.Namespace) -> int:
    script = read_script(args.file, args.encoding)
    confirm = _confirm_on_terminal if args.commit and sys.stdin.isatty() else None
    result = run_script(config.load(args.connection), script, commit=args.commit, confirm=confirm,
                        verbose_errors=args.verbose_errors)
    print(_json(result))
    return 0


def _connections(_: argparse.Namespace) -> int:
    listing = [
        {"name": c.name, "class": c.cls, "timeout_ms": c.timeout_ms}
        for c in config.load_all().values()
    ]
    print(_json(listing))
    return 0


def _hook(args: argparse.Namespace) -> int:
    from cerberus import hook

    return hook.main()


def _doctor(_: argparse.Namespace) -> int:
    report = custody.doctor()
    print(_json(report))
    return 0 if report["clean"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cerberus")
    commands = parser.add_subparsers(dest="command", required=True)

    query = commands.add_parser("query", help="run one guarded SELECT on a declared read connection")
    query.add_argument("connection")
    query.add_argument("sql")
    query.add_argument("--format", choices=("json", "table"), default="json")
    query.add_argument("--verbose-errors", action="store_true",
                       help="show a server error's full message (it can quote a value)")
    query.set_defaults(run=_query)

    script = commands.add_parser(
        "run-script", help="run a script on a writable connection inside a transaction rolled back"
    )
    script.add_argument("connection")
    script.add_argument("file")
    script.add_argument("--encoding", metavar="NAME",
                        help="the script file's encoding (default UTF-8), e.g. latin1 or cp1252")
    script.add_argument("--commit", action="store_true",
                        help="commit instead of rolling back, after typing the connection name on a terminal")
    script.add_argument("--verbose-errors", action="store_true",
                        help="show a server error's full message (it can quote a value)")
    script.set_defaults(run=_run_script)

    commands.add_parser("connections", help="list declared connections (no secrets)").set_defaults(
        run=_connections
    )
    hook = commands.add_parser("hook", help="harness hooks")
    hook.add_argument("harness", choices=("claude-code",))
    hook.set_defaults(run=_hook)

    commands.add_parser("doctor", help="credential custody and deployment checks").set_defaults(
        run=_doctor
    )

    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except Refusal as refusal:
        print(_json(refusal.as_dict()))
        return EXIT_REFUSED
    except Exception as exc:  # noqa: BLE001 — Spec v1.5: never a traceback, never a message
        if args.command == "hook":
            raise  # the hook's own contract: its output is the harness's, not a refusal object
        print(_json(Refusal("internal.error",
                            f"cerberus failed unexpectedly ({type(exc).__name__}); no detail is shown, "
                            "since an error message can quote a value").as_dict()))
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
