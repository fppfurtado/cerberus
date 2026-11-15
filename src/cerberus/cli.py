"""Command-line entry point.

Exit status: 0 success, 1 a check that did not come back clean (``doctor``), 3 a refusal.
"""

from __future__ import annotations

import argparse
import json
import sys

from cerberus import config, custody
from cerberus.read import run_query
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


def _connections(_: argparse.Namespace) -> int:
    listing = [
        {"name": c.name, "class": c.cls, "timeout_ms": c.timeout_ms}
        for c in config.load_all().values()
    ]
    print(_json(listing))
    return 0


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

    commands.add_parser("connections", help="list declared connections (no secrets)").set_defaults(
        run=_connections
    )
    commands.add_parser("doctor", help="credential custody and deployment checks").set_defaults(
        run=_doctor
    )

    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except Refusal as refusal:
        print(_json(refusal.as_dict()))
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
