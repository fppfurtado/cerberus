"""Command-line entry point."""

from __future__ import annotations

import argparse
import json
import sys

from cerberus import custody
from cerberus.refusal import Refusal

EXIT_REFUSED = 3


def _doctor(_: argparse.Namespace) -> int:
    report = custody.doctor()
    print(json.dumps(report, indent=2))
    return 0 if report["clean"] else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cerberus")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("doctor", help="credential custody and deployment checks").set_defaults(
        run=_doctor
    )
    args = parser.parse_args(argv)
    try:
        return args.run(args)
    except Refusal as refusal:
        print(json.dumps(refusal.as_dict()))
        return EXIT_REFUSED


if __name__ == "__main__":
    sys.exit(main())
