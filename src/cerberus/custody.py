"""Credential custody: where a connection's password file may live, and the doctor's checks.

cerberus hands the driver an explicit password file and an empty password, so libpq never falls back
to ``~/.pgpass``, ``PGPASSFILE`` or ``PGPASSWORD``; it never prompts.
"""

from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path

from cerberus.config import Connection, load_all
from cerberus.refusal import Refusal


@dataclass(frozen=True)
class PassEntry:
    host: str
    port: str
    dbname: str
    user: str
    password: str

    def matches(self, conn: Connection) -> bool:
        def field(pattern: str, value: str) -> bool:
            return pattern == "*" or pattern == value

        return (
            field(self.host, conn.host)
            and field(self.port, str(conn.port))
            and field(self.dbname, conn.dbname)
            and field(self.user, conn.user)
        )


def _split(line: str) -> list[str]:
    """Split one libpq password-file line on unescaped colons, undoing ``\\:`` and ``\\\\``."""
    fields, current, escaped = [], [], False
    for ch in line:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == ":" and len(fields) < 4:
            fields.append("".join(current))
            current = []
        else:
            current.append(ch)
    fields.append("".join(current))
    return fields


def read_passfile(path: Path) -> list[PassEntry]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    entries = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        fields = _split(line)
        if len(fields) == 5:
            entries.append(PassEntry(*fields))
    return entries


def inside_working_tree(path: Path) -> bool:
    """True when ``path`` (symlinks followed) sits inside a git working tree."""
    resolved = path.expanduser().resolve()
    for parent in [resolved, *resolved.parents]:
        if (parent / ".git").exists():
            return True
    return False


def check_passfile(conn: Connection) -> Path:
    """Return the resolved password file for ``conn``, or refuse where custody does not hold."""
    if inside_working_tree(conn.passfile):
        raise Refusal(
            "custody.passfile-in-working-tree",
            f"connection {conn.name!r}: its password file resolves to a path inside a git working "
            "tree; move it to the private configuration directory",
        )
    return conn.passfile.expanduser().resolve()


def driver_credentials(conn: Connection) -> dict[str, str]:
    """libpq parameters that confine the credential lookup to the custody file."""
    return {"password": "", "passfile": str(check_passfile(conn))}


def user_pgpass() -> Path:
    return Path.home() / ".pgpass"


def doctor() -> dict[str, object]:
    """Custody report. Prints no secret: passwords are compared in memory only."""
    connections = load_all()
    pgpass = read_passfile(user_pgpass())

    passfiles = []
    custody_passwords: set[str] = set()
    for conn in connections.values():
        entry: dict[str, object] = {"connection": conn.name, "location": str(conn.passfile)}
        if inside_working_tree(conn.passfile):
            entry.update(ok=False, problem="inside a git working tree")
        elif not conn.passfile.exists():
            entry.update(ok=False, problem="missing")
        else:
            mode = stat.S_IMODE(os.stat(conn.passfile).st_mode)
            entry["mode"] = f"{mode:04o}"
            entry["ok"] = mode & 0o077 == 0
            if not entry["ok"]:
                entry["problem"] = "readable by group or others"
            custody_passwords.update(
                e.password for e in read_passfile(conn.passfile) if e.matches(conn)
            )
        passfiles.append(entry)

    still_in_pgpass = sorted(
        conn.name for conn in connections.values() if any(e.matches(conn) for e in pgpass)
    )
    sharing = sorted({e.host for e in pgpass if e.password in custody_passwords})
    clean = all(p["ok"] for p in passfiles) and not still_in_pgpass and not sharing
    return {
        "clean": clean,
        "passfiles": passfiles,
        "connections_in_pgpass": still_in_pgpass,
        "pgpass_hosts_sharing_custody_password": sharing,
    }
