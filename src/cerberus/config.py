"""Connection declarations, read only from the private configuration directory.

The connections file lives at ``$XDG_CONFIG_HOME/cerberus/connections.toml`` (``~/.config`` when
``XDG_CONFIG_HOME`` is unset). Nothing is read from the current directory or any repository.
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from cerberus.refusal import Refusal

CLASSES = ("server-enforced", "client-requested", "writable")
DEFAULT_TIMEOUT_MS = 30000
DEFAULT_ENCODING = "UTF8"


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base).expanduser() / "cerberus"


def connections_file() -> Path:
    return config_dir() / "connections.toml"


@dataclass(frozen=True)
class Connection:
    name: str
    host: str
    port: int
    dbname: str
    user: str
    cls: str
    timeout_ms: int
    client_encoding: str
    search_path: tuple[str, ...] | None
    passfile: Path


def _load_raw() -> dict:
    path = connections_file()
    try:
        with path.open("rb") as fh:
            return tomllib.load(fh)
    except FileNotFoundError:
        raise Refusal(
            "config.missing",
            "no connections file in the private configuration directory "
            "($XDG_CONFIG_HOME/cerberus/connections.toml)",
        ) from None
    except tomllib.TOMLDecodeError as exc:
        raise Refusal("config.invalid", f"the connections file is not valid TOML: {exc}") from None


def _parse(name: str, raw: dict) -> Connection:
    def need(key: str, kind: type):
        value = raw.get(key)
        if not isinstance(value, kind) or isinstance(value, bool):
            raise Refusal("config.invalid", f"connection {name!r}: '{key}' must be a {kind.__name__}")
        return value

    cls = need("class", str)
    if cls not in CLASSES:
        raise Refusal(
            "config.invalid", f"connection {name!r}: 'class' must be one of {', '.join(CLASSES)}"
        )
    timeout_ms = raw.get("timeout_ms", DEFAULT_TIMEOUT_MS)
    if not isinstance(timeout_ms, int) or isinstance(timeout_ms, bool) or timeout_ms <= 0:
        raise Refusal("config.invalid", f"connection {name!r}: 'timeout_ms' must be a positive integer")
    encoding = raw.get("client_encoding", DEFAULT_ENCODING)
    if not isinstance(encoding, str):
        raise Refusal("config.invalid", f"connection {name!r}: 'client_encoding' must be a str")
    search_path = raw.get("search_path")
    if search_path is not None:
        if not isinstance(search_path, list) or not all(isinstance(s, str) for s in search_path):
            raise Refusal("config.invalid", f"connection {name!r}: 'search_path' must be a list of str")
        search_path = tuple(search_path)
    passfile = raw.get("passfile")
    if passfile is not None and not isinstance(passfile, str):
        raise Refusal("config.invalid", f"connection {name!r}: 'passfile' must be a str")
    return Connection(
        name=name,
        host=need("host", str),
        port=need("port", int),
        dbname=need("dbname", str),
        user=need("user", str),
        cls=cls,
        timeout_ms=timeout_ms,
        client_encoding=encoding,
        search_path=search_path,
        passfile=Path(passfile).expanduser() if passfile else config_dir() / "pgpass",
    )


def load_all() -> dict[str, Connection]:
    raw = _load_raw().get("connection", {})
    if not isinstance(raw, dict):
        raise Refusal("config.invalid", "the connections file must hold [connection.NAME] tables")
    return {name: _parse(name, body) for name, body in raw.items()}


def load(name: str) -> Connection:
    connections = load_all()
    if name not in connections:
        raise Refusal("config.unknown-connection", f"no declared connection named {name!r}")
    return connections[name]
