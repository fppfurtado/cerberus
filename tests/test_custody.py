"""SP-T2: connection declarations and credential custody."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from cerberus import cli, config, custody
from cerberus.refusal import Refusal
from cerberus.session import open_connection
from conftest import Cluster

SECRET = "synthetic-test-only"


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An isolated HOME and XDG config directory; nothing from the developer's own."""
    home = tmp_path / "home"
    (home / ".config" / "cerberus").mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(home / ".config"))
    return home


def write_connections(home: Path, body: str) -> None:
    (home / ".config" / "cerberus" / "connections.toml").write_text(body)


def write_secret_file(path: Path, lines: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(line + "\n" for line in lines))
    path.chmod(0o600)


def declare_primary(home: Path, cluster: Cluster, passfile: Path | None = None) -> None:
    extra = f'passfile = "{passfile}"\n' if passfile else ""
    write_connections(
        home,
        f"""
[connection.synth]
host = "{cluster.primary.host}"
port = {cluster.primary.port}
dbname = "{cluster.primary.dbname}"
user = "{cluster.primary.user}"
class = "client-requested"
{extra}""",
    )


def pass_line(cluster: Cluster, password: str = SECRET, host: str | None = None) -> str:
    p = cluster.primary
    return f"{host or p.host}:{p.port}:{p.dbname}:{p.user}:{password}"


# --- declarations come from the private file only -------------------------------------------------


def test_declaration_fields_are_read_from_the_private_file(home: Path) -> None:
    write_connections(
        home,
        """
[connection.full]
host = "db.example.invalid"
port = 6543
dbname = "inventory"
user = "reader"
class = "server-enforced"
timeout_ms = 1500
client_encoding = "LATIN1"
search_path = ["app", "public"]

[connection.minimal]
host = "db.example.invalid"
port = 5432
dbname = "inventory"
user = "reader"
class = "writable"
""",
    )
    full = config.load("full")
    assert (full.host, full.port, full.dbname, full.user) == ("db.example.invalid", 6543, "inventory", "reader")
    assert (full.cls, full.timeout_ms, full.client_encoding) == ("server-enforced", 1500, "LATIN1")
    assert full.search_path == ("app", "public")
    assert full.passfile == home / ".config" / "cerberus" / "pgpass"

    minimal = config.load("minimal")
    assert (minimal.timeout_ms, minimal.client_encoding, minimal.search_path) == (30000, "UTF8", None)


def test_a_connections_file_in_the_current_repository_is_not_read(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = tmp_path / "repo"
    (repo / "cerberus").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    planted = '[connection.planted]\nhost="h"\nport=1\ndbname="d"\nuser="u"\nclass="writable"\n'
    (repo / "connections.toml").write_text(planted)
    (repo / "cerberus" / "connections.toml").write_text(planted)
    monkeypatch.chdir(repo)

    with pytest.raises(Refusal) as missing:
        config.load("planted")
    assert missing.value.rule == "config.missing"

    write_connections(home, "")
    with pytest.raises(Refusal) as unknown:
        config.load("planted")
    assert unknown.value.rule == "config.unknown-connection"


def test_an_invalid_class_is_refused(home: Path) -> None:
    write_connections(
        home, '[connection.x]\nhost="h"\nport=1\ndbname="d"\nuser="u"\nclass="read-only"\n'
    )
    with pytest.raises(Refusal) as refused:
        config.load("x")
    assert refused.value.rule == "config.invalid"


# --- the password file may not live inside a working tree -----------------------------------------


@pytest.mark.parametrize("via_symlink", [False, True])
def test_a_password_file_inside_a_working_tree_is_refused(
    home: Path, tmp_path: Path, cluster: Cluster, via_symlink: bool
) -> None:
    repo = tmp_path / "work-repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    inside = repo / "secrets" / "pgpass"
    write_secret_file(inside, [pass_line(cluster)])
    passfile = inside
    if via_symlink:
        passfile = home / "linked-pgpass"
        passfile.symlink_to(inside)
    declare_primary(home, cluster, passfile)

    with pytest.raises(Refusal) as refused:
        open_connection(config.load("synth"))
    assert refused.value.rule == "custody.passfile-in-working-tree"
    assert "working tree" in refused.value.detail
    assert str(repo) not in refused.value.detail
    assert str(passfile) not in refused.value.detail


# --- only the custody file is a credential source -------------------------------------------------


def test_pgpass_pgpassword_and_pgpassfile_are_not_read(
    home: Path, tmp_path: Path, cluster: Cluster, monkeypatch: pytest.MonkeyPatch
) -> None:
    write_secret_file(home / ".pgpass", [pass_line(cluster)])
    elsewhere = tmp_path / "elsewhere-pgpass"
    write_secret_file(elsewhere, [pass_line(cluster)])
    monkeypatch.setenv("PGPASSWORD", SECRET)
    monkeypatch.setenv("PGPASSFILE", str(elsewhere))
    write_secret_file(home / ".config" / "cerberus" / "pgpass", [])  # custody holds no entry
    declare_primary(home, cluster)

    with pytest.raises(Refusal) as refused:
        open_connection(config.load("synth"))
    assert refused.value.rule == "connection.failed"
    assert SECRET not in refused.value.detail


def test_the_custody_file_is_the_credential_source(home: Path, cluster: Cluster) -> None:
    write_secret_file(home / ".config" / "cerberus" / "pgpass", [pass_line(cluster)])
    declare_primary(home, cluster)
    with open_connection(config.load("synth")) as conn:
        assert conn.execute("SELECT 1").fetchone()[0] == 1


# --- doctor ---------------------------------------------------------------------------------------


def run_doctor(capsys: pytest.CaptureFixture[str]) -> tuple[int, dict, str]:
    code = cli.main(["doctor"])
    out = capsys.readouterr().out
    return code, json.loads(out), out


def test_doctor_reports_pgpass_leftovers_and_shared_passwords_without_secrets(
    home: Path, cluster: Cluster, capsys: pytest.CaptureFixture[str]
) -> None:
    write_secret_file(home / ".config" / "cerberus" / "pgpass", [pass_line(cluster)])
    write_secret_file(
        home / ".pgpass",
        [
            pass_line(cluster),  # the declared connection is still here
            pass_line(cluster, host="other.example.invalid"),  # same password, another host
            pass_line(cluster, password="unrelated-password", host="third.example.invalid"),
        ],
    )
    declare_primary(home, cluster)

    code, report, raw = run_doctor(capsys)
    assert code == 1
    assert report["clean"] is False
    assert report["connections_in_pgpass"] == ["synth"]
    assert set(report["pgpass_hosts_sharing_custody_password"]) == {
        cluster.primary.host, "other.example.invalid",
    }
    assert "third.example.invalid" not in raw
    assert SECRET not in raw
    assert "unrelated-password" not in raw


def test_doctor_is_clean_when_custody_holds(
    home: Path, cluster: Cluster, capsys: pytest.CaptureFixture[str]
) -> None:
    write_secret_file(home / ".config" / "cerberus" / "pgpass", [pass_line(cluster)])
    declare_primary(home, cluster)
    code, report, raw = run_doctor(capsys)
    assert code == 0, raw
    assert report["clean"] is True
    assert report["passfiles"] == [
        {"connection": "synth", "location": str(home / ".config" / "cerberus" / "pgpass"),
         "mode": "0600", "ok": True},
    ]
    assert SECRET not in raw


def test_doctor_flags_a_password_file_readable_by_others(
    home: Path, cluster: Cluster, capsys: pytest.CaptureFixture[str]
) -> None:
    custody_file = home / ".config" / "cerberus" / "pgpass"
    write_secret_file(custody_file, [pass_line(cluster)])
    os.chmod(custody_file, 0o644)
    declare_primary(home, cluster)
    code, report, _ = run_doctor(capsys)
    assert code == 1
    assert report["passfiles"][0]["ok"] is False


def test_password_file_parsing_handles_escapes(tmp_path: Path) -> None:
    f = tmp_path / "p"
    write_secret_file(f, [r"h\:x:5432:*:u:pa\:ss\\word", "# comment", ""])
    [entry] = custody.read_passfile(f)
    assert (entry.host, entry.dbname, entry.password) == ("h:x", "*", "pa:ss\\word")
