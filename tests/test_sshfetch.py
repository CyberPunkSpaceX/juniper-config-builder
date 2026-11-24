import socket
import threading

import pytest

paramiko = pytest.importorskip("paramiko")

from exbuilder import sshfetch  # noqa: E402

CONFIG = "set version 23.4R2\nset system host-name lab-sw1\nset vlans USERS vlan-id 20\n"
LLDP = ("Local Interface    Parent Interface    Chassis Id          Port info          System Name\n"
        "xe-0/1/0           -                   2c:6b:f5:aa:00:01   xe-0/1/2           core-sw1\n")


class FakeJunos(paramiko.ServerInterface):
    def __init__(self, log):
        self.log = log

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        return paramiko.AUTH_SUCCESSFUL if (username, password) == ("netops", "Secret-123") else paramiko.AUTH_FAILED

    def check_channel_exec_request(self, channel, command):
        command = command.decode()
        self.log.append(command)
        out = CONFIG if command.startswith("show configuration") else LLDP if "lldp" in command else "error: unknown\n"

        def answer():  # after the exec request has been acknowledged
            channel.sendall(out.encode())
            channel.send_exit_status(0)
            channel.close()
        threading.Timer(0.05, answer).start()
        return True


@pytest.fixture
def switch():
    """A tiny SSH server on 127.0.0.1 that answers like a Junos switch."""
    state = {"key": paramiko.RSAKey.generate(2048), "commands": []}
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    stop = threading.Event()

    def serve():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            t = paramiko.Transport(conn)
            t.add_server_key(state["key"])
            try:
                t.start_server(server=FakeJunos(state["commands"]))
            except (paramiko.SSHException, EOFError):
                continue

    th = threading.Thread(target=serve, daemon=True)
    th.start()
    state["port"] = srv.getsockname()[1]
    yield state
    stop.set()
    th.join(2)
    srv.close()


@pytest.fixture(autouse=True)
def env(monkeypatch):
    monkeypatch.setenv("EXB_SSH_ALLOW", "127.0.0.0/8")
    monkeypatch.setenv("EXB_SSH_TIMEOUT", "5")
    sshfetch._recent.clear()


def test_allow_list(monkeypatch):
    assert sshfetch.resolve("127.0.0.1") == "127.0.0.1"
    monkeypatch.setenv("EXB_SSH_ALLOW", "10.0.0.0/8")
    with pytest.raises(sshfetch.FetchError, match="outside the allowed networks"):
        sshfetch.resolve("127.0.0.1")
    with pytest.raises(sshfetch.FetchError, match="not a host"):
        sshfetch.resolve("-oProxyCommand=x")
    monkeypatch.setenv("EXB_SSH_ALLOW", "")
    assert not sshfetch.enabled()
    with pytest.raises(sshfetch.FetchError, match="turned off"):
        sshfetch.resolve("127.0.0.1")


def test_fetch_remembers_and_checks_the_host_key(switch, tmp_path):
    r = sshfetch.fetch_one("127.0.0.1", "netops", "Secret-123", tmp_path, port=switch["port"])
    assert r["ok"] and r["new_key"] and "host-name lab-sw1" in r["text"] and "core-sw1" in r["text"]
    assert switch["commands"] == list(sshfetch.COMMANDS)
    (known,) = sshfetch.known_hosts(tmp_path)
    assert known["host"] == f"[127.0.0.1]:{switch['port']}" and known["fingerprint"] == r["fingerprint"]
    assert "Secret-123" not in (tmp_path / "ssh_known_hosts").read_text()
    again = sshfetch.fetch_one("127.0.0.1", "netops", "Secret-123", tmp_path, port=switch["port"])
    assert again["ok"] and not again.get("new_key")
    switch["key"] = paramiko.RSAKey.generate(2048)       # the "switch" gets a new key
    bad = sshfetch.fetch_one("127.0.0.1", "netops", "Secret-123", tmp_path, port=switch["port"])
    assert not bad["ok"] and "CHANGED" in bad["error"]
    assert sshfetch.forget_host(tmp_path, known["host"])
    assert sshfetch.fetch_one("127.0.0.1", "netops", "Secret-123", tmp_path, port=switch["port"])["ok"]


def test_wrong_password_and_rate_limit(switch, tmp_path, monkeypatch):
    r = sshfetch.fetch_one("127.0.0.1", "netops", "nope", tmp_path, port=switch["port"])
    assert not r["ok"] and "sign-in failed" in r["error"]
    monkeypatch.setenv("EXB_SSH_RATE", "2")
    sshfetch.check_rate("u")
    sshfetch.check_rate("u")
    with pytest.raises(sshfetch.FetchError, match="Too many"):
        sshfetch.check_rate("u")


def test_web_route_admin_only(switch, monkeypatch, caplog):
    pytest.importorskip("flask")
    from test_auth import ADMIN, add_user, app, admin, login  # noqa: F401
    from test_builder_web import token
    import tempfile
    from pathlib import Path
    from exbuilder.web import create_app
    with tempfile.TemporaryDirectory() as d:
        monkeypatch.setenv("EXB_DATA_DIR", d)
        monkeypatch.setenv("EXB_USERNAME", ADMIN[0])
        monkeypatch.setenv("EXB_PASSWORD", ADMIN[1])
        application = create_app()
        application.config["TESTING"] = True
        client = application.test_client()
        assert login(client, *ADMIN).status_code == 302
        hdr = {"X-CSRF-Token": token(client)}
        page = client.get("/").get_data(as_text=True)
        assert 'id="ssh-go"' in page
        body = {"hosts": "127.0.0.1", "username": "netops", "password": "Secret-123", "port": switch["port"]}
        with caplog.at_level("WARNING", logger="exbuilder.ssh"):
            resp = client.post("/ssh/fetch", json=body, headers=hdr)
        assert resp.status_code == 200 and resp.json["results"][0]["ok"]
        assert "audit: ssh fetch" in caplog.text and "Secret-123" not in caplog.text
        assert client.post("/ssh/fetch", json={**body, "password": ""}, headers=hdr).status_code == 400
        assert client.get("/ssh/known").json["hosts"]
        add_user(client, "bob", "bob-password-1")
        bob = application.test_client()
        assert login(bob, "bob", "bob-password-1").status_code == 302
        assert 'id="ssh-go"' not in bob.get("/").get_data(as_text=True)
        assert bob.post("/ssh/fetch", json=body, headers={"X-CSRF-Token": token(bob)}).status_code == 403
        assert bob.get("/ssh/known").status_code == 403
        monkeypatch.setenv("EXB_SSH_ALLOW", "")
        assert client.post("/ssh/fetch", json=body, headers=hdr).status_code == 403
        assert 'id="ssh-go"' not in client.get("/").get_data(as_text=True)
        assert Path(d, "ssh_known_hosts").exists()
