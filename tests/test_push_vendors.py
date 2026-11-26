"""Push drivers for Arista, Cisco IOS-XE, NX-OS, Aruba CX and MikroTik, against small fake CLIs over SSH."""

import json
import re
import socket
import threading
import time
from pathlib import Path

import pytest

paramiko = pytest.importorskip("paramiko")
flask = pytest.importorskip("flask")

from exbuilder import push as engine  # noqa: E402
from exbuilder import sshfetch  # noqa: E402
from test_auth import app, admin  # noqa: F401,E402
from test_push import Res, _approved_project, _creds, _form, _know, _post, env  # noqa: F401,E402

EXAMPLES = Path(__file__).parent.parent / "src" / "exbuilder" / "vendor_examples"
NETS = [sshfetch.ipaddress.ip_network("127.0.0.0/8")]


class Fake:
    """Base fake: exec/config prompts, a running config, and a log of every line received."""

    hostname = "sw1"

    def __init__(self):
        self.running = ["hostname sw1", "interface Ethernet1", "   description uplink"]
        self.mode = "exec"
        self.log = []

    def prompt(self):
        return f"\r\n{self.hostname}{'(config)' if self.mode != 'exec' else ''}#"

    def show_running(self):
        return "! Command: show running-config\r\n" + "\r\n".join(self.running) + "\r\nend"

    def handle(self, line):
        return ""

    def ctrl_x(self):
        return ""


class FakeEos(Fake):
    def __init__(self):
        super().__init__()
        self.sessions, self.pending, self.prev = {}, {}, {}
        self.cur = None

    def handle(self, line):
        if line.startswith("terminal") or line == "write memory":
            return "Copy completed successfully." if line == "write memory" else ""
        if line == "show running-config":
            return self.show_running()
        m = re.match(r"configure session (\S+)( abort| commit)?$", line)
        if m:
            name, act = m.group(1), (m.group(2) or "").strip()
            if act == "abort":
                if name in self.pending:
                    self.running = self.prev.pop(name)
                    self.pending.pop(name)
                self.sessions.pop(name, None)
                return ""
            if act == "commit":
                self.pending.pop(name, None)
                self.prev.pop(name, None)
                return ""
            self.cur = name
            self.sessions.setdefault(name, list(self.running))
            self.mode = "config"
            return ""
        if line == "show configuration sessions detail":
            return "\r\n".join(f"  {n}  pending-commit-timer  {t}" for n, t in self.pending.items()) or "none"
        if self.mode == "config":
            if line == "end":
                self.mode = "exec"
                return ""
            if line == "rollback clean-config":
                self.sessions[self.cur] = []
                return ""
            if line == "show session-config diffs":
                return "\r\n".join("+" + x for x in self.sessions[self.cur] if x not in self.running)
            m = re.match(r"commit timer (\d\d:\d\d:\d\d)", line)
            if m:
                self.prev[self.cur] = list(self.running)
                self.running = self.sessions.pop(self.cur)
                self.pending[self.cur] = m.group(1)
                self.mode = "exec"
                return ""
            if "bogus" in line:
                return "% Invalid input (at token 0: 'bogus')"
            self.sessions[self.cur].append(line)
            return ""
        return "% Invalid input"


class FakeIos(Fake):
    def __init__(self):
        super().__init__()
        self.archive = False
        self.timer = None
        self.prev = None

    def handle(self, line):
        if line.startswith("terminal"):
            return ""
        if line == "write memory":
            return "[OK]"
        if line == "show running-config":
            return "Building configuration...\r\n\r\nCurrent configuration : 1234 bytes\r\n" + self.show_running()
        if line == "show archive":
            return ("The maximum archive configurations allowed is 14.\r\nThe next archive file will be named "
                    "flash:switchbuilder-archive-1\r\n Archive #  Name") if self.archive else \
                "Archive feature not enabled"
        if line == "show archive config rollback timer":
            return f"Timer type: Confirm\r\nTimer value: {self.timer} min" if self.timer else \
                "%No Rollback Confirmed Change pending"
        m = re.match(r"configure terminal revert timer (\d+)", line)
        if m:
            if not self.archive:
                return "%Rollback Confirmed Change requires the archive path to be set"
            self.timer, self.prev, self.mode = int(m.group(1)), list(self.running), "config"
            return ""
        if line == "configure terminal":
            self.mode = "config"
            return "Enter configuration commands, one per line.  End with CNTL/Z."
        if line == "configure confirm":
            self.timer = None
            return ""
        if line == "configure revert now":
            self.running, self.timer = self.prev, None
            return "Rollback Done"
        if self.mode == "config":
            if line == "end":
                self.mode = "exec"
                return ""
            if line.strip().startswith("path "):
                self.archive = True
            if "bogus" in line:
                return "                    ^\r\n% Invalid input detected at '^' marker."
            self.running.append(line)
            return ""
        return "% Invalid input detected at '^' marker."


class FakeNxos(Fake):
    def __init__(self):
        super().__init__()
        self.checkpoints, self.jobs, self.schedules, self.session = {}, set(), set(), None

    def handle(self, line):
        if line.startswith("terminal") or line == "copy running-config startup-config":
            return "Copy complete." if line.startswith("copy") else ""
        if line == "show running-config":
            return self.show_running()
        m = re.match(r"checkpoint (\S+)", line)
        if m and self.mode == "exec":
            self.checkpoints[m.group(1)] = list(self.running)
            return "Done"
        m = re.match(r"rollback running-config checkpoint (\S+)", line)
        if m and self.mode == "exec":
            self.running = list(self.checkpoints[m.group(1)])
            self.schedules.clear()
            return "Rollback completed successfully."
        m = re.match(r"show scheduler schedule name (\S+)", line)
        if m:
            return f"Schedule Name : {m.group(1)}\r\nUser Name : netops" if m.group(1) in self.schedules else \
                "ERROR: Schedule not found"
        if line == "configure terminal":
            self.mode = "config"
            return ""
        m = re.match(r"configure session (\S+)", line)
        if m:
            self.mode, self.session = "session", []
            return ""
        if line == "end":
            self.mode = "exec"
            return ""
        if self.mode == "config":
            m = re.match(r"(no )?scheduler schedule name (\S+)", line)
            if m:
                (self.schedules.discard if m.group(1) else self.schedules.add)(m.group(2))
            return ""
        if self.mode == "session":
            if line == "verify":
                return "Verification Successful"
            if line == "commit":
                self.running += self.session
                self.mode = "exec"
                return "Commit Successful"
            if line == "abort":
                self.session = []
                return ""
            if "bogus" in line:
                return "% Invalid command at '^' marker."
            self.session.append(line)
            return ""
        return "% Invalid command"


class FakeCx(Fake):
    def __init__(self):
        super().__init__()
        self.checkpoints, self.auto, self.prev = {}, None, None

    def handle(self, line):
        if line in ("no page", "write memory"):
            return ""
        if line == "show running-config":
            return self.show_running()
        m = re.match(r"copy running-config checkpoint (\S+)", line)
        if m:
            self.checkpoints[m.group(1)] = list(self.running)
            return "Success"
        m = re.match(r"copy checkpoint (\S+) running-config", line)
        if m:
            self.running = list(self.checkpoints[m.group(1)])
            return "Success"
        m = re.match(r"checkpoint auto (\d+)$", line)
        if m:
            self.auto, self.prev = int(m.group(1)), list(self.running)
            return ""
        if line == "checkpoint auto confirm":
            if not self.auto:
                return "Error: auto checkpoint mode is not active"
            self.auto = None
            return ""
        if line == "show checkpoint":
            return "NAME    TYPE   WRITER\r\n" + ("auto-ckpt  auto  User" if self.auto else "")
        if line == "configure terminal":
            self.mode = "config"
            return ""
        if line == "end":
            self.mode = "exec"
            return ""
        if self.mode == "config":
            if "bogus" in line:
                return "Invalid input: bogus"
            self.running.append(line)
            return ""
        return "Invalid input"


class FakeRos(Fake):
    """RouterOS: /export, Safe Mode with Ctrl+X; closing the session in Safe Mode undoes the changes."""

    def __init__(self):
        super().__init__()
        self.running = ["/system identity set name=crs-office-01"]
        self.safe = False
        self.saved = None
        self.users = []

    def prompt(self):
        return "\r\n[netops@crs-office-01] <SAFE> " if self.safe else "\r\n[netops@crs-office-01] > "

    def handle(self, line):
        if line == "/export terse":
            return "# 2026-11-25 23:59:59 by RouterOS 7.16\r\n" + "\r\n".join(self.running)
        if "bogus" in line:
            return "bad command name bogus (line 1 column 1)"
        self.running.append(line)
        return ""

    def ctrl_x(self):
        if self.safe:
            self.safe, self.saved = False, None
            return "[Safe Mode released by user]"
        self.safe, self.saved = True, list(self.running)
        return "[Safe Mode taken]"

    def dropped(self):
        if self.safe:
            self.running, self.safe = self.saved, False


class Server(paramiko.ServerInterface):
    def __init__(self, fake):
        self.fake = fake

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self.fake.log.append(f"login {username}")
        ok = username.split("+")[0] == "netops" and password == "Secret-123"
        return paramiko.AUTH_SUCCESSFUL if ok else paramiko.AUTH_FAILED

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_shell_request(self, channel):
        threading.Thread(target=self.session, args=(channel,), daemon=True).start()
        return True

    def session(self, chan):
        f = self.fake
        mine = {"safe": False}
        chan.sendall(f.prompt().lstrip().encode())
        buf = ""
        try:
            while True:
                data = chan.recv(65536)
                if not data:
                    break
                buf += data.decode()
                while True:
                    if buf.startswith("\x18"):
                        buf = buf[1:]
                        out = f.ctrl_x()
                        mine["safe"] = getattr(f, "safe", False)
                        chan.sendall((out + f.prompt()).encode())
                        continue
                    if "\n" not in buf:
                        break
                    line, buf = buf.split("\n", 1)
                    line = line.rstrip("\r")
                    f.log.append(line)
                    out = f.handle(line)
                    chan.sendall((line + "\r\n" + out + f.prompt()).encode())
        except (OSError, EOFError):
            pass
        finally:
            if mine["safe"] and hasattr(f, "dropped"):
                f.dropped()


def _serve(fake):
    key = paramiko.RSAKey.generate(1024)
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    stop = threading.Event()

    def loop():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
            except OSError:
                continue
            t = paramiko.Transport(conn)
            t.add_server_key(key)
            try:
                t.start_server(server=Server(fake))
            except (paramiko.SSHException, EOFError):
                continue
    threading.Thread(target=loop, daemon=True).start()
    return {"key": key, "port": srv.getsockname()[1], "stop": stop, "srv": srv, "fake": fake}


@pytest.fixture
def serve():
    started = []

    def make(fake):
        s = _serve(fake)
        started.append(s)
        return s
    yield make
    for s in started:
        s["stop"].set()
        s["srv"].close()


def _connect(vendor, s, tmp_path):
    k = s["key"]
    (tmp_path / "ssh_known_hosts").write_text(f"[127.0.0.1]:{s['port']} {k.get_name()} {k.get_base64()}\n")
    return engine.connect(vendor, "127.0.0.1", "netops", "Secret-123", tmp_path, s["port"], NETS)


GOOD = Res("hostname sw1\ninterface Ethernet2\n   description new\n!\nvlan 20\n   name USERS\n")
BAD = Res("vlan 30\nbogus line\n")


def test_arista_session_timer_confirm_and_abort(serve, tmp_path):
    f = FakeEos()
    s = serve(f)
    shell, drv = _connect("arista", s, tmp_path)
    try:
        assert drv.hostname(drv.running()) == "sw1"
        prev = drv.preview(GOOD, "merge")
        assert "+vlan 20" in prev["diff"] and "+interface Ethernet2" in prev["diff"] and prev["check_ok"]
        assert f.running == ["hostname sw1", "interface Ethernet1", "   description uplink"] and not f.sessions
        drv.apply(GOOD, "merge", 7, "12", "c")
        assert "commit timer 00:07:00" in f.log and "vlan 20" in f.running
        assert "pending" in drv.pending_confirm("12")
        drv.confirm("12", "c")
        assert not f.pending and "write memory" in f.log
        drv.apply(Res("vlan 40\n"), "merge", 75, "13", "c")
        assert "commit timer 01:15:00" in f.log
        drv.rollback("13", "c")
        assert "vlan 40" not in f.running and "vlan 20" in f.running
        with pytest.raises(engine.PushError, match="refused 1 line"):
            drv.apply(BAD, "merge", 5, "14", "c")
        assert "vlan 30" not in f.running and not f.pending
    finally:
        shell.close()


def test_cisco_revert_timer(serve, tmp_path):
    f = FakeIos()
    s = serve(f)
    shell, drv = _connect("cisco", s, tmp_path)
    try:
        prev = drv.preview(GOOD, "merge")
        assert "+ archive" in prev["diff"] and "+ vlan 20" in prev["diff"] and "description new" in prev["diff"]
        assert "description uplink" not in prev["diff"]
        drv.apply(GOOD, "merge", 5, "1", "c")
        assert f.archive and "configure terminal revert timer 5" in f.log and "vlan 20" in f.running
        assert "5 min" in drv.pending_confirm()
        drv.confirm("1", "c")
        assert f.timer is None and "write memory" in f.log
        drv.apply(Res("vlan 50\n"), "merge", 5, "2", "c")
        drv.rollback("2", "c")
        assert "vlan 50" not in f.running and "vlan 20" in f.running
        with pytest.raises(engine.PushError, match="rolled back at once"):
            drv.apply(BAD, "merge", 5, "3", "c")
        assert "vlan 30" not in f.running and f.timer is None
    finally:
        shell.close()


def test_nexus_checkpoint_and_scheduled_rollback(serve, tmp_path):
    f = FakeNxos()
    s = serve(f)
    shell, drv = _connect("nexus", s, tmp_path)
    try:
        prev = drv.preview(GOOD, "merge")
        assert prev["check_ok"] and "+ vlan 20" in prev["diff"]
        drv.apply(GOOD, "merge", 9, "4", "c")
        assert "switchbuilder-4" in f.checkpoints and "sb-rollback-4" in f.schedules and "time start +0:0:9" in f.log
        assert drv.pending_confirm("4")
        drv.confirm("4", "c")
        assert not f.schedules and "copy running-config startup-config" in f.log and "vlan 20" in f.running
        drv.apply(Res("vlan 60\n"), "merge", 9, "5", "c")
        drv.rollback("5", "c")
        assert "vlan 60" not in f.running and not f.schedules
        assert not drv.preview(BAD, "merge")["check_ok"]
    finally:
        shell.close()


def test_aruba_checkpoint_auto(serve, tmp_path):
    f = FakeCx()
    s = serve(f)
    shell, drv = _connect("aruba", s, tmp_path)
    try:
        drv.apply(GOOD, "merge", 3, "6", "c")
        assert f.auto == 3 and "sb-before-6" in f.checkpoints and "vlan 20" in f.running
        assert drv.pending_confirm("6")
        drv.confirm("6", "c")
        assert f.auto is None and "write memory" in f.log
        drv.apply(Res("vlan 70\n"), "merge", 3, "7", "c")
        drv.rollback("7", "c")
        assert "vlan 70" not in f.running
        with pytest.raises(engine.PushError, match="refused"):
            drv.apply(BAD, "merge", 3, "8", "c")
        assert "vlan 30" not in f.running
    finally:
        shell.close()


def test_mikrotik_safe_mode_engine(serve, tmp_path):
    f = FakeRos()
    s = serve(f)
    shell, drv = _connect("mikrotik", s, tmp_path)
    assert "login netops+ct" in f.log
    assert drv.hostname(drv.running()) == "crs-office-01"
    drv.apply(Res("# comment\n/interface vlan\nadd name=v20 vlan-id=20\n"), "merge", 5, "1", "c")
    assert f.safe and "add name=v20 vlan-id=20" in f.running
    drv.rollback()
    time.sleep(0.5)
    assert not f.safe and "add name=v20 vlan-id=20" not in f.running
    shell, drv = _connect("mikrotik", s, tmp_path)
    with pytest.raises(engine.PushError, match="Safe Mode undid"):
        drv.apply(Res("/ip address\nbogus\n"), "merge", 5, "2", "c")
    time.sleep(0.5)
    assert "/ip address" not in f.running


def _vendor_project(app, admin, s, vendor):
    _form(admin, "/clients/1", action="ssh", networks="127.0.0.0/8", ssh_user="")
    _know(app, s)
    data = json.loads((EXAMPLES / f"{vendor}-office.json").read_text())
    return _approved_project(admin, data, name=f"{vendor} office")


def test_web_arista_push(app, admin, serve):
    f = FakeEos()
    f.hostname = "ar-office-01"
    f.running[0] = "hostname ar-office-01"
    s = serve(f)
    pid = _vendor_project(app, admin, s, "arista")
    assert _post(admin, "/push/preview", _creds(s, project_id=pid, host="127.0.0.1", mode="replace")).status_code == 200
    r = _post(admin, "/push/preview", _creds(s, project_id=pid, host="127.0.0.1")).json
    assert r["check_ok"] and "+hostname" not in r["diff"] and not r["hostname_mismatch"] and "show session" in r["note"]
    b = admin.get(f"/backups/{r['backup']['id']}").json
    assert b["source"] == "prepush" and "ar-office-01" in b["text"]
    assert _post(admin, f"/push/{r['id']}/apply", _creds(s, minutes=4)).json["status"] == "waiting"
    assert _post(admin, f"/push/{r['id']}/check", _creds(s)).json["pending"]
    assert _post(admin, f"/push/{r['id']}/confirm", _creds(s)).json["status"] == "confirmed"


def test_web_cisco_refuses_replace(app, admin, serve):
    s = serve(FakeIos())
    pid = _vendor_project(app, admin, s, "cisco")
    r = _post(admin, "/push/preview", _creds(s, project_id=pid, host="127.0.0.1", mode="replace"))
    assert r.status_code == 400 and "not offered" in r.json["error"]


def test_web_mikrotik_held_session(app, admin, serve):
    f = FakeRos()
    s = serve(f)
    pid = _vendor_project(app, admin, s, "mikrotik")
    r = _post(admin, "/push/preview", _creds(s, project_id=pid, host="127.0.0.1")).json
    assert "/system identity" in r["diff"] and not r["hostname_mismatch"]
    before = list(f.running)
    assert _post(admin, f"/push/{r['id']}/apply", _creds(s, minutes=2)).json["status"] == "waiting"
    assert f.safe and len(f.running) > len(before)
    time.sleep(1.5)
    chk = _post(admin, f"/push/{r['id']}/check", _creds(s)).json
    assert "Safe Mode" in chk["pending"]
    assert _post(admin, f"/push/{r['id']}/confirm", _creds(s)).json["status"] == "confirmed"
    time.sleep(0.5)
    assert not f.safe and len(f.running) > len(before)

    # Roll back: the held session is closed in Safe Mode and RouterOS undoes it.
    f.running = list(before)
    r = _post(admin, "/push/preview", _creds(s, project_id=pid, host="127.0.0.1")).json
    _post(admin, f"/push/{r['id']}/apply", _creds(s, minutes=2))
    assert f.safe
    assert _post(admin, f"/push/{r['id']}/rollback", _creds(s)).json["status"] == "rolled_back"
    time.sleep(0.5)
    assert f.running == before and not f.safe
