"""EVE-NG labs, against a fake EVE-NG API and fake Junos consoles."""

import json
import re
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from exbuilder import eveng

EXAMPLES = Path(__file__).parent.parent / "src" / "exbuilder" / "map_examples"


def example_items():
    return [{"name": f.stem, "text": f.read_text()} for f in sorted(EXAMPLES.glob("*.conf"))]


@pytest.fixture(autouse=True)
def allow_localhost(monkeypatch):
    monkeypatch.setenv("EXB_SSH_ALLOW", "127.0.0.0/8")


# ------------------------------------------------------------- pure parts
def test_plan_maps_ports_and_links():
    p = eveng.plan(example_items())
    nodes = {n["hostname"]: n for n in p["nodes"]}
    assert set(nodes) == {"core-sw1", "acc-sw1", "acc-sw2"}
    assert nodes["core-sw1"]["ports"] == {"ge-0/0/0": "ge-0/0/0", "xe-0/1/0": "ge-0/0/1", "xe-0/1/1": "ge-0/0/2",
                                          "xe-0/1/2": "ge-0/0/3"}
    assert len(p["links"]) == 4  # two LAG members, one trunk, one routed link
    assert all(set(n["ports"].values()) <= {f"ge-0/0/{i}" for i in range(10)} for n in p["nodes"])


def test_lab_config_rewrites_for_the_lab():
    p = eveng.plan(example_items())
    core = next(n for n in p["nodes"] if n["hostname"] == "core-sw1")
    lines, notes = eveng.lab_config(core["text"], core["ports"], "$6$salt$hash")
    text = "\n".join(lines)
    assert "set interfaces ge-0/0/1 ether-options 802.3ad ae0" in text           # LAG member moved
    assert 'description "to acc-sw2 xe-0/1/0"' in text                          # descriptions untouched
    assert "set chassis aggregated-devices ethernet device-count 2" in text       # LAGs still work
    assert "me0" not in text and "set version" not in text
    assert 'set system login user exb-lab class super-user authentication encrypted-password "$6$salt$hash"' in text
    assert notes
    text = ("set interfaces ge-0/0/5 unit 0 family ethernet-switching vlan members USERS\n"
            "set interfaces interface-range DESKS member ge-0/0/6\n"
            "set interfaces interface-range DESKS unit 0 family ethernet-switching\n"
            "set protocols rstp interface DESKS edge\nset protocols lldp interface ge-0/0/5\n"
            "set interfaces xe-0/1/0 description uplink\nset poe interface all\n")
    lines, notes = eveng.lab_config(text, {"xe-0/1/0": "ge-0/0/0"}, "$6$s$h")
    assert lines[0] == "set interfaces ge-0/0/0 description uplink"
    assert not [ln for ln in lines if "DESKS" in ln or "ge-0/0/5" in ln or "poe" in ln]
    assert any("ports not linked" in n for n in notes)


def test_too_many_links_and_unknown_far_ends():
    core = "set system host-name hub\n" + "".join(
        f'set interfaces ge-0/0/{i} description "to leaf{i}"\n' for i in range(12))
    leaves = [f"set system host-name leaf{i}\nset interfaces ge-0/0/1 description \"to hub ge-0/0/{i}\"\n"
              for i in range(12)]
    p = eveng.plan([{"text": core}] + [{"text": t} for t in leaves])
    assert len(p["nodes"][0]["ports"]) == 10 and any("left out" in n for n in p["notes"])


def test_eve_address_must_be_allowed(monkeypatch):
    monkeypatch.setenv("EXB_SSH_ALLOW", "10.0.0.0/8")
    with pytest.raises(eveng.EveError, match="outside"):
        eveng.check_url("http://127.0.0.1:8080")
    with pytest.raises(eveng.EveError, match="like"):
        eveng.check_url("ftp://10.1.1.1")
    with pytest.raises(eveng.EveError, match="like"):
        eveng.check_url("http://user:pw@10.1.1.1")
    assert eveng.check_url("https://10.1.1.1/")[0] == "https://10.1.1.1"


# -------------------------------------------------------- fake Junos console
class FakeConsole:
    """A Junos serial console: login, CLI, configure, load set terminal, commit, show configuration."""

    def __init__(self, lab_password_box: dict):
        self.box = lab_password_box
        self.config: list[str] = ["set system host-name Amnesiac", "set interfaces ge-0/0/0 unit 0 family inet dhcp"]
        self.commands: list[str] = []
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.stop = threading.Event()
        threading.Thread(target=self.serve, daemon=True).start()

    def serve(self):
        self.srv.settimeout(0.2)
        while not self.stop.is_set():
            try:
                conn, _ = self.srv.accept()
            except OSError:
                continue
            threading.Thread(target=self.session, args=(conn,), daemon=True).start()

    def session(self, conn):
        conn.sendall(bytes([255, 251, 1]) + b"\r\nFreeBSD/amd64 (Amnesiac) (ttyu0)\r\n\r\nlogin: ")
        state, user, loading, buf = "login", "", None, b""
        prompt = {"shell": b"root@:~ # ", "cli": b"root> ", "cfg": b"root# "}
        while True:
            try:
                data = conn.recv(65536)
            except OSError:
                return
            if not data:
                return
            data = re.sub(rb"\xff[\xfb-\xfe].", b"", data)
            buf += data
            while True:
                if loading is not None and b"\x04" in buf:
                    before, buf = buf.split(b"\x04", 1)
                    loading += [ln for ln in before.decode().replace("\r", "\n").split("\n") if ln.strip()]
                    bad = [ln for ln in loading if not ln.startswith("set ")]
                    self.pending = [ln for ln in loading if ln.startswith("set ")]
                    msg = "".join(f"terminal:{i}:(1) syntax error: {ln}\r\n" for i, ln in enumerate(bad))
                    conn.sendall(f"\r\n{msg}load complete\r\n\r\n[edit]\r\n".encode() + prompt["cfg"])
                    loading = None
                    continue
                m = re.search(rb"[\r\n]", buf)
                if not m:
                    break
                line, buf = buf[:m.start()].decode(), buf[m.end():]
                if loading is not None:
                    if line.strip():
                        loading.append(line.strip())
                    continue
                self.commands.append(line)
                if state == "login":
                    if line == "":
                        conn.sendall(b"\r\nlogin: ")
                    elif line == "root":
                        state = "shell" if not self.box.get("root_set") else "pw-root"
                        conn.sendall(prompt["shell"] if state == "shell" else b"Password:")
                    else:
                        user, state = line, "pw"
                        conn.sendall(b"Password:")
                elif state in ("pw", "pw-root"):
                    ok = (state == "pw" and user == "exb-lab" and self.box.get("lab") and
                          self.box["lab"](line))
                    if ok:
                        state = "cli"
                        conn.sendall(b"\r\n" + prompt["cli"])
                    else:
                        state = "login"
                        conn.sendall(b"\r\nLogin incorrect\r\nlogin: ")
                elif state == "shell":
                    if line == "cli":
                        state = "cli"
                    conn.sendall(b"\r\n" + prompt[state])
                elif state == "cli":
                    out = ""
                    if line == "configure":
                        state, out = "cfg", "Entering configuration mode\r\n\r\n[edit]\r\n"
                    elif line.startswith("set cli screen-length"):
                        out = "Screen length set to 0\r\n"
                    elif line.startswith("show configuration"):
                        out = "".join(c + "\r\n" for c in self.config)
                    conn.sendall(f"{line}\r\n{out}".encode() + prompt[state])
                elif state == "cfg":
                    if line == "load set terminal":
                        loading = []
                        conn.sendall(b"[Type ^D at a new line to end input]\r\n")
                        continue
                    if line.startswith("delete "):
                        top = line.split()[1]
                        self.config = [c for c in self.config if c.split()[1] != top]
                    if line == "commit and-quit":
                        self.config += [ln for ln in self.pending if ln not in self.config]
                        if any("root-authentication" in ln for ln in self.config):
                            self.box["root_set"] = True
                        state = "cli"
                        conn.sendall(b"commit complete\r\nExiting configuration mode\r\n\r\n" + prompt["cli"])
                        continue
                    conn.sendall(b"\r\n[edit]\r\n" + prompt[state])

    def close(self):
        self.stop.set()
        self.srv.close()


def test_console_push_and_pull():
    from exbuilder import cryptpw
    box = {}
    con_srv = FakeConsole(box)
    try:
        lines = ["set system host-name lab1", 'set system login user exb-lab class super-user authentication '
                 f'encrypted-password "{cryptpw.sha512_crypt("pw-123")}"', "set vlans USERS vlan-id 20"]
        box["lab"] = lambda pw: pw == "pw-123"
        con = eveng.Console("127.0.0.1", con_srv.port)
        con.login([("root", ""), ("exb-lab", "pw-123")], boot_timeout=10)
        assert con.push(lines, eveng.top_levels(lines)) == "committed"
        con.close()
        assert "set vlans USERS vlan-id 20" in con_srv.config
        assert "delete vlans" in con_srv.commands and "delete chassis auto-image-upgrade" in con_srv.commands
        box["root_set"] = True
        con = eveng.Console("127.0.0.1", con_srv.port)
        con.login([("exb-lab", "pw-123"), ("root", "")], boot_timeout=10)
        text = con.pull()
        con.close()
        assert "set vlans USERS vlan-id 20" in text and "root>" not in text
    finally:
        con_srv.close()


# ------------------------------------------------------------ fake EVE-NG
class FakeEve:
    def __init__(self):
        self.labs, self.folders, self.calls = {}, {"/"}, []
        self.consoles: dict[int, FakeConsole] = {}
        self.box = {}
        fake = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, code, data=None, message="", cookie=None):
                body = json.dumps({"code": code, "status": "success" if code < 400 else "fail",
                                   "message": message, "data": data}).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                if cookie:
                    self.send_header("Set-Cookie", cookie)
                self.end_headers()
                self.wfile.write(body)

            def _body(self):
                n = int(self.headers.get("Content-Length") or 0)
                return json.loads(self.rfile.read(n) or b"{}") if n else {}

            def handle_one(self, method):
                from urllib.parse import unquote
                path = unquote(self.path)
                body = self._body() if method in ("POST", "PUT") else {}
                fake.calls.append((method, path, body))
                if path == "/api/auth/login":
                    if body.get("username") == "builder" and body.get("password") == "eve-pass-1":
                        return self._send(200, cookie="unetlab_session=abc; Path=/")
                    return self._send(400, message="Invalid username/password")
                if "unetlab_session=abc" not in (self.headers.get("Cookie") or ""):
                    return self._send(412, message="User is not authenticated")
                if path == "/api/auth/logout":
                    return self._send(200)
                if path == "/api/status":
                    return self._send(200, {"version": "6.2.0-test"})
                if path == "/api/list/templates/":
                    return self._send(200, {"vjunosswitch": "Juniper vJunos-switch", "vmx": "Juniper vMX",
                                            "linux": "Linux", "vsrxng": "Juniper vSRX NG.missing"})
                m = re.match(r"^/api/list/templates/(\w+)$", path)
                if m:
                    imgs = {"vjunosswitch": ["vjunos-switch-23.2R1.14"], "vmx": ["vmx-22.1"]}.get(m.group(1), [])
                    return self._send(200, {"options": {"image": {"list": {i: i for i in imgs}}}})
                if path.startswith("/api/folders"):
                    if method == "GET":
                        f = path[len("/api/folders"):] or "/"
                        return self._send(200, {}) if f in fake.folders else self._send(404, message="nope")
                    fake.folders.add((body["path"].rstrip("/") + "/" + body["name"]).replace("//", "/"))
                    return self._send(200)
                if path == "/api/labs" and method == "POST":
                    lab = f"{body['path'].rstrip('/')}/{body['name']}.unl"
                    fake.labs[lab] = {"nodes": {}, "networks": {}, "running": False}
                    return self._send(200)
                m = re.match(r"^/api/labs(/.+?\.unl)(/.*)?$", path)
                if not m:
                    return self._send(404, message="unknown")
                lab, rest = m.group(1), m.group(2) or ""
                if lab not in fake.labs:
                    return self._send(404, message="Lab does not exist")
                L = fake.labs[lab]
                if rest == "" and method == "GET":
                    return self._send(200, {"name": lab})
                if rest == "" and method == "DELETE":
                    del fake.labs[lab]
                    return self._send(200)
                if rest == "/nodes" and method == "POST":
                    nid = len(L["nodes"]) + 1
                    con = FakeConsole(fake.box)
                    fake.consoles[nid] = con
                    L["nodes"][str(nid)] = dict(body, id=nid, url=f"telnet://eve.example:{con.port}", ifs={})
                    return self._send(201, {"id": nid})
                if rest == "/nodes" and method == "GET":
                    return self._send(200, L["nodes"])
                if rest == "/networks" and method == "POST":
                    net = len(L["networks"]) + 1
                    L["networks"][net] = body
                    return self._send(201, {"id": net})
                m2 = re.match(r"^/nodes/(\d+)/interfaces$", rest)
                if m2 and method == "PUT":
                    L["nodes"][m2.group(1)]["ifs"].update(body)
                    return self._send(201)
                if rest in ("/nodes/start", "/nodes/stop"):
                    L["running"] = rest.endswith("start")
                    return self._send(200)
                return self._send(404, message="unknown")

            def do_GET(self):
                self.handle_one("GET")

            def do_POST(self):
                self.handle_one("POST")

            def do_PUT(self):
                self.handle_one("PUT")

            def do_DELETE(self):
                self.handle_one("DELETE")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def close(self):
        self.httpd.shutdown()
        for c in self.consoles.values():
            c.close()


def test_eve_client_lists_juniper_images():
    fake = FakeEve()
    try:
        eve = eveng.Eve(fake.url, "builder", "eve-pass-1")
        eve.login()
        imgs = eve.juniper_images()
        assert [(i["template"], i["supported"]) for i in imgs] == [("vjunosswitch", True), ("vmx", False)]
        with pytest.raises(eveng.EveError, match="sign-in failed"):
            eveng.Eve(fake.url, "builder", "wrong").login()
    finally:
        fake.close()


def _wait(client, jid, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        job = client.get(f"/eve/jobs/{jid}").json
        if job["status"] != "running":
            return job
        time.sleep(0.3)
    raise AssertionError("job did not finish: " + json.dumps(job))


def test_build_and_pull_a_lab_from_the_web(monkeypatch, tmp_path):
    pytest.importorskip("flask")
    from test_auth import ADMIN, csrf, login
    from test_builder_web import token
    from exbuilder.web import create_app
    monkeypatch.setenv("EXB_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("EXB_USERNAME", ADMIN[0])
    monkeypatch.setenv("EXB_PASSWORD", ADMIN[1])
    monkeypatch.setattr(eveng.Eve, "console", lambda self, lab, nid: ("127.0.0.1", fake.consoles[int(nid)].port))
    fake = FakeEve()
    try:
        app = create_app()
        app.testing = True
        c = app.test_client()
        assert login(c, *ADMIN).status_code == 302
        hdr = {"X-CSRF-Token": token(c)}
        page = c.get("/").get_data(as_text=True)
        assert "EVE-NG is not set up" in page
        assert c.get("/eve/images").status_code == 400
        f = csrf(c, "/clients/1")
        c.post("/clients/1", data={"csrf_token": f, "action": "eve", "eve_url": "http://8.8.8.8", "eve_user": "builder",
                                   "eve_password": "eve-pass-1", "eve_folder": "/exbuilder"})
        assert "8.8.8.8" not in c.get("/clients/1").get_data(as_text=True).split('name="eve_url"')[1][:80]
        c.post("/clients/1", data={"csrf_token": f, "action": "eve", "eve_url": fake.url, "eve_user": "builder",
                                   "eve_password": "eve-pass-1", "eve_folder": "/exbuilder"})
        import sqlite3
        stored = sqlite3.connect(tmp_path / "users.db").execute("SELECT eve_password FROM clients").fetchone()[0]
        assert "eve-pass-1" not in stored
        resp = c.post("/clients/1", data={"csrf_token": f, "action": "eve_test"}, follow_redirects=True)
        assert "Connected to EVE-NG 6.2.0-test" in resp.get_data(as_text=True)
        imgs = c.get("/eve/images").json["images"]
        assert imgs[0]["images"] == ["vjunos-switch-23.2R1.14"]
        assert "Build lab in EVE-NG" in c.get("/").get_data(as_text=True)

        items = example_items()
        body = {"name": "office-test", "template": "vjunosswitch", "image": "vjunos-switch-23.2R1.14",
                "items": items, "positions": {"core-sw1": {"x": 300, "y": 30}}, "start": True}
        assert c.post("/eve/labs", json={**body, "name": "bad name!"}, headers=hdr).status_code == 400
        fake.box["lab"] = None   # set below, once the job made the lab password
        jid = c.post("/eve/labs", json=body, headers=hdr).json["job"]
        # The fake consoles check the lab password against the hash the job put in the config.
        from exbuilder import cryptpw

        def check(pw):
            for con in fake.consoles.values():
                for ln in con.config:
                    m = re.search(r'login user exb-lab .*encrypted-password "([^"]+)"', ln)
                    if m:
                        salt = m.group(1).split("$")[2]
                        return cryptpw.sha512_crypt(pw, salt) == m.group(1)
            return False
        fake.box["lab"] = check
        job = _wait(c, jid)
        assert job["status"] == "done", job
        lab = fake.labs["/exbuilder/office-test.unl"]
        assert len(lab["nodes"]) == 3 and len(lab["networks"]) == 4 and lab["running"]
        assert all(n["template"] == "vjunosswitch" and n["console"] == "telnet" for n in lab["nodes"].values())
        core_id = next(k for k, n in lab["nodes"].items() if n["name"] == "core-sw1")
        assert lab["nodes"][core_id]["left"] == 360 and set(lab["nodes"][core_id]["ifs"]) == {"1", "2", "3", "4"}
        core = fake.consoles[int(core_id)]
        assert "set interfaces ge-0/0/1 ether-options 802.3ad ae0" in core.config
        assert any(s["text"].endswith("config loaded and committed.") for s in job["steps"])

        labs = c.get("/eve/labs").json["labs"]
        assert labs[0]["name"] == "office-test" and labs[0]["nodes"][0]["ports"]
        # Same name again: refused unless replace is ticked.
        again = _wait(c, c.post("/eve/labs", json={**body, "start": False}, headers=hdr).json["job"])
        assert again["status"] == "failed" and "already exists" in again["steps"][-1]["text"]

        # Pull: real port names come back, the lab login is left out.
        pulled = _wait(c, c.post(f"/eve/labs/{labs[0]['id']}/pull", json={}, headers=hdr).json["job"])
        assert pulled["status"] == "done", pulled
        core_text = next(i["text"] for i in pulled["result"]["items"] if i["name"] == "core-sw1")
        assert "set interfaces xe-0/1/0 ether-options 802.3ad ae0" in core_text
        assert "exb-lab" not in core_text
        kept = [b for b in c.get("/backups").json["backups"] if b["source"] == "eve"]
        assert {b["host"] for b in kept} >= {"core-sw1"} and kept[0]["note"] == "lab office-test"

        assert c.post(f"/eve/labs/{labs[0]['id']}/delete", json={}, headers=hdr).json["ok"]
        assert "/exbuilder/office-test.unl" not in fake.labs and c.get("/eve/labs").json["labs"] == []
    finally:
        fake.close()
