"""One-switch EVE-NG labs for every vendor, against fake consoles for each network OS."""

import json
import re
import socket
import threading
from pathlib import Path

import pytest

from switchbuilder import evelab, eveng
from switchbuilder.generator import build

EXAMPLES = Path(__file__).parent.parent / "src" / "switchbuilder" / "vendor_examples"


def example(vendor):
    name = {"ruckus": "ruckus-office"}.get(vendor, f"{vendor}-office")
    return json.loads((EXAMPLES / f"{name}.json").read_text())


JUNIPER = {"vendor": "juniper", "system": {"hostname": "sw1", "banner": "Authorised use only"},
           "access": {"root_password": "Root-pass-1234"},
           "switch": {"members": [{"fpc": 0, "model": "EX2300-48P"}, {"fpc": 1, "model": "EX2300-48P"}]},
           "vlans": [{"id": "10", "name": "DATA"}],
           "ports": [{"name": "desk", "ports": "ge-0/0/0-20", "mode": "access", "vlan": "DATA"},
                     {"name": "up", "ports": "ge-1/1/0", "mode": "trunk", "vlans": "DATA"}]}


# ------------------------------------------------------------- the project
@pytest.mark.parametrize("vendor", [v for v in evelab.LABS if v != "juniper"])
def test_every_lab_vendor_example_fits_its_lab_switch(vendor):
    p = example(vendor)
    lab, mapping, notes = evelab.lab_project(p, "Lab-pass-123456")
    spec = evelab.LABS[vendor]
    assert lab["switch"]["members"] == [dict(lab["switch"]["members"][0], model=spec.model)]
    assert len(set(mapping.values())) == len(mapping) <= spec.ports
    # Every port group and LAG that had ports is still there, with at least one port.
    want = [r["name"] for r in p["ports"] if r.get("ports") and r.get("mode") != "disabled"]
    assert [r["name"] for r in lab["ports"]] == want
    assert len(lab["lags"]) == len([r for r in p.get("lags") or [] if r.get("members")])
    assert any(u["name"] == "exb-lab" and u["class"] == "super-user" for u in lab["access"]["users"])
    assert lab["system"]["mgmt_address"] == "" and lab["system"]["banner"] == ""
    res = build(lab)
    assert not res.errors, res.errors
    assert "exb-lab" in res.set_text
    lines, _, _ = evelab.lab_text(p, "Lab-pass-123456", "$6$x$y")
    assert lines and not any("ethernet1/1/49" in ln or "Ethernet49" in ln for ln in lines)


def test_juniper_lab_uses_vjunos_ports_and_one_member():
    lines, mapping, notes = evelab.lab_text(JUNIPER, "Lab-pass-123456", "$6$salt$hash")
    assert mapping["ge-0/0/0"] == "ge-0/0/0" and mapping["ge-1/1/0"] == "ge-0/0/1"
    assert set(mapping.values()) == {f"ge-0/0/{i}" for i in range(10)}
    assert "set interfaces ge-0/0/1 unit 0 family ethernet-switching interface-mode trunk" in lines
    assert any(ln.startswith("set interfaces ge-0/0/9 ") for ln in lines)
    assert not any("ge-0/0/20" in ln or "ge-1/" in ln or "virtual-chassis" in ln or "banner" in ln for ln in lines)
    assert lines[-1] == 'set system login user exb-lab class super-user authentication encrypted-password "$6$salt$hash"'
    assert any("stack member" in n for n in notes) and any("12 of the project's ports" in n for n in notes)


@pytest.mark.parametrize("vendor", sorted(evelab.NO_LAB))
def test_vendors_without_a_lab_image_say_why(vendor):
    with pytest.raises(eveng.EveError, match="virtual switch image|no virtual switch"):
        evelab.lab_project(example(vendor), "x")
    assert evelab.catalog()[vendor]["possible"] is False


def test_rename_back_and_strip_lab_user():
    text = "interface Ethernet1\n description to Ethernet10\ninterface Ethernet10\nusername exb-lab secret x\n"
    back = evelab.rename_back(text, {"Ethernet49": "Ethernet1", "Ethernet3": "Ethernet10"})
    assert back.startswith("interface Ethernet49\n description to Ethernet3\ninterface Ethernet3\n")
    assert "exb-lab" not in evelab.strip_lab_user(back)
    # Bare numbers (EXOS) are never renamed: they could be anything.
    assert evelab.rename_back("configure vlan 10 add ports 1", {"49": "1"}) == "configure vlan 10 add ports 1"


# --------------------------------------------------------------- consoles
# What each fake OS says at first boot: (what it prints, what it wants back or None for anything).
BOOT = {
    "eos": [("\r\nZeroTouch Provisioning is active\r\nlocalhost login: ", "admin"), ("localhost>", None)],
    "ios": [("\r\nWould you like to enter the initial configuration dialog? [yes/no]: ", "no"),
            ("\r\nPress RETURN to get started!\r\n", ""), ("Switch>", None)],
    "nxos": [("\r\nAbort Power On Auto Provisioning [yes - continue with normal setup, skip - bypass password and "
              "basic configuration, no - continue with Power On Auto Provisioning] (yes/skip/no)[no]: ", "yes"),
             ("\r\nDo you want to enforce secure password standard (yes/no) [y]: ", "no"),
             ('\r\n    Enter the password for "admin": ', "{lab}"), ('\r\n  Confirm the password for "admin": ', "{lab}"),
             ("\r\nWould you like to enter the basic configuration dialog (yes/no): ", "no"),
             ("\r\nswitch login: ", "admin"), ("Password: ", "{lab}"), ("switch# ", None)],
    "os10": [("\r\nOS10 login: ", "admin"), ("Password: ", "admin"), ("OS10# ", None)],
    "exos": [("\r\nlogin: ", "admin"), ("password: ", ""),
             ("\r\nWould you like to disable Telnet? [y/N]: ", "n"), ("VM_EXOS.1 # ", None)],
    "aoscx": [("\r\nswitch login: ", "admin"), ("Password: ", ""),
              ("\r\nPlease configure the 'admin' user account password.\r\nEnter new password: ", "{lab}"),
              ("Confirm new password: ", "{lab}"), ("switch# ", None)],
    "routeros": [("\r\nMikroTik Login: ", "admin+ct"), ("Password: ", ""),
                 ("\r\nDo you want to see the software license? [Y/n]: ", "n"),
                 ("\r\nnew password> ", "{lab}"), ("repeat new password> ", "{lab}"), ("[admin@MikroTik] > ", None)],
}
SAVE = {"eos": "write memory", "ios": "write memory", "nxos": "copy running-config startup-config",
        "os10": "write memory", "exos": "save configuration", "aoscx": "write memory", "routeros": None}


class FakeOs:
    """A console that goes through BOOT, then echoes commands and keeps what it was told."""

    def __init__(self, dialect: str, lab: str):
        self.dialect, self.lab = dialect, lab
        self.got: list[str] = []
        self.problems: list[str] = []
        self.saved = False
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.booted = False
        self.ztp_cancelled = False
        threading.Thread(target=self.serve, daemon=True).start()

    def close(self):
        self.srv.close()

    def serve(self):
        while True:
            try:
                conn, _ = self.srv.accept()
            except OSError:
                return
            threading.Thread(target=self.session, args=(conn,), daemon=True).start()

    def lines(self, conn):
        buf = b""
        while True:
            while b"\r" not in buf:
                data = conn.recv(65536)
                if not data:
                    return
                buf += re.sub(rb"\xff[\xfb-\xfe].", b"", data)
            line, buf = buf.split(b"\r", 1)
            yield line.decode().lstrip("\n")

    def session(self, conn):
        it = self.lines(conn)
        prompt = ""
        try:
            if not self.booted:
                for say, want in BOOT[self.dialect]:
                    conn.sendall(("\x1b[0m" + say).encode())
                    if want is None:
                        prompt = say
                        break
                    got = next(it)
                    while got == "" and want != "":   # extra Enters while it boots
                        got = next(it)
                    if got != want.replace("{lab}", self.lab):
                        self.problems.append(f"wanted {want!r}, got {got!r}")
                        return
                self.booted = True
            else:   # signing in again to read the config back
                conn.sendall(b"\r\nlogin: ")
                user = next(it)
                conn.sendall(b"Password: ")
                pw = next(it)
                if not (user.startswith("exb-lab") and pw == self.lab) and not (user.startswith("admin") and pw in ("", "admin", self.lab)):
                    self.problems.append(f"login {user}/{pw}")
                prompt = BOOT[self.dialect][-1][0]
                conn.sendall(prompt.encode())
            for line in it:
                self.got.append(line)
                out = line + "\r\n"
                if line == "zerotouch cancel":
                    self.ztp_cancelled = True
                    self.booted = False
                    conn.sendall(out.encode() + b"ZeroTouch cancelled, reloading\r\n\r\nlocalhost login: ")
                    self.booted = True
                    want = next(it)
                    while want == "":   # Enter while it reboots: the login prompt again
                        conn.sendall(b"\r\nlocalhost login: ")
                        want = next(it)
                    conn.sendall(b"localhost>")
                    continue
                if "bogus" in line:
                    out += "% Invalid input detected at '^' marker.\r\n"
                if line == SAVE[self.dialect]:
                    if self.dialect == "exos":
                        conn.sendall((out + "Do you want to save configuration to primary.cfg and overwrite it? (y/N) ").encode())
                        if next(it) == "y":
                            self.saved = True
                        out = "Configuration saved to primary.cfg successfully.\r\n"
                    else:
                        self.saved = True
                if line in ("show running-config", "show running-configuration", "show configuration", "/export"):
                    out += "".join(f"{ln}\r\n" for ln in self.got if not ln.startswith(("show", "terminal", "no page",
                                                                                         "disable clip", "/export")))
                conn.sendall((out + prompt).encode())
        except (StopIteration, OSError):
            return


@pytest.mark.parametrize("dialect", sorted(evelab.DIALECTS))
def test_lab_console_first_boot_push_and_pull(dialect):
    fake = FakeOs(dialect, "Lab-pw-1")
    try:
        con = evelab.LabConsole("127.0.0.1", fake.port, dialect, "Lab-pw-1", timeout=5)
        con.login(boot_timeout=20)
        d = evelab.DIALECTS[dialect]
        refused = con.push([f"{d.comment} a comment", "hostname lab-1", "bogus command", *d.skip, ""])
        con.close()
        assert not fake.problems, fake.problems
        assert "hostname lab-1" in fake.got and f"{d.comment} a comment" not in fake.got
        assert fake.got.count("end") == (1 if "end" in d.leave else 0)   # only ours, after the config
        assert len(refused) == 1 and refused[0].startswith("bogus command  ->  % Invalid input")
        if SAVE[dialect]:
            assert fake.saved
        if dialect == "eos":
            assert fake.ztp_cancelled
        con = evelab.LabConsole("127.0.0.1", fake.port, dialect, "Lab-pw-1", timeout=5)
        con.login(boot_timeout=20)
        text = con.pull()
        con.close()
        assert not fake.problems, fake.problems
        assert "hostname lab-1" in text and "\x1b" not in text
    finally:
        fake.close()


# ------------------------------------------------------------------- web
def test_build_an_arista_lab_from_the_web(monkeypatch, tmp_path):
    pytest.importorskip("flask")
    import test_eveng
    from test_auth import ADMIN, csrf, login
    from test_builder_web import token
    from switchbuilder.web import create_app
    monkeypatch.setenv("EXB_SSH_ALLOW", "127.0.0.0/8")
    monkeypatch.setenv("EXB_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("EXB_USERNAME", ADMIN[0])
    monkeypatch.setenv("EXB_PASSWORD", ADMIN[1])
    from types import SimpleNamespace
    from switchbuilder.web import eve as eve_web
    monkeypatch.setattr(eve_web, "secrets", SimpleNamespace(token_urlsafe=lambda n=16: "Lab-pw-from-test"))
    oses: dict[int, FakeOs] = {}

    def make_console(box):
        f = FakeOs("eos", "Lab-pw-from-test")
        oses[len(oses) + 1] = f
        return f
    monkeypatch.setattr(test_eveng, "FakeConsole", make_console)
    monkeypatch.setattr(test_eveng.FakeEve, "TEMPLATES", {"veos": "Arista vEOS", "vjunosswitch": "Juniper vJunos-switch"},
                        raising=False)
    monkeypatch.setattr(test_eveng.FakeEve, "IMAGES", {"veos": ["veos-4.32.1F"], "vjunosswitch": ["vjunos-switch-23.2R1.14"]},
                        raising=False)
    monkeypatch.setattr(eveng.Eve, "console", lambda self, lab, nid: ("127.0.0.1", oses[int(nid)].port))
    fake = test_eveng.FakeEve()
    try:
        app = create_app()
        app.testing = True
        c = app.test_client()
        assert login(c, *ADMIN).status_code == 302
        hdr = {"X-CSRF-Token": token(c)}
        # FortiSwitch says why there's no lab, in either space.
        assert "Not possible for Fortinet FortiSwitch" in c.get("/build/fortiswitch").get_data(as_text=True)
        assert "EVE-NG labs are built in the <b>Lab</b> space" in c.get("/build/arista").get_data(as_text=True)
        c.post("/space", data={"csrf_token": csrf(c, "/start"), "space": "lab"})
        f = csrf(c, "/clients/1")
        c.post("/clients/1", data={"csrf_token": f, "action": "eve", "eve_url": fake.url, "eve_user": "builder",
                                   "eve_password": "eve-pass-1", "eve_folder": "/exbuilder"})
        resp = c.post("/clients/1", data={"csrf_token": f, "action": "eve_test"}, follow_redirects=True)
        assert "Other vendors with a lab image: Arista vEOS-lab" in resp.get_data(as_text=True)
        page = c.get("/build/arista").get_data(as_text=True)
        assert "Build this switch in EVE-NG" in page and "Build lab from the map" not in page
        info = c.get("/eve/vendor?vendor=arista").json
        assert info["images"][0]["images"] == ["veos-4.32.1F"] and info["lab"]["default"] == "veos"
        assert c.get("/eve/vendor?vendor=unifi").json["lab"]["possible"] is False

        project = example("arista")
        body = {"name": "arista-test", "template": "veos", "image": "veos-4.32.1F", "project": project}
        bad = c.post("/eve/project-labs", json={**body, "project": example("unifi")}, headers=hdr)
        assert bad.status_code == 400 and "UniFi" in bad.json["error"]
        jid = c.post("/eve/project-labs", json=body, headers=hdr).json["job"]
        job = test_eveng._wait(c, jid)
        assert job["status"] == "done", job
        node = fake.labs["/exbuilder/arista-test.unl"]["nodes"]["1"]
        assert node["template"] == "veos" and node["ram"] == 4096 and node["ethernet"] == 13
        os1 = oses[1]
        assert not os1.problems and os1.saved and "configure terminal" in os1.got
        assert any(ln.startswith("username exb-lab") for ln in os1.got)
        assert "interface Ethernet1" in os1.got      # the uplink moved from Ethernet49
        assert any("config typed in and saved" in s["text"] for s in job["steps"])

        labs = c.get("/eve/labs").json["labs"]
        assert labs[0]["nodes"][0]["vendor"] == "arista" and labs[0]["nodes"][0]["ports"]["Ethernet49"] == "Ethernet1"
        pulled = test_eveng._wait(c, c.post(f"/eve/labs/{labs[0]['id']}/pull", json={}, headers=hdr).json["job"])
        assert pulled["status"] == "done", pulled
        text = pulled["result"]["items"][0]["text"]
        assert "interface Ethernet49" in text and "exb-lab" not in text
        assert [b for b in c.get("/backups").json["backups"] if b["source"] == "eve"] == []
    finally:
        fake.close()
