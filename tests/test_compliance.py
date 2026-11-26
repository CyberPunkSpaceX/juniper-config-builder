"""Compliance: score switches against a client's standard."""

import json
from pathlib import Path

import pytest

from exbuilder import compliance as C

ROOT = Path(__file__).parent.parent / "src" / "exbuilder"
ARISTA = json.loads((ROOT / "vendor_examples" / "arista-office.json").read_text())

IOS = """hostname acc-sw9
service password-encryption
username admin privilege 15 secret 9 $9$abc
username jsmith privilege 15 secret 9 $9$def
ip name-server 10.0.0.10
ip http server
ntp server 10.0.0.1
logging host 10.0.0.60
snmp-server community public RO
banner motd ^C Authorized access only ^C
spanning-tree mode rapid-pvst
spanning-tree portfast bpduguard default
interface GigabitEthernet1/0/1
 switchport mode access
interface GigabitEthernet1/0/2
 switchport mode access
line vty 0 4
 transport input telnet ssh
line vty 5 15
 transport input ssh
"""


def _status(r):
    return {x["rule"]: x["status"] for x in r["results"]}


def test_project_scores():
    r = C.check(C.Target("ar", "arista", ARISTA), C.default_standard())
    s = _status(r)
    assert s["ntp"] == s["syslog"] == s["dns"] == s["banner"] == s["no_telnet"] == s["bpdu_guard"] == "pass"
    assert s["snmpv3"] == "fail" and s["unused_off"] == "fail"
    total = sum(w for _k, _t, w, _v in C.RULES)
    assert r["score"] == round(100 * (total - 15 - 5) / total)


def test_standard_values_and_switching_rules_off():
    std = C.clean_standard({"rules": {"ntp": {"on": True, "weight": 10, "value": "10.10.0.1, 10.10.0.2"},
                                      "banner": {"on": True, "weight": "5", "value": "Authorized"},
                                      "timezone": {"on": True, "weight": 5, "value": "UTC"},
                                      "snmpv3": {"on": False}, "nonsense": {"on": True}}})
    assert "nonsense" not in std["rules"] and not std["rules"]["snmpv3"]["on"]
    r = C.check(C.Target("ar", "arista", ARISTA), std)
    s = {x["rule"]: x for x in r["results"]}
    assert s["ntp"]["status"] == "fail" and "10.10.0.2" in s["ntp"]["detail"]
    assert s["banner"]["status"] == "pass" and s["timezone"]["status"] == "fail"
    assert "snmpv3" not in s
    assert C.clean_standard({"rules": {"ntp": {"on": True, "weight": "lots"}}})["rules"]["ntp"]["weight"] == 10


def test_cisco_running_config():
    t = C.from_config("acc-sw9", IOS)
    assert t.vendor == "cisco" and t.project is not None
    r = C.check(t, C.default_standard())
    s = {x["rule"]: x for x in r["results"]}
    assert s["no_telnet"]["status"] == "fail" and "telnet" in s["no_telnet"]["detail"]
    assert s["no_http"]["status"] == "fail"
    assert s["no_default_community"]["status"] == "fail" and s["snmpv3"]["status"] == "fail"
    assert s["ntp"]["status"] == s["syslog"]["status"] == s["banner"]["status"] == "pass"
    assert s["bpdu_guard"]["status"] == "pass"
    assert s["local_users"]["status"] == "pass"
    fixed = IOS.replace(" transport input telnet ssh", " transport input ssh").replace("ip http server", "no ip http server")
    s2 = _status(C.check(C.from_config("acc-sw9", fixed), C.default_standard()))
    assert s2["no_telnet"] == "pass" and s2["no_http"] == "pass"


def test_text_only_brands():
    procurve = "; J9772A Configuration Editor; Created on release #YA.16\nhostname \"hp1\"\nsntp server priority 1 10.0.0.1\n"
    r = C.check(C.from_config("hp1", procurve), C.default_standard())
    s = {x["rule"]: x for x in r["results"]}
    assert r["vendor"] == "procurve" and s["no_telnet"]["status"] == "fail" and s["ntp"]["status"] == "pass"
    assert s["unused_off"]["status"] == "n/a" and s["ssh_root"]["status"] == "n/a"
    good = procurve + "no telnet-server\nno web-management\n"
    assert _status(C.check(C.from_config("hp1", good), C.default_standard()))["no_telnet"] == "pass"
    juniper = (ROOT / "map_examples" / "core-sw1.conf").read_text()
    s = _status(C.check(C.from_config("core", juniper), C.default_standard()))
    assert s["ssh_root"] == "pass" and s["no_telnet"] == "pass" and s["unused_off"] == "n/a"
    s = _status(C.check(C.from_config("core", juniper + "\nset system services ssh root-login allow\nset system services telnet\n"),
                        C.default_standard()))
    assert s["ssh_root"] == "fail" and s["no_telnet"] == "fail"
    out = C.run([C.from_config("hp1", procurve), C.Target("ar", "arista", ARISTA)], C.default_standard())
    assert out["switches"][0]["name"] == "hp1" and out["average"] is not None and out["most_failed"]


# ----------------------------------------------------------------- web
flask = pytest.importorskip("flask")
from test_auth import ADMIN, add_user, app, admin, csrf, login  # noqa: F401,E402
from test_builder_web import pick_space, token  # noqa: E402
from test_clients import _bob  # noqa: E402


def test_web_compliance(app, admin):
    pick_space(admin, "production")
    hdr = {"X-CSRF-Token": token(admin)}
    assert "Compliance" in admin.get("/tools/").get_data(as_text=True)
    assert "the default one" in admin.get("/tools/compliance").get_data(as_text=True)
    pid = admin.post("/projects", json={"name": "ar", "data": ARISTA}, headers=hdr).json["id"]
    with app.app_context():
        from exbuilder.web import auth, backups
        junos = (ROOT / "map_examples" / "core-sw1.conf").read_text()
        backups.store(auth.db(), 1, [{"name": "core-sw1", "address": "10.0.0.9", "text": junos}], "upload", "admin")
        auth.db().commit()
        bid = auth.db().execute("SELECT id FROM config_backups").fetchone()[0]
    r = admin.post("/tools/compliance/run", json={"project_ids": [pid], "backup_ids": [bid],
                                                  "configs": [{"name": "pasted", "text": IOS}]}, headers=hdr)
    assert r.status_code == 200 and len(r.json["switches"]) == 3
    assert r.json["switches"][0]["score"] < r.json["switches"][-1]["score"]
    assert admin.post("/tools/compliance/run", json={}, headers=hdr).status_code == 400
    std = C.default_standard()
    std["rules"]["snmpv3"]["on"] = False
    assert admin.post("/tools/compliance/standard", json=std, headers=hdr).json["ok"]
    assert "changed " in admin.get("/tools/compliance").get_data(as_text=True)
    r = admin.post("/tools/compliance/run", json={"project_ids": [pid]}, headers=hdr)
    assert all(x["rule"] != "snmpv3" for x in r.json["switches"][0]["results"])
    bob = _bob(app, admin, role="editor")
    pick_space(bob, "production")
    assert bob.post("/tools/compliance/standard", json=std, headers={"X-CSRF-Token": token(bob)}).status_code == 403
    assert bob.post("/tools/compliance/run", json={"project_ids": [pid]}, headers={"X-CSRF-Token": token(bob)}).status_code == 200
