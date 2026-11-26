"""Global: a client's switches on one page, and each switch's history of changes."""

import json
import os
import sqlite3
import time
from pathlib import Path

import pytest

flask = pytest.importorskip("flask")

from test_auth import ADMIN, app, admin, csrf  # noqa: F401,E402
from test_builder_web import pick_space, token  # noqa: E402
from test_clients import _bob, _form  # noqa: E402

SW1_OLD = """set system host-name sw1
set system root-authentication encrypted-password "$6$oldsecrethash"
set interfaces ge-0/0/47 description "uplink to sw2 ge-0/0/47"
set vlans users vlan-id 10
"""
SW1_NEW = SW1_OLD.replace("oldsecrethash", "newsecrethash") + "set vlans voice vlan-id 20\n"
SW2 = """set system host-name sw2
set interfaces ge-0/0/47 description "uplink to sw1 ge-0/0/47"
set vlans users vlan-id 10
"""
GOOD = json.loads((Path(__file__).parent.parent / "src" / "switchbuilder" / "vendor_examples" / "arista-office.json").read_text())


def _db():
    conn = sqlite3.connect(Path(os.environ["EXB_DATA_DIR"]) / "users.db")
    conn.row_factory = sqlite3.Row
    return conn


def _seed(admin):
    """Two nightly versions of sw1, one of sw2, and a planned sw3 that is only in a project."""
    from switchbuilder.web import backups
    pick_space(admin, "production")
    admin.get("/global")           # makes the tables
    conn = _db()
    first = backups.store(conn, 1, [{"name": "sw1", "text": SW1_OLD, "address": "10.0.0.1"},
                                    {"name": "sw2", "text": SW2, "address": "10.0.0.2"}], "nightly", "nightly")
    second = backups.store(conn, 1, [{"name": "sw1", "text": SW1_NEW, "address": "10.0.0.1"}], "ssh", ADMIN[0])
    conn.close()
    planned = dict(GOOD, name="Branch")
    planned["system"] = dict(GOOD["system"], hostname="sw3")
    admin.post("/projects", json={"name": "Branch", "data": planned}, headers={"X-CSRF-Token": token(admin)})
    return first, second


def test_global_is_on_the_start_page_and_asks_for_the_client(app, admin):
    assert "/global" in admin.get("/start").get_data(as_text=True)
    _form(admin, "/clients", name="Acme")
    admin.get("/start")                         # Home forgets the picked client
    r = admin.get("/global")
    assert r.status_code == 302 and "/clients/pick?next=/global" in r.location
    pick = admin.get(r.location).get_data(as_text=True)
    assert 'name="next" value="/global"' in pick
    resp = admin.post("/clients/select", data={"csrf_token": csrf(admin, "/start"), "client_id": "1", "next": "/global"})
    assert resp.location.endswith("/global")
    page = admin.get("/global").get_data(as_text=True)
    assert "Global: Default" in page and 'id="jump"' in page


def test_diagram_dropdown_and_history(app, admin):
    first, second = _seed(admin)
    d = admin.get("/global/data").json
    hosts = {s["host"]: s for s in d["switches"]}
    assert set(hosts) == {"sw1", "sw2", "sw3"}
    assert hosts["sw1"]["versions"] == 2 and hosts["sw1"]["address"] == "10.0.0.1"
    assert hosts["sw3"]["planned"] is True and hosts["sw1"]["planned"] is False
    assert any({x["a"], x["b"]} == {"sw1", "sw2"} for x in d["links"])          # cable from the descriptions
    page = admin.get(hosts["sw1"]["url"]).get_data(as_text=True)
    assert "Changes" in page and "newsecrethash" in page                         # editors see the real config

    ev = admin.get("/global/switch/sw1/changes").json["events"]
    configs = [e for e in ev if e["kind"] == "config"]
    assert len(configs) == 2 and configs[0]["who"] == ADMIN[0] and configs[1]["who"] == "nightly"
    one = admin.get(f"/global/switch/sw1/change?kind=config&id={configs[0]['id']}").json
    added = [ln["text"] for s in one["result"]["sections"] for ln in s["lines"] if ln["op"] == "+"]
    assert any("voice" in x for x in added) and one["before"]["who"] == "nightly"
    first_one = admin.get(f"/global/switch/sw1/change?kind=config&id={configs[1]['id']}").json
    assert first_one["first"] is True
    # The planned switch's project shows as a change too, with the config it builds.
    ev3 = admin.get("/global/switch/sw3/changes").json["events"]
    assert [e["kind"] for e in ev3] == ["project"]
    p = admin.get(f"/global/switch/sw3/change?kind=project&id={ev3[0]['id']}").json
    assert p["who"] == ADMIN[0] and p["text"]
    # A change of another switch can't be opened through this one.
    sw2_id = [e for e in admin.get("/global/switch/sw2/changes").json["events"] if e["kind"] == "config"][0]["id"]
    assert admin.get(f"/global/switch/sw1/change?kind=config&id={sw2_id}").status_code == 404
    assert admin.get("/global/switch/nope").status_code == 404


def test_pushes_reviews_and_audit_in_the_history(app, admin):
    _seed(admin)
    conn = _db()
    bids = [r[0] for r in conn.execute("SELECT id FROM config_backups WHERE host = 'sw1' ORDER BY id")]
    conn.execute("INSERT INTO config_pushes (client_id, project_id, project_name, project_sha, vendor, host, status, "
                 "diff, backup_id, after_backup_id, created_by, created_at, created_ts, pushed_by, pushed_at) VALUES "
                 "(1, 1, 'Core', 'x', 'juniper', '10.0.0.1', 'confirmed', ?, ?, ?, 'carol', '2030-01-01 10:00 UTC', ?, "
                 "'carol', '2030-01-01 10:01 UTC')", ("+ set vlans voice vlan-id 20\n+ set system root-authentication "
                                                     "encrypted-password \"$6$pushedsecret\"", bids[0], bids[1], time.time()))
    data = dict(GOOD, name="sw1-project")
    data["system"] = dict(GOOD["system"], hostname="sw1")
    conn.execute("INSERT INTO project_reviews (client_id, lab_project_id, name, vendor, data, sha, status, requested_by, "
                 "requested_at, decided_by, decided_at, promoted_by, promoted_at) VALUES (1, 9, 'sw1-project', 'arista', ?, "
                 "'x', 'promoted', 'dave', '2030-01-02 09:00 UTC', 'erin', '2030-01-02 09:30 UTC', 'erin', "
                 "'2030-01-02 09:31 UTC')", (json.dumps(data),))
    conn.execute("CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, at TEXT, user TEXT, "
                 "client_id INTEGER, client TEXT, space TEXT, ip TEXT, kind TEXT, method TEXT, path TEXT, status INTEGER, "
                 "message TEXT)")
    conn.execute("INSERT INTO audit_log (at, user, client_id, client, space, ip, kind, method, path, status, message) "
                 "VALUES ('2030-01-03 08:00:00 UTC', 'frank', 1, 'Default', 'production', '10.1.1.1', 'event', 'POST', "
                 "'/ssh/fetch', 200, 'SSH fetch of 10.0.0.1 as ''netops'' -> ok')")
    conn.execute("INSERT INTO audit_log (at, user, client_id, client, kind, message) VALUES "
                 "('2030-01-03 08:00:00 UTC', 'frank', 2, 'Other', 'event', 'SSH fetch of 10.0.0.1')")
    conn.commit()
    conn.close()
    ev = admin.get("/global/switch/sw1/changes").json["events"]
    kinds = [e["kind"] for e in ev]
    assert kinds[:5] == ["audit", "review", "review", "review", "push"]      # newest first
    assert [e["who"] for e in ev if e["kind"] == "review"] == ["erin", "erin", "dave"]
    assert len([e for e in ev if e["kind"] == "audit"]) == 1                 # only this client's rows
    push = admin.get(f"/global/switch/sw1/change?kind=push&id={ev[4]['id']}").json
    assert "pushedsecret" in push["diff"] and push["result"]["sections"]
    rid = ev[1]["id"]
    rev = admin.get(f"/global/switch/sw1/change?kind=review&id={rid}").json
    assert rev["promoted_by"] == "erin" and (rev.get("text") or rev.get("result"))

    # A Read-only member: secrets hidden everywhere, and no audit log.
    bob = _bob(app, admin, "viewer")
    pick_space(bob, "production")
    bev = bob.get("/global/switch/sw1/changes").json
    assert bev["redacted"] is True and "audit" not in [e["kind"] for e in bev["events"]]
    assert bob.get(f"/global/switch/sw1/change?kind=audit&id={ev[0]['id']}").status_code == 404
    bpush = bob.get(f"/global/switch/sw1/change?kind=push&id={ev[4]['id']}").get_data(as_text=True)
    assert "pushedsecret" not in bpush and "<hidden>" in json.loads(bpush)["diff"]
    page = bob.get("/global/switch/sw1").get_data(as_text=True)
    assert "newsecrethash" not in page and "oldsecrethash" not in page
    for e in bev["events"]:
        body = bob.get(f"/global/switch/sw1/change?kind={e['kind']}&id={e['id']}").get_data(as_text=True)
        assert "secrethash" not in body and "pushedsecret" not in body


def test_layout_and_discovery_and_client_isolation(app, admin):
    _seed(admin)
    bob = _bob(app, admin, "viewer")
    pick_space(bob, "production")
    h = {"X-CSRF-Token": token(bob)}
    assert bob.post("/global/layout", json={"pos": {"sw1": {"x": 1, "y": 2}}}, headers=h).status_code == 403
    ah = {"X-CSRF-Token": token(admin)}
    assert admin.post("/global/layout", json={"pos": {"sw1": {"x": 100, "y": 60}, "bad": {"x": "?"}}}, headers=ah).json["ok"]
    found = {"nodes": [{"id": "sw2", "name": "sw2.example.com", "read": True, "mgmt": "10.0.0.2"},
                       {"id": "sw4", "name": "sw4", "read": True, "mgmt": "10.0.0.4"},
                       {"id": "phone1", "name": "phone1", "read": False}],
             "links": [{"a": "sw2", "a_if": "ge-0/0/1", "b": "sw4", "b_if": "Gi1/0/1"},
                       {"a": "sw4", "a_if": "Gi1/0/2", "b": "phone1", "b_if": ""}]}
    assert admin.post("/global/layout", json={"discovery": found}, headers=ah).json["links"] == 2
    d = admin.get("/global/data").json
    assert d["pos"]["sw1"] == {"x": 100.0, "y": 60.0} and "bad" not in d["pos"]
    hosts = {s["host"] for s in d["switches"]}
    assert "sw4" in hosts and "phone1" not in hosts                    # neighbours that aren't switches stay out
    assert any({x["a"], x["b"]} == {"sw2", "sw4"} and "LLDP/CDP discovery" in x["found"] for x in d["links"])
    assert d["discovered"]["by"] == ADMIN[0]
    # The viewer sees the same picture, but a client they're not in shows nothing of it.
    assert len(bob.get("/global/data").json["switches"]) == len(d["switches"])
    _form(admin, "/clients", name="Acme")
    admin.post("/clients/select", data={"csrf_token": csrf(admin, "/start"), "client_id": "2", "next": "/global"})
    other = admin.get("/global/data").json
    assert other["client"] == "Acme" and other["switches"] == [] and other["links"] == []
    assert admin.get("/global/switch/sw1").status_code == 404
    assert admin.get("/global/switch/sw1/changes").status_code == 404
    # Lab is its own space.
    pick_space(admin, "lab")
    admin.post("/clients/select", data={"csrf_token": csrf(admin, "/start"), "client_id": "1", "next": "/global"})
    assert admin.get("/global/data").json["switches"] == []
    assert len(admin.get("/global/data?space=production").json["switches"]) == len(d["switches"])
