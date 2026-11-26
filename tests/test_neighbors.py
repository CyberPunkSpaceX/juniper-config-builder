"""Auto network map from LLDP/CDP neighbour output of every brand."""

from pathlib import Path

import pytest

from exbuilder import neighbors as N

DATA = Path(__file__).parent / "data" / "neighbors"


def _t(name):
    return (DATA / name).read_text()


@pytest.mark.parametrize("name, first", [
    ("cisco-lldp.txt", ("Gi1/0/49", "Ethernet1", "core-sw1.example.lan", "10.9.0.1")),
    ("cisco-cdp.txt", ("GigabitEthernet1/0/50", "GigabitEthernet1/0/49", "acc-sw2.example.lan", "10.9.0.12")),
    ("arista.txt", ("Ethernet1", "Gi1/0/49", "acc-sw1", "10.9.0.11")),
    ("juniper.txt", ("ge-0/0/48", "Ethernet2", "core-sw1", "")),
    ("nexus.txt", ("Eth1/1", "Ethernet1/49", "leaf1", "10.9.1.21")),
    ("arubacx.txt", ("1/1/49", "Ethernet3", "core-sw1", "10.9.0.1")),
    ("mikrotik.txt", ("sfp-sfpplus1", "Ethernet4", "core-sw1", "10.9.0.1")),
    ("exos.txt", ("49", "Ethernet5", "core-sw1", "10.9.0.1")),
    ("procurve.txt", ("49", "Ethernet6", "core-sw1", "10.9.0.1")),
])
def test_parse_every_brand(name, first):
    got = N.parse(_t(name))
    e = got[0]
    assert (e["local"], e["port"], e["name"], e["mgmt"]) == first


def test_two_neighbours_each():
    assert [e["name"] for e in N.parse(_t("nexus.txt"))] == ["leaf1", "leaf2"]
    assert [e["name"] for e in N.parse(_t("cisco-cdp.txt"))] == ["acc-sw2.example.lan", "core-sw1"]
    assert N.parse(_t("cisco-cdp.txt"))[0]["platform"] == "cisco WS-C2960X-48FPD-L"
    assert N.parse("nothing here\nat all") == []


def test_map_matches_both_ends_and_names():
    r = N.build_map([{"name": "core-sw1", "address": "10.9.0.1", "text": _t("arista.txt")},
                     {"address": "10.9.0.11", "text": _t("cisco-lldp.txt")},
                     {"name": "ex-idf3", "text": _t("juniper.txt")}])
    names = {n["id"]: n for n in r["nodes"]}
    assert names["acc-sw1"]["read"] and names["acc-sw1"]["mgmt"] == "10.9.0.11"   # named by its neighbour
    assert not names["printer-1"]["read"]
    both = [(l["a"], l["a_if"], l["b"], l["b_if"]) for l in r["links"] if l["seen"] == "both ends"]
    assert ("core-sw1", "Ethernet1", "acc-sw1", "Gi1/0/49") in both
    assert ("core-sw1", "Ethernet2", "ex-idf3", "ge-0/0/48") in both
    assert r["nodes"][0]["id"] == "core-sw1"
    assert any("Seen but not read" in c["message"] for c in r["checks"])


def test_one_sided_and_shared_port():
    one = "Local Intf: Gi1/0/1\nPort id: Gi0/1\nSystem Name: b\n\nLocal Intf: Gi1/0/1\nPort id: Gi0/2\nSystem Name: c\n"
    r = N.build_map([{"name": "a", "text": one}, {"name": "b", "text": ""}])
    msgs = [c["message"] for c in r["checks"]]
    assert any("only seen from one end" in m for m in msgs)
    assert any("2 neighbours on one port" in m for m in msgs)
    assert any(m.startswith("b: no LLDP or CDP neighbours") for m in msgs)


def test_discover_follows_neighbours_inside_allowed_networks():
    import ipaddress
    outputs = {
        "10.9.0.1": _t("arista.txt"),          # neighbours 10.9.0.11 and 10.9.0.13
        "10.9.0.11": _t("cisco-lldp.txt"),     # core again, and a phone at 10.9.30.55
        "10.9.0.13": _t("juniper.txt"),
    }
    calls = []

    def run(host, username, password, data_dir, port, nets, pkey):
        calls.append(host)
        if host not in outputs:
            return {"host": host, "ok": False, "error": f"{host}: could not connect"}
        return {"host": host, "address": host, "ok": True, "text": outputs[host]}

    nets = [ipaddress.ip_network("10.9.0.0/24")]
    r = N.discover(["10.9.0.1"], "u", "p", None, nets, run=run)
    assert calls == ["10.9.0.1", "10.9.0.11", "10.9.0.13"]   # the phone's 10.9.30.55 is outside the networks
    assert {n["id"] for n in r["nodes"] if n["read"]} == {"core-sw1", "acc-sw1", "ex-idf3"}
    assert all(f["ok"] for f in r["fetched"])
    calls.clear()
    r = N.discover(["10.9.0.1"], "u", "p", None, nets, limit=2, run=run)
    assert len(calls) == 2 and any("Stopped at 2 switches" in c["message"] for c in r["checks"])
    calls.clear()
    N.discover(["10.9.0.1"], "u", "p", None, nets, follow=False, run=run)
    assert calls == ["10.9.0.1"]


# ----------------------------------------------------------------- web
flask = pytest.importorskip("flask")
from test_auth import ADMIN, add_user, app, admin, csrf, login  # noqa: F401,E402
from test_builder_web import token  # noqa: E402


def test_web_map(app, admin):
    assert "Auto network map" in admin.get("/tools/").get_data(as_text=True)
    page = admin.get("/tools/map").get_data(as_text=True)
    assert "show cdp neighbors detail" in page and "client admin role and the client's switch networks" in page
    hdr = {"X-CSRF-Token": token(admin)}
    r = admin.post("/tools/map/build", json={"switches": [{"name": "core-sw1", "text": _t("arista.txt")}]}, headers=hdr)
    assert r.status_code == 200 and len(r.json["links"]) == 2
    assert admin.post("/tools/map/build", json={"switches": []}, headers=hdr).status_code == 400
    d = admin.post("/tools/map/discover", json={"seeds": "10.9.0.1", "username": "u", "password": "p"}, headers=hdr)
    assert d.status_code == 403 and "SSH is off" in d.json["error"]
