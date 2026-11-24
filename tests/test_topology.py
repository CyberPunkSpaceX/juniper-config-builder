from pathlib import Path

from exbuilder import topology as T
from exbuilder.generator import build

EX = Path(__file__).parent.parent / "src" / "exbuilder" / "map_examples"


def example():
    return [{"name": n, "text": (EX / f"{n}.conf").read_text()} for n in ("core-sw1", "acc-sw1", "acc-sw2")]


def link(res, a, b):
    ids = {s["hostname"]: s["id"] for s in res["switches"]}
    return [x for x in res["links"] if {x["a"], x["b"]} == {ids[a], ids[b]}]


def test_lldp_lag_link_folds_members():
    res = T.analyze(example())
    (lag,) = link(res, "core-sw1", "acc-sw1")
    assert lag["kind"] == "lag" and lag["a_if"] == "ae0" and lag["b_if"] == "ae0"
    assert sorted(m[0] for m in lag["members"]) == ["xe-0/1/0", "xe-0/1/1"]
    assert "LLDP" in lag["found"] and not lag["issues"]


def test_p2p_and_description_links_with_vlan_checks():
    res = T.analyze(example())
    links = link(res, "core-sw1", "acc-sw2")
    routed = next(x for x in links if x["kind"] == "routed")
    assert {routed["a_if"], routed["b_if"]} == {"ge-0/0/0", "ge-0/0/47"} and "addresses" in routed["found"]
    trunk = next(x for x in links if x["kind"] == "trunk")
    msgs = " ".join(i["message"] for i in trunk["issues"])
    assert "not defined on acc-sw2" in msgs and "VLAN 20, 30 allowed on core-sw1" in msgs
    checks = " ".join(c["message"] for c in res["checks"])
    assert "10.10.10.2 is on both acc-sw1 and acc-sw2" in checks
    assert "Spanning-tree root: core-sw1" in checks and "different names" in checks


def test_mismatches_between_builder_configs():
    def sw(host, port, mode, vlans, native="", mtu=""):
        p = {"system": {"hostname": host}, "access": {"root_password": "Secret-123"},
             "vlans": [{"name": "A", "id": "10"}, {"name": "B", "id": "20"}],
             "ports": [{"name": "UP", "ports": port, "mode": mode, "vlans": vlans, "vlan": vlans, "native": native,
                        "mtu": mtu, "description": f"link to {'sw2' if host == 'sw1' else 'sw1'} {('xe-0/1/1' if host == 'sw1' else 'xe-0/1/0')}"}]}
        return {"text": build(p).set_text}
    res = T.analyze([sw("sw1", "xe-0/1/0", "trunk", "A, B", native="A", mtu="9216"),
                     sw("sw2", "xe-0/1/1", "trunk", "A", native="")])
    (lk,) = res["links"]
    assert (lk["a_if"], lk["b_if"]) == ("xe-0/1/0", "xe-0/1/1")
    msgs = " ".join(i["message"] for i in lk["issues"])
    assert "Native VLAN differs" in msgs and "MTU differs" in msgs and "VLAN 20 allowed on sw1" in msgs
    res = T.analyze([sw("sw1", "xe-0/1/0", "trunk", "A"), sw("sw2", "xe-0/1/1", "access", "A")])
    assert "is trunk but" in res["links"][0]["issues"][0]["message"]


def test_interface_ranges_and_unknown_far_end():
    text = """set system host-name edge1
set interfaces interface-range UPS member-range ge-0/0/0 to ge-0/0/3
set interfaces interface-range UPS description "to core9"
set interfaces interface-range UPS unit 0 family ethernet-switching interface-mode trunk
set vlans X vlan-id 5"""
    sw = T.read_switch(text)
    assert sw["ifs"]["ge-0/0/2"]["mode"] == "trunk" and sw["ifs"]["ge-0/0/3"]["desc"] == "to core9"
    res = T.analyze([{"text": text}, {"text": "set system host-name core9\nset vlans X vlan-id 5"}])
    (lk,) = res["links"]
    assert lk["b_if"] is None and lk["a_if"] == "ge-0/0/0-3" and len(lk["members"]) == 4 and lk["kind"] == "trunk"
    assert "far-end port is not known" in res["links"][0]["issues"][0]["message"]
    assert T.analyze([{"text": "nothing here"}])["checks"][0]["level"] == "error"
