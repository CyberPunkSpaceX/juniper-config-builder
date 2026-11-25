import pytest

from exbuilder import ports, vendors
from exbuilder.generator import build
from test_generator import base, msgs, sets


def test_vendor_catalog_and_fallback():
    keys = [v["key"] for v in vendors.catalog()]
    assert keys == ["juniper", "arista", "cisco", "nexus", "dell", "extreme", "fortiswitch", "mikrotik", "unifi", "ruckus", "aruba", "procurve"]
    assert vendors.get(None).key == "juniper"
    assert vendors.get("nope").key == "juniper"
    assert vendors.get("Arista").key == "arista"
    assert not vendors.get("ruckus").has("evpn_vxlan")
    assert vendors.get("arista").has("vlan_translation")


def test_not_ready_vendor_says_so(monkeypatch):
    monkeypatch.setitem(vendors.VENDORS, "nokia", vendors.Vendor("nokia", "Nokia", "SR Linux", "lab", frozenset()))
    res = build(base(vendor="nokia"))
    assert res.errors and "not ready" in res.errors[0]["message"]


def test_translation_parser():
    assert ports.translations("100>200, 101 to 201;102-202") == [(100, 200), (101, 201), (102, 202)]
    for bad in ("100", "0>5", "5>5", "100>200,100>300", "100>200,101>200", "abc>1"):
        with pytest.raises(ValueError):
            ports.translations(bad)


def _trunk(model, spec, vlans="USERS"):
    return base(switch={"members": [{"fpc": 0, "model": model}]},
                vlans=[{"name": "USERS", "id": "20"}, {"name": "CAM", "id": "30"}],
                ports=[{"name": "uplink", "ports": "ge-0/0/1", "mode": "trunk", "vlans": vlans,
                        "vlan_translate": spec}])


def test_junos_vlan_rewrite():
    res = build(_trunk("EX4300-48P", "120>20, 130>30"))
    assert not res.errors, msgs(res.errors)
    s = sets(res)
    assert "set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan-rewrite translate 120 20" in s
    assert "set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan-rewrite translate 130 30" in s
    # CAM was not in the trunk list: added with a warning
    assert "set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members CAM" in s
    assert "not in the trunk" in msgs(res.warnings)


def test_junos_vlan_rewrite_checks():
    assert "cannot translate" in msgs(build(_trunk("EX2300-24P", "120>20")).warnings)
    res = build(_trunk("EX4300-48P", "30>20"))
    assert "also a VLAN on this switch" in msgs(res.errors)
    res = build(_trunk("EX4300-48P", "120>99"))
    assert "not on the VLANs tab" in msgs(res.errors)
    res = build(base(vlans=[{"name": "USERS", "id": "20"}],
                     ports=[{"ports": "ge-0/0/2", "mode": "access", "vlan": "USERS", "vlan_translate": "120>20"}]))
    assert "only works on trunk" in msgs(res.errors)
    assert res.errors[-1]["field"].endswith("vlan_translate")
