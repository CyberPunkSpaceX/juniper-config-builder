import json
from pathlib import Path

from switchbuilder.cryptpw import sha512_crypt
from switchbuilder.generator import build

EX = Path(__file__).parent.parent / "examples"
HASH = sha512_crypt("Juniper123!", "fixedsalt")


def base(**over):
    p = {"system": {"hostname": "sw1", "ntp_servers": [{"address": "10.0.0.1"}]},
         "access": {"root_password": HASH, "users": [{"name": "admin1", "class": "super-user", "password": HASH}]},
         "switch": {"members": [{"fpc": 0, "model": "EX4400-48P"}]},
         "services": {"delete_first": False},
         "ports": [{"ports": "ge-0/0/47", "mode": "routed", "address": "10.1.1.1/31"}]}
    p.update(over)
    return p


def sets(res):
    return [line for line in res.set_text.splitlines() if line.startswith("set ")]


def msgs(items):
    return " | ".join(m["message"] for m in items)


def test_identity_and_ecmp():
    res = build(base(routing={"loopback": "10.255.0.1", "asn": "65000", "ecmp": True}))
    s = sets(res)
    assert "set interfaces lo0 unit 0 family inet address 10.255.0.1/32" in s
    assert "set routing-options router-id 10.255.0.1" in s
    assert "set routing-options autonomous-system 65000" in s
    assert "set routing-options forwarding-table export ECMP-LOAD-BALANCE" in s
    assert build(base(routing={"asn": "70000000000"})).errors


def test_ospf():
    res = build(base(routing={"loopback": "10.255.0.1/32", "ospf": {"enabled": True, "reference_bandwidth": "100g", "areas": [
        {"area": "0.0.0.0", "interfaces": "ge-0/0/47, lo0, irb.99", "p2p": "ge-0/0/47", "md5_key": "k3y"},
        {"area": "0.0.0.1", "type": "stub", "interfaces": "ge-0/0/47"}]}}))
    s = sets(res)
    assert "set protocols ospf area 0.0.0.0 interface ge-0/0/47.0 interface-type p2p" in s
    assert "set protocols ospf area 0.0.0.0 interface ge-0/0/47.0 authentication md5 1 key k3y" in s
    assert "set protocols ospf area 0.0.0.0 interface lo0.0 passive" in s
    assert "set protocols ospf area 0.0.0.1 stub" in s
    assert "is in area 0.0.0.0 and area 0.0.0.1" in msgs(res.errors)
    assert "irb.99 has no IP address" in msgs(res.warnings)
    assert "no area" in msgs(build(base(routing={"ospf": {"enabled": True}})).errors)


def test_bgp_and_policies():
    res = build(base(
        routing={"asn": "65000", "bgp_groups": [
            {"name": "ISP", "type": "external", "peer_as": "64512", "neighbors": "10.1.1.0 Upstream one\n10.1.1.4 64513",
             "import": "FROM-ISP", "export": "TO-ISP, MISSING", "bfd": "300", "multipath": True},
            {"name": "IBGP", "type": "internal", "neighbors": "10.255.0.2 65001"}]},
        policy={"prefix_lists": [{"name": "MINE", "prefixes": "10.20.0.0/16"}],
                "communities": [{"name": "PREF", "members": "65000:200"}],
                "terms": [{"policy": "TO-ISP", "term": "mine", "prefix_list": "MINE", "match": "orlonger",
                           "community_add": "PREF", "action": "accept"},
                          {"policy": "TO-ISP", "term": "rest", "action": "reject"},
                          {"policy": "FROM-ISP", "term": "dflt", "route_filter": "0.0.0.0/0 exact", "local_pref": "150"},
                          {"policy": "FROM-ISP", "term": "x", "community": "NOPE"}]}))
    s = sets(res)
    assert "set policy-options prefix-list MINE 10.20.0.0/16" in s
    assert "set policy-options policy-statement TO-ISP term mine from prefix-list-filter MINE orlonger" in s
    assert "set policy-options policy-statement TO-ISP term mine then community add PREF" in s
    assert "set policy-options policy-statement FROM-ISP term dflt then local-preference 150" in s
    assert "set protocols bgp group ISP peer-as 64512" in s
    assert 'set protocols bgp group ISP neighbor 10.1.1.0 description "Upstream one"' in s
    assert "set protocols bgp group ISP neighbor 10.1.1.4 peer-as 64513" in s
    assert "set protocols bgp group ISP multipath multiple-as" in s
    assert "set protocols bgp group ISP bfd-liveness-detection minimum-interval 300" in s
    text = msgs(res.errors)
    assert "policy 'MISSING' is not defined" in text
    assert "community 'NOPE' is not defined" in text
    assert "differs from our AS" in text


def test_bgp_needs_asn():
    res = build(base(routing={"bgp_groups": [{"name": "G", "type": "external", "neighbors": "10.1.1.0"}]}))
    text = msgs(res.errors)
    assert "local AS number" in text and "needs a peer AS" in text


def test_evpn_leaf_example():
    p = json.loads((EX / "evpn-leaf.json").read_text())
    p["access"]["root_password"] = "Juniper123!"
    p["access"]["users"][0]["password"] = "Juniper123!"
    res = build(p)
    assert res.errors == []
    s = sets(res)
    for line in [
        "set protocols bgp group EVPN-OVERLAY type internal",
        "set protocols bgp group EVPN-OVERLAY local-address 10.255.0.11",
        "set protocols bgp group EVPN-OVERLAY family evpn signaling",
        "set protocols bgp group EVPN-OVERLAY neighbor 10.255.0.1",
        "set protocols evpn encapsulation vxlan",
        "set protocols evpn extended-vni-list all",
        "set switch-options vtep-source-interface lo0.0",
        "set switch-options route-distinguisher 10.255.0.11:1",
        "set switch-options vrf-target target:65000:1",
        "set vlans USERS vxlan vni 10020",
        "set interfaces irb unit 20 family inet address 10.20.0.2/24 virtual-gateway-address 10.20.0.1",
        "set protocols evpn default-gateway no-gateway-community",
        "set routing-instances TENANT1 instance-type vrf",
        "set routing-instances TENANT1 interface irb.20",
        "set routing-instances TENANT1 interface lo0.100",
        "set routing-instances TENANT1 vrf-target target:65000:9100",
        "set routing-instances TENANT1 protocols evpn ip-prefix-routes vni 9100",
        "set interfaces ae1 esi 00:01:01:01:01:01:01:01:01:01",
        "set interfaces ae1 esi all-active",
        "set interfaces ae1 aggregated-ether-options lacp system-id 00:00:00:01:01:01",
        "set protocols ospf area 0.0.0.0 interface xe-0/2/0.0 interface-type p2p",
    ]:
        assert line in s, line
    h = res.hier_text
    assert h.count("{") == h.count("}")


def test_evpn_spine_and_checks():
    res = build(base(routing={"loopback": "10.255.0.1/32", "asn": "65000", "ospf": {"enabled": True, "areas": [
        {"area": "0", "interfaces": "ge-0/0/47, lo0"}]}},
        evpn={"enabled": True, "role": "spine", "peers": "10.255.0.11\n10.255.0.12"}))
    s = sets(res)
    assert "set protocols bgp group EVPN-OVERLAY cluster 10.255.0.1" in s
    assert not any("vtep-source-interface" in line for line in s)

    res = build(base(switch={"members": [{"fpc": 0, "model": "EX2300-24P"}]},
                     vlans=[{"name": "A", "id": "10", "irb": "10.0.0.2/24", "vni": "5", "vga": "10.9.9.9"},
                            {"name": "B", "id": "20", "vni": "5"}],
                     routing={"loopback": "10.255.0.1/32", "asn": "65000"},
                     evpn={"enabled": True, "peers": "10.255.0.2"}))
    text, warn = msgs(res.errors), msgs(res.warnings)
    assert "is not in 10.0.0.0/24" in text and "VNI 5 is used by both" in text
    assert "not on the EX2300" in warn and "No underlay" in warn

    res = build(base(evpn={"enabled": True}))
    assert "needs an IPv4 loopback" in msgs(res.errors)


def test_esi_format_and_evpn_off():
    res = build(base(routing={"loopback": "10.255.0.1/32", "asn": "65000"}, evpn={"enabled": True, "peers": "10.255.0.2"},
                     lags=[{"name": "ae0", "members": "ge-0/0/1-2", "mode": "trunk", "vlans": "all", "esi": "zz"}]))
    assert "ESI is 10 bytes" in msgs(res.errors)
    res = build(base(lags=[{"name": "ae0", "members": "ge-0/0/1-2", "mode": "trunk", "vlans": "all",
                            "esi": "00:01:01:01:01:01:01:01:01:01"}]))
    assert "EVPN-VXLAN is off" in msgs(res.warnings)
