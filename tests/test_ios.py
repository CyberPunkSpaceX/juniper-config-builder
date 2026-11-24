import json
from pathlib import Path

from exbuilder import ios_models, ports
from exbuilder.cryptpw import cisco_type8, is_type8
from exbuilder.generator import build

EXAMPLE = Path(__file__).parent.parent / "src" / "exbuilder" / "vendor_examples" / "cisco-office.json"


def base(**over):
    p = {"vendor": "cisco", "system": {"hostname": "cs1", "domain": "example.lan", "ntp_servers": [{"address": "10.0.0.1"}]},
         "access": {"users": [{"name": "netadmin", "class": "super-user", "password": "Secret-pass-1"}]},
         "switch": {"members": [{"fpc": 1, "model": "C9300-48P"}]},
         "vlans": [{"name": "USERS", "id": "20"}, {"name": "CAM", "id": "30"}]}
    p.update(over)
    return p


def msgs(items):
    return " | ".join(m["message"] for m in items)


def test_type8_matches_known_hash():
    # hashcat's published example for mode 9200 (password "hashcat")
    assert cisco_type8("hashcat", "TnGX/fE4KGHOVU") == "$8$TnGX/fE4KGHOVU$pEhnEvxrvaynpi8j4f.EMHr6M.FzU8xnZnBr/tJdFWk"
    assert is_type8(cisco_type8("x" * 10))


def test_example_builds_clean():
    res = build(json.loads(EXAMPLE.read_text()))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "switch 2 provision c9300-48p" in t
    assert "clock timezone MST -7 0" in t and "clock summer-time MDT recurring" in t
    assert "interface range GigabitEthernet1/0/1 - 40" in t and "switchport voice vlan 30" in t
    assert "switchport vlan mapping 1050 50" in t
    assert "interface Port-channel1\n" in t and "channel-group 1 mode active" in t
    assert "ip route vrf Mgmt-vrf 0.0.0.0 0.0.0.0 192.168.100.1" in t
    assert "permit 10.10.1.0 0.0.0.255" in t
    assert "Change-me-2026" not in t and "secret 8 $8$" in t
    # snooping trusts trunks and LAGs
    assert "interface GigabitEthernet1/0/47\n" in t
    block = t.split("interface GigabitEthernet1/0/47\n")[1].split("!")[0]
    assert "ip dhcp snooping trust" in block
    assert "ip dhcp snooping trust" in t.split("interface Port-channel1\n")[1].split("!")[0]


def test_port_names_and_stack_numbers():
    assert ports.expand_named("gi1/0/1-2, Te1/1/1", ios_models.ALIASES) == [
        "GigabitEthernet1/0/1", "GigabitEthernet1/0/2", "TenGigabitEthernet1/1/1"]
    res = build(base(ports=[{"ports": "ge-0/0/1", "mode": "access", "vlan": "USERS"}]))
    assert "not a port" in msgs(res.errors)
    res = build(base(switch={"members": [{"fpc": 1, "model": "C9300-48P"}, {"fpc": 1, "model": "C9300-48P"}]}))
    assert "1-8 and used once" in msgs(res.errors)
    res = build(base(switch={"members": [{"fpc": 1, "model": "C9500-16X"}, {"fpc": 2, "model": "C9500-16X"}]}))
    assert "doesn't stack" in msgs(res.errors)


def test_access_trunk_routed_individual():
    res = build(base(ports=[
        {"name": "A", "ports": "Gi1/0/1-2", "mode": "access", "vlan": "USERS", "edge": True, "sticky": True},
        {"name": "T", "ports": "Gi1/0/3", "mode": "trunk", "vlans": "USERS, CAM", "native": "USERS"},
        {"name": "R", "ports": "Te1/1/1", "mode": "routed", "address": "10.9.9.1/30"}],
        services={"use_ranges": False, "storm_control": False}))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "interface GigabitEthernet1/0/1\n switchport mode access\n switchport access vlan 20" in t
    assert "switchport port-security mac-address sticky" in t
    assert "switchport trunk allowed vlan 20,30" in t
    assert "interface TenGigabitEthernet1/1/1\n no switchport\n ip address 10.9.9.1 255.255.255.252" in t


def test_vlan_translation_and_9200_warning():
    res = build(base(ports=[{"ports": "Gi1/0/3", "mode": "trunk", "vlans": "USERS", "vlan_translate": "130>30"}]))
    assert "switchport trunk allowed vlan 20,30" in res.set_text and "switchport vlan mapping 130 30" in res.set_text
    res = build(base(switch={"members": [{"fpc": 1, "model": "C9200L-48P-4G"}]},
                     ports=[{"ports": "Gi1/0/3", "mode": "trunk", "vlans": "USERS", "vlan_translate": "120>20"}]))
    assert "9200 can't translate" in msgs(res.warnings)
    res = build(base(ports=[{"ports": "Gi1/0/3", "mode": "trunk", "vlans": "USERS", "vlan_translate": "30>20"}]))
    assert "also a VLAN on this switch" in msgs(res.errors)


def test_passwords_from_other_vendors_need_retyping():
    res = build(base(access={"users": [{"name": "u1", "class": "super-user", "password": "$6$abc$def"}]}))
    assert "type it again for Cisco" in msgs(res.errors)


def test_routing_and_dot1x():
    res = build(base(routing={"loopback": "10.255.255.2", "asn": "65002",
                              "ospf": {"enabled": True, "areas": [{"area": "0", "interfaces": "Te1/1/1, lo0", "p2p": "Te1/1/1"}]},
                              "bgp_groups": [{"name": "UP", "type": "external", "neighbors": "10.9.9.2 65000 ISP"}]},
                     ports=[{"ports": "Te1/1/1", "mode": "routed", "address": "10.9.9.1/30"},
                            {"ports": "Gi1/0/1", "mode": "access", "vlan": "USERS", "dot1x": "dot1x-mab"}],
                     security={"radius_servers": [{"address": "10.0.0.5", "secret": "s3cr3t"}]}))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "router ospf 1\n router-id 10.255.255.2" in t and " ip ospf 1 area 0\n ip ospf network point-to-point" in t
    assert "passive-interface Loopback0" in t
    assert "neighbor 10.9.9.2 remote-as 65000" in t and "neighbor 10.9.9.2 description ISP" in t
    assert "authentication order dot1x mab" in t and "radius server RADIUS-1" in t and "dot1x system-auth-control" in t


def test_older_catalyst_2960x_classic_ios():
    p = json.loads(EXAMPLE.read_text())
    for m in p["switch"]["members"]:
        m["model"] = "WS-C2960X-48FPD-L"
    p["lags"][0]["members"] = "Te1/0/1, Te2/0/1"
    res = build(p)
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert t.startswith("! Cisco IOS configuration") and "switch 2 provision ws-c2960x-48fpd-l" in t
    assert "ip domain-name example.lan" in t and "Mgmt-vrf" not in t
    assert "interface FastEthernet0\n ip address 192.168.100.31" in t and "ip default-gateway 192.168.100.1" in t
    assert "enable secret 5 $1$" in t and "username netadmin privilege 15 secret 5 $1$" in t
    assert "switchport vlan mapping" not in t and "can't translate VLANs" in msgs(res.warnings)
    assert "channel-group 1 mode active" in t.split("interface TenGigabitEthernet2/0/1\n")[1]
    res = build(base(switch={"members": [{"fpc": 1, "model": "WS-C2960X-24PS-L"}]},
                     routing={"ospf": {"enabled": True, "areas": [{"area": "0", "interfaces": "Vlan20"}]},
                              "asn": "65001", "bgp_groups": [{"name": "UP", "neighbors": "10.0.0.2 65000"}]}))
    assert "can't run OSPF" in msgs(res.errors) and "can't run BGP" in msgs(res.errors)
    # a type 8 hash made for a 9300 can't be reused on a 2960-X
    res = build(base(switch={"members": [{"fpc": 1, "model": "WS-C2960X-24PS-L"}]},
                     access={"users": [{"name": "u1", "class": "super-user", "password": cisco_type8("Secret-pass-1")}]}))
    assert "type it again" in msgs(res.errors)


def test_3650_and_3850_are_ios_xe():
    res = build(base(switch={"members": [{"fpc": 1, "model": "WS-C3850-48P"}, {"fpc": 2, "model": "WS-C3850-48P"}]},
                     ports=[{"ports": "Te1/1/1", "mode": "trunk", "vlans": "USERS", "vlan_translate": "120>20"}]))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "switch 2 provision ws-c3850-48p" in t and "secret 8 $8$" in t and "switchport vlan mapping 120 20" in t
    ports = [p["name"] for p in ios_models.get("WS-C3650-48PD").ports(1)]
    assert ports[-2:] == ["TenGigabitEthernet1/1/3", "TenGigabitEthernet1/1/4"]
