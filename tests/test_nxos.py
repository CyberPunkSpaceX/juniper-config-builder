import json
from pathlib import Path

import pytest

from switchbuilder import nxos_models, ports
from switchbuilder.cryptpw import sha256_crypt
from switchbuilder.generator import build

EXAMPLE = Path(__file__).parent.parent / "src" / "switchbuilder" / "vendor_examples" / "nexus-office.json"


def base(**over):
    p = {"vendor": "nexus", "system": {"hostname": "nx1", "ntp_servers": [{"address": "10.0.0.1"}], "mgmt_vrf": True},
         "access": {"users": [{"name": "netadmin", "class": "super-user", "password": "Secret-pass-1"}]},
         "switch": {"members": [{"fpc": 1, "model": "N9K-C93180YC-FX"}]},
         "vlans": [{"name": "USERS", "id": "20"}, {"name": "CAM", "id": "30"}]}
    p.update(over)
    return p


def msgs(items):
    return " | ".join(m["message"] for m in items)


def test_sha256_crypt_known_vector():
    # From Drepper's specification.
    assert sha256_crypt("Hello world!", "saltstring") == "$5$saltstring$5B8vYYiY.CVt1RlTTf8KbXBH3hsxY/GNooZaBBGWEc5"


def test_example_builds_clean():
    res = build(json.loads(EXAMPLE.read_text()))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert t.startswith("! Cisco NX-OS configuration for")
    for feat in ("lacp", "interface-vlan", "dhcp", "lldp"):
        assert f"\nfeature {feat}\n" in t
    assert t.index("feature lacp") < t.index("interface port-channel1")
    assert "hostname nx-server-01" in t
    assert "interface mgmt0\n   vrf member management\n   ip address 192.168.100.31/24" in t
    assert "vrf context management\n   ip route 0.0.0.0/0 192.168.100.1" in t
    assert "ntp server 10.10.0.1 prefer use-vrf management" in t
    assert "interface Ethernet1/1-40\n   description Servers\n   switchport\n   switchport mode access\n   switchport access vlan 100" in t
    assert "switchport vlan mapping enable\n   switchport vlan mapping 1120 120" in t
    assert "channel-group 1 mode active" in t and "lacp rate fast" in t
    assert "ip dhcp relay address 10.10.0.10" in t
    assert "password 5 $5$" in t and "Change-me-2026" not in t
    assert "clock timezone MST -7 0" in t and "summer time" in msgs(res.warnings)
    assert "banner motd #\nAuthorized access only.\n#" in t and t.endswith("end\n")
    assert "snmp-server community s3cret-ro use-ipv4acl SNMP-CLIENTS-1" in t


def test_port_names():
    assert ports.expand_named("Eth1/1-2, e1/49/1", nxos_models.ALIASES) == ["Ethernet1/1", "Ethernet1/2", "Ethernet1/49/1"]
    res = build(base(ports=[{"ports": "Gi1/0/1", "mode": "access", "vlan": "USERS"}]))
    assert "not a port" in msgs(res.errors)


def test_access_trunk_routed():
    res = build(base(ports=[
        {"name": "A", "ports": "Ethernet1/1-2", "mode": "access", "vlan": "USERS", "edge": True, "mac_limit": "2"},
        {"name": "T", "ports": "Ethernet1/3", "mode": "trunk", "vlans": "USERS, CAM", "native": "USERS"},
        {"name": "R", "ports": "Ethernet1/54", "mode": "routed", "address": "10.9.9.1/30", "mtu": "9216"}],
        services={"use_ranges": False, "storm_control": False}))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "interface Ethernet1/1\n   switchport\n   switchport mode access\n   switchport access vlan 20\n   spanning-tree port type edge" in t
    assert "feature port-security" in t and "switchport port-security maximum 2" in t
    assert "switchport trunk allowed vlan 20,30" in t
    assert "interface Ethernet1/54\n   no switchport\n   mtu 9216\n   ip address 10.9.9.1/30\n   no shutdown" in t
    assert "ip routing" not in t


def test_l2_mtu_and_voice_and_poe():
    res = build(base(ports=[{"ports": "Ethernet1/1", "mode": "access", "vlan": "USERS", "mtu": "9000",
                             "voice": "CAM", "poe": "high"}]))
    assert "1500 or 9216" in msgs(res.errors)
    assert "no voice VLAN" in msgs(res.warnings) and "no PoE" in msgs(res.warnings)


def test_vlan_mapping_checks_and_legacy():
    res = build(base(ports=[{"ports": "Ethernet1/3", "mode": "trunk", "vlans": "USERS", "vlan_translate": "30>20"}]))
    assert "also a VLAN on this switch" in msgs(res.errors)
    res = build(base(switch={"members": [{"fpc": 1, "model": "N3K-C3048TP-1GE"}]},
                     ports=[{"ports": "Ethernet1/3", "mode": "trunk", "vlans": "USERS", "vlan_translate": "120>20"}]))
    assert "Nexus 9000" in msgs(res.errors)


def test_lags_and_stacking():
    res = build(base(lags=[{"name": "ae0", "members": "Ethernet1/49-50", "mode": "trunk", "vlans": "USERS"}]))
    assert "port-channel1 to" in msgs(res.errors)
    res = build(base(lags=[{"name": "Po10", "members": "Eth1/49-50", "mode": "trunk", "vlans": "USERS", "lacp": "static",
                            "min_links": "2"}]))
    t = res.set_text
    assert "channel-group 10 mode on" in t and "interface port-channel10" in t and "lacp min-links 2" in t
    assert "feature lacp" not in t
    res = build(base(switch={"members": [{"fpc": 1, "model": "N9K-C93180YC-FX"}, {"fpc": 2, "model": "N9K-C93180YC-FX"}]}))
    assert "don't stack" in msgs(res.errors)


def test_users_snmp_logging():
    res = build(base(access={"root_password": "Admin-pass-99", "users": [
        {"name": "ro", "class": "read-only", "ssh_keys": "ssh-ed25519 AAAAC3 x@y\nssh-rsa AAAAB3 z@w"}]},
        snmp={"v3_users": [{"name": "mon", "auth": "sha", "auth_password": "authpass1", "priv": "aes128", "priv_password": "privpass1"}],
              "trap_targets": "10.0.0.9"},
        syslog={"hosts": [{"address": "10.0.0.8", "level": "warning", "port": "1514"}], "local_level": "error"}))
    t = res.set_text
    assert "username admin password 5 $5$" in t and "role network-admin" in t
    assert "username ro role network-operator" in t and "username ro sshkey ssh-ed25519 AAAAC3 x@y" in t
    assert "one SSH key" in msgs(res.warnings)
    assert "snmp-server user mon network-operator auth sha authpass1 priv aes-128 privpass1" in t
    assert "snmp-server host 10.0.0.9 traps version 2c" in t and "snmp-server host 10.0.0.9 use-vrf management" in t
    assert "logging server 10.0.0.8 4 port 1514 use-vrf management" in t and "logging logfile messages 3" in t


def test_ospf_bgp_dot1x():
    res = build(base(
        vlans=[{"name": "USERS", "id": "20", "irb": "10.0.20.1/24"}],
        ports=[{"ports": "Ethernet1/49", "mode": "routed", "address": "10.9.9.1/30"},
               {"ports": "Ethernet1/1", "mode": "access", "vlan": "USERS", "dot1x": "dot1x-mab"}],
        security={"radius_servers": [{"address": "10.0.0.5", "secret": "radsecret"}]},
        routing={"loopback": "10.255.0.1", "asn": "65001",
                 "ospf": {"enabled": True, "reference_bandwidth": "100g",
                          "areas": [{"area": "0", "interfaces": "Eth1/49, loopback0", "passive": "vlan 20", "p2p": "Ethernet1/49", "md5_key": "k1"}]},
                 "bgp_groups": [{"name": "UP", "type": "external", "peer_as": "65000", "neighbors": "10.9.9.2", "bfd": "yes"}]}))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    for feat in ("ospf", "bgp", "dot1x", "interface-vlan", "bfd"):
        assert f"feature {feat}\n" in t
    assert "router ospf 1\n   router-id 10.255.0.1\n   auto-cost reference-bandwidth 100 Gbps" in t
    assert "interface Ethernet1/49\n   no switchport\n   ip address 10.9.9.1/30\n   no shutdown\n   ip router ospf 1 area 0.0.0.0\n   ip ospf network point-to-point" in t
    assert "interface Vlan20\n   no shutdown\n   ip address 10.0.20.1/24\n   ip router ospf 1 area 0.0.0.0\n   ip ospf passive-interface" in t
    assert "ip ospf message-digest-key 1 md5 0 k1" in t
    assert "router bgp 65001" in t and "   template peer UP\n      remote-as 65000\n      bfd\n      address-family ipv4 unicast" in t
    assert "   neighbor 10.9.9.2\n      inherit peer UP" in t and "      network 10.255.0.1/32" in t
    assert "dot1x port-control auto\n   dot1x mac-auth-bypass" in t
    assert "radius-server host 10.0.0.5 key radsecret authentication accounting" in t
    assert "aaa group server radius RADIUS\n   server 10.0.0.5\n   use-vrf management" in t
    assert "aaa authentication dot1x default group RADIUS" in t


@pytest.mark.parametrize("model", list(nxos_models.MODELS))
def test_every_model_builds(model):
    res = build(base(switch={"members": [{"fpc": 1, "model": model}]},
                     ports=[{"ports": "Ethernet1/1-2", "mode": "access", "vlan": "USERS"}]))
    assert not res.errors, msgs(res.errors)
