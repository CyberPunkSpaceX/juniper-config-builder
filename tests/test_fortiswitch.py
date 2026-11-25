import json
from pathlib import Path

import pytest

from exbuilder import fortiswitch_models
from exbuilder.generator import build

EXAMPLE = Path(__file__).parent.parent / "src" / "exbuilder" / "vendor_examples" / "fortiswitch-office.json"


def base(**over):
    p = {"vendor": "fortiswitch", "system": {"hostname": "fsw1", "ntp_servers": [{"address": "10.0.0.1"}]},
         "access": {"users": [{"name": "netadmin", "class": "super-user", "password": "Secret-pass-1"}]},
         "switch": {"members": [{"fpc": 1, "model": "FS-448E-FPOE"}]},
         "vlans": [{"name": "USERS", "id": "20"}, {"name": "CAM", "id": "30"}],
         "services": {"storm_control": False}}
    p.update(over)
    return p


def msgs(items):
    return " | ".join(m["message"] for m in items)


def block(text, path):
    start = text.index(f"config {path}\n")
    return text[start:text.index("\nend\n", start) + 5]


def test_example_builds_clean():
    res = build(json.loads(EXAMPLE.read_text()))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert t.startswith("config system global\n    set hostname \"fsw-office-01\"")
    assert "#" not in t
    assert t.index("config switch vlan") < t.index("config switch interface")
    assert t.index("config switch trunk") < t.index("config switch interface")
    assert 'edit "vlan10"\n        set description "MGMT"\n        set ip 10.10.10.6 255.255.255.0' in t
    assert 'edit "port1"\n        set description "Desk ports"\n        set native-vlan 20\n        set edge-port enabled' in t
    assert 'edit "lag1"\n        set mode lacp-active\n        set members "port49" "port50"\n        set lacp-speed fast' in t
    assert 'set accprofile "read_only"' in t and "config system accprofile" in t
    assert "set dhcp-snooping enable" in block(t, "switch vlan")
    assert 'set device "vlan10"' in t and "set distance 20" in t


def test_port_names():
    from exbuilder import ports
    assert ports.expand_named("1-2, port49", fortiswitch_models.ALIASES) == ["port1", "port2", "port49"]
    res = build(base(ports=[{"ports": "Gi1/0/1", "mode": "access", "vlan": "USERS"}]))
    assert "not a port" in msgs(res.errors)


def test_trunk_all_voice_and_routed():
    res = build(base(vlans=[{"name": "USERS", "id": "20"}, {"name": "VOICE", "id": "30", "voice": True}],
                     ports=[{"ports": "port1", "mode": "access", "vlan": "USERS"},
                            {"ports": "port49", "mode": "trunk", "vlans": "all", "native": "USERS"},
                            {"ports": "port50", "mode": "routed", "address": "10.0.0.1/30"}]))
    t = res.set_text
    assert 'edit "port1"\n        set native-vlan 20\n        set allowed-vlans 30' in t
    assert "set allowed-vlans-all enable" in t
    assert "no routed ports" in msgs(res.errors) and "LLDP-MED" in msgs(res.warnings)


def test_physical_port_settings():
    res = build(base(ports=[{"ports": "port1-2", "mode": "disabled"},
                            {"ports": "port3", "mode": "access", "vlan": "USERS", "speed": "100m", "mtu": "9000", "poe": "off"},
                            {"ports": "port49", "mode": "access", "vlan": "USERS", "poe": "high"}]))
    t = block(res.set_text, "switch physical-port")
    assert 'edit "port1"\n        set status down' in t
    assert 'edit "port3"\n        set speed 100full\n        set max-frame-size 9018\n        set poe-status disable' in t
    assert "has no PoE" in msgs(res.warnings)


def test_mgmt_port_and_100f():
    res = build(base(system={"hostname": "fsw1", "mgmt_address": "192.168.1.5/24", "mgmt_gateway": "192.168.1.1"}))
    t = res.set_text
    assert 'edit "mgmt"\n        set ip 192.168.1.5 255.255.255.0' in t
    assert 'set gateway 192.168.1.1\n        set device "mgmt"' in t
    res = build(base(switch={"members": [{"fpc": 1, "model": "FS-124F-POE"}]},
                     system={"hostname": "fsw1", "mgmt_address": "192.168.1.5/24"}))
    assert "no out-of-band" in msgs(res.errors)


def test_dot1x_radius_and_users():
    res = build(base(ports=[{"ports": "port1", "mode": "access", "vlan": "USERS", "dot1x": "dot1x-mab"}],
                     security={"radius_servers": [{"address": "10.0.0.5", "secret": "radsecret"}]},
                     access={"root_password": "Admin-pass-1", "users": [
                         {"name": "ro", "class": "read-only", "password": "Read-only-1", "ssh_keys": "ssh-ed25519 AAAA x@y"}]}))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert t.index("config user group") < t.index("config switch interface")
    assert 'edit "RADIUS-1"\n        set server "10.0.0.5"\n        set secret "radsecret"' in t
    assert 'config port-security\n            set port-security-mode 802.1X\n            set security-groups "dot1x-users"\n            set mac-auth-bypass enable\n        end' in t
    assert 'edit "admin"\n        set password "Admin-pass-1"' in t
    assert 'set ssh-public-key1 "ssh-ed25519 AAAA x@y"' in t


def test_lag_static_and_names():
    res = build(base(lags=[{"name": "Po3", "members": "49-50", "mode": "trunk", "vlans": "USERS", "lacp": "static",
                            "min_links": "2"}]))
    t = res.set_text
    assert 'edit "lag3"\n        set mode static' in t and "set min-bundle 2" in t
    res = build(base(lags=[{"name": "bad name!", "members": "49-50", "mode": "trunk", "vlans": "USERS"}]))
    assert "short name" in msgs(res.errors)


def test_ospf_bgp():
    res = build(base(
        vlans=[{"name": "USERS", "id": "20", "irb": "10.0.20.1/24", "dhcp_relay": True},
               {"name": "UPLINK", "id": "99", "irb": "10.9.9.1/30"}],
        routing={"loopback": "10.255.0.1", "asn": "65001", "dhcp_relay_servers": "10.0.0.10",
                 "ospf": {"enabled": True, "areas": [{"area": "0", "interfaces": "vlan 99, loopback 0", "passive": "vlan 20", "p2p": "vlan 99"}]},
                 "bgp_groups": [{"name": "UP", "type": "external", "peer_as": "65000", "neighbors": "10.9.9.2"}]}))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert 'set dhcp-relay-service enable\n        set dhcp-relay-ip "10.0.0.10"' in t
    o = block(t, "router ospf")
    assert "set router-id 10.255.0.1" in o and "set prefix 10.9.9.0 255.255.255.252" in o
    assert 'edit "vlan99"\n            set network-type point-to-point' in o
    assert 'edit "vlan20"\n            set passive enable' in o
    b = t[t.index("config router bgp"):]
    assert "set as 65001" in b and 'edit "10.9.9.2"\n            set remote-as 65000' in b
    assert "Advanced Features license" in msgs(res.warnings)


@pytest.mark.parametrize("model", list(fortiswitch_models.MODELS))
def test_every_model_builds(model):
    res = build(base(switch={"members": [{"fpc": 1, "model": model}]},
                     ports=[{"ports": "port1-2", "mode": "access", "vlan": "USERS"}]))
    assert not res.errors, msgs(res.errors)
