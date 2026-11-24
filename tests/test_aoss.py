import json
from pathlib import Path

import pytest

from exbuilder import aoss_models as SM
from exbuilder.generator import build

EXAMPLE = Path(__file__).parent.parent / "src" / "exbuilder" / "vendor_examples" / "procurve-office.json"


def base(**over):
    p = {"vendor": "procurve", "system": {"hostname": "hp1", "ntp_servers": [{"address": "10.0.0.1"}]},
         "access": {"users": [{"name": "netadmin", "class": "super-user", "password": "Secret-pass-1"}]},
         "switch": {"members": [{"fpc": 1, "model": "2930F-48G-PoE+-4SFP+"}]},
         "vlans": [{"name": "USERS", "id": "20"}, {"name": "CAM", "id": "30"}]}
    p.update(over)
    return p


def msgs(items):
    return " | ".join(m["message"] for m in items)


def block(text, header):
    return text.split(header + "\n")[1].split("   exit")[0]


def test_port_lists():
    assert SM.expand("1-3, A1-A2, 2/1-2/3, 1/A1") == ["1", "2", "3", "A1", "A2", "2/1", "2/2", "2/3", "1/A1"]
    assert SM.compact(["3", "1", "2", "5", "A2", "A1", "2/1", "2/2"]) == "1-3,5,A1-A2,2/1-2/2"
    with pytest.raises(ValueError):
        SM.expand("1/1-2/4")
    with pytest.raises(ValueError):
        SM.expand("ge-0/0/1")


def test_example_builds_clean():
    res = build(json.loads(EXAMPLE.read_text()))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "!" not in t and t.startswith('hostname "hp-office-01"')
    assert "time timezone -420\ntime daylight-time-rule continental-us-and-canada" in t
    assert 'password manager user-name "netadmin" plaintext "Change-me-2026"' in t
    assert 'password operator user-name "monitor" plaintext "Look-only-2026"' in t
    assert t.index("trunk 49-50 trk1 lacp") < t.index("vlan 10")
    v20 = block(t, "vlan 20")
    assert "untagged 1-40" in v20 and "tagged 41-46,Trk1" in v20
    assert "tagged 1-40,Trk1" in block(t, "vlan 30") and "voice" in block(t, "vlan 30")
    assert "ip address 10.10.10.7 255.255.255.0" in block(t, "vlan 10")
    # one VLAN address and a default route: stays layer 2
    assert "ip default-gateway 10.10.10.1" in t and "ip routing" not in t
    assert "spanning-tree 1-40 admin-edge-port" in t and "spanning-tree 1-40 bpdu-protection" in t
    assert "address-limit 3" in t and "dhcp-snooping trust 41-46,Trk1" in t
    assert "power-over-ethernet high" in block(t, "interface 41-46")
    assert 'banner motd "Authorized access only."' in t


def test_routing_ospf_and_no_routed_ports():
    res = build(base(vlans=[{"name": "USERS", "id": "20", "irb": "10.0.20.1/24"},
                            {"name": "UP", "id": "99", "irb": "10.9.9.1/30"}],
                     routing={"loopback": "10.255.255.3", "static": [{"prefix": "10.50.0.0/16", "next_hop": "10.9.9.2"}],
                              "ospf": {"enabled": True, "areas": [{"area": "0", "interfaces": "vlan 99, lo0", "passive": "vlan 20"}]}},
                     ports=[{"ports": "49", "mode": "routed", "address": "10.8.8.1/30"}]))
    t = res.set_text
    assert "AOS-S has no routed ports" in msgs(res.errors)
    assert "ip routing" in t and "ip route 10.50.0.0 255.255.0.0 10.9.9.2" in t
    assert "ip ospf 10.9.9.1 area backbone" in block(t, "vlan 99")
    assert "ip ospf 10.0.20.1 passive" in block(t, "vlan 20")
    assert "router ospf\n   area backbone\n   enable" in t and "ip router-id 10.255.255.3" in t


def test_stack_oobm_and_old_procurve():
    res = build(base(switch={"members": [{"fpc": 1, "model": "2930M-48G-PoE+"}, {"fpc": 2, "model": "2930M-48G-PoE+"}]},
                     ports=[{"ports": "1/1-1/24, 2/1-2/24", "mode": "access", "vlan": "USERS"}]))
    assert not res.errors, msgs(res.errors)
    assert 'stacking\n   member 1 type "JL322A"\n   member 2 type "JL322A"' in res.set_text
    assert "untagged 1/1-1/24,2/1-2/24" in res.set_text
    res = build(base(switch={"members": [{"fpc": 1, "model": "2930F-48G-PoE+-4SFP+"}]},
                     system={"hostname": "hp1", "mgmt_address": "192.168.1.5/24"}))
    assert "no out-of-band management port" in msgs(res.errors)
    res = build(base(switch={"members": [{"fpc": 1, "model": "ProCurve 2810-48G"}]}))
    assert "sntp server priority 1 10.0.0.1" in res.set_text and "timesync sntp" in res.set_text


def test_users_and_dot1x():
    res = build(base(access={"users": [{"name": "u1", "class": "super-user", "password": "$6$abc$def"}]}))
    assert "type it again for AOS-S" in msgs(res.errors)
    res = build(base(ports=[{"ports": "1-4", "mode": "access", "vlan": "USERS", "dot1x": "dot1x-mab"}],
                     security={"radius_servers": [{"address": "10.0.0.5", "secret": "s3cr3t"}]}))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert 'radius-server host 10.0.0.5 key "s3cr3t"' in t and "aaa port-access authenticator 1-4" in t
    assert "aaa port-access mac-based 1-4" in t
