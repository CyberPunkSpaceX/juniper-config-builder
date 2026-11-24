import json
from pathlib import Path

from exbuilder import fastiron_models, ports
from exbuilder.cryptpw import is_md5, md5_crypt
from exbuilder.generator import build

EXAMPLES = Path(__file__).parent.parent / "src" / "exbuilder" / "vendor_examples"


def base(**over):
    p = {"vendor": "ruckus", "system": {"hostname": "icx1", "domain": "example.lan", "ntp_servers": [{"address": "10.0.0.1"}]},
         "access": {"users": [{"name": "netadmin", "class": "super-user", "password": "Secret-pass-1"}]},
         "switch": {"members": [{"fpc": 1, "model": "ICX7150-48P"}]},
         "vlans": [{"name": "USERS", "id": "20"}, {"name": "CAM", "id": "30"}]}
    p.update(over)
    return p


def msgs(items):
    return " | ".join(m["message"] for m in items)


def block(text, header):
    return text.split(header + "\n")[1].split("!")[0]


def test_md5_crypt_matches_openssl():
    # openssl passwd -1 -salt saltsalt password
    assert md5_crypt("password", "saltsalt") == "$1$saltsalt$qjXMvbEw8oaL.CzflDtaK/"
    assert is_md5(md5_crypt("Secret-pass-1"))


def test_icx_example_builds_clean():
    res = build(json.loads((EXAMPLES / "ruckus-office.json").read_text()))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "stack enable" in t and "hostname icx-office-01" in t
    assert "clock timezone us mountain" in t and "ntp\n server 10.10.0.1" in t
    assert 'lag "To-core" dynamic id 1\n ports ethe 1/3/1 ethe 2/3/1' in t and "primary-port" not in t
    vlan20 = block(t, "vlan 20 name USERS by port")
    assert "tagged lag 1" in vlan20 and "untagged ethe 1/1/1 to 1/1/40 ethe 2/1/1 to 2/1/40" in vlan20
    assert "router-interface ve 20" in vlan20
    assert "ip helper-address 1 10.10.0.10" in block(t, "interface ve 20")
    assert "voice-vlan 30" in block(t, "interface ethe 1/1/1 to 1/1/40")
    assert "dual-mode" not in t
    assert "Change-me-2026" not in t and "password 8 $1$" in t and "enable super-user-password 8 $1$" in t
    # snooping trusts the AP trunk group and the LAG, not the desk ports
    assert "dhcp snooping trust" in block(t, "interface ethe 1/1/41 to 1/1/46 ethe 2/1/41 to 2/1/46")
    assert "dhcp snooping trust" in block(t, "interface lag 1")
    assert "dhcp snooping trust" not in block(t, "interface ethe 1/1/1 to 1/1/40")
    assert t.rstrip().endswith("$\n!\nend")


def test_fcx_example_uses_legacy_syntax():
    res = build(json.loads((EXAMPLES / "ruckus-fcx-closet.json").read_text()))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "primary-port 1/3/1" in t and "dual-mode 20" in t
    # legacy VLAN membership names the LAG's primary port and keeps the native VLAN tagged
    assert "tagged ethe 1/1/1 to 1/1/46 ethe 1/3/1" in block(t, "vlan 20 name USERS by port")
    assert "stack enable" not in t


def test_fgs_is_unit_zero_and_old_syntax():
    p = base(switch={"members": [{"fpc": 1, "model": "FGS648P"}]},
             ports=[{"ports": "0/1/1-24", "mode": "access", "vlan": "USERS"}],
             lags=[{"name": "lag1", "members": "0/2/1-2", "mode": "trunk", "vlans": "USERS, CAM"}])
    res = build(p)
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "sntp server 10.0.0.1" in t and "\nntp\n" not in t
    assert "link-aggregate configure key 10001" in t and 'lag "' not in t
    assert "crypto key generate\n" in t
    assert fastiron_models.get("FGS648P").ports()[0]["name"] == "0/1/1"
    res = build(base(switch={"members": [{"fpc": 1, "model": "FGS648P"}, {"fpc": 2, "model": "FGS648P"}]}))
    assert "doesn't stack" in msgs(res.errors)


def test_port_names_and_stack_rules():
    assert ports.expand_named("1/1/1-2, 1/3/1", fastiron_models.ALIASES) == ["1/1/1", "1/1/2", "1/3/1"]
    res = build(base(ports=[{"ports": "ethe 1/1/1 to 1/1/2", "mode": "access", "vlan": "USERS"}]))
    assert not res.errors, msgs(res.errors)
    res = build(base(ports=[{"ports": "ge-0/0/1", "mode": "access", "vlan": "USERS"}]))
    assert res.errors
    res = build(base(switch={"members": [{"fpc": 1, "model": "ICX7150-48P"}, {"fpc": 2, "model": "ICX7250-48P"}]}))
    assert "can't mix" in msgs(res.errors)
    res = build(base(switch={"members": [{"fpc": 1, "model": "ICX7150-48P"}, {"fpc": 1, "model": "ICX7150-48P"}]}))
    assert "used once" in msgs(res.errors)


def test_passwords_from_other_vendors_need_retyping():
    res = build(base(access={"users": [{"name": "u1", "class": "super-user", "password": "$6$abc$def"}]}))
    assert "type it again for FastIron" in msgs(res.errors) and "needs a password" not in msgs(res.errors)


def test_vlan_translation_is_ignored_with_a_warning():
    res = build(base(ports=[{"ports": "1/1/2", "mode": "trunk", "vlans": "USERS", "vlan_translate": "130>30"}]))
    assert not res.errors and "no per-port VLAN translation" in msgs(res.warnings)


def test_routing_dot1x_and_poe():
    res = build(base(routing={"loopback": "10.255.255.2", "asn": "65002",
                              "ospf": {"enabled": True, "areas": [{"area": "0", "interfaces": "1/3/1, lo0", "p2p": "1/3/1"}]},
                              "bgp_groups": [{"name": "UP", "type": "external", "neighbors": "10.9.9.2 65000 ISP"}]},
                     ports=[{"ports": "1/3/1", "mode": "routed", "address": "10.9.9.1/30"},
                            {"ports": "1/1/1", "mode": "access", "vlan": "USERS", "dot1x": "dot1x-mab", "poe": "high"}],
                     security={"radius_servers": [{"address": "10.0.0.5", "secret": "s3cr3t"}]}))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert "ip address 10.9.9.1 255.255.255.252\n ip ospf area 0\n ip ospf network point-to-point" in t
    assert "interface loopback 1" in t and "router ospf\n area 0" in t
    assert "router bgp\n local-as 65002" in t and "neighbor 10.9.9.2 remote-as 65000" in t
    assert "dot1x port-control auto ethe 1/1/1" in t and "mac-authentication enable ethe 1/1/1" in t
    assert "radius-server host 10.0.0.5" in t and "inline power priority 2" in t
