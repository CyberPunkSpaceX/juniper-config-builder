import json
from pathlib import Path

from switchbuilder import ports, unifi_models
from switchbuilder.generator import build

EXAMPLE = Path(__file__).parent.parent / "src" / "switchbuilder" / "vendor_examples" / "unifi-office.json"


def base(**over):
    p = {"vendor": "unifi", "system": {"hostname": "usw1", "ntp_servers": [{"address": "10.0.0.1"}]},
         "access": {"users": [{"name": "netadmin", "class": "super-user", "password": "Secret-pass-1"}]},
         "switch": {"members": [{"fpc": 1, "model": "USW-Pro-24-PoE"}]},
         "vlans": [{"name": "USERS", "id": "20"}, {"name": "CAM", "id": "30"}],
         "services": {"storm_control": False}}
    p.update(over)
    return p


def msgs(items):
    return " | ".join(m["message"] for m in items)


def test_example_builds_clean():
    res = build(json.loads(EXAMPLE.read_text()))
    assert not res.errors, msgs(res.errors)
    t = res.set_text
    assert t.startswith("UniFi Network settings for usw-office-01 (USW-Pro-24-PoE)")
    assert "MGMT     VLAN 10    VLAN only (the gateway routes it)" in t
    assert "   DESKS:\n     Native VLAN / Network: USERS (20)\n     Tagged VLAN Management: Custom, allow VOICE (30)" in t
    assert "   CAMERAS:\n     Native VLAN / Network: CAMERAS (50)\n     Tagged VLAN Management: Block All" in t
    assert "Ports 25-26: Operation: Aggregate, profile UPLINK" in t
    assert "Ports 1-16: profile DESKS" in t and "IP address: 10.10.10.8" in t
    assert "Change-me-2026" not in t  # passwords are never printed
    assert t.index("Networks (") < t.index("Ethernet port profiles") < t.index("Ports (")


def test_port_names_and_profiles_are_shared():
    assert ports.expand_named("1-3, port5", unifi_models.ALIASES) == ["1", "2", "3", "5"]
    res = build(base(ports=[{"name": "A", "ports": "1-2", "mode": "access", "vlan": "USERS"},
                            {"name": "B", "ports": "5", "mode": "access", "vlan": "USERS"},
                            {"name": "C", "ports": "ge-0/0/1", "mode": "access", "vlan": "USERS"}]))
    assert "Ports 5: profile A" in res.set_text and "   B:" not in res.set_text
    assert "not a port" in msgs(res.errors)


def test_lag_rules():
    res = build(base(lags=[{"name": "UP", "members": "25, 23", "mode": "trunk", "vlans": "all"}]))
    assert "neighbouring ports" in msgs(res.errors)
    res = build(base(lags=[{"name": "UP", "members": "25-26", "lacp": "static", "mode": "trunk", "vlans": "all"}]))
    assert not res.errors and "always use LACP" in msgs(res.warnings)


def test_layer3_vlans_and_routes():
    res = build(base(vlans=[{"name": "USERS", "id": "20", "irb": "10.0.20.1/24", "dhcp_relay": True}],
                     routing={"dhcp_relay_servers": "10.0.0.5",
                              "static": [{"prefix": "10.9.0.0/16", "next_hop": "10.0.20.254"}]}))
    assert not res.errors, msgs(res.errors)
    assert "Router: this switch, gateway 10.0.20.1/24, DHCP relay to 10.0.0.5" in res.set_text
    assert "10.9.0.0/16  next hop 10.0.20.254" in res.set_text
    res = build(base(switch={"members": [{"fpc": 1, "model": "USW-Lite-8-PoE"}]},
                     vlans=[{"name": "USERS", "id": "20", "irb": "10.0.20.1/24"}]))
    assert "can't route" in msgs(res.errors)


def test_dot1x_poe_and_disabled():
    res = build(base(ports=[{"name": "DOT", "ports": "1-4", "mode": "access", "vlan": "USERS", "dot1x": "mab", "poe": "off"},
                            {"name": "OFF", "ports": "5", "mode": "disabled"},
                            {"name": "UP", "ports": "25", "mode": "trunk", "vlans": "USERS", "poe": "high"}],
                     security={"radius_servers": [{"address": "10.0.0.9", "secret": "rad-secret"}], "guest_vlan": "CAM"}))
    t = res.set_text
    assert "802.1X Control: MAC-Based" in t and "PoE: Off" in t
    assert "Authentication server: 10.0.0.9 port 1812" in t and "rad-secret" not in t
    assert "802.1X Control: on, RADIUS profile dot1x-radius, fallback VLAN CAM (30)" in t
    assert "Ports 5: Disabled" in t
    assert "no PoE" in msgs(res.warnings)


def test_unsupported():
    res = build(base(ports=[{"ports": "1", "mode": "routed", "address": "10.0.0.1/30"}],
                     vlans=[{"name": "ONE", "id": "1"}],
                     routing={"ospf": {"enabled": True}}))
    assert "no routed ports" in msgs(res.errors) and "2-4009" in msgs(res.errors)
    assert "don't run OSPF" in msgs(res.warnings)
