import json
from pathlib import Path

import pytest

from exbuilder import models, ports
from exbuilder.cryptpw import is_hashed, sha512_crypt
from exbuilder.generator import build
from exbuilder.junos import Config, q

EXAMPLE = Path(__file__).parent.parent / "examples" / "office-switch.json"
HASH = sha512_crypt("Juniper123!", "fixedsalt")


def base(**over):
    p = {"system": {"hostname": "sw1", "ntp_servers": [{"address": "10.0.0.1"}]},
         "access": {"root_password": HASH, "users": [{"name": "admin1", "class": "super-user", "password": HASH}]},
         "switch": {"members": [{"fpc": 0, "model": "EX2300-24P"}]},
         "services": {"delete_first": False}}
    for k, v in over.items():
        p[k] = v
    return p


def sets(res):
    return [l for l in res.set_text.splitlines() if l.startswith("set ")]


def msgs(items):
    return " | ".join(m["message"] for m in items)


# ----------------------------------------------------------------- helpers
def test_sha512_crypt_matches_glibc_vector():
    assert sha512_crypt("Hello world!", "saltstring") == (
        "$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1")
    assert is_hashed(sha512_crypt("x"))


def test_port_expand_and_compact():
    assert ports.expand("ge-0/0/0-2, xe-0/1/0 ge-1/0/5 to ge-1/0/6") == [
        "ge-0/0/0", "ge-0/0/1", "ge-0/0/2", "xe-0/1/0", "ge-1/0/5", "ge-1/0/6"]
    assert ports.compact(["ge-0/0/3", "ge-0/0/1", "ge-0/0/2", "ge-0/0/9"]) == "ge-0/0/1-3, ge-0/0/9"
    with pytest.raises(ValueError):
        ports.expand("ge-0/0/5-2")
    with pytest.raises(ValueError):
        ports.expand("eth0")


def test_quoting():
    assert q("abc") == "abc"
    assert q('say "hi"\nbye') == '"say \\"hi\\"\\nbye"'


def test_hierarchy_merges_leaf_and_container():
    c = Config()
    c.add(("system", "services"), "ssh")
    c.add(("system", "services", "ssh"), "root-login deny")
    c.add_list(("vlans", "V", "vlan"), "members", ["a", "b"])
    out = c.to_hierarchy()
    assert "ssh {\n            root-login deny;" in out and "ssh;" not in out
    assert "members [ a b ];" in out
    assert c.to_set().count("vlan members") == 2


def test_catalog_models():
    assert {"EX2300-48P", "EX3400-24T", "EX4300-48P", "EX4400-24P"} <= set(models.MODELS)
    m = models.get("EX2300-48P")
    names = [p["name"] for p in m.ports(1)]
    assert names[0] == "ge-1/0/0" and "xe-1/1/3" in names and len(names) == 52
    assert models.get("EX4400-48P").mgmt == "em0"


# ---------------------------------------------------------------- example
def test_example_builds_once_passwords_are_set():
    p = json.loads(EXAMPLE.read_text())
    res = build(p)
    assert "A root password is required" in msgs(res.errors)
    p["access"]["root_password"] = "Juniper123!"
    p["access"]["users"][0]["password"] = "Juniper123!"
    res = build(p)
    assert res.errors == []
    assert set(res.hashed) == {"access.root_password", "access.users.0.password"}
    out = res.set_text
    for line in [
        "set system host-name ex-office-01",
        "set system time-zone America/Edmonton",
        "set vlans USERS vlan-id 20",
        "set vlans USERS l3-interface irb.20",
        "set interfaces irb unit 20 family inet address 10.10.20.1/24",
        "set interfaces interface-range DESKS member-range ge-0/0/0 to ge-0/0/39",
        "set interfaces interface-range DESKS unit 0 family ethernet-switching vlan members USERS",
        "set switch-options voip interface ge-0/0/5.0 vlan VOICE",
        "set interfaces interface-range APS native-vlan-id 10",
        "set interfaces interface-range APS unit 0 family ethernet-switching vlan members MGMT",
        "set interfaces ge-0/0/47 unit 0 family inet address 10.255.0.2/30",
        "set interfaces xe-0/1/0 ether-options 802.3ad ae0",
        "set interfaces ae0 aggregated-ether-options lacp active",
        "set chassis aggregated-devices ethernet device-count 1",
        "set routing-options static route 0.0.0.0/0 next-hop 10.255.0.1",
        "set forwarding-options dhcp-relay group RELAY interface irb.20",
        "set vlans USERS forwarding-options dhcp-security arp-inspection",
        "set protocols rstp interface ge-0/0/0 edge",
        "set interfaces interface-range UNUSED member ge-0/0/46",
        "delete interfaces",
    ]:
        assert line in out, line
    assert "ge-0/0/47" not in [l for l in out.splitlines() if "UNUSED" in l][0]
    assert "Juniper123!" not in out and "Juniper123!" not in res.hier_text
    # Hierarchy: balanced braces, no set/delete lines.
    h = res.hier_text
    assert h.count("{") == h.count("}") and "\nset " not in h and "delete" not in h


# ---------------------------------------------------------------- checks
def test_required_fields():
    res = build({})
    text = msgs(res.errors)
    assert "Host name is required" in text and "root password" in text


def test_bad_values_are_errors():
    res = build(base(vlans=[{"name": "A", "id": "5000"}, {"name": "B", "id": "10", "irb": "10.0.0.0/24"},
                           {"name": "C", "id": "10"}],
                     ports=[{"ports": "ge-0/0/0-3", "mode": "access", "vlan": "NOPE"},
                            {"ports": "ge-0/0/3", "mode": "access"}]))
    text = msgs(res.errors)
    assert "ID must be 1-4094" in text
    assert "network or broadcast" in text
    assert "VLAN ID 10 is used by both" in text
    assert "'NOPE' is not defined" in text
    assert "ge-0/0/3 is already used" in text


def test_trunk_native_is_added_to_members():
    res = build(base(vlans=[{"name": "A", "id": "10"}, {"name": "B", "id": "20"}],
                     ports=[{"ports": "ge-0/0/1", "mode": "trunk", "vlans": "A", "native": "20"}]))
    s = sets(res)
    assert "set interfaces ge-0/0/1 native-vlan-id 20" in s
    assert "set interfaces ge-0/0/1 unit 0 family ethernet-switching vlan members B" in s


def test_routed_group_needs_one_port_and_address():
    res = build(base(ports=[{"ports": "ge-0/0/1-2", "mode": "routed", "address": "10.0.0.1/30"}]))
    assert "only hold one port" in msgs(res.errors)
    res = build(base(ports=[{"ports": "ge-0/0/1", "mode": "routed", "address": "10.0.0.1"}]))
    assert "prefix length" in msgs(res.errors)


def test_lag_checks():
    res = build(base(lags=[{"name": "ae3", "members": "xe-0/1/0-1", "mode": "access", "min_links": "5"},
                           {"name": "lag1", "members": "xe-0/1/2"}]))
    text = msgs(res.errors)
    assert "minimum links must be 1-2" in text and "must be ae0 to ae127" in text
    assert "set chassis aggregated-devices ethernet device-count 4" in sets(res)


def test_unknown_and_vc_ports_warn():
    res = build(base(switch={"members": [{"fpc": 0, "model": "EX3400-24T"}]},
                     ports=[{"ports": "ge-0/0/30", "mode": "access"}, {"ports": "et-0/1/0", "mode": "trunk", "vlans": "all"}]))
    text = msgs(res.warnings)
    assert "ge-0/0/30 is not a port" in text
    assert "vc-port delete pic-slot 1 port 0" in text


def test_ge_in_10g_uplink_is_accepted():
    res = build(base(ports=[{"ports": "ge-0/1/0", "mode": "trunk", "vlans": "all"}]))
    assert "not a port" not in msgs(res.warnings)


def test_virtual_chassis():
    res = build(base(switch={"members": [{"fpc": 0, "model": "EX4300-48P", "serial": "PE111", "role": "routing-engine"},
                                         {"fpc": 1, "model": "EX4300-48P", "serial": "PE222", "role": "routing-engine"}],
                             "vc_preprovisioned": True},
                     ports=[{"ports": "ge-1/0/0-5", "mode": "access"}]))
    s = sets(res)
    assert res.errors == []
    assert "set virtual-chassis preprovisioned" in s and "set virtual-chassis member 1 serial-number PE222" in s
    assert "set virtual-chassis no-split-detection" in s and "set system commit synchronize" in s
    assert "set interfaces interface-range PORTS-1 member-range ge-1/0/0 to ge-1/0/5" in s


def test_snmp_v2_and_v3():
    res = build(base(snmp={"communities": [{"name": "public", "clients": "10.0.0.0/24"}],
                           "v3_users": [{"name": "nms", "auth": "sha256", "auth_password": "authpass1", "priv": "aes128",
                                         "priv_password": "privpass1"},
                                        {"name": "bad", "auth": "sha", "auth_password": "short"}],
                           "trap_targets": "10.0.0.9"}))
    s = sets(res)
    assert "set snmp community public clients 0.0.0.0/0 restrict" in s
    assert "set snmp v3 usm local-engine user nms authentication-sha256 authentication-password authpass1" in s
    assert ("set snmp v3 vacm access group nms-group default-context-prefix security-model usm "
            "security-level privacy read-view all") in s
    assert "set snmp trap-group traps targets 10.0.0.9" in s
    assert "well-known default" in msgs(res.warnings)
    assert "at least 8 characters" in msgs(res.errors)


def test_management_vrf_and_default_route():
    res = build(base(system={"hostname": "sw1", "mgmt_address": "192.168.1.10/24", "mgmt_gateway": "192.168.1.1",
                             "mgmt_vrf": True}))
    s = sets(res)
    assert "set interfaces me0 unit 0 family inet address 192.168.1.10/24" in s
    assert "set system management-instance" in s
    assert "set routing-instances mgmt_junos routing-options static route 0.0.0.0/0 next-hop 192.168.1.1" in s
    assert not any("management-ethernet" in l for l in s)
    res = build(base(system={"hostname": "sw1", "mgmt_address": "192.168.1.10/24", "mgmt_gateway": "192.168.1.1"}))
    assert "set routing-options static route 0.0.0.0/0 next-hop 192.168.1.1" in sets(res)


def test_ipv6_and_static_preference():
    res = build(base(vlans=[{"name": "V", "id": "10", "irb": "10.0.0.1/24, 2001:db8::1/64"}],
                     routing={"static": [{"prefix": "::/0", "next_hop": "2001:db8::fe"},
                                         {"prefix": "10.9.0.0/16", "next_hop": "10.0.0.254", "preference": "200"}]}))
    s = sets(res)
    assert "set interfaces irb unit 10 family inet6 address 2001:db8::1/64" in s
    assert "set routing-options rib inet6.0 static route ::/0 next-hop 2001:db8::fe" in s
    assert "set routing-options static route 10.9.0.0/16 preference 200" in s


def test_poe_skipped_on_non_poe_model():
    res = build(base(switch={"members": [{"fpc": 0, "model": "EX2300-24T"}]},
                     ports=[{"ports": "ge-0/0/1", "mode": "access", "poe": "high"}]))
    assert "has no PoE" in msgs(res.warnings)
    assert not any(l.startswith("set poe") for l in sets(res))


def test_ssh_keys_and_banner():
    res = build(base(access={"root_password": HASH, "users": [
        {"name": "ops", "class": "operator", "ssh_keys": "ssh-ed25519 AAAAC3Nza me@pc\nnot-a-key"}]}))
    s = sets(res)
    assert 'set system login user ops authentication ssh-ed25519 "ssh-ed25519 AAAAC3Nza me@pc"' in s
    assert "SSH key must start with" in msgs(res.errors)


def test_no_ranges_option_writes_each_port():
    res = build(base(ports=[{"ports": "ge-0/0/1-2", "mode": "access"}], services={"use_ranges": False}))
    s = sets(res)
    assert "set interfaces ge-0/0/2 unit 0 family ethernet-switching interface-mode access" in s
    assert not any("interface-range" in l for l in s)


def test_ex4100_models():
    m = models.get("EX4100-48MP")
    names = {p["name"]: p for p in m.ports(0)}
    assert names["mge-0/0/15"]["poe"] and names["ge-0/0/16"]["poe"] and "ge-0/0/15" not in names
    assert names["et-0/1/3"]["kind"] == "vcp" and names["xe-0/2/0"]["kind"] == "uplink"
    assert m.mgmt == "em0"
    assert len(models.get("EX4100-F-12P").ports(0)) == 16
    res = build(base(switch={"members": [{"fpc": 0, "model": "EX4100-24P"}]},
                     ports=[{"ports": "ge-0/0/0-23", "mode": "access"}, {"ports": "xe-0/2/0", "mode": "trunk", "vlans": "all"}]))
    assert res.errors == [] and "not a port" not in msgs(res.warnings)


def test_errors_point_at_fields_and_rows():
    p = json.loads(EXAMPLE.read_text())
    p["system"]["hostname"] = ""
    p["vlans"][1]["id"] = "5000"
    p["ports"].insert(0, {"name": "BAD", "ports": "ge-0/0/99x", "mode": "access"})
    errs = build(p).errors
    host = next(e for e in errs if e["message"] == "Host name is required.")
    assert host["field"] == "system.hostname" and "row" not in host
    vlan = next(e for e in errs if "ID must be 1-4094" in e["message"])
    assert vlan["row"] == "vlans.1" and vlan["field"] == "vlans.1.id"
    bad = next(e for e in errs if e["message"].startswith("BAD:"))
    assert bad["row"] == "ports.0" and bad["field"] == "ports.0.ports"
    # Errors after the tables (services, QoS ...) never inherit a row.
    p["services"]["storm_control"] = True
    p["services"]["storm_percent"] = "500"
    storm = next(e for e in build(p).errors if "Storm control" in e["message"])
    assert "row" not in storm


def test_dot1x_settings_reported_once():
    p = json.loads(EXAMPLE.read_text())
    p["ports"][0]["dot1x"] = "dot1x"
    p["security"] = {"radius_servers": [{"address": "10.0.0.5", "secret": "s3cret"}], "guest_vlan": "NOPE"}
    errs = [e for e in build(p).errors if "Guest VLAN" in e["message"]]
    assert len(errs) == 1 and errs[0]["field"] == "security.guest_vlan"
