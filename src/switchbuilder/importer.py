"""Read an existing Junos EX (ELS) config back into a builder project.

Accepts ``show configuration | display set`` output or the normal curly-brace
config. Every line is either turned into builder fields or listed as "not
imported", so nothing disappears silently. ``check()`` then runs the
builder's own validation and adds best-practice recommendations.
"""

from __future__ import annotations

import copy
import ipaddress
import re
import shlex

from . import models
from . import ports as P
from .generator import DEFAULTS, LAG_DEFAULTS, PORT_DEFAULTS, VLAN_DEFAULTS, build

PHYS = re.compile(r"^(ge|xe|mge|et)-\d{1,2}/\d/\d{1,2}$")
AE = re.compile(r"^ae\d{1,3}$")
NAME_OK = re.compile(r"[^A-Za-z0-9_-]+")

# Lines the builder always writes itself, so they count as understood.
AUTO = [
    "chassis aggregated-devices", "chassis alarm management-ethernet", "system services ssh protocol-version",
    "system syslog file interactive-commands", "system syslog user", "system syslog file messages authorization",
    "version", "system login retry-options", "forwarding-options storm-control-profiles",
    "routing-options forwarding-table export", "policy-options policy-statement ECMP-LOAD-BALANCE",
    "protocols rstp interface all", "protocols lldp interface all", "protocols lldp-med interface all",
    "system services netconf ssh", "system auto-snapshot", "switch-options vtep-source-interface",
]


# --------------------------------------------------------------- set lines
def _hier_to_set(text: str) -> list[str]:
    """Curly-brace config -> set lines."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    tokens = re.findall(r'"(?:\\.|[^"\\])*"|[{};\[\]]|[^\s{};\[\]]+', text)
    out, stack, cur, in_list, lst = [], [], [], False, []
    after_list = False
    i = 0
    while i < len(tokens):
        t = tokens[i]
        if in_list:
            if t == "]":
                in_list = False
                for item in lst:
                    out.append(" ".join(["set", *[x for x in stack if x], *cur, item]))
                lst, cur, after_list = [], [], True
                i += 1
                continue
            else:
                lst.append(t)
        elif t == "[":
            in_list = True
        elif t == "{":
            stack.append(" ".join(cur))
            cur = []
        elif t == "}":
            if stack:
                stack.pop()
            cur = []
        elif t == ";":
            if cur and not after_list:
                out.append(" ".join(["set", *[s for s in stack if s], *cur]))
            cur = []
        else:
            cur.append(t)
        after_list = False
        i += 1
    return [re.sub(r"\s+", " ", line).strip() for line in out]


SHOW_NOISE = re.compile(
    r"^\s*(?:(?:fpc|member)\d+:|-{3,}|\d+\s+\(FPC\s+\d+\).*|Member ID.*|(?:Preprovisioned |Auto-provisioned )?"
    r"Virtual Chassis.*|Mstr.*|JUNOS .*|[A-Z][A-Za-z0-9 ()/_.-]*:\s.*[^;{]|\{(?:master|backup|linecard)(?::\d+)?\})\s*$")


def _drop_show_output(text: str) -> str:
    """Remove 'show version' / 'show virtual-chassis' output pasted around a config
    (detect_models() reads it first)."""
    return "\n".join(ln for ln in text.split("\n") if not SHOW_NOISE.match(ln))


def to_set_lines(text: str) -> list[str]:
    text = _drop_show_output((text or "").replace("\r\n", "\n"))
    # Drop comments (# lines) and the CLI prompt or banner noise.
    lines = [ln for ln in text.split("\n") if not ln.strip().startswith("#")]
    body = "\n".join(lines)
    if "{" in body and not re.search(r"^\s*set\s", body, re.M):
        raw = _hier_to_set(body)
    else:
        raw = [ln.strip() for ln in lines if ln.strip().startswith("set ")]
    out = []
    for ln in raw:
        ln = re.sub(r"^set\s+", "", ln)
        if ln.startswith(("inactive: ", "protect: ")):
            ln = ln.split(" ", 1)[1]
        # 'vlan members [ A B ]' is shorthand for one line per value.
        m = re.match(r"^(.*?)\[\s*(.*?)\s*\](.*)$", ln)
        if m and m.group(2):
            out.extend(f"{m.group(1)}{v}{m.group(3)}" for v in m.group(2).split())
        else:
            out.append(ln)
    return out


def _words(line: str) -> list[str]:
    try:
        return shlex.split(line)
    except ValueError:
        return line.split()


# --------------------------------------------------------------- importer
class _Iface(dict):
    pass


def parse(text: str, model: str = "", detected: dict | None = None) -> dict:
    """Return {project, unparsed, notes, stats}.

    ``model`` is the model the user picked for member 0; ``detected`` is what
    detect_models() found ({fpc: {model, serial, role}}) for every member.
    """
    lines = to_set_lines(text)
    p = copy.deepcopy(DEFAULTS)
    p["services"]["delete_first"] = False
    p["services"]["storm_control"] = False
    p["services"]["bpdu_block_on_edge"] = False
    p["services"]["lldp"] = p["services"]["lldp_med"] = False
    p["services"]["poe_all"] = False
    p["services"]["stp"] = "none"
    p["access"]["retry_options"] = False
    p["access"]["ssh_root_login"] = ""
    p["access"]["ssh_connection_limit"] = p["access"]["ssh_rate_limit"] = ""
    p["syslog"]["log_commands"] = False
    p["system"]["ignore_mgmt_alarm"] = False
    p["system"]["timezone"] = ""
    if model:
        p["switch"]["members"][0]["model"] = model
    s, a, sn, sl, r, sv = p["system"], p["access"], p["snmp"], p["syslog"], p["routing"], p["services"]

    ifs: dict[str, dict] = {}
    ranges: dict[str, dict] = {}
    vlans: dict[str, dict] = {}
    users: dict[str, dict] = {}
    comms: dict[str, dict] = {}
    v3: dict[str, dict] = {}
    syslog_hosts: dict[str, dict] = {}
    ntp: dict[str, dict] = {}
    static: dict[str, dict] = {}
    areas: dict[str, dict] = {}
    groups: dict[str, dict] = {}
    plists: dict[str, list] = {}
    pcomms: dict[str, list] = {}
    terms: dict[tuple, dict] = {}
    members: dict[int, dict] = {}
    edge_ports: set[str] = set()
    ifs_flags: list = []
    cos_trust: set[str] = set()
    builder_qos = any("VOICE-VIDEO-DSCP" in ln for ln in lines)
    if builder_qos:
        p["qos"]["signalling_as_video"] = False
    voice: dict[str, str] = {}
    irb_units: dict[str, dict] = {}
    relay_ifaces: set[str] = set()
    facts: set[str] = set()     # for the recommendations
    unparsed: list[str] = []
    notes: list[str] = []
    used = 0

    def iface(name):
        if name.startswith("interface-range "):
            return None
        return ifs.setdefault(name, {"vlans": [], "addr": []})

    for line in lines:
        w = _words(line)
        if not w:
            continue
        ok = True
        n = len(w)
        j = " ".join(w)
        try:
            # ---------------------------------------------------- system
            if w[0] == "system":
                k = w[1] if n > 1 else ""
                if k == "host-name":
                    s["hostname"] = w[2]
                elif k == "domain-name":
                    s["domain"] = w[2]
                elif k == "domain-search":
                    s["domain_search"] = ", ".join(filter(None, [s["domain_search"], w[2]]))
                elif k == "time-zone":
                    s["timezone"] = w[2]
                elif k == "name-server":
                    s["name_servers"] = ", ".join(filter(None, [s["name_servers"], w[2]]))
                elif k == "ntp" and n > 3 and w[2] == "server":
                    e = ntp.setdefault(w[3], {"address": w[3], "prefer": False})
                    if "prefer" in w[4:]:
                        e["prefer"] = True
                elif k == "ntp" and n > 3 and w[2] == "source-address":
                    s["ntp_source"] = w[3]
                elif k == "ntp" and n > 2 and w[2] in ("boot-server",):
                    pass
                elif k == "login" and n > 2 and w[2] == "message":
                    s["banner"] = w[3].replace("\\n", "\n")
                elif k == "login" and n > 2 and w[2] == "retry-options":
                    a["retry_options"] = True
                elif k == "login" and n > 4 and w[2] == "user":
                    u = users.setdefault(w[3], {"name": w[3], "full_name": "", "class": "super-user", "password": "", "ssh_keys": ""})
                    if w[4] == "class":
                        u["class"] = w[5]
                    elif w[4] == "full-name":
                        u["full_name"] = w[5]
                    elif w[4] == "uid":
                        pass
                    elif w[4] == "authentication" and w[5] == "encrypted-password":
                        u["password"] = w[6]
                    elif w[4] == "authentication" and w[5].startswith(("ssh-", "ecdsa")):
                        u["ssh_keys"] = "\n".join(filter(None, [u["ssh_keys"], w[6]]))
                    else:
                        ok = False
                elif k == "root-authentication" and n > 3 and w[2] == "encrypted-password":
                    a["root_password"] = w[3]
                elif k == "root-authentication" and n > 3 and w[2].startswith(("ssh-", "ecdsa")):
                    a["root_ssh_key"] = w[3]
                elif k == "services":
                    svc = w[2] if n > 2 else ""
                    if svc == "ssh":
                        if n == 3:
                            pass
                        elif w[3] == "root-login":
                            a["ssh_root_login"] = w[4]
                        elif w[3] == "connection-limit":
                            a["ssh_connection_limit"] = w[4]
                        elif w[3] == "rate-limit":
                            a["ssh_rate_limit"] = w[4]
                        elif w[3] == "protocol-version":
                            if "v1" in w[4:]:
                                facts.add("ssh_v1")
                        else:
                            ok = False
                    elif svc == "netconf":
                        a["netconf"] = True
                    elif svc == "web-management":
                        if n > 3 and w[3] == "http":
                            facts.add("http")
                        else:
                            a["web"] = True
                    elif svc in ("telnet", "ftp", "finger", "rlogin", "tftp-server"):
                        facts.add(svc)
                        ok = False
                    elif svc == "dhcp-local-server":
                        ok = False
                    else:
                        ok = False
                elif k == "syslog":
                    if n > 3 and w[2] == "host":
                        h = syslog_hosts.setdefault(w[3], {"address": w[3], "facility": "any", "level": "info", "port": "514"})
                        if n > 5 and w[4] in ("any", "authorization", "change-log", "daemon", "firewall",
                                                 "interactive-commands", "kernel", "user"):
                            h["facility"], h["level"] = w[4], w[5]
                        elif n > 5 and w[4] == "port":
                            h["port"] = w[5]
                        elif n > 5 and w[4] == "source-address":
                            sl["source_address"] = w[5]
                        else:
                            ok = False
                    elif n > 3 and w[2] == "source-address":
                        sl["source_address"] = w[3]
                    elif n > 5 and w[2] == "file" and w[3] == "messages" and w[4] == "any":
                        sl["local_level"] = w[5]
                    elif n > 3 and w[2] == "file" and w[3] == "interactive-commands":
                        sl["log_commands"] = True
                    elif n > 2 and w[2] in ("user", "file", "time-format"):
                        pass
                    else:
                        ok = False
                elif k == "management-instance":
                    s["mgmt_vrf"] = True
                elif k == "auto-snapshot":
                    s["auto_snapshot"] = True
                elif k == "commit":
                    pass
                else:
                    ok = False

            # ---------------------------------------------------- chassis / VC
            elif w[0] == "chassis":
                if n > 2 and w[1] == "alarm" and w[2] == "management-ethernet":
                    s["ignore_mgmt_alarm"] = True
                elif w[1] == "aggregated-devices":
                    pass
                else:
                    ok = False
            elif w[0] == "virtual-chassis":
                if n > 3 and w[1] == "member":
                    m = members.setdefault(int(w[2]), {"fpc": int(w[2]), "model": "", "serial": "", "role": "line-card"})
                    if w[3] == "serial-number":
                        m["serial"] = w[4]
                    elif w[3] == "role":
                        m["role"] = w[4]
                elif n > 1 and w[1] == "preprovisioned":
                    p["switch"]["vc_preprovisioned"] = True
                elif n > 1 and w[1] == "no-split-detection":
                    p["switch"]["vc_no_split_detection"] = True
                else:
                    ok = False

            # ---------------------------------------------------- SNMP
            elif w[0] == "snmp":
                if w[1] == "location":
                    sn["location"] = w[2]
                elif w[1] == "contact":
                    sn["contact"] = w[2]
                elif w[1] == "community" and n > 3:
                    c = comms.setdefault(w[2], {"name": w[2], "access": "read-only", "clients": ""})
                    if w[3] == "authorization":
                        c["access"] = w[4]
                    elif w[3] == "clients":
                        if "restrict" not in w[4:]:
                            c["clients"] = ", ".join(filter(None, [c["clients"], w[4]]))
                    else:
                        ok = False
                elif w[1] == "community":
                    comms.setdefault(w[2], {"name": w[2], "access": "read-only", "clients": ""})
                elif w[1] == "trap-group" and n > 4 and w[3] == "targets":
                    sn["trap_targets"] = ", ".join(filter(None, [sn["trap_targets"], w[4]]))
                    sn["trap_community"] = w[2]
                elif w[1] == "trap-group":
                    pass
                elif w[1] == "v3" and n > 6 and w[2] == "usm" and w[4] == "user":
                    facts.add("snmpv3")
                    u = v3.setdefault(w[5], {"name": w[5], "auth": "sha", "auth_password": "", "priv": "", "priv_password": ""})
                    kind = w[6]
                    secret = w[8] if n > 8 and w[7].endswith("-password") else ""
                    if n > 8 and w[7].endswith("-key"):
                        notes.append(f"SNMPv3 user {w[5]}: the switch stores its passwords encrypted, so type them again on the SNMP tab.")
                    if kind.startswith("authentication-"):
                        u["auth"] = kind.split("-", 1)[1]
                        u["auth_password"] = secret
                    elif kind.startswith("privacy-"):
                        u["priv"] = kind.split("-", 1)[1]
                        u["priv_password"] = secret
                elif w[1] in ("v3", "view"):
                    facts.add("snmpv3")
                else:
                    ok = False

            # ---------------------------------------------------- interfaces
            elif w[0] == "interfaces" and n > 1:
                name = w[1]
                rest = w[2:]
                rng = None
                if name == "interface-range":
                    rng = ranges.setdefault(w[2], {"members": [], "cfg": {"vlans": [], "addr": []}})
                    rest = w[3:]
                    if rest and rest[0] == "member":
                        rng["members"].append(rest[1])
                        rest = []
                    elif rest and rest[0] == "member-range":
                        rng["members"].append(f"{rest[1]} to {rest[3]}")
                        rest = []
                    target = rng["cfg"]
                else:
                    target = iface(name)
                if rest:
                    ok = _iface_line(name, rest, target, irb_units)
                elif rng is None and name not in ifs:
                    ok = False

            # ---------------------------------------------------- VLANs
            elif w[0] == "vlans" and n > 2:
                v = vlans.setdefault(w[1], {**copy.deepcopy(VLAN_DEFAULTS), "name": w[1]})
                k = w[2]
                if k == "vlan-id":
                    v["id"] = w[3]
                elif k == "description":
                    v["description"] = w[3]
                elif k == "l3-interface":
                    v["_irb"] = w[3]
                elif k == "vxlan" and w[3] == "vni":
                    v["vni"] = w[4]
                elif k == "forwarding-options" and n > 3 and w[3] == "dhcp-security":
                    v["snooping"] = True
                    if n > 4 and w[4] == "arp-inspection":
                        v["dai"] = True
                    elif n > 4 and w[4] == "ip-source-guard":
                        v["ipsg"] = True
                    elif n > 4 and w[4] == "group":
                        pass
                elif k == "switch-options" and n > 4 and w[3] == "interface" and "interface-mac-limit" in w:
                    port = w[4].removesuffix(".0")
                    iface(port)["mac_limit"] = w[w.index("interface-mac-limit") + 1]
                else:
                    ok = False

            # ---------------------------------------------------- switch-options
            elif w[0] == "switch-options":
                if n > 4 and w[1] == "voip" and w[2] == "interface" and w[4] == "vlan":
                    voice[w[3].removesuffix(".0")] = w[5]
                elif n > 2 and w[1] == "voip" and w[2] == "interface":
                    pass
                elif n > 3 and w[1] == "interface" and w[3] == "interface-mac-limit":
                    if w[4] != "packet-action":
                        iface(w[2].removesuffix(".0"))["mac_limit"] = w[4]
                    else:
                        iface(w[2].removesuffix(".0"))["mac_action"] = w[5]
                elif n > 3 and w[1] == "interface" and w[3] == "persistent-learning":
                    iface(w[2].removesuffix(".0"))["sticky"] = True
                elif w[1] in ("vtep-source-interface",):
                    pass
                elif w[1] in ("route-distinguisher", "vrf-target"):
                    if w[1] == "vrf-target":
                        p["evpn"]["vrf_target"] = w[2]
                    p["evpn"]["enabled"] = True
                else:
                    ok = False

            # ---------------------------------------------------- routing
            elif w[0] == "routing-options":
                if w[1] == "router-id":
                    r["router_id"] = w[2]
                elif w[1] == "autonomous-system":
                    r["asn"] = w[2]
                elif w[1] == "static" and n > 4 and w[2] == "route":
                    st = static.setdefault(w[3], {"prefix": w[3], "next_hop": "", "preference": ""})
                    if w[4] == "next-hop":
                        st["next_hop"] = ", ".join(filter(None, [st["next_hop"], w[5]]))
                    elif w[4] == "preference":
                        st["preference"] = w[5]
                    else:
                        ok = False
                elif w[1] == "forwarding-table" and "export" in w:
                    r["ecmp"] = True
                else:
                    ok = False
            elif w[0] == "routing-instances" and n > 1 and w[1] == "mgmt_junos":
                if "next-hop" in w and "0.0.0.0/0" in w:
                    s["mgmt_gateway"] = w[w.index("next-hop") + 1]
                    s["mgmt_vrf"] = True
                else:
                    ok = False
            elif w[0] == "protocols":
                if w[1:3] == ["dot1x", "authenticator"]:
                    ok = True
                    if n > 4 and w[3] == "interface":
                        d = iface(w[4].removesuffix(".0"))
                        d.setdefault("dot1x", "dot1x")
                        if "mac-radius" in w:
                            d["dot1x"] = "mab" if "restrict" in w else "dot1x-mab"
                        elif "server-fail" in w:
                            p["security"]["server_fail"] = w[w.index("server-fail") + 1] if w[-1] != "vlan-name" else "vlan"
                        elif "guest-vlan" in w:
                            p["security"]["guest_vlan"] = w[w.index("guest-vlan") + 1]
                elif w[1:3] == ["layer2-control", "recovery-timeout"]:
                    p["security"]["recovery_timeout"] = w[3]
                else:
                    ok = _protocols(w, p, areas, groups, edge_ports, relay_ifaces, facts, ifs_flags)
            elif w[0] == "forwarding-options":
                if n > 1 and w[1] == "storm-control-profiles":
                    sv["storm_control"] = True
                    if "bandwidth-percentage" in w:
                        sv["storm_percent"] = w[w.index("bandwidth-percentage") + 1]
                elif n > 2 and w[1] == "dhcp-relay":
                    if w[2] == "server-group" and n > 4:
                        r["dhcp_relay_servers"] = ", ".join(filter(None, [r["dhcp_relay_servers"], w[4]]))
                    elif w[2] == "group" and "interface" in w:
                        relay_ifaces.add(w[w.index("interface") + 1])
                    elif w[2] in ("group", "server-group", "forward-snooped-clients", "overrides"):
                        pass
                    else:
                        ok = False
                else:
                    ok = False
            elif w[0] == "poe":
                if n > 2 and w[1] == "interface" and w[2] == "all":
                    sv["poe_all"] = True
                elif n > 2 and w[1] == "management":
                    sv["poe_management"] = w[2]
                elif n > 2 and w[1] == "guard-band":
                    sv["poe_guard_band"] = w[2]
                elif n > 3 and w[1] == "fpc" and w[3] in ("fast-poe", "perpetual-poe"):
                    sv["poe_fast" if w[3] == "fast-poe" else "poe_perpetual"] = True
                elif n > 4 and w[1] == "interface" and w[3] == "maximum-power":
                    iface(w[2])["poe_max"] = w[4]
                elif n > 3 and w[1] == "interface":
                    port = w[2]
                    if w[3] == "disable":
                        iface(port)["poe"] = "off"
                    elif w[3] == "priority":
                        iface(port)["poe"] = w[4]
                    else:
                        ok = False
                else:
                    ok = False
            elif w[0] == "access" and n > 3 and w[1] == "radius-server":
                rs = {x["address"]: x for x in p["security"]["radius_servers"]}
                e = rs.get(w[2]) or {"address": w[2], "secret": "", "port": ""}
                if w[3] == "secret":
                    e["secret"] = w[4]
                elif w[3] == "port":
                    e["port"] = w[4]
                elif w[3] == "source-address":
                    p["security"]["radius_source"] = w[4]
                if w[2] not in rs:
                    p["security"]["radius_servers"].append(e)
            elif w[0] == "access" and n > 2 and w[1] == "profile":
                pass
            elif w[0] == "class-of-service":
                facts.add("cos")
                ok = builder_qos
                if builder_qos:
                    qo = p["qos"]
                    qo.update(enabled=True, preset="custom")
                    if n > 4 and w[1] == "schedulers" and w[3] == "transmit-rate" and w[4] == "percent":
                        key = {"VOICE": "voice_percent", "VIDEO": "video_percent", "NETWORK-CONTROL": "control_percent"}.get(w[2])
                        if key:
                            qo[key] = w[5]
                    elif n > 4 and w[1] == "classifiers" and "cs3" in w:
                        qo["signalling_as_video"] = True
                    elif n > 3 and w[1] == "interfaces" and "classifiers" in w:
                        cos_trust.add(w[2])
            elif w[0] == "policy-options" and n > 3 and w[1] == "prefix-list":
                plists.setdefault(w[2], []).append(w[3])
            elif w[0] == "policy-options" and n > 4 and w[1] == "community" and w[3] == "members":
                pcomms.setdefault(w[2], []).extend(w[4:])
            elif w[0] == "policy-options" and n > 5 and w[1] == "policy-statement" and w[3] == "term" \
                    and w[2] != "ECMP-LOAD-BALANCE":
                ok = _term(terms.setdefault((w[2], w[4]), {"policy": w[2], "term": w[4]}), w[5:])
            elif w[0] == "policy-options" and n > 2 and w[2] == "ECMP-LOAD-BALANCE":
                r["ecmp"] = True
            else:
                ok = False
        except (IndexError, ValueError):
            ok = False
        if ok:
            used += 1
        elif not any(j.startswith(x) for x in AUTO):
            unparsed.append("set " + line)
        else:
            used += 1

    # ------------------------------------------------ apply interface ranges
    range_of: dict[str, str] = {}
    for rname, rg in ranges.items():
        try:
            names = P.expand(", ".join(rg["members"]))
        except ValueError:
            names = []
            notes.append(f"Interface range {rname}: could not read its members.")
        for port in names:
            d = ifs.setdefault(port, {"vlans": [], "addr": []})
            for k2, v2 in rg["cfg"].items():
                if k2 in ("vlans", "addr"):
                    d[k2] = d[k2] or list(v2)
                else:
                    d.setdefault(k2, v2)
            range_of[port] = rname

    if builder_qos:
        q = p["qos"]
        q["trust"] = "all" if any(ifs.get(x, {}).get("mode") == "trunk" or AE.match(x) for x in cos_trust) else "access"
        if q["voice_percent"] == "20" and q["video_percent"] == "30":
            q["preset"] = "voice-video"
    for name, flag in ifs_flags:
        ifs.setdefault(name, {"vlans": [], "addr": []})[flag] = True

    # ------------------------------------------------ VLANs and IRBs
    by_id = {}
    for v in vlans.values():
        irb = v.pop("_irb", "")
        if irb:
            unit = irb.split(".", 1)[1] if "." in irb else "0"
            info = irb_units.get(unit, {})
            v["irb"] = ", ".join(info.get("addr", []))
            if info.get("vga"):
                v["vga"] = info["vga"]
            if irb in relay_ifaces:
                v["dhcp_relay"] = True
        if v["id"]:
            by_id[v["id"]] = v["name"]
    p["vlans"] = sorted(vlans.values(), key=lambda v: int(v["id"]) if str(v["id"]).isdigit() else 9999)

    def vname(x):
        return by_id.get(x, x)

    # ------------------------------------------------ management
    for mgmt in ("me0", "em0", "vme"):
        d = ifs.pop(mgmt, None)
        if d and d.get("addr"):
            s["mgmt_interface"] = mgmt if mgmt != "vme" else ""
            s["mgmt_address"] = d["addr"][0]
    lo = ifs.pop("lo0", None)
    if lo and lo.get("addr"):
        r["loopback"] = lo["addr"][0]
    ifs.pop("irb", None)

    # ------------------------------------------------ ports and LAGs
    lag_members: dict[str, list[str]] = {}
    for name, d in ifs.items():
        if d.get("ae"):
            lag_members.setdefault(d["ae"], []).append(name)

    def port_row(name, d):
        row = copy.deepcopy(PORT_DEFAULTS)
        mode = d.get("mode") or ("routed" if d.get("addr") else ("access" if d.get("vlans") else ""))
        if d.get("disable"):
            mode = "disabled"
        row["mode"] = mode or "access"
        row["description"] = d.get("description", "")
        row["mtu"] = d.get("mtu", "")
        row["speed"] = d.get("speed", "")
        row["poe"] = d.get("poe", "")
        row["poe_max"] = d.get("poe_max", "")
        row["mac_action"] = d.get("mac_action", "drop")
        row["sticky"] = bool(d.get("sticky"))
        row["dot1x"] = d.get("dot1x", "")
        row["root_guard"] = bool(d.get("root_guard"))
        row["loop_protect"] = bool(d.get("loop_protect"))
        row["mac_limit"] = d.get("mac_limit", "")
        row["edge"] = name in edge_ports
        vl = [vname(x) for x in d.get("vlans", [])]
        if row["mode"] == "access":
            row["vlan"] = vl[0] if vl else ""
            row["voice"] = vname(voice.get(name, ""))
        elif row["mode"] == "trunk":
            row["vlans"] = ", ".join(vl)
            row["native"] = vname(d.get("native", ""))
        elif row["mode"] == "routed":
            row["address"] = ", ".join(d.get("addr", []))
        return row, mode

    groups_out: dict[tuple, list[str]] = {}
    rows: dict[tuple, dict] = {}
    for name in sorted((n for n in ifs if PHYS.match(n)), key=P.sort_key):
        d = ifs[name]
        if d.get("ae"):
            continue
        row, mode = port_row(name, d)
        if not mode and not d.get("disable") and not any(d.get(k) for k in ("description", "mtu", "speed", "poe")):
            continue
        key = tuple(sorted((k, str(v)) for k, v in row.items()))
        if row["mode"] == "routed":
            key += (("port", name),)
        key += (("range", range_of.get(name, "")),)
        groups_out.setdefault(key, []).append(name)
        rows[key] = row
    used_names = set()
    for key, names in groups_out.items():
        row = rows[key]
        row["ports"] = P.compact(names)
        rng = dict(key).get("range")
        base = rng or row["description"] or {"access": f"ACCESS-{row['vlan'] or 'DEFAULT'}", "trunk": "TRUNK",
                                             "routed": "ROUTED", "disabled": "DISABLED"}[row["mode"]]
        base = NAME_OK.sub("-", base).strip("-").upper()[:40] or "PORTS"
        nm, i = base, 2
        while nm in used_names:
            nm, i = f"{base}-{i}", i + 1
        used_names.add(nm)
        row["name"] = nm
        p["ports"].append(row)
    other = [n for n in ifs if not PHYS.match(n) and not AE.match(n)]
    for n in other:
        notes.append(f"Interface {n} is not something the builder manages, so it was not imported.")

    for name in sorted((n for n in ifs if AE.match(n)), key=lambda x: int(x[2:])):
        d = ifs[name]
        row, mode = port_row(name, d)
        lag = copy.deepcopy(LAG_DEFAULTS)
        lag.update({k: v for k, v in row.items() if k in lag})
        lag["name"] = name
        lag["mode"] = row["mode"] if mode else "trunk"
        lag["members"] = P.compact(lag_members.get(name, []))
        lag["lacp"] = d.get("lacp", "static")
        lag["lacp_fast"] = bool(d.get("lacp_fast"))
        lag["min_links"] = d.get("min_links", "")
        lag["esi"] = d.get("esi", "")
        lag["lacp_system_id"] = d.get("system_id", "")
        p["lags"].append(lag)
    for ae, mem in lag_members.items():
        if ae not in ifs or not AE.match(ae):
            notes.append(f"{P.compact(mem)} belong to {ae}, but {ae} has no config.")

    # ------------------------------------------------ the rest
    p["system"]["ntp_servers"] = list(ntp.values())
    p["access"]["users"] = list(users.values())
    p["snmp"]["communities"] = list(comms.values())
    p["snmp"]["v3_users"] = list(v3.values())
    p["syslog"]["hosts"] = list(syslog_hosts.values())
    r["static"] = list(static.values())
    if areas:
        r["ospf"]["enabled"] = True
        r["ospf"]["areas"] = [{"area": k, "type": v["type"], "interfaces": ", ".join(v["interfaces"]),
                               "passive": ", ".join(v["passive"]), "p2p": ", ".join(v["p2p"]), "md5_key": "",
                               "metrics": ", ".join(v.get("metrics", [])), "ranges": ", ".join(v.get("ranges", []))}
                              for k, v in areas.items()]
    r["bgp_groups"] = [dict(g, neighbors="\n".join(f"{ip} {asn}".strip() for ip, asn in g["neighbors"].items()))
                       for g in groups.values()]
    p["policy"]["prefix_lists"] = [{"name": k, "prefixes": ", ".join(v)} for k, v in plists.items()]
    p["policy"]["communities"] = [{"name": k, "members": ", ".join(v)} for k, v in pcomms.items()]
    p["policy"]["terms"] = [{"protocol": "", "prefix_list": "", "match": "exact", "route_filter": "", "community": "",
                             "action": "next", "local_pref": "", "med": "", "community_add": "", "next_hop_self": False,
                             **t} for t in terms.values()]
    if members:
        p["switch"]["members"] = [dict(m, model=model or DEFAULTS["switch"]["members"][0]["model"])
                                  for _, m in sorted(members.items())]
    for fpc, d in sorted((detected or {}).items()):
        have = next((m for m in p["switch"]["members"] if m["fpc"] == fpc), None)
        if have is None:
            have = {"fpc": fpc, "model": "", "serial": "", "role": "line-card"}
            p["switch"]["members"].append(have)
        if d.get("model") and not (fpc == 0 and model):
            have["model"] = d["model"]
        if d.get("serial") and not have.get("serial"):
            have["serial"] = d["serial"]
        if d.get("role") and len(detected) > 1:
            have["role"] = d["role"]
    p["switch"]["members"].sort(key=lambda m: m["fpc"])
    if not p["system"]["timezone"]:
        p["system"]["timezone"] = "UTC"
    if not a["ssh_root_login"]:
        a["ssh_root_login"] = "allow"   # Junos default when nothing is set
        facts.add("root_login_default")
    if sv["stp"] == "none" and "rstp" in facts:
        sv["stp"] = "rstp"
    p["name"] = s["hostname"] or "Imported switch"
    p["_facts"] = sorted(facts)
    stats = {"lines": len(lines), "imported": used, "not_imported": len(unparsed),
             "vlans": len(p["vlans"]), "port_groups": len(p["ports"]), "lags": len(p["lags"])}
    return {"project": p, "unparsed": unparsed, "notes": notes, "stats": stats}


def _iface_line(name: str, w: list[str], d: dict, irb_units: dict) -> bool:
    n = len(w)
    if w[0] == "description":
        d["description"] = w[1]
    elif w[0] == "disable":
        d["disable"] = True
    elif w[0] == "mtu":
        d["mtu"] = w[1]
    elif w[0] == "speed":
        d["speed"] = w[1]
    elif w[0] == "native-vlan-id":
        d["native"] = w[1]
    elif w[0] in ("ether-options", "gigether-options") and n > 2 and w[1] == "802.3ad":
        d["ae"] = w[2]
    elif w[0] in ("ether-options", "gigether-options") and n > 1 and w[1] == "speed":
        d["speed"] = w[2]
    elif w[0] == "aggregated-ether-options" and n > 1:
        if w[1] == "lacp" and n > 2:
            if w[2] in ("active", "passive"):
                d["lacp"] = w[2]
            elif w[2] == "periodic":
                d["lacp_fast"] = w[3] == "fast"
            elif w[2] == "system-id":
                d["system_id"] = w[3]
            else:
                return False
        elif w[1] == "minimum-links":
            d["min_links"] = w[2]
        else:
            return False
    elif w[0] == "esi" and n > 1:
        if w[1] != "all-active":
            d["esi"] = w[1]
    elif w[0] == "unit" and n > 2:
        unit, rest = w[1], w[2:]
        if name == "irb":
            u = irb_units.setdefault(unit, {"addr": [], "vga": ""})
            if rest[:3] == ["family", "inet", "address"] and len(rest) > 3:
                if rest[3] not in u["addr"]:
                    u["addr"].append(rest[3])
                if "virtual-gateway-address" in rest:
                    u["vga"] = rest[rest.index("virtual-gateway-address") + 1]
                return True
            return rest[0] in ("description",)
        if unit != "0":
            return False
        if rest[0] == "description":
            d.setdefault("description", rest[1])
        elif rest[:2] == ["family", "ethernet-switching"]:
            x = rest[2:]
            if not x:
                d.setdefault("mode", "access")
            elif x[0] == "interface-mode" or x[0] == "port-mode":
                d["mode"] = x[1]
            elif x[:2] == ["vlan", "members"]:
                d["vlans"].append(x[2])
            elif x[0] == "storm-control":
                pass
            else:
                return False
        elif rest[:2] == ["family", "inet"]:
            if len(rest) > 3 and rest[2] == "address":
                d["addr"].append(rest[3])
                if name not in ("lo0", "me0", "em0", "vme"):
                    d["mode"] = "routed"
            elif len(rest) == 2 or rest[2] in ("mtu",):
                d.setdefault("mode", "routed")
            else:
                return False
        else:
            return False
    else:
        return False
    return True


def _term(t: dict, x: list[str]) -> bool:
    """One 'policy-statement P term T ...' line (after the term name) -> the builder's term fields."""
    if x[:1] == ["from"] and len(x) > 2:
        k, v = x[1], x[2]
        if k == "protocol":
            t["protocol"] = v
        elif k == "prefix-list":
            t["prefix_list"] = v
        elif k == "prefix-list-filter" and len(x) > 3:
            t["prefix_list"], t["match"] = v, x[3]
        elif k == "route-filter":
            t["route_filter"] = ", ".join(filter(None, [t.get("route_filter", ""), " ".join(x[2:])]))
        elif k == "community":
            t["community"] = v
        else:
            return False
    elif x[:1] == ["then"] and len(x) > 1:
        k = x[1]
        if k in ("accept", "reject"):
            t["action"] = k
        elif k == "local-preference" and len(x) > 2:
            t["local_pref"] = x[2]
        elif k == "metric" and len(x) > 2:
            t["med"] = x[2]
        elif k == "community" and len(x) > 3 and x[2] in ("add", "set"):
            t["community_add"] = x[3]
        elif x[1:3] == ["next-hop", "self"]:
            t["next_hop_self"] = True
        else:
            return False
    else:
        return False
    return True


def _protocols(w, p, areas, groups, edge_ports, relay_ifaces, facts, ifs_flags) -> bool:
    sv, r = p["services"], p["routing"]
    n = len(w)
    k = w[1] if n > 1 else ""
    if k == "lldp":
        sv["lldp"] = True
    elif k == "lldp-med":
        sv["lldp_med"] = True
    elif k in ("rstp", "mstp", "vstp"):
        facts.add(k)
        sv["stp"] = "rstp" if k == "rstp" else sv["stp"]
        if k != "rstp":
            return False
        if n > 3 and w[2] == "bridge-priority":
            sv["bridge_priority"] = w[3]
        elif n > 2 and w[2] == "bpdu-block-on-edge":
            sv["bpdu_block_on_edge"] = True
        elif n > 4 and w[2] == "interface" and w[4] == "edge":
            edge_ports.add(w[3].removesuffix(".0"))
        elif n > 4 and w[2] == "interface" and w[4] in ("no-root-port", "bpdu-timeout-action"):
            ifs_flags.append((w[3].removesuffix(".0"), "root_guard" if w[4] == "no-root-port" else "loop_protect"))
        elif n > 3 and w[2] == "interface":
            pass
        elif n == 2:
            pass
        else:
            return False
    elif k == "igmp-snooping":
        sv["igmp_snooping"] = True
    elif k == "ospf":
        if n > 3 and w[2] == "reference-bandwidth":
            r["ospf"]["reference_bandwidth"] = w[3]
        elif n > 3 and w[2] == "export":
            r["ospf"]["export"] = w[3]
        elif n > 5 and w[2] == "area" and w[4] == "interface":
            a = areas.setdefault(w[3], {"type": "normal", "interfaces": [], "passive": [], "p2p": []})
            ifn = w[5].removesuffix(".0") if w[5] != "lo0.0" else "lo0"
            if ifn not in a["interfaces"]:
                a["interfaces"].append(ifn)
            if "passive" in w[6:] and ifn not in a["passive"]:
                a["passive"].append(ifn)
            if "p2p" in w[6:] and ifn not in a["p2p"]:
                a["p2p"].append(ifn)
            if "metric" in w[6:-1]:
                a.setdefault("metrics", []).append(f"{ifn} {w[w.index('metric') + 1]}")
        elif n > 5 and w[2] == "area" and w[4] == "area-range":
            areas.setdefault(w[3], {"type": "normal", "interfaces": [], "passive": [], "p2p": []}) \
                .setdefault("ranges", []).append(w[5])
        elif n > 4 and w[2] == "area" and w[4] in ("stub", "nssa"):
            areas.setdefault(w[3], {"type": "normal", "interfaces": [], "passive": [], "p2p": []})["type"] = w[4]
        else:
            return False
    elif k == "bgp" and n > 4 and w[2] == "group":
        g = groups.setdefault(w[3], {"name": w[3], "type": "external", "peer_as": "", "local_address": "", "description": "",
                                     "neighbors": {}, "import": "", "export": "", "bfd": "", "auth_key": "", "multipath": False})
        x = w[4:]
        if x[0] == "type":
            g["type"] = x[1]
        elif x[0] == "peer-as":
            g["peer_as"] = x[1]
        elif x[0] == "local-address":
            g["local_address"] = x[1]
        elif x[0] == "description":
            g["description"] = x[1]
        elif x[0] in ("import", "export"):
            g[x[0]] = ", ".join(filter(None, [g[x[0]], x[1]]))
        elif x[0] == "multipath":
            g["multipath"] = True
        elif x[0] == "bfd-liveness-detection" and len(x) > 2 and x[1] == "minimum-interval":
            g["bfd"] = x[2]
        elif x[0] == "authentication-key":
            g["auth_key"] = x[1]
        elif x[0] == "neighbor":
            g["neighbors"].setdefault(x[1], "")
            if len(x) > 3 and x[2] == "peer-as":
                g["neighbors"][x[1]] = x[3]
            elif len(x) > 2:
                return False
        else:
            return False
    else:
        return False
    return True


# --------------------------------------------------------------- checks
def recommendations(project: dict, facts: list[str] | None = None, unparsed: list[str] | None = None) -> list[dict]:
    """Best-practice advice: [{level high|medium|low, title, why, fix}]."""
    f = set(facts or project.get("_facts") or [])
    p = project
    s, a, sn, sl, sv = p["system"], p["access"], p["snmp"], p["syslog"], p["services"]
    out = []

    def rec(level, title, why, fix):
        out.append({"level": level, "title": title, "why": why, "fix": fix})

    for svc, label in (("telnet", "Telnet"), ("ftp", "FTP"), ("http", "HTTP web management"),
                       ("finger", "finger"), ("rlogin", "rlogin"), ("tftp-server", "TFTP server")):
        if svc in f:
            rec("high", f"{label} is turned on",
                "It sends passwords in clear text that anyone on the network can read.",
                f"delete system services {'web-management http' if svc == 'http' else svc} (use SSH or HTTPS instead).")
    if "ssh_v1" in f:
        rec("high", "SSH version 1 is allowed", "SSH v1 is broken and can be decrypted.", "set system services ssh protocol-version v2")
    if a.get("ssh_root_login") in ("allow", "") or "root_login_default" in f:
        rec("high", "SSH root login is not denied",
            "Attackers try root first. Personal accounts also show who changed what.",
            "Users tab: SSH root login = deny (set system services ssh root-login deny), and sign in with your own account.")
    if not a.get("root_password"):
        rec("high", "No root password", "Junos will not commit a config without one.", "Users tab: set the root password.")
    if not a.get("users"):
        rec("medium", "No personal user accounts", "Everyone would share root, so there is no record of who did what.",
            "Users tab: add a super-user account for each admin.")
    for c in sn.get("communities") or []:
        if c["name"].lower() in ("public", "private"):
            rec("high", f"SNMP community '{c['name']}'", "This is the first name every scanner tries.",
                "SNMP & logs tab: use a long random community name.")
        if c.get("access") == "read-write":
            rec("high", f"SNMP community '{c['name']}' can write", "Anyone with the community can change the switch.",
                "Set it to read-only; make changes over SSH or NETCONF.")
        if not c.get("clients"):
            rec("medium", f"SNMP community '{c['name']}' accepts any address",
                "Any host can query the switch.", "SNMP & logs tab: fill in Allowed clients (for example your monitoring server).")
    if sn.get("communities") and "snmpv3" not in f and not sn.get("v3_users"):
        rec("low", "Only SNMP v2c", "v2c sends the community in clear text.", "SNMP & logs tab: add an SNMP v3 user with SHA and AES.")
    if not s.get("ntp_servers"):
        rec("medium", "No NTP server", "Logs, certificates and troubleshooting need the right time.",
            "System tab: add one or two NTP servers.")
    if not (sl.get("hosts")):
        rec("medium", "No remote syslog server", "Logs are lost when the switch reboots or the disk fills up.",
            "SNMP & logs tab: add a syslog server.")
    if not a.get("retry_options"):
        rec("medium", "No login retry limits", "Password guessing is not slowed down.",
            "Users tab: turn on login retry options.")
    if not s.get("banner"):
        rec("low", "No login banner", "A warning banner helps if you ever need to act on unauthorised access.",
            "System tab: add a banner such as 'Authorized access only'.")
    if not (a.get("ssh_connection_limit") and a.get("ssh_rate_limit")):
        rec("low", "No SSH connection or rate limit", "Limits slow down brute-force attempts.",
            "Users tab: SSH connection limit 10, rate limit 5.")
    access_ports = [x for x in p["ports"] if x["mode"] == "access"]
    if access_ports and not sv.get("bpdu_block_on_edge"):
        rec("medium", "No BPDU protection on user ports",
            "Someone plugging in a small switch or a loop cable can take down the network.",
            "Services tab: turn on BPDU block on edge ports and mark user ports as edge.")
    if access_ports and not any(x.get("edge") for x in access_ports):
        rec("low", "User ports are not RSTP edge ports", "Edge ports come up straight away instead of waiting 30 seconds.",
            "Ports tab: tick Edge port on user port groups.")
    if access_ports and not sv.get("storm_control"):
        rec("medium", "No storm control", "A broadcast storm from one port can flood every VLAN.",
            "Services tab: turn on storm control (5% is a good start).")
    if access_ports and not any(v.get("snooping") for v in p["vlans"]):
        rec("low", "No DHCP snooping", "Stops a rogue DHCP server (often a home router someone plugged in).",
            "VLANs tab: tick DHCP snooping on user VLANs, and mark the uplink ports as DHCP trusted.")
    if any(not x.get("vlan") or x.get("vlan") in ("default", "1") for x in access_ports):
        rec("low", "Some user ports are in the default VLAN", "Unassigned devices end up on the same network as everything else.",
            "Ports tab: give every access port group a VLAN.")
    for x in p["ports"] + p["lags"]:
        if x["mode"] == "trunk" and str(x.get("vlans", "")).strip().lower() == "all":
            rec("low", f"{x.get('name') or x.get('ports')}: trunk carries all VLANs",
                "New VLANs leak onto that link automatically.", "List only the VLANs the far side needs.")
    for lag in p["lags"]:
        if lag.get("lacp") == "static":
            rec("medium", f"{lag['name']} has no LACP", "Without LACP a mis-cabled or half-dead link keeps sending traffic.",
                "LAGs tab: LACP active, and the same on the other side.")
    has_voice = any(x.get("voice") for x in access_ports) or any(v.get("voice") for v in p["vlans"])
    if has_voice and "cos" not in f and not (p.get("qos") or {}).get("enabled"):
        rec("medium", "Voice VLAN without QoS", "Calls can break up when a link is busy.",
            "Services tab: turn on QoS with the voice and video preset.")
    if has_voice and not sv.get("lldp_med"):
        rec("medium", "Voice VLAN without LLDP-MED", "Phones only learn the voice VLAN automatically through LLDP-MED.",
            "Services tab: turn on LLDP-MED.")
    if not sv.get("lldp"):
        rec("low", "LLDP is off", "LLDP shows which device is on each port and helps IP phones and access points.",
            "Services tab: turn on LLDP and LLDP-MED.")
    if sv.get("stp") == "none" and "mstp" not in f and "vstp" not in f:
        rec("medium", "No spanning tree", "A single loop cable will bring the network down.", "Services tab: spanning tree = RSTP.")
    if not s.get("hostname"):
        rec("low", "No host name", "It makes logs and prompts hard to read.", "System tab: set the host name.")
    if unparsed:
        rec("low", f"{len(unparsed)} lines were not imported",
            "The builder does not manage them. They are listed below so you can copy them back after loading the new config.",
            "Review the list, then keep them with 'load merge terminal' after the new config.")
    order = {"high": 0, "medium": 1, "low": 2}
    return sorted(out, key=lambda x: order[x["level"]])


def harden(project: dict) -> tuple[dict, list[str]]:
    """Apply the safe recommended fixes. Returns (new project, what changed)."""
    p = copy.deepcopy(project)
    a, sv, s = p["access"], p["services"], p["system"]
    done = []

    def change(cond, text, fn):
        if cond:
            fn()
            done.append(text)

    change(a.get("ssh_root_login") != "deny", "SSH root login denied", lambda: a.update(ssh_root_login="deny"))
    change(not a.get("retry_options"), "Login retry limits on", lambda: a.update(retry_options=True))
    change(not a.get("ssh_connection_limit"), "SSH connection limit 10", lambda: a.update(ssh_connection_limit="10"))
    change(not a.get("ssh_rate_limit"), "SSH rate limit 5 per minute", lambda: a.update(ssh_rate_limit="5"))
    change(not s.get("banner"), "Login banner added", lambda: s.update(banner="Authorized access only. All activity is logged."))
    change(not p["syslog"].get("log_commands"), "Commands logged", lambda: p["syslog"].update(log_commands=True))
    access = [x for x in p["ports"] if x["mode"] == "access"]
    change(sv.get("stp") == "none", "RSTP on", lambda: sv.update(stp="rstp"))
    change(bool(access) and not sv.get("bpdu_block_on_edge"), "BPDU block on edge ports",
           lambda: sv.update(bpdu_block_on_edge=True))
    change(bool(access) and not all(x.get("edge") for x in access), "User ports marked as RSTP edge ports",
           lambda: [x.update(edge=True) for x in access])
    change(bool(access) and not sv.get("storm_control"), "Storm control on user ports (5%)",
           lambda: sv.update(storm_control=True, storm_percent=sv.get("storm_percent") or "5", storm_scope="access"))
    change(not sv.get("lldp"), "LLDP and LLDP-MED on", lambda: sv.update(lldp=True, lldp_med=True))
    return p, done


def check(text: str, model: str = "", detected: dict | None = None) -> dict:
    """Import, validate and recommend. JSON-friendly."""
    res = parse(text, model, detected)
    project = res["project"]
    facts = project.pop("_facts", [])
    if not res["stats"]["lines"]:
        return {"error": "No configuration found. Paste the output of 'show configuration | display set' "
                         "or the normal curly-brace config."}
    built = build(copy.deepcopy(project))
    score = 100
    recs = recommendations(project, facts, res["unparsed"])
    score -= sum({"high": 10, "medium": 4, "low": 1}[x["level"]] for x in recs)
    score -= 10 * len(built.errors)
    hardened, fixes = harden(project)
    return {"project": project, "hardened": hardened, "fixes": fixes, "stats": res["stats"], "unparsed": res["unparsed"], "notes": res["notes"],
            "errors": built.errors, "warnings": built.warnings, "recommendations": recs,
            "score": max(0, score)}


# ------------------------------------------------------- model detection
SHOW_MODEL = re.compile(r"^\s*Model:\s*(\S+)", re.I | re.M)
SHOW_BLOCK = re.compile(r"^\s*(?:fpc|member)(\d+):\s*$", re.I | re.M)
VC_ROW = re.compile(r"^\s*(\d+)\s+\(FPC\s+\d+\)\s+(\w+)\s+(\S+)\s+(ex[\w-]+)\s+(\d+)\s+(\w+)", re.I | re.M)
PORT_RE = re.compile(r"\b(ge|xe|mge|et)-(\d{1,2})/(\d)/(\d{1,2})\b")


def model_name(raw: str) -> str:
    """'ex4300-48p' -> 'EX4300-48P' when the builder knows that model, else ''."""
    name = (raw or "").strip().upper()
    return name if models.get(name) else ""


def detect_models(text: str) -> dict:
    """Models per Virtual Chassis member, best source first.

    1. 'show virtual-chassis' output (model, serial and role of every member);
    2. 'show version' output ('Model: ex4300-48p', one block per member);
    3. a guess from the port names, PoE settings and management port.

    Returns {"members": {fpc: {model, serial, role, how}}, "unknown": [models
    the builder doesn't know]}. ``how`` says where the model came from.
    """
    text = text or ""
    out: dict[int, dict] = {}
    unknown: list[str] = []
    for m in VC_ROW.finditer(text):
        fpc, status, serial, raw, _prio, role = m.groups()
        name = model_name(raw)
        if not name:
            unknown.append(raw)
            continue
        out[int(fpc)] = {"model": name, "serial": serial if serial != "-" else "",
                         "role": "routing-engine" if role.lower().startswith(("master", "backup", "primary"))
                         else "line-card", "how": "show virtual-chassis"}
    if not out:
        heads = list(SHOW_BLOCK.finditer(text))
        blocks = ([(int(h.group(1)), text[h.end():heads[i + 1].start() if i + 1 < len(heads) else len(text)])
                   for i, h in enumerate(heads)] if heads else [(0, text)])
        for fpc, block in blocks:
            found = SHOW_MODEL.search(block)
            if not found:
                continue
            name = model_name(found.group(1))
            if name:
                out[fpc] = {"model": name, "serial": "", "role": "", "how": "show version"}
            else:
                unknown.append(found.group(1))
    if not out:
        for fpc, name in guess_members(text).items():
            out[fpc] = {"model": name, "serial": "", "role": "", "how": "port names"}
    return {"members": out, "unknown": sorted(set(unknown))}


def guess_members(text: str) -> dict[int, str]:
    """A guess per member from the port names it uses (the smallest model that has them all),
    preferring PoE models when the config sets PoE, multigigabit models for mge ports, and
    EX4100/EX4400 when the management port is em0."""
    lines = to_set_lines(text)
    joined = " ".join(lines)
    per: dict[int, set] = {}
    for kind, fpc, pic, port in PORT_RE.findall(joined):
        per.setdefault(int(fpc), set()).add(f"{kind}-0/{pic}/{port}")
    if not per:
        return {}
    poe = any(ln.startswith("poe interface") for ln in lines)
    em0 = re.search(r"\binterfaces em0\b", joined) is not None
    me0 = re.search(r"\binterfaces me0\b", joined) is not None
    out = {}
    for fpc, names in per.items():
        best = None
        for m in models.MODELS.values():
            family = m.name.split("-")[0]
            if em0 and family not in ("EX4100", "EX4400"):
                continue
            if me0 and family in ("EX4100", "EX4400"):
                continue
            own = {x["name"] for x in m.ports(0)}
            if not names <= own:
                continue
            rank = (bool(m.poe) != poe, len(own), m.name)
            if best is None or rank < best[0]:
                best = (rank, m.name)
        if best:
            out[fpc] = best[1]
    return out


def guess_model(text: str) -> str:
    """The model of member 0 from detect_models(), or ''."""
    d = detect_models(text)["members"].get(0)
    return d["model"] if d else ""
