"""Read a Cisco IOS / IOS-XE (Catalyst), Arista EOS, Cisco NX-OS or Dell OS10 running-config
into a builder project. The four are close cousins; ``parse(text, vendor)`` handles the
differences (CIDR addresses, phone trunks, management VRFs, range headers).

Paste ``show running-config``. Every top-level line or block is either read into
builder fields, counted as understood housekeeping, or listed as not converted.
"""

from __future__ import annotations

import ipaddress
import re

from .. import ios_models
from . import portmap
from .common import Reader, mask_to_prefix, net, vid_list

# Top-level lines that carry nothing the builder needs (or that it always writes itself).
QUIET = re.compile(
    r"^(?:version |!|end$|Building configuration|Current configuration|Last configuration change|"
    r"service |no service |boot|no aaa new-model|aaa new-model|ip routing$|ip ssh version|ip ssh time-out|"
    r"ip ssh authentication-retries|ip scp server|no ip http|ip http |vtp |transceiver type|"
    r"diagnostic bootup|memory free|login on-|login block-for|redundancy|mode sso|license |system mtu$|"
    r"control-plane|call-home|no ip domain lookup|no ip domain-lookup|ip forward-protocol|errdisable recovery cause|"
    r"vlan internal allocation|spanning-tree extend system-id|crypto pki|certificate|archive|"
    r"multilink bundle-name|switch \d+ priority|stack-power|stack-mac|ip dhcp snooping$|ip dhcp snooping information|"
    r"no ip source-route|ip device tracking|device-tracking|access-session|epm logging|enable password|"
    r"lldp timer|lldp holdtime|udld |port-channel load-balance|ip igmp snooping$|vstack|hw-switch|"
    r"no logging console|logging buffered|logging console|logging monitor|logging origin-id|"
    r"service-template|dot1x system-auth-control|authentication critical|mac address-table notification|"
    r"no snmp-server|snmp-server enable traps|snmp-server trap-source|snmp-server ifindex|subscriber templating|"
    r"no device-tracking|platform |exception |vrf definition Mgmt-vrf|ip tftp|ip ftp|alias |macro |"
    r"aaa authentication login default local|aaa authorization exec default local|aaa session-id|"
    r"aaa authentication dot1x default group|aaa authorization network default group|"
    r"feature |vrf instance|management ssh|management api|management console|management telnet|"
    r"aaa authentication policy|aaa accounting|aaa authorization|ssh login-attempts|ssh key|"
    r"password-attributes|logging logfile|logging vrf \S+ source|snmp-server vrf|ip routing vrf|copp |"
    r"system default|system jumbomtu|system qos|interface breakout|hardware |no ip igmp snooping|"
    r"username admin password|username admin role|ip host |cfs |nv overlay|no password strength|"
    r"rmon |no feature|ipv6 unicast-routing|terminal |queue-monitor|daemon |dcbx |"
    r"aaa accounting dot1x default|errdisable recovery|no ip dhcp snooping information|crypto key generate|"
    r"ip ssh rsa keypair-name|ip ssh source-interface|ip ssh dh |no ip http)", re.I)

IFACE_QUIET = re.compile(
    r"^(?:no ip address|no shutdown|switchport$|switchport nonegotiate|switchport trunk encapsulation|"
    r"negotiation auto|load-interval|no cdp |cdp |no keepalive|keepalive|no switchport$|ip route-cache|"
    r"no ip redirects|no ip proxy-arp|no ip unreachables|dot1x timeout|authentication host-mode|"
    r"authentication order|authentication priority|authentication periodic|authentication timer|"
    r"storm-control action|access-session|logging event|srr-queue|priority-queue|mls qos|auto qos|"
    r"service-policy|no lldp|lldp |udld |carrier-delay|ip igmp|ip dhcp snooping limit|"
    r"switchport port-security aging|switchport port-security$|power inline auto$|no mop|"
    r"spanning-tree portfast$|switchport$|no ip address dhcp|vrf member|"
    r"switchport vlan mapping enable|no lldp|lldp transmit|lldp receive|flowcontrol|error-disable|logging event|snmp trap|no snmp trap|hold-queue|bfd )", re.I)

PRIV_CLASS = {15: "super-user", 1: "read-only"}
# Cisco 'redistribute X' -> the protocol name in a routing policy term.
REDIST = {"ospf": "ospf", "bgp": "bgp", "static": "static", "connected": "direct"}
LEVELS = {"emergencies": "emergency", "alerts": "alert", "critical": "critical", "errors": "error",
          "warnings": "warning", "notifications": "notice", "informational": "info", "debugging": "any",
          "0": "emergency", "1": "alert", "2": "critical", "3": "error", "4": "warning", "5": "notice",
          "6": "info", "7": "any"}
_IFNAME = re.compile(r"^([A-Za-z-]+?)\s*(\d+(?:/\d+)*)(?:\.(\d+))?$")
_TYPE7 = "dsfd;kfoA,.iyewrkldJKDHSUBsgvca69834ncxv9873254k;fg87"


def type7(text: str) -> str:
    """Undo Cisco's reversible 'password 7' scrambling."""
    try:
        seed = int(text[:2])
        raw = bytes.fromhex(text[2:])
    except ValueError:
        return ""
    return "".join(chr(b ^ ord(_TYPE7[(seed + i) % len(_TYPE7)])) for i, b in enumerate(raw))


def _canon_port(name: str, vendor: str = "cisco") -> str | None:
    m = _IFNAME.match(name.strip())
    if not m or m.group(3):
        return None
    if vendor == "cisco":
        word = ios_models.ALIASES.get(m.group(1).lower())
        return f"{word}{m.group(2)}" if word else None
    try:
        names = portmap.expand(vendor, name.strip())
    except ValueError:
        return None
    return names[0] if len(names) == 1 else None


def _ports(name: str, vendor: str) -> list[str]:
    """An interface header that names several ports (Ethernet1-40, range ethernet1/1/1-1/1/40)."""
    text = re.sub(r"^range\s+", "", name.strip(), flags=re.I)
    text = re.sub(r"\s*-\s*", "-", text)
    try:
        return portmap.expand(vendor, text)
    except ValueError:
        return []


def _addr(kw: list[str]) -> str:
    """'ip address 10.0.0.1 255.255.255.0' or 'ip address 10.0.0.1/24'."""
    if "/" in kw[2]:
        return kw[2]
    return mask_to_prefix(kw[2], kw[3]) if len(kw) > 3 else kw[2]


def blocks(text: str) -> list[tuple[str, list[str]]]:
    """Top-level lines with their indented children; banners become one block each."""
    lines = (text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n")
    out: list[tuple[str, list[str]]] = []
    i = 0
    while i < len(lines):
        ln = lines[i].rstrip()
        i += 1
        if not ln.strip():
            continue
        m = re.match(r"^banner (motd|login|exec)\s*$", ln)
        if m:
            body = []
            while i < len(lines) and lines[i].strip() != "EOF":
                body.append(lines[i])
                i += 1
            i += 1
            out.append((f"banner {m.group(1)}", body))
            continue
        m = re.match(r"^banner (motd|login|exec)\s+(\^C|\S)(.*)$", ln)
        if m:
            delim = "^C" if m.group(2) == "^C" else m.group(2)
            body, rest = [], m.group(3)
            if delim in rest:
                body.append(rest.split(delim, 1)[0])
            else:
                if rest:
                    body.append(rest)
                while i < len(lines) and delim not in lines[i]:
                    body.append(lines[i])
                    i += 1
                if i < len(lines):
                    body.append(lines[i].split(delim, 1)[0])
                    i += 1
            out.append((f"banner {m.group(1)}", [b for b in body]))
            continue
        if ln[0] in " \t" and out and not out[-1][0].startswith("banner "):
            out[-1][1].append(ln.strip())
        elif ln[0] in " \t":
            out.append((ln.strip(), []))
        else:
            out.append((ln.strip(), []))
    return out


def parse(text: str, vendor: str = "cisco") -> dict:
    r = Reader(vendor)
    p = r.p
    s, a, sn, sl, rt, sv = p["system"], p["access"], p["snmp"], p["syslog"], p["routing"], p["services"]
    users: dict[str, dict] = {}
    ospf_nets: list[tuple[str, str]] = []
    ospf_passive: list[str] = []
    ospf_area: dict = {}
    peers: dict[str, dict] = {}
    ospf_ranges: dict[str, list[str]] = {}
    redist: list[tuple[str, str, str]] = []   # (into protocol, from protocol, route-map)
    vty_acls: list[str] = []
    bgp_nets: list[str] = []
    acls: dict[str, list[str]] = {}
    plists: dict[str, list[str]] = {}
    rmaps: list[dict] = []
    radius: dict[str, dict] = {}
    radius_named: dict = {}
    mgmt_port = ""
    for head, kids in blocks(text):
        w = head.split()
        k = w[0].lower()
        try:
            if QUIET.match(head):
                continue
            if k == "hostname" and len(w) > 1:
                s["hostname"] = w[1].strip('"')
            elif head.startswith(("ip domain name ", "ip domain-name ")):
                rest = _no_vrf(w[2:] if w[1] == "domain-name" else w[3:])
                if rest[:1] == ["vrf"]:
                    rest = rest[2:]
                s["domain"] = rest[0]
            elif head.startswith("ip name-server "):
                rest = _no_vrf(w[2:])
                if rest[:1] == ["vrf"]:
                    rest = rest[2:]
                s["name_servers"] = ", ".join(filter(None, [s["name_servers"], *rest]))
            elif head.startswith("ntp server "):
                rest = w[2:]
                if rest[:1] == ["vrf"]:
                    rest = rest[2:]
                if rest:
                    s["ntp_servers"].append({"address": rest[0], "prefer": "prefer" in rest})
            elif head.startswith("ntp source "):
                s["ntp_source"] = w[2]
            elif head.startswith("clock timezone ") and "/" in w[-1]:
                s["timezone"] = w[-1]
            elif head.startswith("clock timezone "):
                r.notes.append(f"Time zone '{' '.join(w[2:])}': Cisco uses fixed offsets; pick the matching time zone "
                               "on the Switch tab (set to UTC for now).")
            elif head.startswith("clock summer-time"):
                pass
            elif head.startswith("banner "):
                if head == "banner motd" or not s["banner"]:
                    s["banner"] = "\n".join(kids).strip()
            elif head.startswith("enable secret "):
                a["root_password"] = _secret(w[2:], r, "enable secret")
            elif k == "username" and len(w) > 2:
                u = users.setdefault(w[1], {"name": w[1].lower(), "class": "super-user", "password": ""})
                if "privilege" in w or "priv-lvl" in w:
                    lvl = int(w[w.index("privilege" if "privilege" in w else "priv-lvl") + 1])
                    u["class"] = PRIV_CLASS.get(lvl, "operator")
                if "role" in w:
                    role = w[w.index("role") + 1].lower()
                    u["class"] = ("super-user" if role in ("network-admin", "sysadmin", "netadmin", "secadmin")
                                  else "read-only" if role in ("network-operator", "netoperator") else u["class"])
                for kw in ("secret", "password"):
                    if kw in w:
                        rest = [x for x in w[w.index(kw) + 1:] if x not in ("sha512", "nopassword")]
                        u["password"] = _secret(rest, r, f"user {w[1]}")
            elif head.startswith("snmp-server community "):
                low = [x.lower() for x in w[3:]]
                acc = "read-write" if "rw" in low or "network-admin" in low else "read-only"
                rest = [x for x in w[3:] if x.lower() not in ("ro", "rw", "acl", "group", "network-operator",
                                                              "network-admin", "use-ipv4acl", "view")]
                acl = rest[0] if rest else ""
                known = next((c for c in sn["communities"] if c["name"] == w[2]), None)
                if known is None:
                    sn["communities"].append({"name": w[2], "access": acc, "clients": ""})
                elif acc == "read-write":
                    known["access"] = acc
                if acl:
                    r.notes.append(f"SNMP community {w[2]}: access list {acl} was not converted; "
                                   "add the allowed hosts on the Services tab.")
            elif head.startswith("snmp-server location "):
                sn["location"] = head.split(None, 2)[2].strip('"')
            elif head.startswith("snmp-server contact "):
                sn["contact"] = head.split(None, 2)[2].strip('"')
            elif head.startswith("snmp-server host "):
                sn["trap_targets"] = ", ".join(filter(None, [sn["trap_targets"], w[2]]))
                rest = [x for x in w[3:] if x not in ("traps", "informs", "version", "1", "2c", "3")]
                if rest and not sn["trap_community"]:
                    sn["trap_community"] = rest[0]
            elif re.match(r"^logging (?:vrf \S+ )?(?:host |server )?\d+\.\d+\.\d+\.\d+", head):
                rest = w[3:] if w[1] == "vrf" else w[1:]
                if rest[0] in ("host", "server"):
                    rest = rest[1:]
                lvl = LEVELS.get(rest[1], "info") if len(rest) > 1 and rest[1].isdigit() else \
                    {"log-emerg": "emergency", "log-alert": "alert", "log-crit": "critical", "log-err": "error",
                     "log-warning": "warning", "log-notice": "notice", "log-info": "info",
                     "log-debug": "any"}.get(rest[rest.index("severity") + 1] if "severity" in rest else "", "info")
                sl["hosts"].append({"address": rest[0], "level": lvl, "facility": "any"})
            elif head.startswith("logging trap "):
                lvl = LEVELS.get(w[2].lower(), "info")
                for h in sl["hosts"]:
                    h["level"] = lvl
                sl["_level"] = lvl
            elif head.startswith("logging source-interface "):
                r.notes.append("Syslog source interface: set the source address on the Services tab.")
            elif k == "vlan" and len(w) > 1 and re.fullmatch(r"[\d,-]+", w[1]):
                for vid in vid_list(w[1]):
                    v = r.vlan(vid)
                    for kid in kids:
                        if kid.startswith("name "):
                            r.vlan(vid, kid[5:])
                        elif kid.startswith("state ") or kid == "shutdown":
                            pass
                        else:
                            r.skip(f"vlan {vid} / {kid}")
            elif k == "switch" and len(w) > 3 and w[2] == "provision":
                r.members[int(w[1])] = _model(w[3])
            elif head.startswith("spanning-tree mode "):
                sv["stp"] = "rstp" if w[2] in ("rapid-pvst", "pvst", "mst", "mstp", "rstp") else "none"
                if w[2] in ("pvst", "mst", "mstp"):
                    r.notes.append(f"Spanning tree mode {w[2]} becomes RSTP (the builder writes RSTP).")
            elif head.startswith("spanning-tree vlan ") and "priority" in w:
                prio = int(w[w.index("priority") + 1])
                sv["bridge_priority"] = "0" if prio == 0 else f"{prio // 1024}k"
            elif head.startswith("spanning-tree portfast bpduguard default"):
                sv["bpdu_block_on_edge"] = True
            elif head.startswith("spanning-tree portfast default") or head.startswith("spanning-tree portfast edge default"):
                r.notes.append("Portfast on all access ports by default: tick Edge port on the access port groups.")
            elif head.startswith("spanning-tree"):
                r.skip(head)
            elif head == "lldp run":
                sv["lldp"] = True
            elif head.startswith("ip dhcp snooping vlan "):
                for vid in vid_list(w[4]):
                    r.vlan(vid)["snooping"] = True
            elif head.startswith("ip arp inspection vlan "):
                for vid in vid_list(w[4]):
                    r.vlan(vid)["dai"] = True
            elif head.startswith("ip default-gateway "):
                s["mgmt_gateway"] = w[2]
            elif head.startswith("management route ") and len(w) > 3:
                if w[2] in ("0.0.0.0/0", "0.0.0.0"):
                    s["mgmt_gateway"] = w[-1]
                else:
                    r.skip(head)
            elif head.startswith("vrf context "):
                for kid in kids:
                    kw = kid.split()
                    if w[2] == "management" and kid.startswith("ip route ") and kw[2] == "0.0.0.0/0":
                        s["mgmt_gateway"] = kw[3]
                    else:
                        r.skip(f"{head} / {kid}")
            elif head.startswith("ip route "):
                rest = _no_vrf(w[2:])
                vrf = ""
                if rest[:1] == ["vrf"]:
                    vrf, rest = rest[1], rest[2:]
                if rest and "/" in rest[0]:
                    rest = rest[:1] + ["/"] + rest[1:]
                if len(rest) >= 3:
                    pfx = rest[0] if rest[1] == "/" else net(rest[0], rest[1])
                    hop = rest[2]
                    if vrf and vrf.lower().startswith("mgmt"):
                        if pfx == "0.0.0.0/0":
                            s["mgmt_gateway"] = hop
                        else:
                            r.skip(head)
                    elif vrf:
                        r.skip(head)
                    elif re.match(r"^\d+\.\d+\.\d+\.\d+$", hop):
                        rt["static"].append({"prefix": pfx, "next_hop": hop})
                    else:
                        r.skip(head)
            elif k == "interface" and (w[1].lower() == "range" or re.search(r"\d-|,", " ".join(w[1:]))):
                names = _ports(" ".join(w[1:]), vendor)
                if not names:
                    r.skip(head)
                    continue
                for nm in names:
                    _interface(r, nm, kids)
            elif k == "interface" and len(w) > 1:
                mgmt_port = _interface(r, " ".join(w[1:]), kids) or mgmt_port
            elif head.startswith("router ospf "):
                for kid in kids:
                    kw = kid.split()
                    if kid.startswith("router-id "):
                        rt["router_id"] = kw[1]
                    elif kid.startswith("network ") and len(kw) >= 5:
                        ospf_nets.append((net(kw[1], _wild(kw[2])), kw[4]))
                    elif kid.startswith("passive-interface ") and kw[1] != "default":
                        ospf_passive.append(kw[1])
                    elif kid == "passive-interface default":
                        ospf_area["passive_default"] = True
                    elif kid.startswith("auto-cost reference-bandwidth "):
                        rt["ospf"]["reference_bandwidth"] = f"{kw[2]}m"
                    elif kid.startswith("area ") and len(kw) >= 5 and kw[2] == "range":
                        ospf_ranges.setdefault(kw[1], []).append(net(kw[3], kw[4]) if "/" not in kw[3] else kw[3])
                    elif kid.startswith("redistribute ") and len(kw) > 1 and kw[1] in REDIST:
                        redist.append(("ospf", REDIST[kw[1]], kw[kw.index("route-map") + 1] if "route-map" in kw else ""))
                    elif kid.startswith(("area ", "redistribute ", "default-information", "summary-address")):
                        r.later.append(f"OSPF: '{kid}' was not converted; set it up by hand on the new switch.")
                    elif kid.startswith(("log-adjacency-changes", "no passive-interface")):
                        if kid.startswith("no passive-interface"):
                            ospf_area.setdefault("active", []).append(kw[2])
                    else:
                        r.skip(f"router ospf / {kid}")
            elif head.startswith("router bgp "):
                rt["asn"] = w[2]
                for kid in kids:
                    kw = kid.split()
                    if kid.startswith("bgp router-id "):
                        rt["router_id"] = kw[2]
                    elif kid.startswith("neighbor ") and len(kw) > 3 and kw[2] == "remote-as":
                        peers.setdefault(kw[1], {})["as"] = kw[3]
                    elif kid.startswith("neighbor ") and len(kw) > 3 and kw[2] == "description":
                        peers.setdefault(kw[1], {})["description"] = kid.split(None, 3)[3]
                    elif kid.startswith("neighbor ") and len(kw) > 3 and kw[2] == "password":
                        peers.setdefault(kw[1], {})["password"] = _secret(kw[3:], r, "BGP password")
                    elif kid.startswith("neighbor ") and len(kw) > 4 and kw[2] == "route-map":
                        peers.setdefault(kw[1], {})["import" if kw[4] == "in" else "export"] = kw[3]
                    elif kid.startswith("neighbor ") and len(kw) > 3 and kw[2] == "update-source":
                        peers.setdefault(kw[1], {})["source"] = kw[3]
                    elif kid.startswith("network ") and len(kw) >= 2:
                        bgp_nets.append(net(kw[1], kw[3]) if "mask" in kw else kw[1])
                    elif kid.startswith("redistribute ") and len(kw) > 1 and kw[1] in REDIST:
                        redist.append(("bgp", REDIST[kw[1]], kw[kw.index("route-map") + 1] if "route-map" in kw else ""))
                    elif kid.startswith("redistribute "):
                        r.later.append(f"BGP: '{kid}' was not converted; add an export policy term for it by hand.")
                    elif kid.startswith(("bgp log-neighbor", "address-family", "exit-address", "no bgp default",
                                         "bgp send-community")) or \
                            (kid.startswith("neighbor ") and (kw[-1] == "activate" or "send-community" in kw)):
                        pass
                    else:
                        r.skip(f"router bgp / {kid}")
            elif k == "radius" and len(w) > 2 and w[1] == "server":
                d = radius_named.setdefault(w[2], {"address": "", "secret": "", "port": ""})
                for kid in kids:
                    kw = kid.split()
                    if kid.startswith("address ipv4 "):
                        d["address"] = kw[2]
                        if "auth-port" in kw:
                            d["port"] = kw[kw.index("auth-port") + 1]
                    elif kid.startswith("key "):
                        d["secret"] = kw[-1] if kw[1] not in ("7",) else type7(kw[2])
            elif head.startswith("radius-server host "):
                d = radius.setdefault(w[2], {"address": w[2], "secret": "", "port": ""})
                if "key" in w:
                    rest = w[w.index("key") + 1:]
                    d["secret"] = type7(rest[1]) if rest[:1] == ["7"] and len(rest) > 1 else rest[-1]
                if "auth-port" in w:
                    d["port"] = w[w.index("auth-port") + 1]
            elif k == "line":
                for kid in kids:
                    if "transport input" in kid and "telnet" in kid:
                        r.notes.append(f"{head}: Telnet was allowed; the builder writes SSH only.")
                    elif kid.startswith("access-class ") and head.startswith("line vty"):
                        vty_acls.append(kid.split()[1])
            elif head.startswith("ip access-list standard ") or re.match(r"^access-list \d+ (permit|deny) ", head):
                if w[0] == "access-list":
                    acls.setdefault(w[1], []).append(" ".join(w[2:]))
                else:
                    acls.setdefault(w[3], []).extend(kids)
                r.skip(head + (f"  (+{len(kids)} lines)" if kids else ""))
            elif head.startswith("ip prefix-list ") and len(w) > 4:
                rest = w[2:]
                name = rest[0]
                if rest[1:2] == ["seq"]:
                    rest = [name] + rest[3:]
                if rest[1:2] == ["description"]:
                    continue
                plists.setdefault(name, []).append(" ".join(rest[1:]))
            elif head.startswith("route-map ") and len(w) > 1:
                rmaps.append({"name": w[1], "action": w[2] if len(w) > 2 else "permit",
                              "seq": w[3] if len(w) > 3 else str(len(rmaps) * 10 + 10), "kids": kids})
            elif head.startswith(("aaa ", "ip access-list", "access-list", "class-map", "policy-map", "route-map",
                                  "ip prefix-list", "vrf definition", "ip vrf", "monitor session", "track ",
                                  "ip sla", "key chain", "event manager", "flow ", "username")):
                r.skip(head + (f"  (+{len(kids)} lines)" if kids else ""))
            else:
                r.skip(head + (f"  (+{len(kids)} lines)" if kids else ""))
        except (IndexError, ValueError):
            r.skip(head)
    p["access"]["users"] = list(users.values())
    sec = p["security"]
    sec["radius_servers"] = [d for d in [*radius.values(), *radius_named.values()] if d["address"]]
    if sl.get("_level"):
        for h in sl["hosts"]:
            h["level"] = sl["_level"]
    sl.pop("_level", None)
    if mgmt_port:
        s["mgmt_interface"] = ""
    _ospf(r, ospf_nets, ospf_passive, ospf_area, ospf_ranges)
    uses = [(x, x, "") for pr in peers.values() for x in (pr.get("import"), pr.get("export")) if x]
    for into, frm, rm in redist:
        if into == "bgp" and not peers:
            continue
        uses.append((rm, f"{rm or 'REDIST'}-{frm.upper()}-TO-{into.upper()}", frm))
    _policies(r, acls, plists, rmaps, uses)
    for into, frm, rm in redist:
        name = f"{rm or 'REDIST'}-{frm.upper()}-TO-{into.upper()}"
        if into == "ospf" and rt["ospf"]["enabled"]:
            rt["ospf"]["export"] = ", ".join(filter(None, [rt["ospf"]["export"], name]))
        elif into == "bgp":
            r.redist_bgp.append(name)
    _bgp(r, peers, bgp_nets)
    for acl in dict.fromkeys(vty_acls):
        good, bad = _acl_prefixes(acls.get(acl, []))
        if good:
            a["ssh_from"] = ", ".join(dict.fromkeys(filter(None, [*a.get("ssh_from", "").split(", "), *good])))
            r.notes.append(f"SSH access list {acl} on the vty lines became 'SSH only from {a['ssh_from']}' "
                           "(a filter on the loopback on Juniper). Check that your own address is in it.")
        for b in bad:
            r.later.append(f"Access list {acl}: '{b}' was not converted.")
        if acl not in acls:
            r.later.append(f"The vty lines use access list {acl}, but it is not in the config.")
    if s["mgmt_gateway"] and not s["mgmt_address"] and not any(x["prefix"] == "0.0.0.0/0" for x in rt["static"]):
        # 'ip default-gateway' with no management port: the switch's own default route.
        rt["static"].append({"prefix": "0.0.0.0/0", "next_hop": s["mgmt_gateway"]})
        s["mgmt_gateway"] = ""
        r.notes.append("'ip default-gateway' became a static default route, since there is no management port "
                       "address. Check it on the Routing tab.")
    done = r.acls_used | {x for x in vty_acls if x in acls}
    if done:
        # Converted access lists are not "not read"; lines they could not carry are listed in the notes.
        r.unparsed = [x for x in r.unparsed if not (
            (x.split()[:3] == ["ip", "access-list", "standard"] and len(x.split()) > 3 and x.split()[3] in done)
            or (x.split()[:1] == ["access-list"] and len(x.split()) > 1 and x.split()[1] in done))]
    r.notes.extend(r.later)
    return {"project": r.project(), "unparsed": r.unparsed, "notes": r.notes}


def _wild(w: str) -> str:
    """OSPF wildcard (0.0.0.255) -> mask."""
    try:
        return ".".join(str(255 - int(x)) for x in w.split("."))
    except ValueError:
        return w


def _model(raw: str) -> str:
    want = raw.lower()
    for m in ios_models.MODELS.values():
        if m.provision == want or m.name.lower() == want:
            return m.name
    return raw.upper()


def _secret(rest: list[str], r: Reader, label: str) -> str:
    """'0 text' / '7 xxx' -> plain text; '5|8|9 $..' -> the hash (the target may not take it)."""
    if not rest:
        return ""
    if rest[0] == "0" and len(rest) > 1:
        return rest[1]
    if rest[0] == "7" and len(rest) > 1:
        return type7(rest[1])
    if rest[0] in ("5", "8", "9") and len(rest) > 1:
        return rest[1]
    return rest[0]


def _interface(r: Reader, name: str, kids: list[str]) -> str:
    """Read one interface block. Returns the name if it is the management port."""
    m = _IFNAME.match(name)
    word = (m.group(1) if m else name).lower()
    if word in ("vlan",) and m:
        vid = int(m.group(2))
        svi = r.svis.setdefault(vid, {"addr": [], "relay": False})
        for kid in kids:
            kw = kid.split()
            if kid.startswith("ip address ") and len(kw) >= 3 and kw[2] != "dhcp":
                svi["addr"].append(_addr(kw))
            elif kid.startswith("ip ospf "):
                _if_ospf(r, f"Vlan{vid}", kw)
            elif kid.startswith(("ip helper-address ", "ip dhcp relay address ")):
                svi["relay"] = True
                r.relay.append(kw[-1])
            elif kid.startswith("description "):
                desc = kid.split(None, 1)[1].strip('"')
                if r.vendor == "dell" and not r.vlan(vid)["name"]:
                    r.vlan(vid, desc)   # OS10 has no VLAN names; the builder writes the name as the description
                else:
                    r.vlan(vid)["description"] = desc
            elif kid == "shutdown" or IFACE_QUIET.match(kid):
                pass
            elif kid.startswith("vrf forwarding "):
                r.skip(f"interface {name} / {kid}")
            else:
                r.skip(f"interface {name} / {kid}")
        return ""
    if word in ("loopback",) and m:
        for kid in kids:
            kw = kid.split()
            if kid.startswith("ip address ") and len(kw) >= 3 and not r.p["routing"]["loopback"]:
                r.p["routing"]["loopback"] = _addr(kw)
            elif kid.startswith("ip ospf "):
                _if_ospf(r, "Loopback0", kw)
            elif not IFACE_QUIET.match(kid) and not kid.startswith("description"):
                r.skip(f"interface {name} / {kid}")
        return ""
    if word in ("port-channel", "po") and m:
        d = r.lag(int(m.group(2)))
        _port_kids(r, name, d, kids)
        return ""
    if re.match(r"^(?:management\d|mgmt\d|mgmt1/1/1)$", name.strip(), re.I) or \
            re.match(r"^(GigabitEthernet0/0|FastEthernet0|Gi0/0|Fa0)$", name.strip()) or \
            any(re.match(r"^vrf (?:forwarding|member) (?:mgmt|management)", k, re.I) for k in kids):
        for kid in kids:
            kw = kid.split()
            if kid.startswith("ip address ") and len(kw) >= 3 and kw[2] != "dhcp":
                r.p["system"]["mgmt_address"] = _addr(kw)
            if kid.startswith(("vrf forwarding", "vrf member", "vrf ")):
                r.p["system"]["mgmt_vrf"] = True
        return name
    canon = _canon_port(name, r.vendor)
    if canon is None:
        r.skip(f"interface {name}" + (f"  (+{len(kids)} lines)" if kids else ""))
        return ""
    d = r.iface(canon)
    _port_kids(r, name, d, kids)
    return ""


def _port_kids(r: Reader, name: str, d: dict, kids: list[str]) -> None:
    d["touched"] = d.get("touched") or bool(kids)
    for kid in kids:
        kw = kid.split()
        low = kid.lower()
        if low.startswith("description "):
            d["description"] = kid.split(None, 1)[1].strip('"')
        elif low == "shutdown":
            d["shutdown"] = True
        elif low == "switchport mode trunk phone":
            d["mode"], d["phone"] = "access", True     # EOS phone trunk: data VLAN untagged, phone VLAN tagged
        elif low.startswith("switchport phone vlan ") and kw[3].isdigit():
            d["voice"] = int(kw[3])
            r.vlan(int(kw[3]))
        elif low.startswith("switchport phone trunk"):
            pass
        elif low.startswith("switchport mode "):
            d["mode"] = {"access": "access", "trunk": "trunk"}.get(kw[2], d.get("mode", ""))
            if kw[2] not in ("access", "trunk"):
                r.skip(f"interface {name} / {kid}")
        elif low.startswith("switchport access vlan "):
            d["vlan"] = int(kw[3])
            r.vlan(int(kw[3]))
        elif low.startswith("switchport voice vlan ") and kw[3].isdigit():
            d["voice"] = int(kw[3])
            r.vlan(int(kw[3]))
        elif low.startswith("switchport trunk allowed vlan "):
            rest = kw[4:]
            if rest[:1] == ["add"]:
                d["allowed"] = (d.get("allowed") or []) + vid_list(rest[1])
            elif rest[:1] == ["all"]:
                d["allowed"] = None
            elif rest[:1] == ["none"]:
                d["allowed"] = []
            else:
                d["allowed"] = vid_list(rest[0])
            for vid in d["allowed"] or []:
                r.vlan(vid)
        elif low.startswith("switchport trunk native vlan "):
            d["native"] = int(kw[4])
        elif low.startswith(("switchport vlan mapping ", "switchport vlan translation ")) and len(kw) > 4 and kw[3].isdigit():
            d["vlan_translate"] = ", ".join(filter(None, [d.get("vlan_translate", ""), f"{kw[3]}>{kw[4]}"]))
        elif (low.startswith("spanning-tree portfast") and "disable" not in low) or \
                low in ("spanning-tree port type edge", "spanning-tree port type edge trunk"):
            d["edge"] = True
        elif low.startswith("spanning-tree bpduguard enable"):
            d["edge"] = True
        elif low == "spanning-tree guard root":
            d["root_guard"] = True
        elif low == "spanning-tree guard loop":
            d["loop_protect"] = True
        elif low.startswith("channel-group ") and len(kw) >= 2:
            d["lag"] = int(kw[1])
            mode = kw[3] if len(kw) > 3 else "on"
            d["lacp"] = {"active": "active", "passive": "passive"}.get(mode, "static")
            r.lag(int(kw[1]))
        elif low in ("lacp rate fast", "lacp timer fast"):
            d["lacp_fast"] = True
        elif low.startswith("port-channel min-links ") or low.startswith("lacp min-bundle "):
            d["min_links"] = kw[-1]
        elif low.startswith("ip ospf "):
            _if_ospf(r, _canon_port(name, r.vendor) or name, kw)
        elif low == "no switchport":
            d["no_switchport"] = True   # routed only with an address (OS10 LAG members say it too)
        elif low.startswith("ip address ") and len(kw) >= 3:
            d.setdefault("addr", []).append(_addr(kw))
            d["mode"] = "routed"
        elif low in ("power inline never", "poe disabled", "no poe", "poe disable"):
            d["poe"] = "off"
        elif low.startswith("poe priority ") and kw[2] in ("high", "low", "critical"):
            d["poe"] = "high" if kw[2] in ("high", "critical") else "low"
        elif low.startswith("poe limit ") and kw[2].replace(".", "").isdigit():
            d["poe_max"] = kw[2]
        elif low.startswith("power inline port priority "):
            d["poe"] = kw[4]
        elif low.startswith("power inline auto max ") or low.startswith("power inline static max "):
            d["poe_max"] = str(round(int(kw[4]) / 1000))
        elif low.startswith("switchport port-security mac-address maximum "):
            d["mac_limit"] = kw[4]
        elif low.startswith("switchport port-security maximum "):
            d["mac_limit"] = kw[3]
        elif low == "switchport port-security mac-address sticky":
            d["sticky"] = True
        elif low.startswith("switchport port-security violation "):
            d["mac_action"] = {"shutdown": "shutdown", "restrict": "drop-and-log", "protect": "drop"}.get(kw[3], "drop")
        elif low in ("authentication port-control auto", "access-session port-control auto"):
            d["dot1x"] = d.get("dot1x") or "dot1x"
        elif low == "dot1x pae authenticator":
            d["dot1x"] = "dot1x-mab" if d.get("mab") else "dot1x"
            d["has_dot1x"] = True
        elif low == "mab":
            d["mab"] = True
            d["dot1x"] = "dot1x-mab" if d.get("has_dot1x") else "mab"
        elif low == "ip dhcp snooping trust":
            d["dhcp_trusted"] = True
        elif low.startswith("mtu "):
            d["mtu"] = kw[1]
        elif low.startswith("speed ") and kw[1] != "auto":
            d["speed"] = {"10": "10m", "100": "100m", "1000": "1g", "2500": "2.5g", "5000": "5g",
                          "10000": "10g", "25000": "25g", "40000": "40g", "100000": "100g"}.get(kw[1], "")
        elif low.startswith("storm-control "):
            r.p["services"]["storm_control"] = True
        elif low.startswith("duplex "):
            if kw[1] != "auto":
                r.skip(f"interface {name} / {kid}")
        elif IFACE_QUIET.match(low):
            pass
        else:
            r.skip(f"interface {name} / {kid}")
    if d.get("mab") and d.get("has_dot1x"):
        d["dot1x"] = "dot1x-mab"
    if d.get("phone") and d.get("native"):
        d["vlan"] = d.pop("native")
    if d.get("mode") == "trunk" and d.get("vlan") and not d.get("native"):
        d["native"] = d.pop("vlan")     # OS10: 'switchport access vlan' on a trunk is its untagged VLAN
    for k in ("mab", "has_dot1x", "phone", "no_switchport"):
        d.pop(k, None)


def _if_ospf(r: Reader, ifname: str, kw: list[str]) -> None:
    """Interface lines: 'ip ospf 1 area 0', 'ip ospf network point-to-point', 'ip ospf cost 10'."""
    if len(kw) >= 5 and kw[3] == "area":
        r.ospf_if[ifname] = kw[4]
    elif kw[2:4] == ["network", "point-to-point"]:
        r.ospf_p2p.add(ifname)
    elif kw[2] == "cost" and len(kw) > 3 and kw[3].isdigit():
        r.ospf_cost[ifname] = kw[3]
    elif kw[2] in ("cost", "authentication", "message-digest-key", "hello-interval", "dead-interval", "priority"):
        r.later.append(f"OSPF on {ifname}: '{' '.join(kw)}' was not converted.")
    else:
        r.skip(f"interface {ifname} / {' '.join(kw)}")


def _area_id(a: str) -> str:
    return a if "." in a else (str(ipaddress.IPv4Address(int(a))) if a.isdigit() else a)


def _ospf(r: Reader, nets, passive, opts, ranges=None) -> None:
    if not nets and not r.ospf_if:
        return
    rt = r.p["routing"]
    rt["ospf"]["enabled"] = True
    areas: dict[str, dict] = {}
    cands = [(f"Vlan{vid}", s["addr"]) for vid, s in r.svis.items()]
    cands += [(n, d.get("addr", [])) for n, d in r.ifs.items() if d.get("addr")]
    if rt["loopback"]:
        cands.append(("Loopback0", [rt["loopback"]]))
    for pfx, area in nets:
        try:
            network = ipaddress.IPv4Network(pfx, strict=False)
        except ValueError:
            continue
        a = areas.setdefault(_area_id(area), {"area": _area_id(area), "type": "normal", "interfaces": [], "passive": [],
                                              "p2p": [], "md5_key": ""})
        for ifname, addrs in cands:
            for ad in addrs:
                try:
                    if ipaddress.IPv4Interface(ad).ip in network and ifname not in a["interfaces"]:
                        a["interfaces"].append(ifname)
                except ValueError:
                    pass
    for ifname, area in r.ospf_if.items():
        a = areas.setdefault(_area_id(area), {"area": _area_id(area), "type": "normal", "interfaces": [], "passive": [],
                                              "p2p": [], "md5_key": ""})
        if ifname not in a["interfaces"]:
            a["interfaces"].append(ifname)
    canon_passive = {_canon_port(x, r.vendor) or x.replace("Vlan ", "Vlan") for x in passive}
    for a in areas.values():
        if opts.get("passive_default"):
            active = {_canon_port(x, r.vendor) or x for x in opts.get("active", [])}
            pas = [i for i in a["interfaces"] if i not in active]
        else:
            pas = [i for i in a["interfaces"] if i in canon_passive]
        a["passive"] = ", ".join(pas)
        a["interfaces"] = ", ".join(i for i in a["interfaces"] if i not in pas)
        a["p2p"] = ", ".join(i for i in a["interfaces"].split(", ") if i in r.ospf_p2p)
        every = [i for i in (a["interfaces"] + ", " + a["passive"]).split(", ") if i]
        a["metrics"] = ", ".join(f"{i} {r.ospf_cost[i]}" for i in every if i in r.ospf_cost)
        a["ranges"] = ""
    for area, pfx in (ranges or {}).items():
        a = areas.setdefault(_area_id(area), {"area": _area_id(area), "type": "normal", "interfaces": "",
                                              "passive": "", "p2p": "", "md5_key": "", "metrics": "", "ranges": ""})
        a["ranges"] = ", ".join(pfx)
    rt["ospf"]["areas"] = list(areas.values())


def _no_vrf(rest: list[str]) -> list[str]:
    """Drop NX-OS 'use-vrf NAME' from a line's words."""
    if "use-vrf" in rest:
        i = rest.index("use-vrf")
        rest = rest[:i] + rest[i + 2:]
    return rest


def _acl_prefixes(lines: list[str]) -> tuple[list[str], list[str]]:
    """Standard ACL lines -> (permitted prefixes, lines that could not become a prefix)."""
    out, bad = [], []
    for ln in lines:
        kw = ln.split()
        if kw and kw[0].isdigit():
            kw = kw[1:]
        if not kw or kw[0] in ("remark",):
            continue
        if kw[0] == "deny":
            if kw[1:2] != ["any"]:
                bad.append(ln)
            continue
        if kw[0] != "permit" or len(kw) < 2:
            bad.append(ln)
        elif kw[1] == "any":
            out.append("0.0.0.0/0")
        elif kw[1] == "host" and len(kw) > 2:
            out.append(f"{kw[2]}/32")
        elif len(kw) > 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", kw[2]):
            out.append(net(kw[1], _wild(kw[2])))
        else:
            out.append(f"{kw[1]}/32" if "/" not in kw[1] else kw[1])
    return out, bad


def _policies(r: Reader, acls: dict, plists: dict, rmaps: list, uses: list) -> None:
    """Prefix lists, and the route-maps that BGP neighbors and redistribution use -> routing policies.

    ``uses`` holds (route-map, policy name, protocol): a neighbor's route-map keeps its name; a
    'redistribute ospf route-map X' becomes its own policy that only looks at OSPF routes.
    """
    pol = r.p["policy"]
    made: dict[str, list[str]] = {}
    for name, entries in plists.items():
        good = []
        for e in entries:
            kw = e.split()
            if kw[0] == "deny" and kw[1] == "0.0.0.0/0" and kw[2:] == ["le", "32"]:
                continue  # the deny-everything line at the end: Junos policies end the same way below
            if kw[0] == "permit" and len(kw) == 2:
                good.append(kw[1])
            else:
                r.later.append(f"Prefix list {name}: '{e}' was not converted (only plain permit lines are).")
        if good:
            made[name] = good
    used_acls: set[str] = set()
    terms: list[dict] = []
    blank = {"policy": "", "term": "", "protocol": "", "prefix_list": "", "match": "exact", "route_filter": "",
             "community": "", "action": "accept", "local_pref": "", "med": "", "community_add": "",
             "next_hop_self": False}
    seen: set[str] = set()
    for rm_name, policy, proto in uses:
        if policy in seen:
            continue
        seen.add(policy)
        entries = [rm for rm in rmaps if rm["name"] == rm_name] if rm_name else []
        if rm_name and not entries:
            r.later.append(f"Route-map {rm_name} is used but not in the config; {policy} accepts everything.")
        if not entries:
            terms.append({**blank, "policy": policy, "term": "all", "protocol": proto})
            continue
        for rm in entries:
            t = {**blank, "policy": policy, "term": f"seq-{rm['seq']}", "protocol": proto,
                 "action": "accept" if rm["action"] == "permit" else "reject"}
            for kid in rm["kids"]:
                kw = kid.split()
                if kid.startswith("match ip address prefix-list "):
                    t["prefix_list"] = kw[4]
                elif kid.startswith("match ip address ") and len(kw) > 3:
                    t["prefix_list"] = kw[3]
                    used_acls.add(kw[3])
                elif kid.startswith("set local-preference "):
                    t["local_pref"] = kw[2]
                elif kid.startswith("set metric ") and kw[2].isdigit():
                    t["med"] = kw[2]
                elif kid.startswith("set community "):
                    vals = [x for x in kw[2:] if x != "additive"]
                    cname = f"{rm['name']}-{rm['seq']}"
                    if not any(c["name"] == cname for c in pol["communities"]):
                        pol["communities"].append({"name": cname, "members": ", ".join(vals)})
                    t["community_add"] = cname
                    if "additive" not in kw and policy == rm_name:
                        r.later.append(f"Route-map {rm['name']} {rm['seq']}: 'set community' replaced the "
                                       "communities on Cisco; the new config adds them instead. Check it if that matters.")
                elif kid.startswith("set ip next-hop self") or kid == "set ip next-hop peer-address":
                    t["next_hop_self"] = True
                else:
                    r.later.append(f"Route-map {rm['name']} {rm['seq']}: '{kid}' was not converted.")
            terms.append(t)
        # Cisco route-maps deny whatever no entry matched. A redistribution policy only says so for its
        # own protocol, so other routes still reach the next policy.
        terms.append({**blank, "policy": policy, "term": "deny-rest", "protocol": proto, "action": "reject"})
    for rm in rmaps:
        if rm["name"] not in {u[0] for u in uses}:
            r.skip(f"route-map {rm['name']} {rm['action']} {rm['seq']}  (+{len(rm['kids'])} lines, not used)")
    for name in sorted(used_acls):
        good, bad = _acl_prefixes(acls.get(name, []))
        if good:
            made.setdefault(name, good)
        for b in bad:
            r.later.append(f"Access list {name}: '{b}' was not converted.")
        if name not in acls:
            r.later.append(f"Route-maps use access list {name}, but it is not in the config.")
    r.acls_used |= used_acls
    for name in {t["prefix_list"] for t in terms if t["prefix_list"]} - set(made):
        for t in terms:
            if t["prefix_list"] == name:
                t["prefix_list"] = ""
                r.later.append(f"Policy {t['policy']}: prefix list {name} has no entries the builder can write, "
                               "so that term now matches every route. Check it.")
    pol["prefix_lists"] = [{"name": k, "prefixes": ", ".join(v)} for k, v in made.items()]
    pol["terms"] = terms


def _bgp(r: Reader, peers: dict, nets: list[str]) -> None:
    rt = r.p["routing"]
    if not peers:
        return
    groups: dict[tuple, dict] = {}
    for ip, pr in peers.items():
        typ = "internal" if pr.get("as") == rt["asn"] else "external"
        key = (typ, pr.get("import", ""), pr.get("export", ""), pr.get("password", ""), pr.get("source", ""))
        g = groups.get(key)
        if g is None:
            base = re.sub(r"[^A-Za-z0-9_-]+", "-", pr.get("description", "")).strip("-")[:30]
            name = base or ("IBGP" if typ == "internal" else "EBGP")
            if any(x["name"] == name for x in groups.values()):
                name = f"{name}-{len(groups) + 1}"
            g = groups[key] = {"name": name, "type": typ, "peer_as": "", "local_address": "", "neighbors": [],
                               "import": pr.get("import", ""), "export": pr.get("export", ""), "multipath": False,
                               "bfd": "", "auth_key": pr.get("password", ""), "description": pr.get("description", "")}
            if pr.get("source"):
                r.later.append(f"BGP group {name}: update-source {pr['source']} was not converted; set the local "
                               "address on the Routing tab.")
        g["neighbors"].append(f"{ip} {pr.get('as', '')}".strip() if typ == "external" else ip)
    pol = r.p["policy"]
    if nets:
        # Cisco announces 'network' prefixes that are in the routing table; Junos announces what the export
        # policy accepts. A group with its own export route-map already decides; others get BGP-NETWORKS.
        pol["terms"].append({"policy": "BGP-NETWORKS", "term": "networks", "protocol": "", "prefix_list": "",
                             "match": "exact", "route_filter": ", ".join(f"{n} exact" for n in nets),
                             "community": "", "action": "accept", "local_pref": "", "med": "",
                             "community_add": "", "next_hop_self": False})
    for g in groups.values():
        out = [*r.redist_bgp]
        if nets and not g["export"]:
            out.append("BGP-NETWORKS")
        elif nets:
            plist = {t["prefix_list"] for t in pol["terms"] if t["policy"] == g["export"] and t["action"] == "accept"}
            have = {p for pl in pol["prefix_lists"] if pl["name"] in plist for p in pl["prefixes"].split(", ")}
            missing = [n for n in nets if n not in have]
            if missing:
                r.later.append(f"BGP group {g['name']}: 'network' {', '.join(missing)} is not matched by export "
                               f"policy {g['export']}, so Junos won't announce it. Add it to that policy if needed.")
        if r.redist_bgp and g["export"]:
            r.later.append(f"BGP group {g['name']}: redistributed routes go through {', '.join(r.redist_bgp)} before "
                           f"{g['export']}. On Cisco the neighbor's route-map also filtered them; check the order.")
        g["export"] = ", ".join(filter(None, [*out, g["export"]]))
    rt["bgp_groups"] = [dict(g, neighbors="\n".join(g["neighbors"])) for g in groups.values()]
