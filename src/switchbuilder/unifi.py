"""Turn a project into a UniFi Network settings sheet.

UniFi switches have no config to paste: they are set up in the UniFi Network
application. So this writes the settings to make there, in order: networks
(VLANs) first, then Ethernet port profiles, then the switch's own ports in the
Port Manager. Menu names follow UniFi Network 9 and move a little between versions.
"""

from __future__ import annotations

import re

from . import ports as P
from . import unifi_models as UM, vendors
from .eos import _dedupe
from .generator import HOSTNAME, NAME, USERNAME, Ctx, Result, _addresses, _ip, _list, _s, _truthy, _vlan_name, normalize

VENDOR = vendors.VENDORS["unifi"]
SPEEDS = {"10m": "10 Mbps FDX", "100m": "100 Mbps FDX", "1g": "1 Gbps FDX", "2.5g": "2.5 Gbps FDX",
          "10g": "10 Gbps FDX", "25g": "25 Gbps FDX"}
DOT1X = {"dot1x": "Auto (802.1X)", "dot1x-mab": "Auto (802.1X), with MAC-based fallback", "mab": "MAC-Based"}


class UCtx(Ctx):
    def __init__(self, project: dict):
        super().__init__(project)
        self.umodels: list = []
        self.layer3 = False
        self.site: list[str] = []
        self.device: list[str] = []
        self.auth: list[str] = []
        self.globals: list[str] = []
        self.networks: list[list[str]] = []
        self.profiles: dict[str, list[str]] = {}
        self.portrows: list[tuple[str, str]] = []   # (ports, what)
        self.lagrows: list[tuple[str, str]] = []
        self.routes: list[str] = []
        self.radius: list[str] = []
        self.svis: dict[int, list] = {}
        self.dot1x = False
        self.jumbo = False
        self.snooping = False


def _vid(ctx: UCtx, name: str) -> int:
    return int(ctx.vlan_by_name[name]["id"])


def _runs(names: list[str]) -> str:
    nums = sorted(int(n) for n in names)
    out, start = [], None
    for i, v in enumerate(nums):
        if start is None:
            start = v
        if i + 1 == len(nums) or nums[i + 1] != v + 1:
            out.append(str(start) if start == v else f"{start}-{v}")
            start = None
    return ", ".join(out)


# ------------------------------------------------------------------ sections
def _switch(ctx: UCtx) -> None:
    members = ctx.p["switch"].get("members") or []
    if len(members) > 1:
        ctx.error("Switch", "UniFi switches don't stack. Use one switch per project.")
    for m in members[:1]:
        ctx.at("switch.members", m)
        model = UM.get(m.get("model", ""))
        if model:
            ctx.umodels.append(model)
            ctx.layer3 = model.layer3
            for port in model.ports:
                ctx.known[port["name"]] = port
        elif m.get("model") != UM.CUSTOM:
            ctx.error("Switch", f"Unknown UniFi model '{m.get('model')}'. Pick one from the list or Custom.", "model")
        else:
            ctx.layer3 = True
    ctx.at("", None)
    try:
        for name in P.expand_named(ctx.p["switch"].get("custom_ports", ""), UM.ALIASES):
            ctx.known.setdefault(name, {"name": name, "kind": "access", "speed": "", "poe": False})
    except ValueError as exc:
        ctx.error("Switch", f"Custom ports: {exc}")


def _system(ctx: UCtx) -> None:
    s = ctx.p["system"]
    host = _s(s.get("hostname"))
    if not host:
        ctx.error("System", "Host name is required.", "system.hostname")
    elif not HOSTNAME.match(host):
        ctx.error("System", f"Host name '{host}' may only use letters, digits and hyphens.", "system.hostname")
    else:
        ctx.device.append(f"Name: {host}")
    tz = _s(s.get("timezone"))
    if tz:
        ctx.site.append(f"Time zone: {tz}")
    ntp = [_s(n.get("address")) for n in s.get("ntp_servers") or [] if _s(n.get("address"))]
    if ntp:
        ctx.site.append("NTP servers: " + ", ".join(ntp[:4]))
        if len(ntp) > 4:
            ctx.warn("System", "UniFi takes four NTP servers; the rest are left out.")
    else:
        ctx.warn("System", "No NTP server: UniFi devices then use the UniFi defaults.")
    if _s(s.get("domain")):
        ctx.site.append(f"Domain name: {_s(s.get('domain'))}")
    addrs = _addresses(ctx, "System", "Switch address", s.get("mgmt_address"))
    v4 = [a for a in addrs if a.version == 4]
    dns = [ns for ns in _list(s.get("name_servers")) if _ip(ctx, "System", "DNS server", ns)]
    gw = _s(s.get("mgmt_gateway"))
    if v4:
        a = v4[0]
        ctx.device += ["IP configuration: Static", f"IP address: {a.ip}", f"Subnet mask: {a.netmask}"]
        if gw and (gw_ip := _ip(ctx, "System", "Gateway", gw)):
            if gw_ip not in a.network:
                ctx.warn("System", f"Gateway {gw} is not in the switch's subnet {a.network}.")
            ctx.device.append(f"Gateway: {gw}")
        if dns:
            ctx.device.append("DNS: " + ", ".join(dns[:2]))
        if _s(s.get("mgmt_interface")):
            ctx.warn("System", "UniFi has no separate management port; the address is on the management VLAN "
                               "(the network it belongs to).")
    else:
        ctx.device.append("IP configuration: DHCP (on the management network)")
        if gw:
            ctx.warn("System", "Gateway is set but the switch has no static address.")
    if _truthy(s.get("mgmt_vrf")):
        ctx.warn("System", "UniFi has no management VRF.")
    if (s.get("banner") or "").strip():
        ctx.warn("System", "UniFi switches have no login banner.")


def _access(ctx: UCtx) -> None:
    a = ctx.p["access"]
    users = [u for u in a.get("users") or [] if _s(u.get("name")) and u.get("class") != "unauthorized"]
    supers = [u for u in users if u.get("class") == "super-user"]
    for u in users:
        ctx.at("access.users", u)
        if not USERNAME.match(_s(u.get("name"))):
            ctx.error("Access", f"User '{_s(u.get('name'))}': use lower-case letters, digits, '.', '_' or '-'.", "name")
    ctx.at("", None)
    first = supers[0] if supers else None
    pw = _s(a.get("root_password")) or (_s(first.get("password")) if first else "")
    if pw.startswith("$"):
        ctx.error("Access", "This password was hashed for another vendor; type it again for UniFi.", "access.root_password")
        pw = ""
    if first or pw:
        ctx.auth.append(f"Username: {_s(first.get('name')) if first else 'admin'}")
        if pw:
            if len(pw) < 8:
                ctx.error("Access", "The device password needs at least 8 characters.", "access.root_password")
            ctx.auth.append("Password: (the password from the Users tab; type it in the app)")
        keys = [k.strip() for u in users for k in (u.get("ssh_keys") or "").splitlines() if k.strip()]
        for k in keys:
            ctx.auth.append(f"SSH key: {k[:40]}…" if len(k) > 40 else f"SSH key: {k}")
    if len(users) > 1 or (users and not supers):
        ctx.warn("Access", "UniFi devices have one SSH login, written from the first super-user. People who manage the "
                           "network get their own UniFi OS accounts (Admins & Users), with full or view-only roles.")
    if not (first or pw):
        ctx.warn("Access", "No device password: UniFi makes a random one. Set your own to keep SSH access for support.")
    if _truthy(a.get("netconf")) or _truthy(a.get("web")):
        ctx.warn("Access", "UniFi switches are managed by the UniFi app only (no NETCONF or web UI on the switch).")


def _snmp_syslog(ctx: UCtx) -> None:
    s = ctx.p["snmp"]
    comms = [c for c in s.get("communities") or [] if _s(c.get("name"))]
    if comms:
        ctx.site.append(f"SNMP: on, v1/v2c community {_s(comms[0].get('name'))}")
        if len(comms) > 1:
            ctx.warn("SNMP", "UniFi takes one SNMP community; the first one is used.")
        if any(_s(c.get("clients")) for c in comms):
            ctx.warn("SNMP", "UniFi SNMP has no list of allowed clients; filter it on your firewall.")
        if any(c.get("access") == "read-write" for c in comms):
            ctx.warn("SNMP", "UniFi SNMP is read-only.")
    if s.get("v3_users"):
        u = s["v3_users"][0]
        ctx.site.append(f"SNMPv3: on, user {_s(u.get('name'))} (type the password in the app)")
    if _s(s.get("trap_targets")):
        ctx.warn("SNMP", "UniFi switches don't send SNMP traps; use UniFi notifications or syslog.")
    hosts = [h for h in ctx.p["syslog"].get("hosts") or [] if _s(h.get("address"))]
    if hosts:
        h = hosts[0]
        if _ip(ctx, "Logging", "Syslog server", _s(h.get("address"))):
            ctx.site.append(f"Remote syslog: {_s(h.get('address'))} port {_s(h.get('port')) or '514'}")
        if len(hosts) > 1:
            ctx.warn("Logging", "UniFi sends syslog to one server; the first one is used.")


def _vlans(ctx: UCtx) -> None:
    vlans = [v for v in ctx.p["vlans"] if _s(v.get("name")) or _s(v.get("id"))]
    if not vlans:
        ctx.warn("VLANs", "No VLANs yet: every port stays on the Default network.")
    for v in vlans:
        ctx.at("vlans", v)
        name, vid = _s(v.get("name")), _s(v.get("id"))
        if not NAME.match(name):
            ctx.error("VLANs", f"VLAN name '{name}' must start with a letter and use letters, digits, '-', '_' or '.'.", "name")
            continue
        if not vid.isdigit() or not 2 <= int(vid) <= 4009:
            ctx.error("VLANs", f"VLAN {name}: ID must be 2-4009 in UniFi (1 is the Default network).", "id")
            continue
        n = int(vid)
        if name.lower() in {x.lower() for x in ctx.vlan_by_name}:
            ctx.error("VLANs", f"VLAN name '{name}' is used twice.", "name")
            continue
        if n in ctx.vlan_by_id:
            ctx.error("VLANs", f"VLAN ID {n} is used by both {ctx.vlan_by_id[n]['name']} and {name}.", "id")
            continue
        ctx.vlan_by_name[name] = v
        ctx.vlan_by_id[n] = v
        row = [name, str(n)]
        addrs = _addresses(ctx, "VLANs", f"VLAN {name} address", v.get("irb"))
        v4 = [a for a in addrs if a.version == 4]
        if v4:
            if not ctx.layer3:
                ctx.error("VLANs", f"VLAN {name}: this switch can't route. Leave the address empty (the gateway "
                                   "routes) or pick a Layer 3 model (Pro, Pro Max, Pro Aggregation).", "irb")
                row.append("VLAN only (the gateway routes it)")
            else:
                ctx.svis[n] = v4
                row.append(f"Router: this switch, gateway {v4[0].ip}/{v4[0].network.prefixlen}")
                if _truthy(v.get("dhcp_relay")):
                    servers = _list(ctx.p["routing"].get("dhcp_relay_servers"))
                    if servers:
                        row[-1] += ", DHCP relay to " + ", ".join(servers)
                    else:
                        ctx.error("Routing", "VLANs use DHCP relay but no DHCP server is set on the Routing tab.")
        else:
            row.append("VLAN only (the gateway routes it)")
            if _truthy(v.get("dhcp_relay")):
                ctx.error("VLANs", f"VLAN {name}: DHCP relay needs a VLAN address on a Layer 3 switch.", "irb")
        if _truthy(v.get("snooping")):
            ctx.snooping = True
        extra = []
        if _truthy(ctx.p["services"].get("igmp_snooping")):
            extra.append("IGMP snooping on")
        if _truthy(v.get("dai")) or _truthy(v.get("ipsg")):
            ctx.warn("VLANs", f"VLAN {name}: ARP inspection and IP source guard are not available on UniFi switches.")
        if _s(v.get("vni")) or _s(v.get("vga")) or _s(v.get("vrf")):
            ctx.warn("VLANs", f"VLAN {name}: VNI, virtual gateway and VRF are not available on UniFi.")
        row.append(", ".join(extra))
        ctx.networks.append(row)
    ctx.at("", None)


def _claim(ctx: UCtx, section: str, label: str, names: list[str]) -> list[str]:
    ok = []
    for name in names:
        if name in ctx.used:
            ctx.error(section, f"{label}: port {name} is already used by {ctx.used[name]}.", "ports" if section == "Ports" else "members")
            continue
        if ctx.known and name not in ctx.known:
            ctx.warn(section, f"{label}: {name} is not a port on the selected model.")
        ctx.used[name] = label
        ok.append(name)
    return ok


def _profile(ctx: UCtx, section: str, label: str, row: dict, mode: str, names: list[str]) -> list[str]:
    """Ethernet port profile settings for a port group or LAG."""
    svc = ctx.p["services"]
    out: list[str] = []
    if mode == "disabled":
        return ["Port: Disabled"]
    if mode == "access":
        vlan = _vlan_name(ctx, section, label, row.get("vlan"), "vlan")
        out.append(f"Native VLAN / Network: {vlan} ({_vid(ctx, vlan)})" if vlan else "Native VLAN / Network: Default")
        voice = _vlan_name(ctx, section, f"{label} voice", row.get("voice"), "voice")
        if not voice and not _s(row.get("voice")):
            voice = next((v["name"] for v in ctx.p["vlans"] if _truthy(v.get("voice")) and v["name"] != vlan
                          and v["name"] in ctx.vlan_by_name), "")
        if voice and voice == vlan:
            ctx.error(section, f"{label}: the voice VLAN must differ from the data VLAN.", "voice")
            voice = ""
        if voice:
            out += [f"Tagged VLAN Management: Custom, allow {voice} ({_vid(ctx, voice)})", "LLDP-MED: on (phones learn the voice VLAN)"]
        else:
            out.append("Tagged VLAN Management: Block All")
        dot1x = _s(row.get("dot1x"))
        if dot1x:
            out.append(f"802.1X Control: {DOT1X.get(dot1x, 'Auto (802.1X)')}")
            ctx.dot1x = True
        if _s(row.get("mac_limit")) or _truthy(row.get("sticky")):
            ctx.warn(section, f"{label}: UniFi has no MAC limit; Port Security takes a fixed list of allowed MAC "
                              "addresses instead. Not written.")
    else:  # trunk
        refs = _list(row.get("vlans"))
        if not refs:
            ctx.error(section, f"{label}: a trunk needs at least one VLAN (or 'all').", "vlans")
        native = _vlan_name(ctx, section, f"{label} native", row.get("native"), "native")
        out.append(f"Native VLAN / Network: {native} ({_vid(ctx, native)})" if native
                   else "Native VLAN / Network: None (tagged only)")
        if any(r.lower() == "all" for r in refs):
            out.append("Tagged VLAN Management: Allow All")
        else:
            tagged = [n for r in refs if (n := _vlan_name(ctx, section, label, r, "vlans")) and n != native]
            if tagged:
                out.append("Tagged VLAN Management: Custom, allow " + ", ".join(f"{t} ({_vid(ctx, t)})" for t in tagged))
        if _s(row.get("vlan_translate")):
            ctx.error(section, f"{label}: VLAN translation is not available on UniFi.", "vlan_translate")
    if _truthy(row.get("root_guard")) or _truthy(row.get("loop_protect")):
        ctx.warn(section, f"{label}: UniFi has no per-port root guard or loop protect; it runs loop protection "
                          "switch-wide.")
    poe = _s(row.get("poe"))
    if poe:
        no_poe = [p for p in names if p in ctx.known and not ctx.known[p].get("poe")]
        if no_poe and len(no_poe) == len(names):
            ctx.warn(section, f"{label}: these ports have no PoE; PoE setting skipped.")
        elif poe == "off":
            out.append("PoE: Off")
        else:
            out.append("PoE: PoE+ (auto)")
            if poe == "high":
                ctx.warn(section, f"{label}: UniFi has no PoE priority; the switch powers ports in order.")
    if _s(row.get("poe_max")):
        ctx.warn(section, f"{label}: UniFi has no per-port PoE power limit.")
    speed = _s(row.get("speed")).lower()
    if speed:
        if speed in SPEEDS:
            out.append(f"Link speed: {SPEEDS[speed]} (autonegotiation off)")
        else:
            ctx.error(section, f"{label}: speed must be one of {', '.join(SPEEDS)}.", "speed")
    mtu = _s(row.get("mtu"))
    if mtu and mtu != "1500":
        if mtu.isdigit() and 1500 < int(mtu) <= 9216:
            ctx.jumbo = True
        else:
            ctx.error(section, f"{label}: MTU must be 1500-9216.", "mtu")
    if _truthy(svc.get("storm_control")) and (mode == "access" or svc.get("storm_scope") == "all"):
        out.append("Storm Control: on (broadcast, multicast and unknown unicast)")
    return out


def _add_profile(ctx: UCtx, label: str, body: list[str]) -> str:
    """Reuse a profile with the same settings; return its name."""
    for name, other in ctx.profiles.items():
        if other == body:
            return name
    name = label
    n = 2
    while name in ctx.profiles:
        name, n = f"{label}-{n}", n + 1
    ctx.profiles[name] = body
    return name


def _ports(ctx: UCtx) -> None:
    for i, row in enumerate([r for r in ctx.p["ports"] if _s(r.get("ports"))]):
        ctx.at("ports", row)
        label = _s(row.get("name")) or f"Port group {i + 1}"
        try:
            names = P.expand_named(row.get("ports"), UM.ALIASES)
        except ValueError as exc:
            ctx.error("Ports", f"{label}: {exc} (example: 1-24, 26).", "ports")
            continue
        names = _claim(ctx, "Ports", label, names)
        if not names:
            continue
        mode = row.get("mode") or "access"
        if mode == "routed":
            ctx.error("Ports", f"{label}: UniFi switches have no routed ports; put the address on a VLAN.", "mode")
            continue
        if mode not in ("access", "trunk", "disabled"):
            ctx.error("Ports", f"{label}: unknown mode '{mode}'.", "mode")
            continue
        body = _profile(ctx, "Ports", label, row, mode, names)
        what = "Disabled" if mode == "disabled" else f"profile {_add_profile(ctx, label, body)}"
        desc = _s(row.get("description"))
        ctx.portrows.append((_runs(names), what + (f", name \"{desc}\"" if desc else "")))
        for n in names:
            ctx.res.ports[n] = {"use": mode, "label": label, "role": _s(row.get("role")),
                                "voice": any(b.startswith("LLDP-MED") for b in body)}
    ctx.at("", None)


def _lags(ctx: UCtx) -> None:
    for row in [r for r in ctx.p["lags"] if _s(r.get("name")) or _s(r.get("members"))]:
        ctx.at("lags", row)
        name = _s(row.get("name")) or "LAG"
        try:
            members = P.expand_named(row.get("members"), UM.ALIASES)
        except ValueError as exc:
            ctx.error("LAGs", f"{name}: {exc}", "members")
            continue
        members = _claim(ctx, "LAGs", name, members)
        if not members:
            ctx.error("LAGs", f"{name}: add member ports.", "members")
            continue
        nums = sorted(int(m) for m in members)
        if nums != list(range(nums[0], nums[0] + len(nums))):
            ctx.error("LAGs", f"{name}: UniFi aggregates neighbouring ports only (like 25-26).", "members")
            continue
        if len(nums) > 8:
            ctx.error("LAGs", f"{name}: UniFi takes up to 8 ports in an aggregate.", "members")
            continue
        if len(nums) == 1:
            ctx.warn("LAGs", f"{name}: only one member port, so there's no redundancy.")
        if row.get("lacp") == "static":
            ctx.warn("LAGs", f"{name}: UniFi aggregates always use LACP; the other side must run LACP too.")
        if _s(row.get("min_links")):
            ctx.warn("LAGs", f"{name}: UniFi has no minimum links setting.")
        if _s(row.get("esi")):
            ctx.warn("LAGs", f"{name}: EVPN multihoming is not available on UniFi.")
        mode = row.get("mode") or "trunk"
        if mode == "routed":
            ctx.error("LAGs", f"{name}: UniFi switches have no routed ports.", "mode")
            continue
        body = _profile(ctx, "LAGs", name, {**row, "poe": "", "poe_max": ""}, mode, members)
        prof = _add_profile(ctx, name, body)
        desc = _s(row.get("description"))
        ctx.lagrows.append((f"{nums[0]}-{nums[-1]}" if len(nums) > 1 else str(nums[0]),
                            f"Operation: Aggregate, profile {prof}" + (f", name \"{desc}\"" if desc else "")))
        for mem in members:
            ctx.res.ports[mem] = {"use": "lag", "label": name}
    ctx.at("", None)


def _routing(ctx: UCtx) -> None:
    r = ctx.p["routing"]
    routes = [x for x in r.get("static") or [] if _s(x.get("prefix"))]
    for x in routes:
        ctx.at("routing.static", x)
        prefix = "0.0.0.0/0" if _s(x.get("prefix")) == "default" else _s(x.get("prefix"))
        net = _ip(ctx, "Routing", "Route", prefix, allow_net=True)
        if not net:
            continue
        nh = _s(x.get("next_hop"))
        if not ctx.svis:
            if str(net) == "0.0.0.0/0":
                if nh != _s(ctx.p["system"].get("mgmt_gateway")):
                    ctx.warn("Routing", "A UniFi switch's default route is the Gateway on the System tab; "
                                        "this route is not written.")
                continue
            ctx.error("Routing", f"Route {net}: only a Layer 3 switch with VLAN addresses takes static routes; "
                                 "add it on the gateway instead.", "prefix")
            continue
        if nh in ("discard", "reject"):
            ctx.routes.append(f"{net}  type Black Hole")
        elif nh and _ip(ctx, "Routing", f"Route {net} next hop", nh):
            ctx.routes.append(f"{net}  next hop {nh}" + (f", distance {_s(x.get('preference'))}" if _s(x.get("preference")) else ""))
        elif not nh:
            ctx.error("Routing", f"Route {net}: add a next hop.", "next_hop")
    ctx.at("", None)
    if _truthy((r.get("ospf") or {}).get("enabled")):
        ctx.warn("OSPF", "UniFi switches don't run OSPF; it is not written.")
    if any(_s(g.get("neighbors")) for g in r.get("bgp_groups") or []):
        ctx.warn("BGP", "UniFi switches don't run BGP; it is not written.")


def _services(ctx: UCtx) -> None:
    s = ctx.p["services"]
    stp = s.get("stp") or "rstp"
    ctx.globals.append("Spanning Tree: " + {"none": "Disabled", "stp": "STP"}.get(stp, "RSTP"))
    if stp == "none":
        ctx.warn("Services", "Spanning tree is off: a cabling loop will take the network down.")
    if stp == "mstp":
        ctx.warn("Services", "UniFi runs STP or RSTP; RSTP is used.")
    prio = _s(s.get("bridge_priority")).lower()
    if prio and stp != "none":
        m = re.fullmatch(r"(\d+)(k?)", prio)
        val = int(m.group(1)) * (1024 if m.group(2) else 1) if m else -1
        val = 4096 * round(val / 4096) if m and m.group(2) else val
        if 0 <= val <= 61440 and val % 4096 == 0:
            ctx.device.append(f"Spanning tree priority: {val}")
        else:
            ctx.error("Services", "Bridge priority must be 0, 4k, 8k ... 60k (steps of 4k).", "services.bridge_priority")
    if ctx.snooping:
        ctx.globals.append("DHCP Snooping: on")
    if ctx.jumbo:
        ctx.globals.append("Jumbo Frames: on (needed for an MTU above 1500)")
    if not _truthy(s.get("lldp")):
        ctx.warn("Services", "UniFi switches always run LLDP.")
    if ctx.dot1x:
        sec = ctx.p.get("security") or {}
        servers = [x for x in sec.get("radius_servers") or [] if _s(x.get("address"))]
        if not servers:
            ctx.error("Security", "802.1X / MAB ports need at least one RADIUS server.")
        for x in servers:
            ctx.at("security.radius_servers", x)
            if not _ip(ctx, "Security", "RADIUS server", _s(x.get("address"))):
                continue
            if not _s(x.get("secret")):
                ctx.error("Security", f"RADIUS server {_s(x.get('address'))} needs a shared secret.", "secret")
                continue
            ctx.radius.append(f"Authentication server: {_s(x.get('address'))} port {_s(x.get('port')) or '1812'} "
                              "(type the shared secret in the app)")
        ctx.at("", None)
        line = "802.1X Control: on, RADIUS profile dot1x-radius"
        gv = _s(sec.get("guest_vlan"))
        if gv and gv in ctx.vlan_by_name:
            line += f", fallback VLAN {gv} ({_vid(ctx, gv)})"
        ctx.globals.append(line)
    if _truthy(s.get("disable_unused")) and ctx.known:
        unused = [n for n, info in ctx.known.items() if n not in ctx.used]
        if unused:
            ctx.portrows.append((_runs(unused), "Disabled (not in use)"))
            for n in unused:
                ctx.res.ports.setdefault(n, {"use": "disabled", "label": "Unused"})
    p = ctx.p
    if _truthy((p.get("evpn") or {}).get("enabled")):
        ctx.warn("EVPN", "EVPN-VXLAN is not available on UniFi switches.")
    if _truthy((p.get("qos") or {}).get("enabled")):
        ctx.warn("QoS", "QoS is not written for UniFi.")


def _text(ctx: UCtx) -> str:
    model = ctx.umodels[0].name if ctx.umodels else "custom model"
    host = _s(ctx.p["system"].get("hostname")) or "switch"
    out = [f"UniFi Network settings for {host} ({model})",
           "UniFi switches are set up in the UniFi Network app, not with commands.",
           "Make these settings from top to bottom. Menu names are from UniFi Network 9.", ""]
    n = 0

    def section(title: str, lines: list[str]) -> None:
        nonlocal n
        if not lines:
            return
        n += 1
        out.append(f"{n}. {title}")
        out.extend("   " + ln for ln in lines)
        out.append("")

    section("Site settings (Settings > System)", ctx.site)
    section("Device SSH login (Settings > System > Advanced > Device Authentication)", ctx.auth)
    if ctx.networks:
        w = max(len(r[0]) for r in ctx.networks)
        rows = [f"{r[0]:<{w}}  VLAN {r[1]:<4}  {r[2]}" + (f"; {r[3]}" if r[3] else "") for r in ctx.networks]
        section("Networks (Settings > Networks > New Virtual Network, one per VLAN)", rows)
    section("Global switch settings (Settings > Networks > Global Switch Settings)", ctx.globals)
    if ctx.radius:
        section("RADIUS profile dot1x-radius (Settings > Profiles > RADIUS)", ctx.radius)
    plines = []
    for name, body in ctx.profiles.items():
        plines.append(f"{name}:")
        plines.extend("  " + b for b in body)
    section("Ethernet port profiles (Settings > Profiles > Ethernet Ports)", plines)
    section(f"The switch: {host} (UniFi Devices > {host} > Settings)", ctx.device)
    if ctx.lagrows:
        section("Aggregates (UniFi Devices > the switch > Port Manager: pick the first port)",
                [f"Ports {p}: {w}" for p, w in ctx.lagrows])
    if ctx.portrows:
        section("Ports (UniFi Devices > the switch > Port Manager)", [f"Ports {p}: {w}" for p, w in ctx.portrows])
    if ctx.routes:
        section("Static routes (Settings > Routing > Static Routes, device: this switch)", ctx.routes)
    out.append("Then click Apply Changes. The switch provisions itself, which takes a minute.")
    return "\n".join(out) + "\n"


def build(project: dict) -> Result:
    p = normalize(project)
    ctx = UCtx(p)
    for step in (_switch, _system, _access, _snmp_syslog, _vlans, _ports, _lags, _routing, _services):
        step(ctx)
        ctx.row = None
    text = _text(ctx)
    ctx.res.errors = _dedupe(ctx.res.errors)
    ctx.res.warnings = _dedupe(ctx.res.warnings)
    ctx.res.set_text = text
    ctx.res.hier_text = text
    ctx.res.hostname = _s(p["system"].get("hostname")) or "switch"
    return ctx.res
