"""Turn a project into a MikroTik RouterOS v7 script (CRS3xx switches).

The switch is one bridge (``bridge1``) with hardware VLAN filtering. A port's
untagged VLAN is its ``pvid`` on the bridge port; VLAN membership lives in
``/interface bridge vlan``. A VLAN gets an address through a VLAN interface on
the bridge (``vlan10``), and the bridge itself must be tagged in that VLAN.

``vlan-filtering=yes`` is set last: switching it on with a wrong VLAN table
can lock you out, so the script is meant to be run in Safe Mode.

Passwords go in as plain text; RouterOS stores them hashed.
"""

from __future__ import annotations

import ipaddress
import re

from . import ports as P
from . import routeros_models as RM, vendors
from . import routing as R
from .eos import _dedupe
from .generator import (HOSTNAME, NAME, USERNAME, Ctx, Result, _addresses, _ip, _list, _s, _truthy, _vlan_name,
                        normalize)

VENDOR = vendors.VENDORS["mikrotik"]
BRIDGE = "bridge1"
LEVELS = {"emergency": ["critical"], "alert": ["critical"], "critical": ["critical"],
          "error": ["error", "critical"], "warning": ["warning", "error", "critical"],
          "notice": ["warning", "error", "critical"], "info": ["info", "warning", "error", "critical"],
          "any": ["info", "warning", "error", "critical", "debug"]}
_LAG = re.compile(r"^(?:lag|ae|po|port-channel|trunk|bond(?:ing)?)\s*(\d{1,3})$", re.I)
_TZ = re.compile(r"^[A-Za-z]+(?:/[A-Za-z0-9_+-]+){0,2}$")


def _q(text: str) -> str:
    """A RouterOS quoted string ($ and ? would be read as a variable / help)."""
    out = text.replace("\\", "\\\\").replace('"', '\\"').replace("$", "\\$").replace("?", "\\?")
    return f'"{out}"'


def _v(text: str) -> str:
    """A value: bare when it is plain, quoted otherwise."""
    return text if re.fullmatch(r"[A-Za-z0-9._:/,+-]+", text) else _q(text)


class MCtx(Ctx):
    def __init__(self, project: dict):
        super().__init__(project)
        self.rmodels: list = []
        self.sections: dict[str, list[str]] = {}
        self.bports: dict[str, dict] = {}         # bridge port -> {pvid, frame, opts}
        self.vtable: dict[int, dict] = {}         # vid -> {"tagged": [], "untagged": []}
        self.svis: dict[int, list] = {}
        self.eth: dict[str, list[str]] = {}       # ethernet port -> settings
        self.mgmt_port = ""
        self.mgmt_gw = ""
        self.plaintext = False
        self.snooping = False
        self.dot1x_ports: list[tuple[str, str]] = []

    def add(self, menu: str, line: str) -> None:
        body = self.sections.setdefault(menu, [])
        if line not in body:
            body.append(line)

    def vlan_member(self, vid: int, port: str, tagged: bool) -> None:
        row = self.vtable.setdefault(vid, {"tagged": [], "untagged": []})
        key = "tagged" if tagged else "untagged"
        if port not in row[key]:
            row[key].append(port)


def _vid(ctx: MCtx, name: str) -> int:
    return int(ctx.vlan_by_name[name]["id"])


def _vid_list(ids) -> str:
    ids = sorted(set(ids))
    out, start = [], None
    for i, v in enumerate(ids):
        if start is None:
            start = v
        if i + 1 == len(ids) or ids[i + 1] != v + 1:
            out.append(str(start) if start == v else f"{start}-{v}")
            start = None
    return ",".join(out)


# ------------------------------------------------------------------ sections
def _switch(ctx: MCtx) -> None:
    members = ctx.p["switch"].get("members") or []
    if len(members) > 1:
        ctx.error("Switch", "MikroTik switches don't stack. Use one switch per project.")
    for m in members[:1]:
        ctx.at("switch.members", m)
        model = RM.get(m.get("model", ""))
        if model:
            ctx.rmodels.append(model)
            for port in model.ports:
                ctx.known[port["name"]] = port
        elif m.get("model") != RM.CUSTOM:
            ctx.error("Switch", f"Unknown MikroTik model '{m.get('model')}'. Pick one from the list or Custom.", "model")
    ctx.at("", None)
    try:
        for name in P.expand_named(ctx.p["switch"].get("custom_ports", ""), RM.ALIASES):
            ctx.known.setdefault(name, {"name": name, "kind": "access", "speed": "", "poe": False})
    except ValueError as exc:
        ctx.error("Switch", f"Custom ports: {exc}")
    if ctx.rmodels and ctx.rmodels[0].family == "CHR":
        ctx.warn("Switch", "CHR bridges in software: fine for a lab, but there is no PoE and no hardware offload.")


def _password(ctx: MCtx, section: str, label: str, value, key: str) -> str | None:
    value = _s(value)
    if not value:
        return None
    short = key if not ctx.row else key.rsplit(".", 1)[-1]
    if value.startswith("$"):
        ctx.error(section, f"{label}: this password was hashed for another vendor; type it again for MikroTik.", short)
        return None
    if len(value) < 8:
        ctx.error(section, f"{label}: use at least 8 characters.", short)
        return None
    ctx.plaintext = True
    return value


def _system(ctx: MCtx) -> None:
    s = ctx.p["system"]
    host = _s(s.get("hostname"))
    if not host:
        ctx.error("System", "Host name is required.", "system.hostname")
    elif not HOSTNAME.match(host):
        ctx.error("System", f"Host name '{host}' may only use letters, digits and hyphens.", "system.hostname")
    else:
        ctx.add("/system identity", f"set name={_v(host)}")
    tz = _s(s.get("timezone"))
    if tz:
        if _TZ.match(tz):
            ctx.add("/system clock", f"set time-zone-autodetect=no time-zone-name={tz}")
        else:
            ctx.error("System", f"Time zone '{tz}' should be a name like Europe/Amsterdam.", "system.timezone")
    dns = [ns for ns in _list(s.get("name_servers")) if _ip(ctx, "System", "DNS server", ns)]
    if dns:
        ctx.add("/ip dns", f"set servers={','.join(dns)}")
    if _s(s.get("domain")) or _s(s.get("domain_search")):
        ctx.warn("System", "RouterOS has no DNS search domain; the domain is not written.")
    ntp = [_s(n.get("address")) for n in s.get("ntp_servers") or [] if _s(n.get("address"))]
    ntp = [a for a in ntp if re.match(r"^[A-Za-z0-9.:-]+$", a)]
    if not ntp:
        ctx.warn("System", "No NTP server: logs and certificates need the right time.")
    else:
        ctx.add("/system ntp client", "set enabled=yes")
        for a in ntp:
            ctx.add("/system ntp client servers", f"add address={a}")
    if _s(s.get("ntp_source")):
        ctx.warn("System", "The NTP source address is not written for MikroTik.")
    addrs = _addresses(ctx, "System", "Management port", s.get("mgmt_address"))
    gw = _s(s.get("mgmt_gateway"))
    mif = _s(s.get("mgmt_interface"))
    if addrs:
        if not mif:
            ctx.error("System", "MikroTik switches have no separate management port. Name a port to use for "
                                "management (like ether1), or leave this empty and give a VLAN an address.",
                      "system.mgmt_interface")
        else:
            try:
                mif = P.expand_named(mif, RM.ALIASES)[0]
            except (ValueError, IndexError):
                ctx.error("System", f"Management port '{mif}' is not a port name (like ether1).", "system.mgmt_interface")
                mif = ""
        if mif:
            ctx.mgmt_port = mif
            ctx.used[mif] = "Management"
            ctx.res.ports[mif] = {"use": "mgmt", "label": "Management"}
            ctx.add("/interface ethernet", f"set {mif} comment=Management")
            for a in addrs:
                ctx.add("/ip address" if a.version == 4 else "/ipv6 address",
                        f"add address={a} interface={mif} comment=Management")
            if gw and (gw_ip := _ip(ctx, "System", "Management gateway", gw)):
                if not any(gw_ip in a.network for a in addrs if a.version == gw_ip.version):
                    ctx.warn("System", f"Management gateway {gw} is not in the management subnet.")
                ctx.mgmt_gw = gw
            ctx.warn("System", f"{mif} is taken out of the bridge for management. Plug your laptop into another "
                               "port while you load this, or you'll lose the session when it moves.")
    elif gw:
        ctx.warn("System", "Management gateway is set but the management port has no address.")
    if _truthy(s.get("mgmt_vrf")):
        ctx.warn("System", "The management VRF is not written for MikroTik; the port uses the main routing table.")
    banner = (s.get("banner") or "").strip()
    if banner:
        ctx.add("/system note", f"set show-at-login=yes note={_q(banner)}")


def _access(ctx: MCtx) -> None:
    a = ctx.p["access"]
    for i, u in enumerate(a.get("users") or []):
        ctx.at("access.users", u)
        name = _s(u.get("name"))
        if not name:
            continue
        if not USERNAME.match(name) or name == "admin":
            ctx.error("Access", f"User '{name}': use lower-case letters, digits, '.', '_' or '-' (not admin).", "name")
            continue
        cls = u.get("class") or "read-only"
        if cls == "unauthorized":
            continue
        pw = _password(ctx, "Access", f"User {name}", u.get("password"), f"access.users.{i}.password")
        if not pw:
            if not _s(u.get("password")):
                ctx.error("Access", f"User '{name}' needs a password.", "password")
            continue
        group = {"super-user": "full", "operator": "write"}.get(cls, "read")
        ctx.add("/user", f"add name={name} group={group} password={_q(pw)}")
        keys = [k.strip() for k in (u.get("ssh_keys") or "").splitlines() if k.strip()]
        for k in keys:
            ctx.add("/user ssh-keys", f"add user={name} key={_q(k)}")
    ctx.at("", None)
    root = _password(ctx, "Access", "admin password", a.get("root_password"), "access.root_password")
    if root:
        ctx.add("/user", f"set [find name=admin] password={_q(root)}")
    elif not any(u.get("class") == "super-user" and _s(u.get("name")) for u in a.get("users") or []):
        ctx.warn("Access", "No admin password or full user: admin keeps the password printed on the switch's sticker.")
    if any(_s(u.get("ssh_keys")) for u in a.get("users") or []):
        ctx.warn("Access", "SSH keys are added with '/user ssh-keys add', which needs RouterOS 7.12 or later.")
    if ctx.plaintext:
        ctx.warn("Access", "RouterOS takes passwords in plain text in a script and stores them hashed. They stay "
                           "readable in this project, so keep the project private.")
    for svc in ("telnet", "ftp", "www", "api"):
        ctx.add("/ip service", f"set {svc} disabled=yes")
    if not _truthy(a.get("web")):
        ctx.add("/ip service", "set www-ssl disabled=yes")
    if _truthy(a.get("netconf")):
        ctx.warn("Access", "RouterOS has no NETCONF; it offers the REST API over HTTPS (www-ssl) instead.")


def _snmp(ctx: MCtx) -> None:
    s = ctx.p["snmp"]
    comms = [c for c in s.get("communities") or [] if _s(c.get("name"))]
    targets = [t for t in _list(s.get("trap_targets")) if _ip(ctx, "SNMP", "Trap target", t)]
    if not (comms or targets):
        return
    names = []
    for c in comms:
        ctx.at("snmp.communities", c)
        name = _s(c.get("name"))
        if not re.fullmatch(r"[A-Za-z0-9_.@#%+=-]{1,32}", name):
            ctx.error("SNMP", f"Community '{name}' may only use letters, digits and _ . @ # % + = - (max 32).", "name")
            continue
        clients = [cl for cl in _list(c.get("clients")) if _ip(ctx, "SNMP", f"Community {name} client", cl, allow_net=True)]
        if not clients:
            ctx.warn("SNMP", f"Community '{name}' accepts any source address. Add the allowed clients.")
        nets = ",".join(str(ipaddress.ip_network(cl if "/" in cl else cl + ("/32" if ":" not in cl else "/128"),
                                                 strict=False)) for cl in clients) or "0.0.0.0/0"
        rw = "yes" if c.get("access") == "read-write" else "no"
        ctx.add("/snmp community", f"add name={name} addresses={nets} read-access=yes write-access={rw}")
        names.append(name)
    ctx.at("", None)
    if names and "public" not in names:
        ctx.add("/snmp community", "set [find name=public] disabled=yes")
    line = "set enabled=yes"
    if _s(s.get("location")):
        line += f" location={_q(_s(s.get('location')))}"
    if _s(s.get("contact")):
        line += f" contact={_q(_s(s.get('contact')))}"
    if targets:
        trap = _s(s.get("trap_community")) or (names[0] if names else "")
        if not trap:
            ctx.error("SNMP", "Trap targets need a community.", "snmp.trap_community")
        else:
            line += f" trap-community={trap} trap-target={','.join(targets)} trap-version=2"
    ctx.add("/snmp", line)
    if s.get("v3_users"):
        ctx.warn("SNMP", "SNMPv3 users are not written for MikroTik yet (add them under /snmp community with "
                         "security=private).")


def _syslog(ctx: MCtx) -> None:
    hosts = [h for h in ctx.p["syslog"].get("hosts") or [] if _s(h.get("address"))]
    for n, h in enumerate(hosts, 1):
        ctx.at("syslog.hosts", h)
        addr = _s(h.get("address"))
        if not _ip(ctx, "Logging", "Syslog server", addr):
            continue
        line = f"add name=remote{n} target=remote remote={addr}"
        port = _s(h.get("port"))
        if port and port != "514":
            if port.isdigit() and 1 <= int(port) <= 65535:
                line += f" remote-port={port}"
            else:
                ctx.error("Logging", f"Syslog port '{port}' is not valid.", "port")
        ctx.add("/system logging action", line)
        for topic in LEVELS.get(h.get("level") or "info", LEVELS["info"]):
            ctx.add("/system logging", f"add action=remote{n} topics={topic}")
    ctx.at("", None)


def _vlans(ctx: MCtx) -> None:
    vlans = [v for v in ctx.p["vlans"] if _s(v.get("name")) or _s(v.get("id"))]
    if not vlans:
        ctx.warn("VLANs", "No VLANs yet: every port stays in VLAN 1.")
    for v in vlans:
        ctx.at("vlans", v)
        name, vid = _s(v.get("name")), _s(v.get("id"))
        if not NAME.match(name):
            ctx.error("VLANs", f"VLAN name '{name}' must start with a letter and use letters, digits, '-', '_' or '.'.", "name")
            continue
        if not vid.isdigit() or not 1 <= int(vid) <= 4094:
            ctx.error("VLANs", f"VLAN {name}: ID must be 1-4094.", "id")
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
        ctx.vtable.setdefault(n, {"tagged": [], "untagged": []})
        if _truthy(v.get("snooping")):
            ctx.snooping = True
        if _truthy(v.get("dai")) or _truthy(v.get("ipsg")):
            ctx.warn("VLANs", f"VLAN {name}: ARP inspection and IP source guard are not available on RouterOS switches.")
        addrs = _addresses(ctx, "VLANs", f"VLAN {name} address", v.get("irb"))
        if addrs:
            ctx.svis[n] = addrs
            ctx.l3_ifaces.add(f"vlan{n}")
            ctx.vlan_member(n, BRIDGE, True)
        elif _truthy(v.get("dhcp_relay")):
            ctx.error("VLANs", f"VLAN {name}: DHCP relay needs a VLAN address.", "irb")
        if _s(v.get("vni")) or _s(v.get("vga")) or _s(v.get("vrf")):
            ctx.warn("VLANs", f"VLAN {name}: VNI, virtual gateway and VRF are not written for MikroTik.")
    ctx.at("", None)


def _claim(ctx: MCtx, section: str, label: str, names: list[str]) -> list[str]:
    ok = []
    for name in names:
        if name in ctx.used:
            ctx.error(section, f"{label}: {name} is already used by {ctx.used[name]}.", "ports" if section == "Ports" else "members")
            continue
        if ctx.known and name not in ctx.known:
            ctx.warn(section, f"{label}: {name} is not a port on the selected model.")
        ctx.used[name] = label
        ok.append(name)
    return ok


def _bridge_port(ctx: MCtx, section: str, label: str, port: str, row: dict, mode: str) -> None:
    """Bridge port settings and VLAN table entries for one port or bond."""
    svc = ctx.p["services"]
    opts: list[str] = []
    pvid = None
    if mode == "access":
        vlan = _vlan_name(ctx, section, label, row.get("vlan"), "vlan")
        if vlan:
            pvid = _vid(ctx, vlan)
            ctx.vlan_member(pvid, port, False)
        elif not _s(row.get("vlan")):
            ctx.warn(section, f"{label}: no access VLAN, so the port uses VLAN 1.")
        voice = _vlan_name(ctx, section, f"{label} voice", row.get("voice"), "voice")
        if not voice and not _s(row.get("voice")):
            voice = next((v["name"] for v in ctx.p["vlans"] if _truthy(v.get("voice")) and v["name"] != vlan
                          and v["name"] in ctx.vlan_by_name), "")
        if voice and voice == vlan:
            ctx.error(section, f"{label}: the voice VLAN must differ from the data VLAN.", "voice")
            voice = ""
        if voice:
            ctx.vlan_member(_vid(ctx, voice), port, True)
            ctx.voice_note = True
        frame = "admit-all" if voice else "admit-only-untagged-and-priority-tagged"
        if _truthy(row.get("edge")):
            opts.append("edge=yes")
            if _truthy(svc.get("bpdu_block_on_edge")):
                opts.append("bpdu-guard=yes")
        if _s(row.get("mac_limit")) or _truthy(row.get("sticky")):
            ctx.warn(section, f"{label}: MAC limits and sticky MAC are not available on RouterOS switches; skipped.")
        if _truthy(row.get("dhcp_trusted")):
            opts.append("trusted=yes")
        dot1x = _s(row.get("dot1x"))
        if dot1x:
            ctx.dot1x_ports.append((port, dot1x))
    else:  # trunk
        refs = _list(row.get("vlans"))
        if not refs:
            ctx.error(section, f"{label}: a trunk needs at least one VLAN (or 'all').", "vlans")
        native = _vlan_name(ctx, section, f"{label} native", row.get("native"), "native")
        if native:
            pvid = _vid(ctx, native)
            ctx.vlan_member(pvid, port, False)
        if any(r.lower() == "all" for r in refs):
            tagged = [vid for vid in ctx.vlan_by_id]
        else:
            tagged = [_vid(ctx, n) for r in refs if (n := _vlan_name(ctx, section, label, r, "vlans"))]
        for t in tagged:
            if t != pvid:
                ctx.vlan_member(t, port, True)
        frame = "admit-all" if native else "admit-only-vlan-tagged"
        if _truthy(row.get("root_guard")):
            opts.append("restricted-role=yes")
        opts.append("trusted=yes")
        if _s(row.get("vlan_translate")):
            ctx.error(section, f"{label}: VLAN translation is not written for MikroTik.", "vlan_translate")
    ctx.bports[port] = {"mode": mode, "pvid": pvid, "frame": frame, "opts": opts, "comment": _s(row.get("description")) or label}


def _eth(ctx: MCtx, section: str, label: str, row: dict, names: list[str], mode: str) -> None:
    sets: list[str] = []
    if mode == "disabled":
        sets.append("disabled=yes")
    speed = _s(row.get("speed")).lower()
    if speed:
        ctx.warn(section, f"{label}: RouterOS speed names depend on the port type; set the speed by hand "
                          "('/interface ethernet set … auto-negotiation=no speed=…').")
    mtu = _s(row.get("mtu"))
    if mtu:
        if mtu.isdigit() and 1500 <= int(mtu) <= 9000:
            sets.append(f"mtu={mtu} l2mtu={int(mtu) + 92 if int(mtu) <= 9000 else 9092}")
        else:
            ctx.error(section, f"{label}: MTU must be 1500-9000.", "mtu")
    if _truthy(row.get("loop_protect")):
        sets.append("loop-protect=on")
    poe, pmax = _s(row.get("poe")), _s(row.get("poe_max"))
    poe_names = names
    if poe or pmax:
        no_poe = [p for p in names if p in ctx.known and not ctx.known[p].get("poe")]
        if no_poe:
            ctx.warn(section, f"{label}: {', '.join(no_poe[:3])}{'…' if len(no_poe) > 3 else ''} has no PoE; PoE setting skipped.")
        poe_names = [p for p in names if p not in no_poe]
    for n in names:
        body = list(sets)
        if n in poe_names:
            if poe == "off":
                body.append("poe-out=off")
            elif poe in ("high", "low"):
                body.append(f"poe-priority={10 if poe == 'high' else 90}")
            if pmax:
                if re.fullmatch(r"\d+(\.\d+)?", pmax) and 0 < float(pmax) <= 90000:
                    w = float(pmax) / 1000 if float(pmax) > 100 else float(pmax)
                    ctx.warn(section, f"{label}: RouterOS has no per-port PoE power limit; {w:g} W is not written.")
                else:
                    ctx.error(section, f"{label}: PoE limit must be a number of watts.", "poe_max")
        if body:
            ctx.eth.setdefault(n, [])
            for b in body:
                if b not in ctx.eth[n]:
                    ctx.eth[n].append(b)


def _ports(ctx: MCtx) -> None:
    for i, row in enumerate([r for r in ctx.p["ports"] if _s(r.get("ports"))]):
        ctx.at("ports", row)
        label = _s(row.get("name")) or f"Port group {i + 1}"
        try:
            names = P.expand_named(row.get("ports"), RM.ALIASES)
        except ValueError as exc:
            ctx.error("Ports", f"{label}: {exc} (example: ether1-24, sfp-sfpplus1).", "ports")
            continue
        names = _claim(ctx, "Ports", label, names)
        if not names:
            continue
        mode = row.get("mode") or "access"
        if mode == "routed":
            ctx.error("Ports", f"{label}: routed ports are not written for MikroTik; put the address on a VLAN, "
                               "or use the management port.", "mode")
            continue
        if mode not in ("access", "trunk", "disabled"):
            ctx.error("Ports", f"{label}: unknown mode '{mode}'.", "mode")
            continue
        for n in names:
            if mode != "disabled":
                _bridge_port(ctx, "Ports", label, n, row, mode)
            voice = mode == "access" and ctx.bports.get(n, {}).get("frame") == "admit-all"
            ctx.res.ports[n] = {"use": mode, "label": label, "voice": voice, "role": _s(row.get("role"))}
        _eth(ctx, "Ports", label, row, names, mode)
    ctx.at("", None)


def _lags(ctx: MCtx) -> None:
    seen = set()
    for row in [r for r in ctx.p["lags"] if _s(r.get("name")) or _s(r.get("members"))]:
        ctx.at("lags", row)
        raw = _s(row.get("name"))
        m = _LAG.fullmatch(raw) or re.fullmatch(r"(\d{1,3})", raw)
        if m:
            name = f"bond{int(m.group(1))}"
        elif re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,14}", raw):
            name = raw
        else:
            ctx.error("LAGs", f"LAG name '{raw}' must be a short name like bond1.", "name")
            continue
        if name in seen:
            ctx.error("LAGs", f"{name} is listed twice.", "name")
            continue
        seen.add(name)
        try:
            members = P.expand_named(row.get("members"), RM.ALIASES)
        except ValueError as exc:
            ctx.error("LAGs", f"{name}: {exc}", "members")
            continue
        members = _claim(ctx, "LAGs", name, members)
        if not members:
            ctx.error("LAGs", f"{name}: add member ports.", "members")
            continue
        if len(members) == 1:
            ctx.warn("LAGs", f"{name}: only one member port, so there's no redundancy.")
        lacp = row.get("lacp") if row.get("lacp") in ("active", "passive", "static") else "active"
        line = f"add name={name} slaves={','.join(members)}"
        if lacp == "static":
            line += " mode=balance-xor"
        else:
            line += " mode=802.3ad lacp-rate=" + ("1sec" if _truthy(row.get("lacp_fast")) else "30secs")
            if lacp == "passive":
                ctx.warn("LAGs", f"{name}: RouterOS LACP is always active; that works with a passive partner.")
        line += " transmit-hash-policy=layer-3-and-4"
        ml = _s(row.get("min_links"))
        if ml:
            if ml.isdigit() and 1 <= int(ml) <= len(members):
                line += f" min-links={ml}"
            else:
                ctx.error("LAGs", f"{name}: minimum links must be 1-{len(members)}.", "min_links")
        if _s(row.get("description")):
            line += f" comment={_q(_s(row.get('description')))}"
        if _s(row.get("esi")):
            ctx.warn("LAGs", f"{name}: EVPN multihoming is not written for MikroTik (MLAG is set up by hand).")
        ctx.add("/interface bonding", line)
        mode = row.get("mode") or "trunk"
        if mode == "routed":
            ctx.error("LAGs", f"{name}: routed LAGs are not written for MikroTik.", "mode")
        elif mode in ("access", "trunk"):
            _bridge_port(ctx, "LAGs", name, name, {**row, "edge": row.get("edge")}, mode)
        _eth(ctx, "LAGs", name, {**row, "poe": "", "poe_max": "", "speed": ""}, members, "trunk")
        for mem in members:
            ctx.res.ports[mem] = {"use": "lag", "label": name}
    ctx.at("", None)


def _l3(ctx: MCtx) -> None:
    r = ctx.p["routing"]
    for vid, addrs in sorted(ctx.svis.items()):
        name = ctx.vlan_by_id[vid]["name"]
        ctx.add("/interface vlan", f"add interface={BRIDGE} name=vlan{vid} vlan-id={vid} comment={_v(name)}")
        for a in addrs:
            ctx.add("/ip address" if a.version == 4 else "/ipv6 address", f"add address={a} interface=vlan{vid}")
    servers = [sv for sv in _list(r.get("dhcp_relay_servers")) if _ip(ctx, "Routing", "DHCP server", sv)]
    relay = [int(v["id"]) for v in ctx.vlan_by_name.values() if _truthy(v.get("dhcp_relay")) and int(v["id"]) in ctx.svis]
    if relay and not servers:
        ctx.error("Routing", "VLANs use DHCP relay but no DHCP server is set on the Routing tab.")
    for vid in relay:
        v4 = [a for a in ctx.svis[vid] if a.version == 4]
        if servers and v4:
            ctx.add("/ip dhcp-relay", f"add name=relay-vlan{vid} interface=vlan{vid} dhcp-server={','.join(servers)} "
                                      f"local-address={v4[0].ip} disabled=no")
    lo = _s(r.get("loopback"))
    if lo:
        addrs = _addresses(ctx, "Routing", "Loopback", lo if "/" in lo else f"{lo}/32")
        v4 = [a for a in addrs if a.version == 4]
        if v4:
            ctx.add("/interface bridge", "add name=loopback0 protocol-mode=none comment=Loopback")
            ctx.add("/ip address", f"add address={v4[0].ip}/32 interface=loopback0")
            ctx.loopback_ip = str(v4[0].ip)
    rid = _s(r.get("router_id")) or (ctx.loopback_ip or "")
    if rid:
        try:
            ipaddress.IPv4Address(rid)
            ctx.router_id = rid
        except ValueError:
            ctx.error("Routing", f"Router ID '{rid}' must be an IPv4 address.", "routing.router_id")
    asn = _s(r.get("asn"))
    if asn:
        if asn.isdigit() and 1 <= int(asn) <= 4294967295:
            ctx.asn = int(asn)
        else:
            ctx.error("Routing", "AS number must be 1-4294967295.", "routing.asn")


def _static(ctx: MCtx) -> None:
    routes = [x for x in ctx.p["routing"].get("static") or [] if _s(x.get("prefix"))]
    if ctx.mgmt_gw:
        dist = " distance=200" if any(_s(x.get("prefix")) in ("0.0.0.0/0", "default") for x in routes) else ""
        ctx.add("/ip route", f"add dst-address=0.0.0.0/0 gateway={ctx.mgmt_gw}{dist} comment=Management")
    for x in routes:
        ctx.at("routing.static", x)
        prefix = "0.0.0.0/0" if _s(x.get("prefix")) == "default" else _s(x.get("prefix"))
        net = _ip(ctx, "Routing", "Route", prefix, allow_net=True)
        if not net:
            continue
        menu = "/ip route" if net.version == 4 else "/ipv6 route"
        line = f"add dst-address={net}"
        nh = _s(x.get("next_hop"))
        if nh in ("discard", "reject"):
            line += " blackhole"
            if nh == "reject":
                ctx.warn("Routing", f"Route {net}: RouterOS v7 has no reject route; it is written as a blackhole.")
        else:
            nh_ip = _ip(ctx, "Routing", f"Route {net} next hop", nh) if nh else None
            if not nh_ip:
                if not nh:
                    ctx.error("Routing", f"Route {net}: add a next hop (an IP, 'discard' or 'reject').", "next_hop")
                continue
            if not any(nh_ip in a.network for addrs in ctx.svis.values() for a in addrs if a.version == nh_ip.version):
                ctx.warn("Routing", f"Route {net}: next hop {nh} is not in any VLAN subnet on this switch.")
            line += f" gateway={nh}"
        pref = _s(x.get("preference"))
        if pref:
            if pref.isdigit() and 1 <= int(pref) <= 255:
                line += f" distance={pref}"
            else:
                ctx.error("Routing", f"Route {net}: preference (distance) must be 1-255.", "preference")
                continue
        ctx.add(menu, line)
    ctx.at("", None)


def _ospf_iface(ctx: MCtx, raw: str) -> str | None:
    t = raw.strip()
    m = re.fullmatch(r"(?:irb\.|vlan\s*)(\d{1,4})", t, re.I)
    if re.fullmatch(r"(?:lo|loopback)\s*0?(?:\.0)?", t, re.I) and ctx.loopback_ip:
        return "loopback0"
    if m and int(m.group(1)) in ctx.svis:
        return f"vlan{int(m.group(1))}"
    if t in ctx.vlan_by_name and _vid(ctx, t) in ctx.svis:
        return f"vlan{_vid(ctx, t)}"
    if ctx.mgmt_port and t == ctx.mgmt_port:
        return t
    return None


def _ospf(ctx: MCtx) -> None:
    o = ctx.p["routing"].get("ospf") or {}
    if not _truthy(o.get("enabled")):
        return
    line = "add name=ospf1 version=2"
    if ctx.router_id:
        line += f" router-id={ctx.router_id}"
    ctx.add("/routing ospf instance", line)
    for a in o.get("areas") or []:
        ctx.at("routing.ospf.areas", a)
        area = _s(a.get("area")) or "0.0.0.0"
        if not re.fullmatch(r"\d+|\d+\.\d+\.\d+\.\d+", area):
            ctx.error("OSPF", f"Area '{area}' must be a number or dotted (0.0.0.0).", "area")
            continue
        if area.isdigit():
            area = str(ipaddress.IPv4Address(int(area)))
        aname = "backbone" if area == "0.0.0.0" else "area-" + area.replace(".", "-")
        kind = a.get("type") or "normal"
        ctx.add("/routing ospf area", f"add name={aname} area-id={area} instance=ospf1"
                                      + (f" type={kind}" if kind in ("stub", "nssa") else ""))
        passive = {x.lower() for x in P.iface_list(a.get("passive"))}
        p2p = {x.lower() for x in P.iface_list(a.get("p2p"))}
        if _s(a.get("md5_key")):
            ctx.warn("OSPF", f"Area {area}: OSPF authentication is not written for MikroTik yet.")
        for raw in P.iface_list(a.get("interfaces")) + sorted(passive):
            name = _ospf_iface(ctx, raw)
            if not name:
                ctx.error("OSPF", f"Area {area}: '{raw}' must be a VLAN with an address (vlan 20) or the loopback.",
                          "interfaces")
                continue
            line = f"add area={aname} interfaces={name}"
            if raw.strip().lower() in passive or name == "loopback0":
                line += " passive"
            if raw.strip().lower() in p2p:
                line += " type=ptp"
            ctx.add("/routing ospf interface-template", line)
    ctx.at("", None)


def _bgp(ctx: MCtx) -> None:
    groups = [g for g in ctx.p["routing"].get("bgp_groups") or [] if _s(g.get("name")) or _s(g.get("neighbors"))]
    if not groups:
        return
    if not ctx.asn:
        ctx.error("BGP", "BGP needs the switch's AS number (Routing tab).", "routing.asn")
        return
    n = 0
    for g in groups:
        ctx.at("routing.bgp_groups", g)
        gname = _s(g.get("name")) or "PEERS"
        external = (g.get("type") or "external") == "external"
        peer_as = _s(g.get("peer_as"))
        if peer_as and not (peer_as.isdigit() and 1 <= int(peer_as) <= 4294967295):
            ctx.error("BGP", f"Group {gname}: peer AS must be 1-4294967295.", "peer_as")
            continue
        neighbors = R._neighbors(ctx, "BGP", f"Group {gname}", g.get("neighbors", ""))
        if not neighbors:
            ctx.error("BGP", f"Group {gname} has no neighbors.", "neighbors")
            continue
        if _s(g.get("import")) or _s(g.get("export")):
            ctx.warn("BGP", f"Group {gname}: import/export policies are not written for MikroTik yet.")
        for ip, asn, desc in neighbors:
            remote = ctx.asn if not external else (asn or (int(peer_as) if peer_as else None))
            if not remote:
                ctx.error("BGP", f"Group {gname}: neighbor {ip} needs a peer AS (on the group or after the IP).", "neighbors")
                continue
            n += 1
            line = (f"add name={re.sub(r'[^A-Za-z0-9_-]', '-', gname)}-{n} as={ctx.asn} remote.address={ip} "
                    f"remote.as={remote} local.role={'ebgp' if external else 'ibgp'}")
            if ctx.router_id:
                line += f" router-id={ctx.router_id}"
            if _s(g.get("local_address")):
                line += f" local.address={_s(g.get('local_address'))}"
            if _s(g.get("auth_key")):
                line += f" tcp-md5-key={_q(_s(g.get('auth_key')))}"
            if _s(g.get("bfd")):
                line += " use-bfd=yes"
            if ctx.loopback_ip:
                line += " output.network=bgp-networks"
            if desc:
                line += f" comment={_q(desc)}"
            ctx.add("/routing bgp connection", line)
    ctx.at("", None)
    if n and ctx.loopback_ip:
        ctx.add("/ip firewall address-list", f"add list=bgp-networks address={ctx.loopback_ip}/32")


def _services(ctx: MCtx) -> None:
    s = ctx.p["services"]
    if not _truthy(s.get("lldp")):
        ctx.add("/ip neighbor discovery-settings", "set discover-interface-list=none")
    stp = s.get("stp") or "rstp"
    bridge = f"add name={BRIDGE} vlan-filtering=no"
    if stp == "none":
        bridge += " protocol-mode=none"
        ctx.warn("Services", "Spanning tree is off: a cabling loop will take the network down.")
    else:
        bridge += f" protocol-mode={'mstp' if stp == 'mstp' else 'rstp'}"
        prio = _s(s.get("bridge_priority")).lower()
        if prio:
            m = re.fullmatch(r"(\d+)(k?)", prio)
            val = int(m.group(1)) * (1024 if m.group(2) else 1) if m else -1
            val = 4096 * round(val / 4096) if m and m.group(2) else val
            if 0 <= val <= 61440 and val % 4096 == 0:
                bridge += f" priority=0x{val:x}"
            else:
                ctx.error("Services", "Bridge priority must be 0, 4k, 8k ... 60k (steps of 4k).", "services.bridge_priority")
    if ctx.snooping:
        bridge += " dhcp-snooping=yes"
    if _truthy(s.get("igmp_snooping")):
        bridge += " igmp-snooping=yes"
    ctx.bridge_line = bridge
    if _truthy(s.get("storm_control")):
        pct = _s(s.get("storm_percent")) or "5"
        if pct.isdigit() and 1 <= int(pct) <= 100:
            scope = s.get("storm_scope") or "access"
            names = [port for port, bp in ctx.bports.items()
                     if port in ctx.known and (scope == "all" or bp["mode"] == "access")]
            if names:
                ctx.add("/interface ethernet switch port", f"set {','.join(names)} storm-rate={pct}")
        else:
            ctx.error("Services", "Storm control percent must be 1-100.", "services.storm_percent")
    if getattr(ctx, "voice_note", False):
        ctx.warn("Ports", "Voice VLANs are added as tagged VLANs on the access ports. Phones need to learn them from "
                          "LLDP-MED (RouterOS 7.16+: '/ip neighbor discovery-settings set lldp-med-net-policy-vlan=…') "
                          "or from DHCP.")
    if ctx.dot1x_ports:
        sec = ctx.p.get("security") or {}
        servers = [x for x in sec.get("radius_servers") or [] if _s(x.get("address"))]
        if not servers:
            ctx.error("Security", "802.1X / MAB ports need at least one RADIUS server.")
        for x in servers:
            ctx.at("security.radius_servers", x)
            addr = _s(x.get("address"))
            if not _ip(ctx, "Security", "RADIUS server", addr):
                continue
            if not _s(x.get("secret")):
                ctx.error("Security", f"RADIUS server {addr} needs a shared secret.", "secret")
                continue
            line = f"add service=dot1x address={addr} secret={_q(_s(x.get('secret')))}"
            if _s(x.get("port")):
                line += f" authentication-port={_s(x.get('port'))}"
            ctx.add("/radius", line)
        ctx.at("", None)
        for port, mode in ctx.dot1x_ports:
            types = {"dot1x": "dot1x", "dot1x-mab": "dot1x,mac-auth", "mab": "mac-auth"}.get(mode, "dot1x")
            line = f"add interface={port} auth-types={types}"
            gv = _s(sec.get("guest_vlan"))
            if gv and gv in ctx.vlan_by_name:
                line += f" guest-vlan-id={_vid(ctx, gv)}"
            if _s(sec.get("reauth")).isdigit():
                line += f" reauth-timeout={_s(sec.get('reauth'))}s"
            ctx.add("/interface dot1x server", line)
    if _truthy(s.get("disable_unused")) and ctx.known:
        unused = [n for n, info in ctx.known.items() if n not in ctx.used and info["kind"] in ("access", "uplink")]
        for n in unused:
            ctx.eth.setdefault(n, []).append("disabled=yes")
            ctx.res.ports.setdefault(n, {"use": "disabled", "label": "Unused"})


def _unsupported(ctx: MCtx) -> None:
    p = ctx.p
    if _truthy((p.get("evpn") or {}).get("enabled")):
        ctx.warn("EVPN", "EVPN-VXLAN is not written for MikroTik.")
    if any((p.get("policy") or {}).get(k) for k in ("prefix_lists", "communities", "terms")):
        ctx.warn("Policies", "Routing policies are not written for MikroTik yet.")
    if _truthy((p.get("qos") or {}).get("enabled")):
        ctx.warn("QoS", "QoS is not written for MikroTik yet.")


ORDER = ["/system identity", "/system clock", "/system note", "/ip dns", "/system ntp client", "/system ntp client servers",
         "/user", "/user ssh-keys", "/ip service", "/snmp community", "/snmp", "/system logging action",
         "/system logging", "/ip neighbor discovery-settings"]


def build(project: dict) -> Result:
    p = normalize(project)
    ctx = MCtx(p)
    ctx.bridge_line = ""
    for step in (_switch, _system, _access, _snmp, _syslog, _vlans, _ports, _lags, _l3, _static, _ospf, _bgp,
                 _services, _unsupported):
        step(ctx)
        ctx.row = None
    out = ["# MikroTik RouterOS v7 script, made by Switch Config Builder.",
           "# Load it in Safe Mode (Ctrl+X) so a mistake rolls back on its own."]

    def section(menu: str, lines: list[str], note: str = "") -> None:
        if not lines:
            return
        out.append("")
        if note:
            out.append(f"# {note}")
        out.append(menu)
        out.extend(lines)

    for menu in ORDER:
        section(menu, ctx.sections.get(menu, []))
    section("/interface bonding", ctx.sections.get("/interface bonding", []), "LAGs (bonds) before they join the bridge")
    section("/interface bridge", [ctx.bridge_line] + ctx.sections.get("/interface bridge", []),
            "The bridge; VLAN filtering is switched on at the end")
    bp = []
    for port, b in ctx.bports.items():
        line = f"add bridge={BRIDGE} interface={port}"
        if b["pvid"]:
            line += f" pvid={b['pvid']}"
        line += f" frame-types={b['frame']}"
        if b["opts"]:
            line += " " + " ".join(b["opts"])
        line += f" comment={_v(b['comment'])}"
        bp.append(line)
    section("/interface bridge port", bp)
    vl = []
    for vid in sorted(ctx.vtable):
        row = ctx.vtable[vid]
        if not row["tagged"] and not row["untagged"]:
            continue
        line = f"add bridge={BRIDGE} vlan-ids={vid}"
        if row["tagged"]:
            line += f" tagged={','.join(row['tagged'])}"
        if row["untagged"]:
            line += f" untagged={','.join(row['untagged'])}"
        line += f" comment={_v(ctx.vlan_by_id[vid]['name'])}"
        vl.append(line)
    section("/interface bridge vlan", vl)
    groups: dict[str, list[str]] = {}
    for n, v in ctx.eth.items():
        if v:
            groups.setdefault(" ".join(v), []).append(n)
    eth = [f"set {','.join(names)} {body}" for body, names in groups.items()]
    section("/interface ethernet", ctx.sections.get("/interface ethernet", []) + eth)
    for menu in ("/interface ethernet switch port", "/interface vlan", "/ip address", "/ipv6 address", "/ip route",
                 "/ipv6 route", "/ip dhcp-relay", "/routing ospf instance", "/routing ospf area",
                 "/routing ospf interface-template", "/ip firewall address-list", "/routing bgp connection",
                 "/radius", "/interface dot1x server"):
        section(menu, ctx.sections.get(menu, []))
    if ctx.bports:
        section("/interface bridge", [f"set {BRIDGE} vlan-filtering=yes"], "Last step: switch on VLAN filtering")
    else:
        ctx.warn("Ports", "No ports join the bridge yet, so VLAN filtering is left off.")
    if not any(BRIDGE in r["tagged"] for r in ctx.vtable.values()) and not ctx.mgmt_port:
        ctx.warn("System", "No VLAN address and no management port: once VLAN filtering is on you can only reach "
                           "the switch with Winbox MAC or the serial console.")
    text = "\n".join(out) + "\n"
    ctx.res.errors = _dedupe(ctx.res.errors)
    ctx.res.warnings = _dedupe(ctx.res.warnings)
    ctx.res.set_text = text
    ctx.res.hier_text = text
    ctx.res.hostname = _s(p["system"].get("hostname")) or "switch"
    return ctx.res
