"""Turn a project into Fortinet FortiSwitchOS CLI (standalone FortiSwitch).

FortiSwitchOS uses the FortiOS style: ``config <table>`` / ``edit <entry>`` /
``set ...`` / ``next`` / ``end``. A switch port's untagged VLAN is its
``native-vlan`` and its tagged VLANs are ``allowed-vlans`` (in ``config switch
interface``); speed, PoE and shutdown live in ``config switch physical-port``.
A VLAN's address is a ``config system interface`` entry on the ``internal``
interface. LAGs are ``config switch trunk`` entries that then act as one port.

The CLI takes no comment lines, so the output has none. Passwords go in as
plain text; the switch encrypts them.
"""

from __future__ import annotations

import ipaddress
import re

from . import fortiswitch_models as FM, vendors
from . import ports as P
from . import routing as R
from .eos import _dedupe
from .generator import (DOMAIN, HOSTNAME, NAME, USERNAME, Ctx, Result, _addresses, _ip, _list, _s, _truthy,
                        _vlan_name, normalize)

VENDOR = vendors.VENDORS["fortiswitch"]
SPEEDS = {"10m": "10full", "100m": "100full", "1g": "1000full", "10g": "10000full", "25g": "25000full",
          "40g": "40000full", "100g": "100000full"}
LEVELS = {"emergency": "emergency", "alert": "alert", "critical": "critical", "error": "error",
          "warning": "warning", "notice": "notification", "info": "information", "any": "debug"}
_LAG = re.compile(r"^(?:lag|ae|po|port-channel|trunk)\s*(\d{1,3})$", re.I)


def _q(text: str) -> str:
    return '"' + text.replace('"', "'") + '"'


def _mask(a) -> str:
    return f"{a.ip} {a.netmask}"


class Table:
    """One 'config X' table: edit entries with their set lines (in first-use order)."""

    def __init__(self, path: str):
        self.path = path
        self.entries: dict[str, list[str]] = {}

    def edit(self, key: str, *lines: str) -> list[str]:
        body = self.entries.setdefault(key, [])
        for ln in lines:
            if ln not in body:
                body.append(ln)
        return body

    def text(self) -> list[str]:
        if not self.entries:
            return []
        out = [f"config {self.path}"]
        for key, body in self.entries.items():
            out.append(f"    edit {key}")
            out.extend("        " + ln for ln in body)
            out.append("    next")
        out.append("end")
        return out


class FCtx(Ctx):
    def __init__(self, project: dict):
        super().__init__(project)
        self.out: list[str] = []
        self.fmodels: list = []
        self.sysif = Table("system interface")
        self.vlan = Table("switch vlan")
        self.trunk = Table("switch trunk")
        self.phys = Table("switch physical-port")
        self.swif = Table("switch interface")
        self.routes = Table("router static")
        self.svis: dict[int, list] = {}
        self.dot1x_ports: list[str] = []
        self.plaintext = False
        self.lag_names: dict[str, str] = {}

    def block(self, path: str, *lines: str) -> None:
        self.out.append(f"config {path}")
        self.out.extend("    " + ln for ln in lines)
        self.out.append("end")


def _vid(ctx: FCtx, name: str) -> int:
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
def _switch(ctx: FCtx) -> None:
    members = ctx.p["switch"].get("members") or []
    if len(members) > 1:
        ctx.error("Switch", "FortiSwitches don't stack. Use one switch per project (an MCLAG pair is two projects).")
    for m in members[:1]:
        ctx.at("switch.members", m)
        model = FM.get(m.get("model", ""))
        if model:
            ctx.fmodels.append(model)
            for port in model.ports:
                ctx.known[port["name"]] = port
        elif m.get("model") != FM.CUSTOM:
            ctx.error("Switch", f"Unknown FortiSwitch model '{m.get('model')}'. Pick one from the list or Custom.", "model")
    ctx.at("", None)
    try:
        for name in P.expand_named(ctx.p["switch"].get("custom_ports", ""), FM.ALIASES):
            ctx.known.setdefault(name, {"name": name, "kind": "access", "speed": "", "poe": False})
    except ValueError as exc:
        ctx.error("Switch", f"Custom ports: {exc}")


def _password(ctx: FCtx, section: str, label: str, value, key: str) -> str | None:
    value = _s(value)
    if not value:
        return None
    short = key if not ctx.row else key.rsplit(".", 1)[-1]
    if value.startswith("$"):
        ctx.error(section, f"{label}: this password was hashed for another vendor; type it again for FortiSwitch.", short)
        return None
    if len(value) < 8 or len(value) > 64 or re.search(r"[\s\"']", value):
        ctx.error(section, f"{label}: use 8-64 characters with no spaces or quotes.", short)
        return None
    ctx.plaintext = True
    return value


def _system(ctx: FCtx) -> None:
    s = ctx.p["system"]
    glob = []
    host = _s(s.get("hostname"))
    if not host:
        ctx.error("System", "Host name is required.", "system.hostname")
    elif not HOSTNAME.match(host) or len(host) > 35:
        ctx.error("System", f"Host name '{host}' may only use letters, digits and hyphens (max 35).", "system.hostname")
    else:
        glob.append(f"set hostname {_q(host)}")
    if _truthy(ctx.p["access"].get("retry_options")):
        glob += ["set admin-lockout-threshold 3", "set admin-lockout-duration 300"]
    if glob:
        ctx.block("system global", *glob)
    tz = _s(s.get("timezone"))
    if tz and tz != "UTC":
        ctx.warn("System", f"FortiSwitchOS picks the time zone from a numbered list; set it with 'config system global', "
                           f"'set timezone' (press ? for the list) for {tz}.")
    dns = [ns for ns in _list(s.get("name_servers")) if _ip(ctx, "System", "DNS server", ns)]
    domain = _s(s.get("domain"))
    if domain and not DOMAIN.match(domain):
        ctx.error("System", f"Domain '{domain}' is not a valid domain name.", "system.domain")
        domain = ""
    if dns or domain:
        lines = []
        if dns:
            lines.append(f"set primary {dns[0]}")
        if len(dns) > 1:
            lines.append(f"set secondary {dns[1]}")
        if len(dns) > 2:
            ctx.warn("System", "FortiSwitchOS takes two DNS servers; the rest are left out.")
        if domain:
            lines.append(f"set domain {_q(domain)}")
        ctx.block("system dns", *lines)
    ntp = [_s(n.get("address")) for n in s.get("ntp_servers") or [] if _s(n.get("address"))]
    ntp = [a for a in ntp if re.match(r"^[A-Za-z0-9.:-]+$", a)]
    if not ntp:
        ctx.warn("System", "No NTP server: logs and certificates need the right time.")
    else:
        lines = ["set ntpsync enable", "set type custom", "config ntpserver"]
        for i, a in enumerate(ntp, 1):
            lines += [f"    edit {i}", f"        set server {_q(a)}", "    next"]
        lines.append("end")
        ctx.block("system ntp", *lines)
    if _s(s.get("ntp_source")):
        ctx.warn("System", "The NTP source address is not written for FortiSwitch.")
    has_mgmt = not ctx.fmodels or bool(ctx.fmodels[0].mgmt)
    addrs = _addresses(ctx, "System", "Management port (mgmt)", s.get("mgmt_address"))
    v4 = [a for a in addrs if a.version == 4]
    gw = _s(s.get("mgmt_gateway"))
    if addrs and not has_mgmt:
        ctx.error("System", f"The {ctx.fmodels[0].name} has no out-of-band management port; manage it through a VLAN "
                            "address instead.", "system.mgmt_address")
    elif v4:
        access = "ping https ssh" + (" snmp" if ctx.p["snmp"].get("communities") else "")
        ctx.sysif.edit('"mgmt"', f"set ip {_mask(v4[0])}", f"set allowaccess {access}")
        if gw and (gw_ip := _ip(ctx, "System", "Management gateway", gw)):
            if gw_ip not in v4[0].network:
                ctx.warn("System", f"Management gateway {gw} is not in the management subnet.")
            ctx.mgmt_gw = gw
    elif gw:
        ctx.warn("System", "Management gateway is set but the management port has no address.")
    if _truthy(s.get("mgmt_vrf")):
        ctx.warn("System", "FortiSwitchOS has no management VRF; the mgmt port uses the normal routing table.")
    banner = (s.get("banner") or "").strip()
    if banner:
        ctx.warn("System", "The login banner is set with 'config system replacemsg admin pre_admin-disclaimer-text'; "
                           "not written.")


def _access(ctx: FCtx) -> None:
    a = ctx.p["access"]
    admins = []
    ro = False
    for i, u in enumerate(a.get("users") or []):
        ctx.at("access.users", u)
        name = _s(u.get("name"))
        if not name:
            continue
        if not USERNAME.match(name) or name in ("admin",) or len(name) > 35:
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
        profile = "super_admin" if cls == "super-user" else "read_only"
        ro = ro or profile == "read_only"
        body = [f"set accprofile {_q(profile)}", f"set password {_q(pw)}"]
        keys = [k.strip() for k in (u.get("ssh_keys") or "").splitlines() if k.strip()]
        for n, k in enumerate(keys[:3], 1):
            body.append(f"set ssh-public-key{n} {_q(k)}")
        admins.append((name, body))
    ctx.at("", None)
    root = _password(ctx, "Access", "admin password", a.get("root_password"), "access.root_password")
    if ro:
        ctx.block("system accprofile", 'edit "read_only"', *["    " + x for x in (
            "set admingrp read", "set loggrp read", "set netgrp read", "set routegrp read", "set sysgrp read")], "next")
    if root or admins:
        lines = []
        if root:
            lines += ['edit "admin"', f"    set password {_q(root)}", "next"]
        for name, body in admins:
            lines += [f"edit {_q(name)}", *["    " + b for b in body], "next"]
        ctx.block("system admin", *lines)
    if not root and not any(u.get("class") == "super-user" and _s(u.get("name")) for u in a.get("users") or []):
        ctx.warn("Access", "No admin password or super-user: the built-in admin keeps its current (maybe empty) password.")
    if ctx.plaintext:
        ctx.warn("Access", "FortiSwitchOS takes passwords in plain text in a pasted config and encrypts them on the switch. "
                           "They stay readable in this project, so keep the project private.")
    if _truthy(a.get("netconf")):
        ctx.warn("Access", "FortiSwitchOS has no NETCONF; it offers a REST API over HTTPS.")


def _snmp(ctx: FCtx) -> None:
    s = ctx.p["snmp"]
    comms = [c for c in s.get("communities") or [] if _s(c.get("name"))]
    targets = [t for t in _list(s.get("trap_targets")) if _ip(ctx, "SNMP", "Trap target", t)]
    if not (comms or targets or _s(s.get("location")) or _s(s.get("contact"))):
        return
    info = ["set status enable"]
    if _s(s.get("location")):
        info.append(f"set location {_q(_s(s.get('location')))}")
    if _s(s.get("contact")):
        info.append(f"set contact-info {_q(_s(s.get('contact')))}")
    ctx.block("system snmp sysinfo", *info)
    lines = []
    for i, c in enumerate(comms, 1):
        ctx.at("snmp.communities", c)
        name = _s(c.get("name"))
        if not re.fullmatch(r"[A-Za-z0-9_.@#%+=-]{1,35}", name):
            ctx.error("SNMP", f"Community '{name}' may only use letters, digits and _ . @ # % + = - (max 35).", "name")
            continue
        if c.get("access") == "read-write":
            ctx.warn("SNMP", f"Community '{name}': FortiSwitch SNMP is read-only; it is written as read-only.")
        clients = [cl for cl in _list(c.get("clients")) if _ip(ctx, "SNMP", f"Community {name} client", cl, allow_net=True)]
        if not clients:
            ctx.warn("SNMP", f"Community '{name}' accepts any source address. Add the allowed clients.")
        lines += [f"edit {i}", f"    set name {_q(name)}", "    config hosts"]
        n = 0
        for cl in clients:
            net = ipaddress.ip_network(cl if "/" in cl else cl + "/32", strict=False)
            n += 1
            lines += [f"        edit {n}", f"            set ip {net.network_address} {net.netmask}",
                      "            set host-type query", "        next"]
        if i == 1 or _s(s.get("trap_community")) == name:
            for t in targets:
                n += 1
                lines += [f"        edit {n}", f"            set ip {t} 255.255.255.255", "            set host-type trap",
                          "        next"]
        lines += ["    end", "next"]
    ctx.at("", None)
    if targets and not comms:
        ctx.error("SNMP", "Trap targets need a community.", "snmp.trap_community")
    if lines:
        ctx.block("system snmp community", *lines)
    if s.get("v3_users"):
        ctx.warn("SNMP", "SNMPv3 users are not written for FortiSwitch yet ('config system snmp user').")


def _syslog(ctx: FCtx) -> None:
    hosts = [h for h in ctx.p["syslog"].get("hosts") or [] if _s(h.get("address"))]
    if not hosts:
        return
    h = hosts[0]
    if len(hosts) > 1:
        ctx.warn("Logging", "This writes the first syslog server; FortiSwitchOS adds more with 'config log syslogd2 setting'.")
    ctx.at("syslog.hosts", h)
    addr = _s(h.get("address"))
    if _ip(ctx, "Logging", "Syslog server", addr):
        lines = ["set status enable", f"set server {_q(addr)}"]
        port = _s(h.get("port"))
        if port and port != "514":
            if port.isdigit() and 1 <= int(port) <= 65535:
                lines.append(f"set port {port}")
            else:
                ctx.error("Logging", f"Syslog port '{port}' is not valid.", "port")
        ctx.block("log syslogd setting", *lines)
        ctx.block("log syslogd filter", f"set severity {LEVELS.get(h.get('level') or 'info', 'information')}")
    ctx.at("", None)


def _vlans(ctx: FCtx) -> None:
    vlans = [v for v in ctx.p["vlans"] if _s(v.get("name")) or _s(v.get("id"))]
    if not vlans:
        ctx.warn("VLANs", "No VLANs yet: every port stays in VLAN 1.")
    for v in vlans:
        ctx.at("vlans", v)
        name, vid = _s(v.get("name")), _s(v.get("id"))
        if not NAME.match(name) or len(name) > 32:
            ctx.error("VLANs", f"VLAN name '{name}' must start with a letter, use letters, digits, '-', '_' or '.', max 32.", "name")
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
        body = ctx.vlan.edit(str(n), f"set description {_q(name)}")
        if _truthy(v.get("snooping")):
            body.append("set dhcp-snooping enable")
        if _truthy(v.get("dai")):
            body.append("set arp-inspection enable")
        if _truthy(v.get("ipsg")):
            ctx.warn("VLANs", f"VLAN {name}: IP source guard is set per port on FortiSwitch; not written.")
        addrs = _addresses(ctx, "VLANs", f"VLAN {name} address", v.get("irb"))
        if addrs:
            ctx.svis[n] = addrs
            ctx.l3_ifaces.add(f"vlan{n}")
        elif _truthy(v.get("dhcp_relay")):
            ctx.error("VLANs", f"VLAN {name}: DHCP relay needs a VLAN address.", "irb")
        if _s(v.get("vni")) or _s(v.get("vga")) or _s(v.get("vrf")):
            ctx.warn("VLANs", f"VLAN {name}: VNI, virtual gateway and VRF are not written for FortiSwitch.")
    ctx.at("", None)


def _claim(ctx: FCtx, section: str, label: str, names: list[str]) -> list[str]:
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


def _iface_body(ctx: FCtx, section: str, label: str, row: dict, mode: str) -> list[str]:
    """'config switch interface' lines for a port or trunk."""
    body: list[str] = []
    svc = ctx.p["services"]
    desc = _s(row.get("description"))
    if desc:
        body.append(f"set description {_q(desc[:63])}")
    if mode == "access":
        vlan = _vlan_name(ctx, section, label, row.get("vlan"), "vlan")
        if vlan:
            body.append(f"set native-vlan {_vid(ctx, vlan)}")
        elif not _s(row.get("vlan")):
            ctx.warn(section, f"{label}: no access VLAN, so the port uses VLAN 1.")
        voice = _vlan_name(ctx, section, f"{label} voice", row.get("voice"), "voice")
        if not voice and not _s(row.get("voice")):
            voice = next((v["name"] for v in ctx.p["vlans"] if _truthy(v.get("voice")) and v["name"] != vlan
                          and v["name"] in ctx.vlan_by_name), "")
        if voice and voice == vlan:
            ctx.error(section, f"{label}: the voice VLAN must differ from the data VLAN.", "voice")
        elif voice:
            body.append(f"set allowed-vlans {_vid(ctx, voice)}")
            ctx.voice_note = True
        if _truthy(row.get("edge")):
            body.append("set edge-port enabled")
            if _truthy(svc.get("bpdu_block_on_edge")):
                body.append("set stp-bpdu-guard enabled")
        limit = _s(row.get("mac_limit"))
        if limit:
            if limit.isdigit() and 1 <= int(limit) <= 128:
                body.append(f"set learning-limit {limit}")
            else:
                ctx.error(section, f"{label}: MAC limit must be 1-128 on FortiSwitch.", "mac_limit")
        if _truthy(row.get("sticky")):
            ctx.warn(section, f"{label}: sticky MAC is not written for FortiSwitch; skipped.")
        if _truthy(row.get("dhcp_trusted")):
            body += ["set dhcp-snooping trusted", "set arp-inspection-trust trusted"]
        dot1x = _s(row.get("dot1x"))
        if dot1x:
            sec = ["set port-security-mode 802.1X", 'set security-groups "dot1x-users"']
            if dot1x in ("dot1x-mab", "mab"):
                sec.append("set mac-auth-bypass enable")
            if dot1x == "mab":
                ctx.warn(section, f"{label}: FortiSwitch runs MAB as a fallback after 802.1X; devices that can't do "
                                  "802.1X still get in by MAC.")
            body += ["config port-security", *["    " + x for x in sec], "end"]
            ctx.dot1x_ports.append(label)
    elif mode == "trunk":
        refs = _list(row.get("vlans"))
        if not refs:
            ctx.error(section, f"{label}: a trunk needs at least one VLAN (or 'all').", "vlans")
        native = _vlan_name(ctx, section, f"{label} native", row.get("native"), "native")
        if native:
            body.append(f"set native-vlan {_vid(ctx, native)}")
        if any(r.lower() == "all" for r in refs):
            body.append("set allowed-vlans-all enable")
        else:
            tagged = [_vid(ctx, n) for r in refs if (n := _vlan_name(ctx, section, label, r, "vlans"))]
            tagged = [t for t in tagged if not native or t != _vid(ctx, native)]
            if tagged:
                body.append(f"set allowed-vlans {_vid_list(tagged)}")
        if _truthy(row.get("root_guard")):
            body.append("set stp-root-guard enabled")
        if _truthy(row.get("loop_protect")):
            body.append("set loop-guard enabled")
        body.append("set dhcp-snooping trusted")
        if _s(row.get("vlan_translate")):
            ctx.error(section, f"{label}: VLAN translation is not written for FortiSwitch.", "vlan_translate")
    elif mode == "routed":
        ctx.error(section, f"{label}: FortiSwitch has no routed ports; put the address on a VLAN with one access port.", "mode")
    elif mode != "disabled":
        ctx.error(section, f"{label}: unknown mode '{mode}'.", "mode")
    if mode != "trunk" and _s(row.get("vlan_translate")):
        ctx.error(section, f"{label}: VLAN translation is not written for FortiSwitch.", "vlan_translate")
    return body


def _phys_body(ctx: FCtx, section: str, label: str, row: dict, names: list[str], mode: str) -> list[str]:
    body: list[str] = []
    if mode == "disabled":
        body.append("set status down")
    speed = _s(row.get("speed")).lower()
    if speed:
        if speed in SPEEDS:
            body.append(f"set speed {SPEEDS[speed]}")
        else:
            ctx.error(section, f"{label}: speed must be one of {', '.join(SPEEDS)}.", "speed")
    mtu = _s(row.get("mtu"))
    if mtu:
        if mtu.isdigit() and 1500 <= int(mtu) <= 9216:
            body.append(f"set max-frame-size {int(mtu) + 18}")
        else:
            ctx.error(section, f"{label}: MTU must be 1500-9216.", "mtu")
    poe, pmax = _s(row.get("poe")), _s(row.get("poe_max"))
    if poe or pmax:
        no_poe = [p for p in names if p in ctx.known and not ctx.known[p].get("poe")]
        if no_poe:
            ctx.warn(section, f"{label}: {', '.join(no_poe[:3])}{'…' if len(no_poe) > 3 else ''} has no PoE; PoE setting skipped.")
        if len(no_poe) < len(names):
            if poe == "off":
                body.append("set poe-status disable")
            elif poe in ("high", "low"):
                body.append(f"set poe-port-priority {poe}-priority")
            if pmax:
                ctx.warn(section, f"{label}: the PoE power limit is not written for FortiSwitch.")
    return body


def _ports(ctx: FCtx) -> None:
    for i, row in enumerate([r for r in ctx.p["ports"] if _s(r.get("ports"))]):
        ctx.at("ports", row)
        label = _s(row.get("name")) or f"Port group {i + 1}"
        try:
            names = P.expand_named(row.get("ports"), FM.ALIASES)
        except ValueError as exc:
            ctx.error("Ports", f"{label}: {exc} (example: port1-24, port49).", "ports")
            continue
        names = _claim(ctx, "Ports", label, names)
        if not names:
            continue
        mode = row.get("mode") or "access"
        body = _iface_body(ctx, "Ports", label, row, mode)
        phys = _phys_body(ctx, "Ports", label, row, names, mode)
        for n in names:
            if body:
                ctx.swif.edit(_q(n), *body)
            if phys:
                ctx.phys.edit(_q(n), *phys)
            voice = mode == "access" and any(ln.startswith("set allowed-vlans") for ln in body)
            ctx.res.ports[n] = {"use": mode, "label": label, "voice": voice, "role": _s(row.get("role"))}
    ctx.at("", None)


def _lags(ctx: FCtx) -> None:
    seen = set()
    for row in [r for r in ctx.p["lags"] if _s(r.get("name")) or _s(r.get("members"))]:
        ctx.at("lags", row)
        raw = _s(row.get("name"))
        m = _LAG.fullmatch(raw) or re.fullmatch(r"(\d{1,3})", raw)
        if m:
            name = f"lag{int(m.group(1))}"
        elif re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,14}", raw):
            name = raw
        else:
            ctx.error("LAGs", f"LAG name '{raw}' must be a short name like lag1 (max 15 characters).", "name")
            continue
        if name in seen:
            ctx.error("LAGs", f"{name} is listed twice.", "name")
            continue
        seen.add(name)
        try:
            members = P.expand_named(row.get("members"), FM.ALIASES)
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
        body = [f"set mode {'static' if lacp == 'static' else 'lacp-' + lacp}",
                "set members " + " ".join(_q(x) for x in members)]
        if lacp != "static" and _truthy(row.get("lacp_fast")):
            body.append("set lacp-speed fast")
        ml = _s(row.get("min_links"))
        if ml:
            if ml.isdigit() and 1 <= int(ml) <= len(members):
                body.append(f"set min-bundle {ml}")
            else:
                ctx.error("LAGs", f"{name}: minimum links must be 1-{len(members)}.", "min_links")
        if _s(row.get("description")):
            body.append(f"set description {_q(_s(row.get('description'))[:63])}")
        if _s(row.get("esi")):
            ctx.warn("LAGs", f"{name}: EVPN multihoming is not written for FortiSwitch (MCLAG is set up by hand).")
        ctx.trunk.edit(_q(name), *body)
        mode = row.get("mode") or "trunk"
        sw = _iface_body(ctx, "LAGs", name, {**row, "description": ""}, mode)
        if sw:
            ctx.swif.edit(_q(name), *sw)
        for mem in members:
            ctx.res.ports[mem] = {"use": "lag", "label": name}
    ctx.at("", None)


def _l3(ctx: FCtx) -> None:
    r = ctx.p["routing"]
    servers = [sv for sv in _list(r.get("dhcp_relay_servers")) if _ip(ctx, "Routing", "DHCP server", sv)]
    relay = {int(v["id"]) for v in ctx.vlan_by_name.values() if _truthy(v.get("dhcp_relay")) and _s(v.get("irb"))}
    if relay and not servers:
        ctx.error("Routing", "VLANs use DHCP relay but no DHCP server is set on the Routing tab.")
    for vid, addrs in sorted(ctx.svis.items()):
        name = ctx.vlan_by_id[vid]["name"]
        v4 = [a for a in addrs if a.version == 4]
        body = ctx.sysif.edit(f'"vlan{vid}"', f"set description {_q(name)}")
        if v4:
            body.append(f"set ip {_mask(v4[0])}")
        if len(v4) > 1:
            ctx.warn("VLANs", f"VLAN {name}: FortiSwitch takes one IPv4 address per interface (secondaries are not written).")
        if any(a.version == 6 for a in addrs):
            ctx.warn("VLANs", f"VLAN {name}: IPv6 addresses are not written for FortiSwitch yet.")
        body += ["set allowaccess ping https ssh", f"set vlanid {vid}", 'set interface "internal"']
        if vid in relay and servers:
            body += ["set dhcp-relay-service enable", "set dhcp-relay-ip " + " ".join(_q(s) for s in servers)]
    lo = _s(r.get("loopback"))
    if lo:
        addrs = _addresses(ctx, "Routing", "Loopback", lo if "/" in lo else f"{lo}/32")
        v4 = [a for a in addrs if a.version == 4]
        if v4:
            ctx.sysif.edit('"loopback0"', "set type loopback", f"set ip {_mask(v4[0])}", "set allowaccess ping")
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


def _device_for(ctx: FCtx, nh) -> str | None:
    for vid, addrs in ctx.svis.items():
        if any(nh in a.network for a in addrs if a.version == nh.version):
            return f"vlan{vid}"
    return None


def _static(ctx: FCtx) -> None:
    routes = [x for x in ctx.p["routing"].get("static") or [] if _s(x.get("prefix"))]
    n = 0
    gw = getattr(ctx, "mgmt_gw", None)
    if gw:
        n += 1
        ctx.routes.edit(str(n), "set dst 0.0.0.0 0.0.0.0", f"set gateway {gw}", 'set device "mgmt"')
        if any(_s(x.get("prefix")) in ("0.0.0.0/0", "default") for x in routes):
            ctx.warn("Routing", "There's a default route and a management gateway; the one with the lower distance wins. "
                                "Give the management route a higher distance by hand if needed.")
    for x in routes:
        ctx.at("routing.static", x)
        prefix = "0.0.0.0/0" if _s(x.get("prefix")) == "default" else _s(x.get("prefix"))
        net = _ip(ctx, "Routing", "Route", prefix, allow_net=True)
        if not net:
            continue
        if net.version == 6:
            ctx.warn("Routing", f"Route {net}: IPv6 routes are not written for FortiSwitch yet.")
            continue
        body = [f"set dst {net.network_address} {net.netmask}"]
        nh = _s(x.get("next_hop"))
        if nh in ("discard", "reject"):
            body.append("set blackhole enable")
        else:
            nh_ip = _ip(ctx, "Routing", f"Route {net} next hop", nh) if nh else None
            if not nh_ip:
                if not nh:
                    ctx.error("Routing", f"Route {net}: add a next hop (an IP, 'discard' or 'reject').", "next_hop")
                continue
            dev = _device_for(ctx, nh_ip)
            if not dev:
                ctx.warn("Routing", f"Route {net}: next hop {nh} is not in any VLAN subnet on this switch.")
            body.append(f"set gateway {nh}")
            if dev:
                body.append(f"set device {_q(dev)}")
        pref = _s(x.get("preference"))
        if pref:
            if pref.isdigit() and 1 <= int(pref) <= 255:
                body.append(f"set distance {pref}")
            else:
                ctx.error("Routing", f"Route {net}: preference (distance) must be 1-255.", "preference")
                continue
        n += 1
        ctx.routes.edit(str(n), *body)
    ctx.at("", None)


def _ospf(ctx: FCtx) -> None:
    o = ctx.p["routing"].get("ospf") or {}
    if not _truthy(o.get("enabled")):
        return
    ctx.warn("OSPF", "OSPF on FortiSwitch needs the Advanced Features license (FortiSwitch 400 series and up).")
    lines = []
    if ctx.router_id:
        lines.append(f"set router-id {ctx.router_id}")
    else:
        ctx.error("OSPF", "FortiSwitch OSPF needs a router ID or loopback (Routing tab).", "routing.router_id")
    areas, nets, ifaces = [], [], []
    for a in o.get("areas") or []:
        ctx.at("routing.ospf.areas", a)
        area = _s(a.get("area")) or "0.0.0.0"
        if not re.fullmatch(r"\d+|\d+\.\d+\.\d+\.\d+", area):
            ctx.error("OSPF", f"Area '{area}' must be a number or dotted (0.0.0.0).", "area")
            continue
        if area.isdigit():
            area = str(ipaddress.IPv4Address(int(area)))
        kind = a.get("type") or "normal"
        areas += [f"    edit {area}"] + ([f"        set type {kind}"] if kind in ("stub", "nssa") else []) + ["    next"]
        passive = {x.lower() for x in P.iface_list(a.get("passive"))}
        p2p = {x.lower() for x in P.iface_list(a.get("p2p"))}
        if _s(a.get("md5_key")):
            ctx.warn("OSPF", f"Area {area}: OSPF authentication is not written for FortiSwitch yet.")
        for raw in P.iface_list(a.get("interfaces")) + sorted(passive):
            t = raw.strip()
            m = re.fullmatch(r"(?:irb\.|vlan\s*)(\d{1,4})", t, re.I)
            if re.fullmatch(r"(?:lo|loopback)\s*0?(?:\.0)?", t, re.I) and ctx.loopback_ip:
                name, net = "loopback0", ipaddress.ip_network(f"{ctx.loopback_ip}/32")
            elif m and int(m.group(1)) in ctx.svis:
                vid = int(m.group(1))
                name = f"vlan{vid}"
                net = next(a.network for a in ctx.svis[vid] if a.version == 4)
            elif t in ctx.vlan_by_name and _vid(ctx, t) in ctx.svis:
                name = f"vlan{_vid(ctx, t)}"
                net = next(a.network for a in ctx.svis[_vid(ctx, t)] if a.version == 4)
            else:
                ctx.error("OSPF", f"Area {area}: '{raw}' must be a VLAN with an address (vlan 20) or the loopback; "
                                  "FortiSwitch runs OSPF on VLAN interfaces.", "interfaces")
                continue
            nets += [f"    edit {len(nets) // 4 + 1}", f"        set prefix {net.network_address} {net.netmask}",
                     f"        set area {area}", "    next"]
            opts = []
            if t.lower() in passive or name == "loopback0":
                opts.append("        set passive enable")
            if t.lower() in p2p:
                opts.append("        set network-type point-to-point")
            if opts:
                ifaces += [f"    edit {_q(name)}", *opts, "    next"]
    ctx.at("", None)
    if areas:
        lines += ["config area", *areas, "end"]
    if nets:
        lines += ["config network", *nets, "end"]
    if ifaces:
        lines += ["config interface", *ifaces, "end"]
    ctx.ospf_lines = lines


def _bgp(ctx: FCtx) -> None:
    groups = [g for g in ctx.p["routing"].get("bgp_groups") or [] if _s(g.get("name")) or _s(g.get("neighbors"))]
    if not groups:
        return
    if not ctx.asn:
        ctx.error("BGP", "BGP needs the switch's AS number (Routing tab).", "routing.asn")
        return
    ctx.warn("BGP", "BGP on FortiSwitch needs the Advanced Features license (FortiSwitch 400 series and up).")
    lines = [f"set as {ctx.asn}"]
    if ctx.router_id:
        lines.append(f"set router-id {ctx.router_id}")
    neigh = []
    for g in groups:
        ctx.at("routing.bgp_groups", g)
        name = _s(g.get("name")) or "PEERS"
        external = (g.get("type") or "external") == "external"
        peer_as = _s(g.get("peer_as"))
        if peer_as and not (peer_as.isdigit() and 1 <= int(peer_as) <= 4294967295):
            ctx.error("BGP", f"Group {name}: peer AS must be 1-4294967295.", "peer_as")
            continue
        neighbors = R._neighbors(ctx, "BGP", f"Group {name}", g.get("neighbors", ""))
        if not neighbors:
            ctx.error("BGP", f"Group {name} has no neighbors.", "neighbors")
            continue
        if _s(g.get("import")) or _s(g.get("export")):
            ctx.warn("BGP", f"Group {name}: import/export policies are not written for FortiSwitch yet.")
        for ip, asn, desc in neighbors:
            remote = ctx.asn if not external else (asn or (int(peer_as) if peer_as else None))
            if not remote:
                ctx.error("BGP", f"Group {name}: neighbor {ip} needs a peer AS (on the group or after the IP).", "neighbors")
                continue
            body = [f"        set remote-as {remote}"]
            if _s(g.get("auth_key")):
                body.append(f"        set password {_q(_s(g.get('auth_key')))}")
            if _s(g.get("bfd")):
                body.append("        set bfd enable")
            if _s(g.get("local_address")) and ctx.loopback_ip == _s(g.get("local_address")):
                body.append('        set update-source "loopback0"')
            neigh += [f"    edit {_q(ip)}", *body, "    next"]
    ctx.at("", None)
    if neigh:
        lines += ["config neighbor", *neigh, "end"]
    if ctx.loopback_ip:
        lines += ["config network", "    edit 1", f"        set prefix {ctx.loopback_ip} 255.255.255.255", "    next", "end"]
    ctx.bgp_lines = lines


def _services(ctx: FCtx) -> None:
    s = ctx.p["services"]
    if not _truthy(s.get("lldp")):
        ctx.service_blocks.append(("switch lldp settings", ["set status disable"]))
    stp = s.get("stp")
    if stp == "rstp":
        prio = _s(s.get("bridge_priority")).lower()
        if prio:
            m = re.fullmatch(r"(\d+)(k?)", prio)
            val = int(m.group(1)) * (1024 if m.group(2) else 1) if m else -1
            val = 4096 * round(val / 4096) if m and m.group(2) else val
            if 0 <= val <= 61440 and val % 4096 == 0:
                ctx.service_blocks.append(("switch stp instance", ['edit "0"', f"    set priority {val}", "next"]))
            else:
                ctx.error("Services", "Bridge priority must be 0, 4k, 8k ... 60k (steps of 4k).", "services.bridge_priority")
    elif stp == "none":
        ctx.service_blocks.append(("switch stp settings", ["set status disable"]))
        ctx.warn("Services", "Spanning tree is off: a cabling loop will take the network down.")
    if _truthy(s.get("storm_control")):
        pct = _s(s.get("storm_percent")) or "5"
        ctx.warn("Services", f"FortiSwitch sets storm control in packets per second ('config switch storm-control'); "
                             f"the {pct}% is not written.")
    if getattr(ctx, "voice_note", False):
        ctx.warn("Ports", "Voice VLANs are added as tagged VLANs. For phones to learn them, give the ports an LLDP-MED "
                          "profile with a voice network policy ('config switch lldp profile'); not written.")
    if ctx.dot1x_ports:
        sec = ctx.p.get("security") or {}
        servers = [x for x in sec.get("radius_servers") or [] if _s(x.get("address"))]
        if not servers:
            ctx.error("Security", "802.1X / MAB ports need at least one RADIUS server.")
        rad = []
        names = []
        for i, x in enumerate(servers, 1):
            ctx.at("security.radius_servers", x)
            addr = _s(x.get("address"))
            if not _ip(ctx, "Security", "RADIUS server", addr):
                continue
            if not _s(x.get("secret")):
                ctx.error("Security", f"RADIUS server {addr} needs a shared secret.", "secret")
                continue
            name = f"RADIUS-{i}"
            names.append(name)
            rad += [f'edit "{name}"', f'    set server "{addr}"', f"    set secret {_q(_s(x.get('secret')))}"]
            if _s(x.get("port")):
                rad.append(f"    set radius-port {_s(x.get('port'))}")
            rad.append("next")
        ctx.at("", None)
        if rad:
            ctx.pre_blocks.append(("user radius", rad))
            ctx.pre_blocks.append(("user group", ['edit "dot1x-users"', "    set member " + " ".join(f'"{n}"' for n in names),
                                                      "next"]))
    if _truthy(s.get("disable_unused")) and ctx.known:
        unused = [n for n, info in ctx.known.items() if n not in ctx.used and info["kind"] in ("access", "uplink")]
        for n in unused:
            ctx.phys.edit(_q(n), "set status down")
            ctx.res.ports.setdefault(n, {"use": "disabled", "label": "Unused"})


def _unsupported(ctx: FCtx) -> None:
    p = ctx.p
    if _truthy((p.get("evpn") or {}).get("enabled")):
        ctx.warn("EVPN", "EVPN-VXLAN is not written for FortiSwitch.")
    if any((p.get("policy") or {}).get(k) for k in ("prefix_lists", "communities", "terms")):
        ctx.warn("Policies", "Routing policies are not written for FortiSwitch yet.")
    if _truthy((p.get("qos") or {}).get("enabled")):
        ctx.warn("QoS", "QoS is not written for FortiSwitch yet.")


def build(project: dict) -> Result:
    p = normalize(project)
    ctx = FCtx(p)
    ctx.ospf_lines = []
    ctx.bgp_lines = []
    ctx.service_blocks = []
    ctx.pre_blocks = []
    for step in (_switch, _system, _access, _snmp, _syslog, _vlans, _ports, _lags, _l3, _static, _ospf, _bgp,
                 _services, _unsupported):
        step(ctx)
        ctx.row = None
    out = list(ctx.out)
    for path, lines in ctx.pre_blocks:
        out += [f"config {path}", *["    " + ln for ln in lines], "end"]
    # VLANs and LAGs first, so the interfaces and ports that use them load.
    for table in (ctx.vlan, ctx.trunk, ctx.sysif, ctx.phys, ctx.swif, ctx.routes):
        out += table.text()
    for path, lines in ctx.service_blocks:
        out += [f"config {path}", *["    " + ln for ln in lines], "end"]
    if ctx.ospf_lines:
        out += ["config router ospf", *["    " + ln for ln in ctx.ospf_lines], "end"]
    if ctx.bgp_lines:
        out += ["config router bgp", *["    " + ln for ln in ctx.bgp_lines], "end"]
    text = "\n".join(out) + "\n"
    ctx.res.errors = _dedupe(ctx.res.errors)
    ctx.res.warnings = _dedupe(ctx.res.warnings)
    ctx.res.set_text = text
    ctx.res.hier_text = text
    ctx.res.hostname = _s(p["system"].get("hostname")) or "switch"
    return ctx.res
