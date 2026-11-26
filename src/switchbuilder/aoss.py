"""Turn a project into HPE Aruba / ProCurve AOS-S configuration (ProVision).

AOS-S is VLAN-centric like FastIron: each ``vlan N`` context lists its
``untagged`` and ``tagged`` ports, and holds the VLAN's IP address. Port
settings such as edge ports, BPDU protection and port security are top-level
commands that take a port list (``spanning-tree 1-40 admin-edge-port``).
LAGs are trunks: ``trunk 49-50 trk1 lacp``, then ``Trk1`` acts as one port.

The AOS-S CLI doesn't take comment lines, so the output has none: notes go to
the warnings. Passwords go in as ``plaintext``; the switch hashes them.
"""

from __future__ import annotations

import ipaddress
import re
import zoneinfo
from datetime import datetime

from . import aoss_models as SM, vendors
from . import ports as P
from .eos import _dedupe
from .generator import (DOMAIN, HOSTNAME, NAME, USERNAME, Ctx, Result, _addresses, _ip, _list, _s, _truthy,
                        _vlan_name, normalize)

VENDOR = vendors.VENDORS["procurve"]
SPEEDS = {"10m": "10-full", "100m": "100-full", "1g": "1000-full"}
LEVELS = {"emergency": "major", "alert": "major", "critical": "major", "error": "error",
          "warning": "warning", "notice": "info", "info": "info", "any": "debug"}
POE = {"high": "high", "low": "low"}
_TRK = re.compile(r"^(?:trk|lag|ae|po|port-channel)\s*(\d{1,3})$", re.I)


class Text:
    """AOS-S CLI text: top-level lines and 'context / body / exit' blocks."""

    def __init__(self):
        self.items: list = []
        self.blocks: dict[str, list[str]] = {}

    def line(self, text: str) -> None:
        self.items.append(text)

    def block(self, header: str, *lines: str) -> list[str]:
        body = self.blocks.get(header)
        if body is None:
            body = self.blocks[header] = []
            self.items.append((header,))
        for ln in lines:
            if ln not in body:
                body.append(ln)
        return body

    def text(self) -> str:
        out: list[str] = []
        for item in self.items:
            if isinstance(item, tuple):
                out.append(item[0])
                out.extend("   " + ln for ln in self.blocks[item[0]])
                out.append("   exit")
            else:
                out.append(item)
        return "\n".join(out) + "\n"


def _q(text: str) -> str:
    return '"' + text.replace('"', "'") + '"'


def _tz(tz: str) -> tuple[int, str] | None:
    """'America/Edmonton' -> (-420, 'continental-us-and-canada')."""
    try:
        zone = zoneinfo.ZoneInfo(tz)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        return None
    year = datetime.now().year
    jan, jul = datetime(year, 1, 15, tzinfo=zone), datetime(year, 7, 15, tzinfo=zone)
    std = min(jan.utcoffset(), jul.utcoffset())
    minutes = int(std.total_seconds() // 60)
    if jan.utcoffset() == jul.utcoffset():
        rule = "none"
    elif tz.startswith(("America/", "Canada/", "US/")):
        rule = "continental-us-and-canada"
    elif tz.startswith("Europe/"):
        rule = "western-europe"
    elif jan.utcoffset() > jul.utcoffset():
        rule = "southern-hemisphere"
    else:
        rule = "user-defined"
    return minutes, rule


class SCtx(Ctx):
    def __init__(self, project: dict):
        super().__init__(project)
        self.cfg = Text()
        self.smodels: list = []
        self.legacy = False
        self.stacked = False
        self.tagged: dict[int, list[str]] = {}
        self.untagged: dict[int, list[str]] = {}
        self.vlan_lines: dict[int, list[str]] = {}
        self.port_lines: list[str] = []          # top-level per-port commands
        self.iface: dict[str, list[str]] = {}    # interface context -> lines
        self.trunk_ports: list[str] = []         # trusted for DHCP snooping / ARP protect
        self.trunks: dict[str, str] = {}         # member port -> TrkN
        self.dot1x: dict[str, list[str]] = {"dot1x": [], "mab": []}
        self.ospf_ifaces: list = []
        self.plaintext = False
        self.routing = False
        self.banner = None


def _member(ctx: SCtx, vid: int, port: str, tagged: bool) -> None:
    (ctx.tagged if tagged else ctx.untagged).setdefault(vid, [])
    lst = (ctx.tagged if tagged else ctx.untagged)[vid]
    if port not in lst:
        lst.append(port)


def _plist(names: list[str]) -> str:
    trk = sorted((n for n in names if n.startswith("Trk")), key=lambda n: int(n[3:]))
    return ",".join(x for x in (SM.compact([n for n in names if not n.startswith("Trk")]), ",".join(trk)) if x)


# ------------------------------------------------------------------ sections
def _switch(ctx: SCtx) -> None:
    members = ctx.p["switch"].get("members") or []
    if not members:
        ctx.error("Switch", "Add at least one switch.")
    seen = set()
    for m in members:
        ctx.at("switch.members", m)
        try:
            num = int(m.get("fpc", 1))
        except (TypeError, ValueError):
            num = -1
        if num == 0 and len(members) == 1:
            num = 1
        if not 1 <= num <= 10 or num in seen:
            ctx.error("Switch", f"Stack member number {m.get('fpc')} must be 1-10 and used once.", "fpc")
            continue
        seen.add(num)
        model = SM.get(m.get("model", ""))
        if model:
            ctx.smodels.append((num, model))
            for port in model.ports(num):
                ctx.known[port["name"]] = port
            if len(members) > 1 and not model.stack:
                ctx.error("Switch", f"{model.name}: stacking is not written for this model. Use one switch per project.",
                          "model")
        elif m.get("model") != SM.CUSTOM:
            ctx.error("Switch", f"Unknown AOS-S model '{m.get('model')}'. Pick one from the list or Custom.", "model")
    ctx.at("", None)
    families = {mod.family for _, mod in ctx.smodels}
    if len(families) > 1:
        ctx.error("Switch", f"A stack can't mix {' and '.join(sorted(families))} switches.")
    ctx.legacy = any(mod.legacy for _, mod in ctx.smodels)
    if len(members) > 1 and ctx.smodels:
        ctx.stacked = True
        body = ctx.cfg.block("stacking")
        for num, mod in ctx.smodels:
            if mod.stack:
                body.append(f"member {num} type {_q(mod.stack)}")
        ctx.warn("Switch", "Stacking: cable the stack and let the members join (they reboot) before you load the rest.")
    try:
        for name in SM.expand(ctx.p["switch"].get("custom_ports", "")):
            ctx.known.setdefault(name, {"name": name, "kind": "access", "speed": "", "poe": False})
    except ValueError as exc:
        ctx.error("Switch", f"Custom ports: {exc}")


def _password(ctx: SCtx, section: str, label: str, value, key: str) -> str | None:
    value = _s(value)
    if not value:
        return None
    short = key if not ctx.row else key.rsplit(".", 1)[-1]
    if value.startswith("$"):
        ctx.error(section, f"{label}: this password was hashed for another vendor; type it again for AOS-S.", short)
        return None
    if len(value) < 8 or len(value) > 64 or re.search(r"[\s\"']", value):
        ctx.error(section, f"{label}: use 8-64 characters with no spaces or quotes.", short)
        return None
    ctx.plaintext = True
    return value


def _system(ctx: SCtx) -> None:
    s, cfg = ctx.p["system"], ctx.cfg
    host = _s(s.get("hostname"))
    if not host:
        ctx.error("System", "Host name is required.", "system.hostname")
    elif not HOSTNAME.match(host) or len(host) > 32:
        ctx.error("System", f"Host name '{host}' may only use letters, digits and hyphens (max 32).", "system.hostname")
    else:
        cfg.line(f"hostname {_q(host)}")
    tz = _s(s.get("timezone"))
    if tz and tz != "UTC":
        z = _tz(tz)
        if not z:
            ctx.error("System", f"Time zone '{tz}' is not known.", "system.timezone")
        else:
            cfg.line(f"time timezone {z[0]}")
            if z[1] == "user-defined":
                ctx.warn("System", f"{tz} has a summer time rule AOS-S doesn't know; set 'time daylight-time-rule "
                                   "user-defined' by hand.")
            else:
                cfg.line(f"time daylight-time-rule {z[1]}")
    domain = _s(s.get("domain"))
    if domain:
        if DOMAIN.match(domain):
            cfg.line(f"ip dns domain-name {_q(domain)}")
        else:
            ctx.error("System", f"Domain '{domain}' is not a valid domain name.", "system.domain")
    for i, ns in enumerate(_list(s.get("name_servers"))[:3], 1):
        if _ip(ctx, "System", "DNS server", ns):
            cfg.line(f"ip dns server-address priority {i} {ns}")
    ntp = [_s(n.get("address")) for n in s.get("ntp_servers") or [] if _s(n.get("address"))]
    ntp = [a for a in ntp if re.match(r"^[0-9a-fA-F:.]+$", a) and _ip(ctx, "System", "NTP server", a)]
    if not ntp:
        ctx.warn("System", "No NTP server: logs and certificates need the right time.")
    elif ctx.legacy:
        cfg.line("timesync sntp")
        cfg.line("sntp unicast")
        for i, a in enumerate(ntp[:2], 1):
            cfg.line(f"sntp server priority {i} {a}")
    else:
        cfg.line("timesync ntp")
        cfg.line("ntp unicast")
        for a in ntp[:8]:
            cfg.line(f"ntp server {a} iburst")
        cfg.line("ntp enable")
    has_oobm = any(mod.has_oobm for _, mod in ctx.smodels)
    addrs = _addresses(ctx, "System", "Management port", s.get("mgmt_address"))
    gw = _s(s.get("mgmt_gateway"))
    if addrs and ctx.smodels and not has_oobm:
        ctx.error("System", f"The {ctx.smodels[0][1].name} has no out-of-band management port; manage it through a "
                            "VLAN address instead.", "system.mgmt_address")
    elif addrs:
        v4 = [a for a in addrs if a.version == 4]
        body = cfg.block("oobm", *[f"ip address {a.ip} {a.netmask}" for a in v4])
        if gw and _ip(ctx, "System", "Management gateway", gw):
            body.append(f"ip default-gateway {gw}")
        body.append("enable")
    elif gw:
        ctx.warn("System", "Management gateway is set but the management port has no address.")
    if _truthy(s.get("mgmt_vrf")):
        ctx.warn("System", "AOS-S keeps the OOBM port apart by itself; there is no management VRF to turn on.")
    banner = (s.get("banner") or "").strip()
    if banner:
        if '"' in banner:
            ctx.error("System", "The banner can't contain double quotes on AOS-S.", "system.banner")
        else:
            ctx.banner = banner


def _access(ctx: SCtx) -> None:
    a, cfg = ctx.p["access"], ctx.cfg
    root = _password(ctx, "Access", "Manager password (root password)", a.get("root_password"), "access.root_password")
    manager = operator = None
    for i, u in enumerate(a.get("users") or []):
        ctx.at("access.users", u)
        name = _s(u.get("name"))
        if not name:
            continue
        if not USERNAME.match(name) or len(name) > 64:
            ctx.error("Access", f"User '{name}': use lower-case letters, digits, '.', '_' or '-'.", "name")
            continue
        cls = u.get("class") or "read-only"
        if cls == "unauthorized":
            continue
        pw = _password(ctx, "Access", f"User {name}", u.get("password"), f"access.users.{i}.password")
        if not pw:
            if not _s(u.get("password")):
                ctx.error("Access", f"User '{name}' needs a password.", "password")
            continue
        if _s(u.get("ssh_keys")):
            ctx.warn("Access", f"User {name}: AOS-S loads SSH keys from a file ('copy tftp pub-key-file ...'); skipped.")
        if cls == "super-user" and manager is None:
            manager = (name, pw)
        elif cls != "super-user" and operator is None:
            operator = (name, pw)
        else:
            ctx.warn("Access", f"User {name}: AOS-S has one manager and one operator account; extra users need "
                               "'aaa authentication local-user' (16.x) or RADIUS. Skipped.")
    ctx.at("", None)
    if manager:
        cfg.line(f"password manager user-name {_q(manager[0])} plaintext {_q(manager[1])}")
        if root:
            ctx.warn("Access", "The manager account comes from the first super-user, so the root password isn't used.")
    elif root:
        cfg.line(f"password manager user-name \"manager\" plaintext {_q(root)}")
    else:
        ctx.error("Access", "Set a root password or a super-user: a switch without a manager password lets anyone in.",
                  "access.root_password")
    if operator:
        cfg.line(f"password operator user-name {_q(operator[0])} plaintext {_q(operator[1])}")
    if ctx.plaintext:
        ctx.warn("Access", "AOS-S takes passwords in plain text in a pasted config and hashes them on the switch. "
                           "They stay readable in this project, so keep the project private.")
    cfg.line("ip ssh")
    cfg.line("no telnet-server")
    if _truthy(a.get("web")):
        cfg.line("web-management ssl")
        cfg.line("no web-management plaintext")
    else:
        cfg.line("no web-management")
    if _truthy(a.get("retry_options")):
        cfg.line("aaa authentication num-attempts 3")
    if _truthy(a.get("netconf")):
        ctx.warn("Access", "NETCONF is not available on AOS-S; use the REST API on 16.x.")


def _snmp(ctx: SCtx) -> None:
    s, cfg = ctx.p["snmp"], ctx.cfg
    comms = [c for c in s.get("communities") or [] if _s(c.get("name"))]
    if _s(s.get("location")):
        cfg.line(f"snmp-server location {_q(_s(s.get('location')))}")
    if _s(s.get("contact")):
        cfg.line(f"snmp-server contact {_q(_s(s.get('contact')))}")
    if comms or s.get("v3_users"):
        cfg.line('no snmp-server community "public"')
    for c in comms:
        ctx.at("snmp.communities", c)
        name = _s(c.get("name"))
        if not re.fullmatch(r"[A-Za-z0-9_.@#%+=-]{1,32}", name):
            ctx.error("SNMP", f"Community '{name}' may only use letters, digits and _ . @ # % + = - (max 32).", "name")
            continue
        rw = c.get("access") == "read-write"
        cfg.line(f"snmp-server community {_q(name)} {'manager unrestricted' if rw else 'operator'}")
        if _list(c.get("clients")):
            ctx.warn("SNMP", f"Community '{name}': AOS-S limits managers with 'ip authorized-managers', which also "
                             "limits SSH and the web UI; not written. Filter SNMP on your firewall instead.")
    ctx.at("", None)
    if s.get("v3_users"):
        ctx.warn("SNMP", "SNMPv3 users on AOS-S are set up with 'snmpv3 enable' at the CLI (it asks for the "
                         "passwords); not written.")
    comm = _s(s.get("trap_community")) or (comms[0]["name"] if comms else "")
    for t in _list(s.get("trap_targets")):
        if _ip(ctx, "SNMP", "Trap target", t):
            if comm:
                cfg.line(f"snmp-server host {t} community {_q(comm)}")
            else:
                ctx.error("SNMP", "Trap targets need a community.", "snmp.trap_community")


def _syslog(ctx: SCtx) -> None:
    s, cfg = ctx.p["syslog"], ctx.cfg
    level = None
    for h in s.get("hosts") or []:
        ctx.at("syslog.hosts", h)
        addr = _s(h.get("address"))
        if not addr or not _ip(ctx, "Logging", "Syslog server", addr):
            continue
        port = _s(h.get("port"))
        if port and port != "514":
            ctx.warn("Logging", f"Syslog server {addr}: AOS-S sends to port 514 only on older releases; check yours.")
        cfg.line(f"logging {addr}")
        level = LEVELS.get(h.get("level") or "info", "info")
    ctx.at("", None)
    if level and level != "debug":
        cfg.line(f"logging severity {level}")


def _vlans(ctx: SCtx) -> None:
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
        lines = ctx.vlan_lines.setdefault(n, [])
        addrs = _addresses(ctx, "VLANs", f"VLAN {name} address", v.get("irb"))
        for a in addrs:
            if a.version == 4:
                lines.append(f"ip address {a.ip} {a.netmask}")
            else:
                lines.append(f"ipv6 address {a.with_prefixlen}")
        if addrs:
            ctx.l3_ifaces.add(f"vlan {n}")
        elif _truthy(v.get("dhcp_relay")):
            ctx.error("VLANs", f"VLAN {name}: DHCP relay needs a VLAN address.", "irb")
        if _truthy(v.get("voice")):
            lines.append("voice")
        if _s(v.get("vni")) or _s(v.get("vga")) or _s(v.get("vrf")):
            ctx.warn("VLANs", f"VLAN {name}: VNI, virtual gateway and VRF are not available on AOS-S.")
    ctx.at("", None)


def _vid(ctx: SCtx, name: str) -> int:
    return int(ctx.vlan_by_name[name]["id"])


def _claim(ctx: SCtx, section: str, label: str, names: list[str]) -> list[str]:
    ok, module = [], []
    for name in names:
        if name in ctx.used:
            ctx.error(section, f"{label}: {name} is already used by {ctx.used[name]}.", "ports" if section == "Ports" else "members")
            continue
        info = ctx.known.get(name)
        if ctx.known and info is None:
            ctx.warn(section, f"{label}: {name} is not a port on the selected model(s).")
        elif info and info["kind"] == "module":
            module.append(name)
        ctx.used[name] = label
        ok.append(name)
    if module:
        ctx.warn(section, f"{label}: {SM.compact(module)} {'needs' if len(module) == 1 else 'need'} the optional module installed.")
    return ok


def _vlans_for(ctx: SCtx, section: str, label: str, row: dict, refs: list[str]) -> str:
    """Add the ports to their VLANs; returns the mode."""
    mode = row.get("mode") or "access"
    if mode == "access":
        vlan = _vlan_name(ctx, section, label, row.get("vlan"), "vlan")
        if vlan:
            for r in refs:
                _member(ctx, _vid(ctx, vlan), r, False)
        elif not _s(row.get("vlan")):
            ctx.warn(section, f"{label}: no access VLAN, so the ports stay in VLAN 1.")
        voice = _vlan_name(ctx, section, f"{label} voice", row.get("voice"), "voice")
        if not voice and not _s(row.get("voice")):
            voice = next((v["name"] for v in ctx.p["vlans"] if _truthy(v.get("voice")) and v["name"] != vlan
                          and v["name"] in ctx.vlan_by_name), "")
        if voice and voice == vlan:
            ctx.error(section, f"{label}: the voice VLAN must differ from the data VLAN.", "voice")
        elif voice:
            for r in refs:
                _member(ctx, _vid(ctx, voice), r, True)
    elif mode == "trunk":
        names = _list(row.get("vlans"))
        if not names:
            ctx.error(section, f"{label}: a trunk needs at least one VLAN (or 'all').", "vlans")
        if any(n.lower() == "all" for n in names):
            vids = [vid for vid in ctx.vlan_by_id if vid != 1]
        else:
            vids = [_vid(ctx, n) for r in names if (n := _vlan_name(ctx, section, label, r, "vlans"))]
        native = _vlan_name(ctx, section, f"{label} native", row.get("native"), "native")
        nid = _vid(ctx, native) if native else None
        for vid in vids:
            if vid != nid:
                for r in refs:
                    _member(ctx, vid, r, True)
        if nid:
            for r in refs:
                _member(ctx, nid, r, False)
        elif ctx.vlan_by_id:
            ctx.warn(section, f"{label}: no native VLAN, so the ports also stay untagged in VLAN 1.")
        ctx.trunk_ports.extend(refs)
        if _truthy(row.get("root_guard")):
            ctx.port_lines.append(f"spanning-tree {_plist(refs)} root-guard")
        if _truthy(row.get("loop_protect")):
            ctx.port_lines.append(f"loop-protect {_plist(refs)}")
    elif mode == "routed":
        ctx.error(section, f"{label}: AOS-S has no routed ports; put the address on a VLAN with one access port.", "mode")
    elif mode != "disabled":
        ctx.error(section, f"{label}: unknown mode '{mode}'.", "mode")
    if _s(row.get("vlan_translate")):
        ctx.warn(section, f"{label}: AOS-S has no per-port VLAN translation; the mapping is ignored.")
    return mode


def _port_groups(ctx: SCtx) -> None:
    svc = ctx.p["services"]
    for i, row in enumerate([r for r in ctx.p["ports"] if _s(r.get("ports"))]):
        ctx.at("ports", row)
        label = _s(row.get("name")) or f"Port group {i + 1}"
        try:
            names = SM.expand(row.get("ports"))
        except ValueError as exc:
            ctx.error("Ports", f"{label}: {exc} (example: 1-24, 49).", "ports")
            continue
        names = _claim(ctx, "Ports", label, names)
        if not names:
            continue
        mode = _vlans_for(ctx, "Ports", label, row, names)
        plist = SM.compact(names)
        body = ctx.iface.setdefault(plist, [])
        desc = _s(row.get("description"))
        if desc:
            body.append(f"name {_q(desc[:64])}")
        if mode == "disabled":
            body.append("disable")
        speed = _s(row.get("speed")).lower()
        if speed:
            if speed in SPEEDS:
                body.append(f"speed-duplex {SPEEDS[speed]}")
            else:
                ctx.warn("Ports", f"{label}: only 10m, 100m and 1g can be forced on AOS-S; faster ports follow the optic.")
        if _s(row.get("mtu")):
            ctx.warn("Ports", f"{label}: AOS-S sets jumbo frames per VLAN ('jumbo'); the port MTU is not written.")
        if mode == "access":
            if _truthy(row.get("edge")) and _s(svc.get("stp")) != "none":
                ctx.port_lines.append(f"spanning-tree {plist} admin-edge-port")
                if _truthy(svc.get("bpdu_block_on_edge")):
                    ctx.port_lines.append(f"spanning-tree {plist} bpdu-protection")
            limit = _s(row.get("mac_limit"))
            if limit:
                if limit.isdigit() and 1 <= int(limit) <= 64:
                    action = "send-disable" if _s(row.get("mac_action")) == "shutdown" else "send-alarm"
                    ctx.port_lines.append(f"port-security {plist} learn-mode limited-continuous address-limit {limit} "
                                          f"action {action}")
                else:
                    ctx.error("Ports", f"{label}: MAC limit must be 1-64 on AOS-S.", "mac_limit")
            if _truthy(row.get("sticky")):
                ctx.warn("Ports", f"{label}: sticky MAC is not written for AOS-S; skipped.")
            if _truthy(row.get("dhcp_trusted")):
                ctx.trunk_ports.extend(names)
            dot1x = _s(row.get("dot1x"))
            if dot1x in ("dot1x", "dot1x-mab"):
                ctx.dot1x["dot1x"].extend(names)
            if dot1x in ("mab", "dot1x-mab"):
                ctx.dot1x["mab"].extend(names)
        poe, pmax = _s(row.get("poe")), _s(row.get("poe_max"))
        if poe or pmax:
            no_poe = [p for p in names if p in ctx.known and not ctx.known[p].get("poe")]
            if no_poe:
                ctx.warn("Ports", f"{label}: {', '.join(no_poe[:3])}{'…' if len(no_poe) > 3 else ''} has no PoE; PoE setting skipped.")
            if len(no_poe) < len(names):
                if poe == "off":
                    body.append("no power-over-ethernet")
                elif poe in POE:
                    body.append(f"power-over-ethernet {POE[poe]}")
                if pmax and poe != "off":
                    try:
                        watts = float(pmax)
                    except ValueError:
                        watts = -1
                    if 1 <= watts <= 30:
                        body.append("poe-allocate-by value")
                        body.append(f"poe-value {int(watts)}")
                    else:
                        ctx.error("Ports", f"{label}: maximum PoE power must be 1-30 watts on AOS-S.", "poe_max")
        for port in names:
            voice = mode == "access" and (bool(_s(row.get("voice"))) or any(
                _truthy(v.get("voice")) and v["name"] != _s(row.get("vlan")) for v in ctx.p["vlans"]))
            ctx.res.ports[port] = {"use": mode, "label": label, "voice": voice, "role": _s(row.get("role"))}
    ctx.at("", None)


def _lags(ctx: SCtx) -> None:
    seen = set()
    for row in [r for r in ctx.p["lags"] if _s(r.get("name")) or _s(r.get("members"))]:
        ctx.at("lags", row)
        raw = _s(row.get("name"))
        m = _TRK.fullmatch(raw) or re.fullmatch(r"(\d{1,3})", raw)
        num = int(m.group(1)) if m else -1
        if not 1 <= num <= 144:
            ctx.error("LAGs", f"LAG name '{raw}' must be Trk1 to Trk144.", "name")
            continue
        trk = f"Trk{num}"
        if num in seen:
            ctx.error("LAGs", f"{trk} is listed twice.", "name")
            continue
        seen.add(num)
        try:
            members = SM.expand(row.get("members"))
        except ValueError as exc:
            ctx.error("LAGs", f"{trk}: {exc}", "members")
            continue
        members = _claim(ctx, "LAGs", trk, members)
        if not members:
            ctx.error("LAGs", f"{trk}: add member ports.", "members")
            continue
        if len(members) == 1:
            ctx.warn("LAGs", f"{trk}: only one member port, so there's no redundancy.")
        if len(members) > 8:
            ctx.error("LAGs", f"{trk}: an AOS-S trunk takes at most 8 ports.", "members")
        lacp = row.get("lacp") if row.get("lacp") in ("active", "passive", "static") else "active"
        ctx.cfg.line(f"trunk {SM.compact(members)} {trk.lower()} {'trunk' if lacp == 'static' else 'lacp'}")
        if lacp == "passive":
            ctx.warn("LAGs", f"{trk}: AOS-S trunks with LACP are active; passive is not written.")
        if _s(row.get("min_links")):
            ctx.warn("LAGs", f"{trk}: minimum links are not written for AOS-S.")
        if _s(row.get("esi")):
            ctx.warn("LAGs", f"{trk}: EVPN multihoming is not available on AOS-S.")
        if (row.get("mode") or "trunk") == "routed":
            ctx.error("LAGs", f"{trk}: AOS-S has no routed trunks; use a VLAN address.", "mode")
            continue
        _vlans_for(ctx, "LAGs", trk, row, [trk])
        desc = _s(row.get("description"))
        if desc:
            ctx.iface.setdefault(trk, []).append(f"name {_q(desc[:64])}")
        for mem in members:
            ctx.trunks[mem] = trk
            ctx.res.ports[mem] = {"use": "lag", "label": trk}
    ctx.at("", None)


def _write_vlans(ctx: SCtx) -> None:
    r = ctx.p["routing"]
    servers = [sv for sv in _list(r.get("dhcp_relay_servers")) if _ip(ctx, "Routing", "DHCP server", sv)]
    relay = {int(v["id"]) for v in ctx.vlan_by_name.values() if _truthy(v.get("dhcp_relay")) and _s(v.get("irb"))}
    if relay and not servers:
        ctx.error("Routing", "VLANs use DHCP relay but no DHCP server is set on the Routing tab.")
    for vid in sorted(ctx.vlan_by_id):
        v = ctx.vlan_by_id[vid]
        body = ctx.cfg.block(f"vlan {vid}", f"name {_q(v['name'])}")
        if ctx.untagged.get(vid):
            body.append(f"untagged {_plist(ctx.untagged[vid])}")
        if ctx.tagged.get(vid):
            body.append(f"tagged {_plist(ctx.tagged[vid])}")
        body.extend(ctx.vlan_lines.get(vid, []))
        if vid in relay:
            body.extend(f"ip helper-address {sv}" for sv in servers)
    # A switch with one VLAN address and only a default route stays layer 2 ('ip default-gateway');
    # more VLAN addresses, other routes or OSPF turn routing on.
    nets = [vid for vid, ls in ctx.vlan_lines.items() if any(ln.startswith("ip address") for ln in ls)]
    routes = [x for x in r.get("static") or [] if _s(x.get("prefix"))]
    only_default = all(_s(x.get("prefix")) in ("0.0.0.0/0", "default") for x in routes) and len(routes) <= 1
    ctx.routing = len(nets) > 1 or (routes and not only_default) or _truthy((r.get("ospf") or {}).get("enabled"))
    if ctx.routing:
        ctx.cfg.line("ip routing")
    if ctx.legacy and ctx.routing:
        ctx.warn("Routing", "Older ProCurve switches route only on the 2910al and up; check yours before you load it.")


def _write_ports(ctx: SCtx) -> None:
    for plist, lines in ctx.iface.items():
        if lines:
            ctx.cfg.block(f"interface {plist}", *lines)
    for ln in ctx.port_lines:
        ctx.cfg.line(ln)


def _static(ctx: SCtx) -> None:
    r, cfg = ctx.p["routing"], ctx.cfg
    routes = [x for x in r.get("static") or [] if _s(x.get("prefix"))]
    if not ctx.routing and routes:
        nh = _s(routes[0].get("next_hop"))
        if _ip(ctx, "Routing", "Default route next hop", nh):
            cfg.line(f"ip default-gateway {nh}")
        return
    for x in routes:
        ctx.at("routing.static", x)
        prefix = "0.0.0.0/0" if _s(x.get("prefix")) == "default" else _s(x.get("prefix"))
        net = _ip(ctx, "Routing", "Route", prefix, allow_net=True)
        if not net:
            continue
        nh = _s(x.get("next_hop"))
        if nh in ("discard", "reject"):
            target = "blackhole" if nh == "discard" else "reject"
        else:
            if not nh or not _ip(ctx, "Routing", f"Route {net} next hop", nh):
                if not nh:
                    ctx.error("Routing", f"Route {net}: add a next hop (an IP, 'discard' or 'reject').", "next_hop")
                continue
            target = nh
        if net.version == 6:
            cfg.line(f"ipv6 route {net} {target}")
        else:
            pref = _s(x.get("preference"))
            cfg.line(f"ip route {net.network_address} {net.netmask} {target}" + (f" distance {pref}" if pref else ""))
    ctx.at("", None)


def _ospf(ctx: SCtx) -> None:
    r = ctx.p["routing"]
    o = r.get("ospf") or {}
    lo = _s(r.get("loopback"))
    rid = _s(r.get("router_id")) or lo.split("/")[0]
    if rid:
        try:
            ipaddress.IPv4Address(rid)
            ctx.cfg.line(f"ip router-id {rid}")
        except ValueError:
            ctx.error("Routing", f"Router ID '{rid}' must be an IPv4 address.", "routing.router_id")
    if lo:
        addrs = _addresses(ctx, "Routing", "Loopback", lo if "/" in lo else f"{lo}/32")
        if addrs:
            ctx.cfg.block("interface loopback 0", *[f"ip address {a.ip}" for a in addrs if a.version == 4])
    if not _truthy(o.get("enabled")):
        return
    body = ctx.cfg.block("router ospf")
    for a in o.get("areas") or []:
        ctx.at("routing.ospf.areas", a)
        area = _s(a.get("area")) or "0"
        if not re.fullmatch(r"\d+|\d+\.\d+\.\d+\.\d+", area):
            ctx.error("OSPF", f"Area '{area}' must be a number or dotted (0.0.0.0).", "area")
            continue
        dotted = area if "." in area else str(ipaddress.IPv4Address(int(area)))
        name = "backbone" if dotted == "0.0.0.0" else dotted
        kind = a.get("type") or "normal"
        body.append(f"area {name}" + (f" {kind}" if kind in ("stub", "nssa") else ""))
        passive = {x.lower() for x in P.iface_list(a.get("passive"))}
        for raw in P.iface_list(a.get("interfaces")) + list(passive):
            m = re.fullmatch(r"(?:irb\.|vlan\s*|ve\s*)(\d{1,4})", raw.strip(), re.I)
            if re.fullmatch(r"(?:lo|loopback)\s*0?(?:\.0)?", raw.strip(), re.I) and lo:
                ctx.cfg.block("interface loopback 0", f"ip ospf {lo.split('/')[0]} area {name}")
                continue
            if not m or int(m.group(1)) not in ctx.vlan_by_id:
                ctx.error("OSPF", f"Area {area}: '{raw}' must be a VLAN with an address (vlan 20) or the loopback; "
                                  "AOS-S runs OSPF on VLANs.", "interfaces")
                continue
            vid = int(m.group(1))
            ips = [ln.split()[2] for ln in ctx.vlan_lines.get(vid, []) if ln.startswith("ip address")]
            if not ips:
                ctx.error("OSPF", f"Area {area}: VLAN {vid} has no address.", "interfaces")
                continue
            vb = ctx.cfg.block(f"vlan {vid}")
            vb.append(f"ip ospf {ips[0]} area {name}")
            if raw.lower() in passive:
                vb.append(f"ip ospf {ips[0]} passive")
        if _s(a.get("md5_key")):
            ctx.warn("OSPF", f"Area {area}: OSPF MD5 keys are set per VLAN with 'ip ospf md5-auth-key-chain'; not written.")
        if _s(a.get("p2p")):
            ctx.warn("OSPF", f"Area {area}: point-to-point is not written for AOS-S.")
    ctx.at("", None)
    body.append("enable")


def _services(ctx: SCtx) -> None:
    s, cfg = ctx.p["services"], ctx.cfg
    sec = ctx.p.get("security") or {}
    if not _truthy(s.get("lldp")):
        cfg.line("no lldp run")
    stp = s.get("stp")
    if stp == "rstp":
        cfg.line("spanning-tree")
        cfg.line("spanning-tree force-version rstp-operation")
        prio = _s(s.get("bridge_priority")).lower()
        if prio:
            m = re.fullmatch(r"(\d+)(k?)", prio)
            val = int(m.group(1)) * (1024 if m.group(2) else 1) if m else -1
            val = 4096 * round(val / 4096) if m and m.group(2) else val
            if 0 <= val <= 61440 and val % 4096 == 0:
                cfg.line(f"spanning-tree priority {val // 4096}")
            else:
                ctx.error("Services", "Bridge priority must be 0, 4k, 8k ... 60k (steps of 4k).", "services.bridge_priority")
    elif stp == "none":
        ctx.warn("Services", "Spanning tree is off: a cabling loop will take the network down.")
    rt = _s(sec.get("recovery_timeout"))
    if rt and ctx.port_lines and any("bpdu-protection" in ln for ln in ctx.port_lines):
        if rt.isdigit() and 1 <= int(rt) <= 65535:
            cfg.line(f"spanning-tree bpdu-protection-timeout {rt}")
        else:
            ctx.error("Security", "Auto-recovery time must be 1-65535 seconds on AOS-S.", "security.recovery_timeout")
    if _truthy(s.get("storm_control")):
        ctx.warn("Services", "Storm control on AOS-S is 'broadcast-limit' per port on some models only; not written.")
    snoop = [int(v["id"]) for v in ctx.vlan_by_name.values() if _truthy(v.get("snooping")) or _truthy(v.get("dai"))]
    dai = [int(v["id"]) for v in ctx.vlan_by_name.values() if _truthy(v.get("dai"))]
    trust = _plist(list(dict.fromkeys(ctx.trunk_ports)))
    if snoop:
        cfg.line("dhcp-snooping")
        cfg.line(f"dhcp-snooping vlan {' '.join(str(v) for v in sorted(snoop))}")
        if trust:
            cfg.line(f"dhcp-snooping trust {trust}")
        cfg.line("no dhcp-snooping option 82")
        ctx.warn("Services", "DHCP snooping is on: trunk and LAG ports are trusted, access ports are not. "
                             "Tick 'DHCP trusted' on an access port that has a DHCP server behind it.")
    if dai:
        cfg.line(f"arp-protect vlan {' '.join(str(v) for v in sorted(dai))}")
        if trust:
            cfg.line(f"arp-protect trust {trust}")
        cfg.line("arp-protect")
    if any(_truthy(v.get("ipsg")) for v in ctx.vlan_by_name.values()):
        ctx.warn("VLANs", "IP source guard ('dynamic-ip-lockdown') is not written for AOS-S yet.")
    if any(_truthy(s.get(k)) for k in ("poe_fast", "poe_perpetual")) or _s(s.get("poe_guard_band")):
        ctx.warn("Services", "Perpetual/fast PoE and guard band are Juniper options; not written for AOS-S.")
    if ctx.dot1x["dot1x"] or ctx.dot1x["mab"]:
        servers = [x for x in sec.get("radius_servers") or [] if _s(x.get("address"))]
        if not servers:
            ctx.error("Security", "802.1X / MAB ports need at least one RADIUS server.")
        for x in servers:
            ctx.at("security.radius_servers", x)
            addr = _s(x.get("address"))
            if not _ip(ctx, "Security", "RADIUS server", addr):
                continue
            secret = _s(x.get("secret"))
            if not secret:
                ctx.error("Security", f"RADIUS server {addr} needs a shared secret.", "secret")
                continue
            port = _s(x.get("port"))
            cfg.line(f"radius-server host {addr}" + (f" auth-port {port}" if port and port != "1812" else "")
                     + f" key {_q(secret)}")
        ctx.at("", None)
        if ctx.dot1x["dot1x"]:
            cfg.line("aaa authentication port-access eap-radius")
            cfg.line(f"aaa port-access authenticator {SM.compact(ctx.dot1x['dot1x'])}")
            cfg.line("aaa port-access authenticator active")
        if ctx.dot1x["mab"]:
            cfg.line(f"aaa port-access mac-based {SM.compact(ctx.dot1x['mab'])}")
    if _truthy(s.get("disable_unused")) and ctx.known:
        unused = [n for n, info in ctx.known.items() if n not in ctx.used and info["kind"] in ("access", "uplink")]
        if unused:
            cfg.block(f"interface {SM.compact(unused)}", 'name "Unused - disabled"', "disable")
            for n in unused:
                ctx.res.ports.setdefault(n, {"use": "disabled", "label": "Unused"})
    if ctx.banner:
        cfg.line(f"banner motd {_q(ctx.banner)}")


def _unsupported(ctx: SCtx) -> None:
    p = ctx.p
    if any(_s(g.get("neighbors")) for g in p["routing"].get("bgp_groups") or []):
        ctx.warn("BGP", "BGP is not written for AOS-S (only the 3810M and 5400R run it, with a premium licence).")
    if _truthy((p.get("evpn") or {}).get("enabled")):
        ctx.warn("EVPN", "EVPN-VXLAN is not available on AOS-S.")
    if any((p.get("policy") or {}).get(k) for k in ("prefix_lists", "communities", "terms")):
        ctx.warn("Policies", "Routing policies are not written for AOS-S.")
    if _truthy((p.get("qos") or {}).get("enabled")):
        ctx.warn("QoS", "QoS is not written for AOS-S yet.")
    if ctx.legacy:
        ctx.warn("Switch", "Older ProCurve software may not take 'plaintext' passwords in a pasted config; if a "
                           "password line is refused, set it with 'password manager' at the prompt.")


def build(project: dict) -> Result:
    p = normalize(project)
    ctx = SCtx(p)
    for step in (_switch, _system, _access, _snmp, _syslog, _vlans, _port_groups, _lags, _write_vlans, _write_ports,
                 _static, _ospf, _services, _unsupported):
        step(ctx)
        ctx.row = None
    text = ctx.cfg.text()
    ctx.res.errors = _dedupe(ctx.res.errors)
    ctx.res.warnings = _dedupe(ctx.res.warnings)
    ctx.res.set_text = text
    ctx.res.hier_text = text
    ctx.res.hostname = _s(p["system"].get("hostname")) or "switch"
    return ctx.res
