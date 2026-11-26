"""Turn a project into Extreme Networks ExtremeXOS / Switch Engine commands.

EXOS has no config blocks: everything is a one-line ``configure`` / ``create``
/ ``enable`` command, so the output reads like a script (save it as a .xsf
file and run ``load script``, or paste it). VLANs have names and take their
ports with ``configure vlan USERS add ports 1-40 untagged``; every port starts
untagged in the ``Default`` VLAN, so that is emptied first. A LAG is a sharing
group named after its first port (the master port), and that port stands for
the LAG in VLANs. The management port is the ``Mgmt`` VLAN in ``VR-Mgmt``.

Passwords go in as plain text (``create account admin NAME "..."``); EXOS
encrypts them with its own scheme.
"""

from __future__ import annotations

import ipaddress
import re
import zoneinfo
from datetime import datetime

from . import __version__, exos_models as XM, vendors
from . import ports as P
from . import routing as R
from .eos import _dedupe
from .generator import (DOMAIN, HOSTNAME, NAME, USERNAME, Ctx, Result, _addresses, _ip, _list, _s, _truthy,
                        _vlan_name, normalize)

VENDOR = vendors.VENDORS["extreme"]
SPEEDS = {"10m": "10", "100m": "100", "1g": "1000", "10g": "10000"}
LEVELS = {"emergency": "Critical", "alert": "Critical", "critical": "Critical", "error": "Error",
          "warning": "Warning", "notice": "Notice", "info": "Info", "any": "Debug-Summary"}
_LAG = re.compile(r"^(?:lag|ae|po|port-channel|sharing)\s*(\d{1,3})$", re.I)


def _q(text: str) -> str:
    return '"' + text.replace('"', "'") + '"'


class XCtx(Ctx):
    def __init__(self, project: dict):
        super().__init__(project)
        self.lines: list[str] = []
        self.xmodels: list = []
        self.stacked = False
        self.vlan_names: dict[int, str] = {}
        self.untagged: dict[int, list[str]] = {}
        self.tagged: dict[int, list[str]] = {}
        self.vlan_addr: dict[int, list] = {}
        self.port_cmds: list[str] = []
        self.edge: list[str] = []
        self.bpdu: list[str] = []
        self.trusted: list[str] = []
        self.lag_master: dict[str, str] = {}   # LAG name -> master port
        self.mgmt_vr = "VR-Default"
        self.plaintext = False
        self.routing = False

    def comment(self, text: str) -> None:
        if self.lines:
            self.lines.append("#")
        self.lines.append(f"# {text}")

    def line(self, text: str) -> None:
        self.lines.append(text)


def _vid(ctx: XCtx, name: str) -> int:
    return int(ctx.vlan_by_name[name]["id"])


def _member(ctx: XCtx, vid: int, port: str, tagged: bool) -> None:
    lst = (ctx.tagged if tagged else ctx.untagged).setdefault(vid, [])
    if port not in lst:
        lst.append(port)


# ------------------------------------------------------------------ sections
def _switch(ctx: XCtx) -> None:
    members = ctx.p["switch"].get("members") or []
    if not members:
        ctx.error("Switch", "Add at least one switch.")
    ctx.stacked = len(members) > 1
    seen = set()
    for m in members:
        ctx.at("switch.members", m)
        try:
            slot = int(m.get("fpc", 1))
        except (TypeError, ValueError):
            slot = -1
        if slot == 0 and len(members) == 1:
            slot = 1
        if not 1 <= slot <= 8 or slot in seen:
            ctx.error("Switch", f"Stack slot {m.get('fpc')} must be 1-8 and used once.", "fpc")
            continue
        seen.add(slot)
        model = XM.get(m.get("model", ""))
        if model:
            ctx.xmodels.append((slot, model))
            for port in model.ports(slot, ctx.stacked):
                ctx.known[port["name"]] = port
            if ctx.stacked and not model.stack:
                ctx.error("Switch", f"{model.name} doesn't stack. Use one switch per project.", "model")
        elif m.get("model") != XM.CUSTOM:
            ctx.error("Switch", f"Unknown Extreme model '{m.get('model')}'. Pick one from the list or Custom.", "model")
    ctx.at("", None)
    if ctx.stacked and ctx.xmodels:
        ctx.warn("Switch", "SummitStack: enable stacking on each switch first ('enable stacking', slot numbers, reboot); "
                           "ports are then named slot:port (2:1).")
    try:
        for name in XM.expand(ctx.p["switch"].get("custom_ports", "")):
            ctx.known.setdefault(name, {"name": name, "kind": "access", "speed": "", "poe": False})
    except ValueError as exc:
        ctx.error("Switch", f"Custom ports: {exc}")


def _password(ctx: XCtx, section: str, label: str, value, key: str) -> str | None:
    value = _s(value)
    if not value:
        return None
    short = key if not ctx.row else key.rsplit(".", 1)[-1]
    if value.startswith("$"):
        ctx.error(section, f"{label}: this password was hashed for another vendor; type it again for EXOS.", short)
        return None
    if len(value) < 8 or len(value) > 32 or re.search(r"[\s\"']", value):
        ctx.error(section, f"{label}: use 8-32 characters with no spaces or quotes.", short)
        return None
    ctx.plaintext = True
    return value


def _tz(tz: str):
    """'America/Edmonton' -> ('MST', -420, has_dst)."""
    try:
        zone = zoneinfo.ZoneInfo(tz)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        return None
    year = datetime.now().year
    jan, jul = datetime(year, 1, 15, 12, tzinfo=zone), datetime(year, 7, 15, 12, tzinfo=zone)
    std = jan if jan.utcoffset() <= jul.utcoffset() else jul
    name = re.sub(r"[^A-Za-z]", "", std.tzname() or "")[:6] or "LOCAL"
    return name, int(std.utcoffset().total_seconds() // 60), jan.utcoffset() != jul.utcoffset()


def _system(ctx: XCtx) -> None:
    s = ctx.p["system"]
    ctx.comment("System")
    host = _s(s.get("hostname"))
    if not host:
        ctx.error("System", "Host name is required.", "system.hostname")
    elif not HOSTNAME.match(host) or len(host) > 32:
        ctx.error("System", f"Host name '{host}' may only use letters, digits and hyphens (max 32).", "system.hostname")
    else:
        ctx.line(f"configure snmp sysName {_q(host)}")
    addrs = _addresses(ctx, "System", "Management port (Mgmt)", s.get("mgmt_address"))
    use_mgmt = bool(addrs) and _truthy(s.get("mgmt_vrf"))
    ctx.mgmt_vr = "VR-Mgmt" if use_mgmt else "VR-Default"
    tz = _s(s.get("timezone"))
    if tz and tz != "UTC":
        z = _tz(tz)
        if not z:
            ctx.error("System", f"Time zone '{tz}' is not known.", "system.timezone")
        else:
            name, minutes, dst = z
            if dst and not tz.startswith(("America/", "Canada/", "US/")):
                ctx.warn("System", f"{tz}: EXOS 'autodst' follows the North American rule; set the summer time dates "
                                   "with 'configure timezone ... autodst begins ... ends ...' by hand.")
            ctx.line(f"configure timezone name {name} {minutes} {'autodst' if dst else 'noautodst'}")
    domain = _s(s.get("domain"))
    search = [domain] if domain else []
    search += [d for d in _list(s.get("domain_search")) if d != domain]
    for d in search:
        if DOMAIN.match(d):
            ctx.line(f"configure dns-client add domain-suffix {d}")
        else:
            ctx.error("System", f"Domain '{d}' is not a valid domain name.", "system.domain")
    for ns in _list(s.get("name_servers"))[:8]:
        if _ip(ctx, "System", "DNS server", ns):
            ctx.line(f"configure dns-client add name-server {ns} vr {ctx.mgmt_vr}")
    ntp = [_s(n.get("address")) for n in s.get("ntp_servers") or [] if _s(n.get("address"))]
    if not ntp:
        ctx.warn("System", "No NTP server: logs and certificates need the right time.")
    for a in ntp:
        if re.match(r"^[A-Za-z0-9.:-]+$", a):
            ctx.line(f"configure ntp server add {a} vr {ctx.mgmt_vr}")
    if ntp:
        ctx.line("enable ntp")
    if _s(s.get("ntp_source")):
        ctx.warn("System", "EXOS picks the NTP source from the VR's routing; the NTP source address is not written.")
    if addrs:
        for a in addrs:
            ctx.line(f"configure vlan Mgmt ipaddress {a.with_prefixlen}")
        gw = _s(s.get("mgmt_gateway"))
        if gw and (gw_ip := _ip(ctx, "System", "Management gateway", gw)):
            if not any(gw_ip in a.network for a in addrs if a.version == gw_ip.version):
                ctx.warn("System", f"Management gateway {gw} is not in the management subnet.")
            ctx.line(f"configure iproute add default {gw} vr VR-Mgmt")
        if not use_mgmt:
            ctx.warn("System", "The Mgmt port is always in VR-Mgmt. With 'Management VRF' off, NTP, DNS, SNMP traps and "
                               "logging go out through VR-Default (the switch ports) instead.")
    elif _s(s.get("mgmt_gateway")):
        ctx.warn("System", "Management gateway is set but the Mgmt port has no address.")
    banner = (s.get("banner") or "").strip()
    if banner:
        ctx.warn("System", "EXOS asks for the banner text at the CLI ('configure banner before-login'); not written.")


def _access(ctx: XCtx) -> None:
    a = ctx.p["access"]
    ctx.comment("Accounts and remote access")
    if _s(a.get("root_password")):
        ctx.warn("Access", "EXOS asks for the built-in admin password at the CLI ('configure account admin'); "
                           "the root password is not written. Add a super-user below instead.")
    names = set()
    admins = 0
    for i, u in enumerate(a.get("users") or []):
        ctx.at("access.users", u)
        name = _s(u.get("name"))
        if not name:
            continue
        if not USERNAME.match(name) or name in ("admin", "user", "root") or len(name) > 32:
            ctx.error("Access", f"User '{name}': use lower-case letters, digits, '.', '_' or '-' (not admin, user or root).", "name")
            continue
        if name in names:
            ctx.error("Access", f"User '{name}' is listed twice.", "name")
            continue
        names.add(name)
        cls = u.get("class") or "read-only"
        if cls == "unauthorized":
            continue
        pw = _password(ctx, "Access", f"User {name}", u.get("password"), f"access.users.{i}.password")
        if not pw:
            if not _s(u.get("password")):
                ctx.error("Access", f"User '{name}' needs a password.", "password")
            continue
        admins += cls == "super-user"
        ctx.line(f"create account {'admin' if cls == 'super-user' else 'user'} {name} {_q(pw)}")
        if _s(u.get("ssh_keys")):
            ctx.warn("Access", f"User {name}: EXOS adds SSH keys with 'create sshd2 user-key' and 'configure sshd2 "
                               "user-key ... add user'; add the key by hand.")
    ctx.at("", None)
    if not admins:
        ctx.warn("Access", "No super-user account: only the built-in admin can change the config.")
    if ctx.plaintext:
        ctx.warn("Access", "EXOS takes passwords in plain text in a script and encrypts them on the switch. They stay "
                           "readable in this project, so keep the project private.")
    ctx.line("enable ssh2")
    ctx.line("disable telnet")
    if _truthy(a.get("web")):
        ctx.line("enable web https")
        ctx.line("disable web http")
    else:
        ctx.line("disable web http")
    if _truthy(a.get("retry_options")):
        ctx.line("configure account all password-policy lockout-on-login-failures on")
    if _truthy(a.get("netconf")):
        ctx.warn("Access", "NETCONF on EXOS needs the netconf app ('enable netconf' on 22.x and later); not written.")


def _snmp(ctx: XCtx) -> None:
    s = ctx.p["snmp"]
    comms = [c for c in s.get("communities") or [] if _s(c.get("name"))]
    targets = _list(s.get("trap_targets"))
    if not (comms or targets or s.get("v3_users") or _s(s.get("location")) or _s(s.get("contact"))):
        return
    ctx.comment("SNMP")
    if _s(s.get("location")):
        ctx.line(f"configure snmp sysLocation {_q(_s(s.get('location')))}")
    if _s(s.get("contact")):
        ctx.line(f"configure snmp sysContact {_q(_s(s.get('contact')))}")
    if comms:
        ctx.line("configure snmpv2c delete community all")
        ctx.line("enable snmp access snmp-v1v2c")
    for c in comms:
        ctx.at("snmp.communities", c)
        name = _s(c.get("name"))
        if not re.fullmatch(r"[A-Za-z0-9_.@#%+=-]{1,32}", name):
            ctx.error("SNMP", f"Community '{name}' may only use letters, digits and _ . @ # % + = - (max 32).", "name")
            continue
        if name.lower() in ("public", "private"):
            ctx.warn("SNMP", f"Community '{name}' is a well-known default; pick something harder to guess.")
        ctx.line(f"configure snmpv2c add community {'readwrite' if c.get('access') == 'read-write' else 'readonly'} {_q(name)}")
        if _list(c.get("clients")):
            ctx.warn("SNMP", f"Community '{name}': EXOS limits SNMP clients with an access profile (policy file); not "
                             "written. Filter SNMP on your firewall instead.")
    ctx.at("", None)
    if s.get("v3_users"):
        ctx.warn("SNMP", "SNMPv3 users are not written for EXOS yet ('configure snmpv3 add user').")
    comm = _s(s.get("trap_community")) or (comms[0]["name"] if comms else "")
    for t in targets:
        if _ip(ctx, "SNMP", "Trap target", t):
            if comm:
                ctx.line(f"configure snmp add trapreceiver {t} community {_q(comm)} vr {ctx.mgmt_vr}")
            else:
                ctx.error("SNMP", "Trap targets need a community.", "snmp.trap_community")


def _syslog(ctx: XCtx) -> None:
    hosts = [h for h in ctx.p["syslog"].get("hosts") or [] if _s(h.get("address"))]
    if not hosts:
        return
    ctx.comment("Logging")
    for h in hosts:
        ctx.at("syslog.hosts", h)
        addr = _s(h.get("address"))
        if not _ip(ctx, "Logging", "Syslog server", addr):
            continue
        port = _s(h.get("port"))
        if port and port != "514" and not (port.isdigit() and 1 <= int(port) <= 65535):
            ctx.error("Logging", f"Syslog port '{port}' is not valid.", "port")
            continue
        target = f"{addr}{':' + port if port and port != '514' else ''} vr {ctx.mgmt_vr} local0"
        ctx.line(f"configure syslog add {target}")
        ctx.line(f"enable log target syslog {target}")
        ctx.line(f"configure log target syslog {target} filter DefaultFilter severity {LEVELS.get(h.get('level') or 'info', 'Info')}")
    ctx.at("", None)


def _vlans(ctx: XCtx) -> None:
    vlans = [v for v in ctx.p["vlans"] if _s(v.get("name")) or _s(v.get("id"))]
    if not vlans:
        ctx.warn("VLANs", "No VLANs yet: every port stays in the Default VLAN.")
    for v in vlans:
        ctx.at("vlans", v)
        name, vid = _s(v.get("name")), _s(v.get("id"))
        if not NAME.match(name) or len(name) > 32:
            ctx.error("VLANs", f"VLAN name '{name}' must start with a letter, use letters, digits, '-', '_' or '.', max 32.", "name")
            continue
        if not vid.isdigit() or not 2 <= int(vid) <= 4094:
            ctx.error("VLANs", f"VLAN {name}: ID must be 2-4094 (VLAN 1 is the Default VLAN on EXOS).", "id")
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
        # 'Default' and 'Mgmt' are built-in VLAN names (EXOS names ignore case).
        ctx.vlan_names[n] = f"{name}-{n}" if name.lower() in ("default", "mgmt") else name
        if ctx.vlan_names[n] != name:
            ctx.warn("VLANs", f"VLAN {name}: EXOS already has a VLAN called {name.capitalize()}, so this one is named "
                              f"{ctx.vlan_names[n]} on the switch.")
        addrs = _addresses(ctx, "VLANs", f"VLAN {name} address", v.get("irb"))
        if addrs:
            ctx.vlan_addr[n] = addrs
            ctx.l3_ifaces.add(f"vlan {n}")
        elif _truthy(v.get("dhcp_relay")):
            ctx.error("VLANs", f"VLAN {name}: DHCP relay needs a VLAN address.", "irb")
        if _truthy(v.get("dai")) or _truthy(v.get("ipsg")):
            ctx.warn("VLANs", f"VLAN {name}: ARP validation and IP source guard are not written for EXOS yet.")
        if _s(v.get("vni")) or _s(v.get("vga")) or _s(v.get("vrf")):
            ctx.warn("VLANs", f"VLAN {name}: VNI, virtual gateway and VRF are not written for EXOS.")
    ctx.at("", None)


def _claim(ctx: XCtx, section: str, label: str, names: list[str]) -> list[str]:
    ok = []
    for name in names:
        if name in ctx.used:
            ctx.error(section, f"{label}: {name} is already used by {ctx.used[name]}.", "ports" if section == "Ports" else "members")
            continue
        if ctx.known and name not in ctx.known:
            ctx.warn(section, f"{label}: {name} is not a port on the selected model(s).")
        ctx.used[name] = label
        ok.append(name)
    return ok


def _vlans_for(ctx: XCtx, section: str, label: str, row: dict, refs: list[str]) -> str:
    mode = row.get("mode") or "access"
    if mode == "access":
        vlan = _vlan_name(ctx, section, label, row.get("vlan"), "vlan")
        if vlan:
            for r in refs:
                _member(ctx, _vid(ctx, vlan), r, False)
        elif not _s(row.get("vlan")):
            ctx.warn(section, f"{label}: no access VLAN, so the ports end up in no VLAN once Default is emptied.")
        voice = _vlan_name(ctx, section, f"{label} voice", row.get("voice"), "voice")
        if not voice and not _s(row.get("voice")):
            voice = next((v["name"] for v in ctx.p["vlans"] if _truthy(v.get("voice")) and v["name"] != vlan
                          and v["name"] in ctx.vlan_by_name), "")
        if voice and voice == vlan:
            ctx.error(section, f"{label}: the voice VLAN must differ from the data VLAN.", "voice")
        elif voice:
            for r in refs:
                _member(ctx, _vid(ctx, voice), r, True)
            ctx.port_cmds.append(f"configure lldp ports {XM.compact(refs)} advertise vendor-specific med policy "
                                 f"application voice vlan {ctx.vlan_names[_vid(ctx, voice)]} dscp 46")
    elif mode == "trunk":
        names = _list(row.get("vlans"))
        if not names:
            ctx.error(section, f"{label}: a trunk needs at least one VLAN (or 'all').", "vlans")
        if any(n.lower() == "all" for n in names):
            vids = list(ctx.vlan_by_id)
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
        ctx.trusted.extend(refs)
        if _truthy(row.get("root_guard")):
            ctx.port_cmds.append(f"configure stpd s0 ports restricted-role enable {XM.compact(refs)}")
        if _truthy(row.get("loop_protect")):
            ctx.warn(section, f"{label}: loop protection is not written for EXOS (ELRP does this); skipped.")
    elif mode == "routed":
        ctx.error(section, f"{label}: EXOS has no routed ports; put the address on a VLAN with one access port.", "mode")
    elif mode != "disabled":
        ctx.error(section, f"{label}: unknown mode '{mode}'.", "mode")
    if _s(row.get("vlan_translate")):
        ctx.error(section, f"{label}: per-port VLAN translation is not written for EXOS.", "vlan_translate")
    return mode


def _port_groups(ctx: XCtx) -> None:
    for i, row in enumerate([r for r in ctx.p["ports"] if _s(r.get("ports"))]):
        ctx.at("ports", row)
        label = _s(row.get("name")) or f"Port group {i + 1}"
        try:
            names = XM.expand(row.get("ports"))
        except ValueError as exc:
            ctx.error("Ports", f"{label}: {exc} (example: 1-24, 49).", "ports")
            continue
        names = _claim(ctx, "Ports", label, names)
        if not names:
            continue
        mode = _vlans_for(ctx, "Ports", label, row, names)
        _port_settings(ctx, "Ports", label, row, names, mode)
        for port in names:
            voice = mode == "access" and (bool(_s(row.get("voice"))) or any(
                _truthy(v.get("voice")) and v["name"] != _s(row.get("vlan")) for v in ctx.p["vlans"]))
            ctx.res.ports[port] = {"use": mode, "label": label, "voice": voice, "role": _s(row.get("role"))}
    ctx.at("", None)


def _port_settings(ctx: XCtx, section: str, label: str, row: dict, names: list[str], mode: str) -> None:
    plist = XM.compact(names)
    desc = _s(row.get("description"))
    if desc:
        ctx.port_cmds.append(f"configure ports {plist} description-string {_q(desc[:255])}")
    if mode == "disabled":
        ctx.port_cmds.append(f"disable ports {plist}")
    speed = _s(row.get("speed")).lower()
    if speed:
        if speed in SPEEDS:
            ctx.port_cmds.append(f"configure ports {plist} auto off speed {SPEEDS[speed]} duplex full")
        else:
            ctx.error(section, f"{label}: speed must be one of {', '.join(SPEEDS)} on EXOS.", "speed")
    if _s(row.get("mtu")):
        ctx.warn(section, f"{label}: EXOS turns on jumbo frames per port ('enable jumbo-frame ports'); the MTU is not written.")
    if mode == "access":
        if _truthy(row.get("edge")):
            ctx.edge.extend(names)
            if _truthy(ctx.p["services"].get("bpdu_block_on_edge")):
                ctx.bpdu.extend(names)
        limit = _s(row.get("mac_limit"))
        vlan = _vlan_name(ctx, section, label, row.get("vlan"), None) if _s(row.get("vlan")) else None
        if limit:
            if not (limit.isdigit() and 1 <= int(limit) <= 500000):
                ctx.error(section, f"{label}: MAC limit must be a number.", "mac_limit")
            elif vlan:
                ctx.port_cmds.append(f"configure ports {plist} vlan {ctx.vlan_names[_vid(ctx, vlan)]} limit-learning {limit}")
        if _truthy(row.get("sticky")):
            ctx.warn(section, f"{label}: sticky MAC is not written for EXOS; skipped.")
        if _truthy(row.get("dhcp_trusted")):
            ctx.trusted.extend(names)
        if _s(row.get("dot1x")):
            ctx.warn(section, f"{label}: 802.1X / MAB (netlogin) is not written for EXOS yet.")
    poe, pmax = _s(row.get("poe")), _s(row.get("poe_max"))
    if poe or pmax:
        no_poe = [p for p in names if p in ctx.known and not ctx.known[p].get("poe")]
        if no_poe:
            ctx.warn(section, f"{label}: {', '.join(no_poe[:3])}{'…' if len(no_poe) > 3 else ''} has no PoE; PoE setting skipped.")
        yes = XM.compact([p for p in names if p not in no_poe])
        if yes:
            if poe == "off":
                ctx.port_cmds.append(f"disable inline-power ports {yes}")
            elif poe in ("high", "low"):
                ctx.port_cmds.append(f"configure inline-power priority {poe} ports {yes}")
            if pmax and poe != "off":
                try:
                    watts = float(pmax)
                except ValueError:
                    watts = -1
                if 3 <= watts <= 90:
                    ctx.port_cmds.append(f"configure inline-power operator-limit {int(watts * 1000)} ports {yes}")
                else:
                    ctx.error(section, f"{label}: maximum PoE power must be 3-90 watts.", "poe_max")


def _lags(ctx: XCtx) -> None:
    seen = set()
    for row in [r for r in ctx.p["lags"] if _s(r.get("name")) or _s(r.get("members"))]:
        ctx.at("lags", row)
        raw = _s(row.get("name")) or "lag"
        if raw.lower() in seen:
            ctx.error("LAGs", f"{raw} is listed twice.", "name")
            continue
        seen.add(raw.lower())
        try:
            members = XM.expand(row.get("members"))
        except ValueError as exc:
            ctx.error("LAGs", f"{raw}: {exc}", "members")
            continue
        members = _claim(ctx, "LAGs", raw, members)
        if not members:
            ctx.error("LAGs", f"{raw}: add member ports.", "members")
            continue
        members.sort(key=XM.key)
        master = members[0]
        label = f"{raw} (master port {master})"
        if len(members) == 1:
            ctx.warn("LAGs", f"{label}: only one member port, so there's no redundancy.")
        if len(members) > 8:
            ctx.error("LAGs", f"{label}: an EXOS LAG takes at most 8 ports.", "members")
        lacp = row.get("lacp") if row.get("lacp") in ("active", "passive", "static") else "active"
        ctx.port_cmds.append(f"enable sharing {master} grouping {XM.compact(members)} algorithm address-based L3_L4"
                             + ("" if lacp == "static" else " lacp"))
        if lacp == "passive":
            ctx.port_cmds.append(f"configure sharing {master} lacp activity-mode passive")
        if lacp != "static" and _truthy(row.get("lacp_fast")):
            ctx.port_cmds.append(f"configure sharing {master} lacp timeout short")
        ml = _s(row.get("min_links"))
        if ml:
            if ml.isdigit() and 1 <= int(ml) <= len(members):
                ctx.port_cmds.append(f"configure sharing {master} minimum-active {ml}")
            else:
                ctx.error("LAGs", f"{label}: minimum links must be 1-{len(members)}.", "min_links")
        if _s(row.get("esi")):
            ctx.warn("LAGs", f"{label}: EVPN multihoming is not written for EXOS (MLAG is set up by hand).")
        ctx.lag_master[raw] = master
        mode = _vlans_for(ctx, "LAGs", label, row, [master])
        row2 = {**row, "edge": False, "speed": ""}
        _port_settings(ctx, "LAGs", label, row2, [master], mode)
        for mem in members:
            ctx.res.ports[mem] = {"use": "lag", "label": raw}
    ctx.at("", None)


def _write_vlans(ctx: XCtx) -> None:
    r = ctx.p["routing"]
    ctx.comment("VLANs (every port starts untagged in Default, so it is emptied first)")
    if ctx.p["ports"] or ctx.p["lags"]:
        ctx.line("configure vlan Default delete ports all")
    for vid in sorted(ctx.vlan_by_id):
        ctx.line(f"create vlan {ctx.vlan_names[vid]} tag {vid}")
    for vid in sorted(ctx.vlan_by_id):
        name = ctx.vlan_names[vid]
        if ctx.untagged.get(vid):
            ctx.line(f"configure vlan {name} add ports {XM.compact(ctx.untagged[vid])} untagged")
        if ctx.tagged.get(vid):
            ctx.line(f"configure vlan {name} add ports {XM.compact(ctx.tagged[vid])} tagged")
    servers = [sv for sv in _list(r.get("dhcp_relay_servers")) if _ip(ctx, "Routing", "DHCP server", sv)]
    relay = {int(v["id"]) for v in ctx.vlan_by_name.values() if _truthy(v.get("dhcp_relay")) and _s(v.get("irb"))}
    if relay and not servers:
        ctx.error("Routing", "VLANs use DHCP relay but no DHCP server is set on the Routing tab.")
    if ctx.vlan_addr:
        ctx.comment("VLAN addresses and routing")
    for vid, addrs in sorted(ctx.vlan_addr.items()):
        for a in addrs:
            ctx.line(f"configure vlan {ctx.vlan_names[vid]} ipaddress {a.with_prefixlen}")
        ctx.line(f"enable ipforwarding {'ipv6 ' if all(a.version == 6 for a in addrs) else ''}vlan {ctx.vlan_names[vid]}")
    if relay and servers:
        for sv in servers:
            ctx.line(f"configure bootprelay add {sv} vr VR-Default")
        for vid in sorted(relay):
            ctx.line(f"enable bootprelay ipv4 vlan {ctx.vlan_names[vid]}")


def _write_ports(ctx: XCtx) -> None:
    if ctx.port_cmds:
        ctx.comment("Ports and LAGs")
    for c in ctx.port_cmds:
        ctx.line(c)


def _l3(ctx: XCtx) -> None:
    r = ctx.p["routing"]
    lo = _s(r.get("loopback"))
    if lo:
        addrs = _addresses(ctx, "Routing", "Loopback", lo if "/" in lo else f"{lo}/32")
        if addrs:
            ctx.line("create vlan lo0")
            ctx.line("enable loopback-mode vlan lo0")
            for a in addrs:
                ctx.line(f"configure vlan lo0 ipaddress {a.with_prefixlen}")
                if a.version == 4:
                    ctx.loopback_ip = str(a.ip)
            ctx.line("enable ipforwarding vlan lo0")
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


def _static(ctx: XCtx) -> None:
    routes = [x for x in ctx.p["routing"].get("static") or [] if _s(x.get("prefix"))]
    if routes:
        ctx.comment("Static routes")
    for x in routes:
        ctx.at("routing.static", x)
        prefix = "0.0.0.0/0" if _s(x.get("prefix")) == "default" else _s(x.get("prefix"))
        net = _ip(ctx, "Routing", "Route", prefix, allow_net=True)
        if not net:
            continue
        dest = "default" if net.prefixlen == 0 else str(net)
        nh = _s(x.get("next_hop"))
        pref = _s(x.get("preference"))
        if pref:
            ctx.warn("Routing", f"Route {net}: EXOS sets a metric, not a preference; the preference is not written.")
        if nh in ("discard", "reject"):
            ctx.line(f"configure iproute add blackhole {dest}")
            continue
        nh_ip = _ip(ctx, "Routing", f"Route {net} next hop", nh) if nh else None
        if not nh_ip:
            if not nh:
                ctx.error("Routing", f"Route {net}: add a next hop (an IP, 'discard' or 'reject').", "next_hop")
            continue
        if not any(nh_ip in iface.network for _, iface in ctx.l3_networks if iface.version == nh_ip.version):
            ctx.warn("Routing", f"Route {net}: next hop {nh} is not in any subnet on this switch.")
        ctx.line(f"configure {'iproute' if net.version == 4 else 'iproute ipv6'} add {dest} {nh}")
    ctx.at("", None)


def _ospf_vlan(ctx: XCtx, raw: str) -> str | None:
    t = raw.strip()
    if re.fullmatch(r"(?:lo|loopback)\s*0?(?:\.0)?", t, re.I):
        return "lo0" if ctx.loopback_ip else None
    m = re.fullmatch(r"(?:irb\.|vlan\s*|ve\s*)(\d{1,4})", t, re.I)
    if m and int(m.group(1)) in ctx.vlan_addr:
        return ctx.vlan_names[int(m.group(1))]
    if t in ctx.vlan_by_name and _vid(ctx, t) in ctx.vlan_addr:
        return ctx.vlan_names[_vid(ctx, t)]
    return None


def _ospf(ctx: XCtx) -> None:
    o = ctx.p["routing"].get("ospf") or {}
    if not _truthy(o.get("enabled")):
        return
    ctx.comment("OSPF (needs the Advanced Edge license or higher)")
    if ctx.router_id:
        ctx.line(f"configure ospf routerid {ctx.router_id}")
    else:
        ctx.warn("OSPF", "Set a router ID or loopback (Routing tab) so OSPF has a stable ID.")
    if _s(o.get("reference_bandwidth")) or _s(o.get("export")):
        ctx.warn("OSPF", "Reference bandwidth and export policies are not written for EXOS yet.")
    for a in o.get("areas") or []:
        ctx.at("routing.ospf.areas", a)
        area = _s(a.get("area")) or "0.0.0.0"
        if not re.fullmatch(r"\d+|\d+\.\d+\.\d+\.\d+", area):
            ctx.error("OSPF", f"Area '{area}' must be a number or dotted (0.0.0.0).", "area")
            continue
        if area.isdigit():
            area = str(ipaddress.IPv4Address(int(area)))
        if area != "0.0.0.0":
            ctx.line(f"create ospf area {area}")
            kind = a.get("type") or "normal"
            if kind in ("stub", "nssa"):
                ctx.line(f"configure ospf area {area} {kind} summary stub-default-cost 1")
        if _s(a.get("md5_key")):
            ctx.warn("OSPF", f"Area {area}: OSPF authentication is not written for EXOS yet.")
        passive = {x.lower() for x in P.iface_list(a.get("passive"))}
        p2p = {x.lower() for x in P.iface_list(a.get("p2p"))}
        for raw in P.iface_list(a.get("interfaces")) + sorted(passive):
            vlan = _ospf_vlan(ctx, raw)
            if not vlan:
                ctx.error("OSPF", f"Area {area}: '{raw}' must be a VLAN with an address (vlan 20) or the loopback; "
                                  "EXOS runs OSPF on VLANs.", "interfaces")
                continue
            quiet = raw.lower() in passive or vlan == "lo0"
            ctx.line(f"configure ospf add vlan {vlan} area {area}" + (" passive" if quiet else ""))
            if raw.lower() in p2p:
                ctx.line(f"configure ospf vlan {vlan} link-type point-to-point")
    ctx.at("", None)
    ctx.line("enable ospf")


def _bgp(ctx: XCtx) -> None:
    groups = [g for g in ctx.p["routing"].get("bgp_groups") or [] if _s(g.get("name")) or _s(g.get("neighbors"))]
    if not groups:
        return
    if not ctx.asn:
        ctx.error("BGP", "BGP needs the switch's AS number (Routing tab).", "routing.asn")
        return
    ctx.comment("BGP (needs the Core license)")
    ctx.line("disable bgp")
    ctx.line(f"configure bgp AS-number {ctx.asn}")
    if ctx.router_id:
        ctx.line(f"configure bgp routerid {ctx.router_id}")
    if any(_truthy(g.get("multipath")) for g in groups) or _truthy(ctx.p["routing"].get("ecmp")):
        ctx.line("configure bgp maximum-paths 4")
    if ctx.loopback_ip:
        ctx.line(f"configure bgp add network {ctx.loopback_ip}/32")
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
        if _s(g.get("import")) or _s(g.get("export")) or _s(g.get("bfd")):
            ctx.warn("BGP", f"Group {name}: policies and BFD are not written for EXOS yet.")
        local = _s(g.get("local_address"))
        for ip, asn, desc in neighbors:
            remote = ctx.asn if not external else (asn or (int(peer_as) if peer_as else None))
            if not remote:
                ctx.error("BGP", f"Group {name}: neighbor {ip} needs a peer AS (on the group or after the IP).", "neighbors")
                continue
            ctx.line(f"create bgp neighbor {ip} remote-AS-number {remote}")
            d = desc or _s(g.get("description")) or name
            ctx.line(f"configure bgp neighbor {ip} description {_q(d)}")
            if local:
                ctx.line(f"configure bgp neighbor {ip} source-interface ipaddress {local}")
            if _s(g.get("auth_key")):
                ctx.line(f"configure bgp neighbor {ip} password {_q(_s(g.get('auth_key')))}")
            ctx.line(f"enable bgp neighbor {ip}")
    ctx.at("", None)
    ctx.line("enable bgp")


def _services(ctx: XCtx) -> None:
    s = ctx.p["services"]
    ctx.comment("Switching services")
    if not _truthy(s.get("lldp")):
        ctx.line("disable lldp ports all")
    stp = s.get("stp")
    if stp == "rstp":
        ctx.line("configure stpd s0 mode dot1w")
        for vid in sorted(ctx.vlan_by_id):
            ctx.line(f"enable stpd s0 auto-bind vlan {ctx.vlan_names[vid]}")
        prio = _s(s.get("bridge_priority")).lower()
        if prio:
            m = re.fullmatch(r"(\d+)(k?)", prio)
            val = int(m.group(1)) * (1024 if m.group(2) else 1) if m else -1
            val = 4096 * round(val / 4096) if m and m.group(2) else val
            if 0 <= val <= 61440 and val % 4096 == 0:
                ctx.line(f"configure stpd s0 priority {val}")
            else:
                ctx.error("Services", "Bridge priority must be 0, 4k, 8k ... 60k (steps of 4k).", "services.bridge_priority")
        if ctx.edge:
            ctx.line(f"configure stpd s0 ports link-type edge {XM.compact(ctx.edge)}")
        if ctx.bpdu:
            ctx.line(f"configure stpd s0 ports bpdu-restrict enable {XM.compact(ctx.bpdu)}")
        ctx.line("enable stpd s0")
    elif stp == "none":
        ctx.line("disable stpd s0")
        ctx.warn("Services", "Spanning tree is off: a cabling loop will take the network down.")
    if _truthy(s.get("storm_control")):
        ctx.warn("Services", "EXOS sets storm control as a packet rate ('configure ports ... rate-limit flood'); not written.")
    snoop = [ctx.vlan_names[int(v["id"])] for v in ctx.vlan_by_name.values() if _truthy(v.get("snooping"))]
    for name in snoop:
        ctx.line(f"enable ip-security dhcp-snooping vlan {name} ports all violation-action drop-packet")
    if snoop and ctx.trusted:
        ctx.line(f"configure trusted-ports {XM.compact(list(dict.fromkeys(ctx.trusted)))} trust-for dhcp-server")
    if _truthy(s.get("disable_unused")) and ctx.known:
        unused = [n for n, info in ctx.known.items() if n not in ctx.used and info["kind"] in ("access", "uplink")]
        if unused:
            ctx.line(f"disable ports {XM.compact(unused)}")
            for n in unused:
                ctx.res.ports.setdefault(n, {"use": "disabled", "label": "Unused"})


def _unsupported(ctx: XCtx) -> None:
    p = ctx.p
    if _truthy((p.get("evpn") or {}).get("enabled")):
        ctx.warn("EVPN", "EVPN-VXLAN is not written for EXOS.")
    if any((p.get("policy") or {}).get(k) for k in ("prefix_lists", "communities", "terms")):
        ctx.warn("Policies", "Routing policies are not written for EXOS yet.")
    if _truthy((p.get("qos") or {}).get("enabled")):
        ctx.warn("QoS", "QoS is not written for EXOS yet.")
    if any(_s(r.get("dot1x")) for r in p["ports"]):
        ctx.warn("Security", "802.1X / MAB (netlogin) is not written for EXOS yet.")


def header(p: dict) -> list[str]:
    name = _s(p.get("name")) or _s(p.get("system", {}).get("hostname")) or "switch"
    model = ", ".join(f"{_s(m.get('model'))}" for m in p["switch"].get("members") or [])
    return [f"Extreme Networks EXOS / Switch Engine commands for {name}", f"Hardware: {model}",
            f"Made by Multi-Vendor Switch Config Builder {__version__}. Review before you load it."]


def build(project: dict) -> Result:
    p = normalize(project)
    ctx = XCtx(p)
    for t in header(p):
        ctx.line(f"# {t}")
    for step in (_switch, _system, _access, _snmp, _syslog, _vlans, _port_groups, _lags, _write_vlans, _l3,
                 _write_ports, _static, _ospf, _bgp, _services, _unsupported):
        step(ctx)
        ctx.row = None
    text = "\n".join(ctx.lines) + "\n"
    ctx.res.errors = _dedupe(ctx.res.errors)
    ctx.res.warnings = _dedupe(ctx.res.warnings)
    ctx.res.set_text = text
    ctx.res.hier_text = text
    ctx.res.hostname = _s(p["system"].get("hostname")) or "switch"
    return ctx.res
