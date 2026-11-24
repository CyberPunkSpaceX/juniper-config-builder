"""Turn a project into Brocade / Ruckus FastIron configuration (ICX, FCX, FGS, FLS).

FastIron is VLAN-centric: ports join VLANs inside the ``vlan`` block (tagged
or untagged) instead of the port naming its VLANs. The project format is the
same as for the other builders; the generator gathers each VLAN's members
from the port groups and LAGs. Older families (see fastiron_models.legacy/old)
get the older syntax for native VLANs, LAGs, NTP and 802.1X.
"""

from __future__ import annotations

import ipaddress
import re
import zoneinfo
from datetime import datetime

from . import __version__, fastiron_models as FM, vendors
from . import ports as P
from . import routing as R
from .cryptpw import is_md5, md5_crypt
from .eos import _dedupe
from .generator import (DOMAIN, HOSTNAME, NAME, USERNAME, Ctx, Result, _addresses, _ip, _list, _s, _truthy,
                        _vlan_name, normalize)
from .textcfg import Blocks

VENDOR = vendors.VENDORS["ruckus"]
SPEEDS = {"10m": "10-full", "100m": "100-full", "1g": "1000-full", "2.5g": "2500-full", "5g": "5g-full",
          "10g": "10g-full", "25g": "25g-full", "40g": "40g-full", "100g": "100g-full"}
PRIV = {"super-user": "0", "operator": "4", "read-only": "5"}
SNMP_AUTH = {"md5": "md5", "sha": "sha", "sha224": "sha", "sha256": "sha", "sha384": "sha", "sha512": "sha"}
SNMP_PRIV = {"aes128": "aes", "des": "des", "3des": "des"}
POE_PRIO = {"high": "2", "low": "3"}
_LAG = re.compile(r"^(?:lag|ae|po|port-channel)\s*(\d{1,3})$", re.I)


def _ports(spec) -> list[str]:
    text = re.sub(r"\b(?:ethernet|ethe|eth|e)\s+(?=\d)", "", _s(spec), flags=re.I)
    return P.expand_named(text, FM.ALIASES)


def _ethe(names: list[str]) -> str:
    """['1/1/1', '1/1/2', '1/1/5'] -> 'ethe 1/1/1 to 1/1/2 ethe 1/1/5'."""
    return " ".join(f"ethe {a}" if a == b else f"ethe {a} to {b}" for a, b in P.named_runs(names))


def _mask(a) -> str:
    return f"ip address {a.ip} {a.netmask}" if a.version == 4 else f"ipv6 address {a.with_prefixlen}"


class FiCtx(Ctx):
    def __init__(self, project: dict):
        super().__init__(project)
        self.cfg = Blocks(indent=" ")
        self.fmodels: list = []
        self.legacy = False
        self.old = False
        self.svis: dict[int, list] = {}
        self.tagged: dict[int, list[str]] = {}     # vlan id -> member refs ('1/1/1' or 'lag 1')
        self.untagged: dict[int, list[str]] = {}
        self.native_of: dict[str, int] = {}        # port -> its untagged VLAN
        self.iface: dict[str, list[str]] = {}      # port group header -> lines (kept in order)
        self.trunk_ports: list[str] = []
        self.trunk_headers: list[str] = []
        self.dot1x: list[str] = []
        self.mab: list[str] = []
        self.banner = None
        self.lag_ids: dict[str, str] = {}          # member port -> 'lag N' (modern) or primary port (legacy)


# ------------------------------------------------------------------ helpers
def _secret(ctx: FiCtx, section: str, label: str, value, key: str) -> str | None:
    value = _s(value)
    if not value:
        return None
    if is_md5(value):
        return value
    short = key if not ctx.row else key.rsplit(".", 1)[-1]
    if value.startswith("$"):
        ctx.error(section, f"{label}: this password was hashed for another vendor; type it again for FastIron.", short)
        return None
    if len(value) < 8 or " " in value:
        ctx.error(section, f"{label}: use at least 8 characters and no spaces.", short)
        return None
    hashed = md5_crypt(value)
    ctx.res.hashed[key] = hashed
    return hashed


def _member(ctx: FiCtx, vid: int, ref: str, tagged: bool) -> None:
    (ctx.tagged if tagged else ctx.untagged).setdefault(vid, [])
    lst = (ctx.tagged if tagged else ctx.untagged)[vid]
    if ref not in lst:
        lst.append(ref)


def _timezone(tz: str) -> list[str] | None:
    try:
        zone = zoneinfo.ZoneInfo(tz)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        return None
    year = datetime.now().year
    jan, jul = datetime(year, 1, 15, tzinfo=zone), datetime(year, 7, 15, tzinfo=zone)
    std = min(jan.utcoffset(), jul.utcoffset())
    hours = int(std.total_seconds() // 3600)
    mins = int(abs(std.total_seconds()) % 3600 // 60)
    us = {-5: "eastern", -6: "central", -7: "mountain", -8: "pacific", -9: "alaska", -10: "hawaii"}
    lines = []
    if tz.startswith("America/") and hours in us and not mins:
        lines.append(f"clock timezone us {us[hours]}")
    else:
        sign = "+" if hours >= 0 else "-"
        lines.append(f"clock timezone gmt GMT{sign}{abs(hours):02d}" + (f":{mins:02d}" if mins else ""))
    if jan.utcoffset() != jul.utcoffset():
        lines.append("clock summer-time")
    return lines


# ------------------------------------------------------------------ sections
def _switch(ctx: FiCtx) -> None:
    members = ctx.p["switch"].get("members") or []
    if not members:
        ctx.error("Switch", "Add at least one switch.")
    seen = set()
    for m in members:
        ctx.at("switch.members", m)
        try:
            unit = int(m.get("fpc", 1))
        except (TypeError, ValueError):
            unit = -1
        if unit == 0 and len(members) == 1:
            unit = 1
        if not 1 <= unit <= 12 or unit in seen:
            ctx.error("Switch", f"Stack unit {m.get('fpc')} must be 1-12 and used once.", "fpc")
            continue
        seen.add(unit)
        model = FM.get(m.get("model", ""))
        if model:
            ctx.fmodels.append((unit, model))
            for port in model.ports(unit):
                ctx.known[port["name"]] = port
            if len(members) > 1 and not model.stack:
                ctx.error("Switch", f"{model.name} doesn't stack. Use one switch per project.", "model")
        elif m.get("model") != FM.CUSTOM:
            ctx.error("Switch", f"Unknown Brocade/Ruckus model '{m.get('model')}'. Pick one from the list or Custom.", "model")
    ctx.at("", None)
    families = {mod.family for _, mod in ctx.fmodels}
    if len(families) > 1:
        ctx.error("Switch", f"A stack can't mix {' and '.join(sorted(families))} switches.")
    ctx.legacy = any(mod.legacy for _, mod in ctx.fmodels)
    ctx.old = any(mod.old for _, mod in ctx.fmodels)
    if len(members) > 1:
        ctx.cfg.comment("Stack: run 'stack enable' on unit 1, then 'stack secure-setup' to join the others.")
        ctx.cfg.comment("The units and their modules are added to the config when they join.")
    try:
        for name in _ports(ctx.p["switch"].get("custom_ports", "")):
            ctx.known.setdefault(name, {"name": name, "kind": "access", "speed": "", "poe": False})
    except ValueError as exc:
        ctx.error("Switch", f"Custom ports: {exc}")


def _system(ctx: FiCtx) -> None:
    s, cfg = ctx.p["system"], ctx.cfg
    cfg.comment("System")
    host = _s(s.get("hostname"))
    if not host:
        ctx.error("System", "Host name is required.", "system.hostname")
    elif not HOSTNAME.match(host):
        ctx.error("System", f"Host name '{host}' may only use letters, digits and hyphens (max 63).", "system.hostname")
    else:
        cfg.line(f"hostname {host}")
    domain = _s(s.get("domain"))
    if domain:
        if DOMAIN.match(domain):
            cfg.line(f"ip dns domain-list {domain}")
        else:
            ctx.error("System", f"Domain '{domain}' is not a valid domain name.", "system.domain")
    dns = [ns for ns in _list(s.get("name_servers")) if _ip(ctx, "System", "DNS server", ns)]
    if dns:
        cfg.line(f"ip dns server-address {' '.join(dns[:4])}")
    tz = _s(s.get("timezone"))
    if tz and tz != "UTC":
        lines = _timezone(tz)
        if lines:
            for ln in lines:
                cfg.line(ln)
        else:
            ctx.error("System", f"Time zone '{tz}' is not known.", "system.timezone")
    ntp = [n for n in s.get("ntp_servers") or [] if _s(n.get("address"))]
    if not ntp:
        ctx.warn("System", "No NTP server: logs and certificates need the right time.")
    servers = []
    for n in ntp:
        addr = _s(n.get("address"))
        if re.match(r"^[0-9a-fA-F:.]+$", addr) and not _ip(ctx, "System", "NTP server", addr):
            continue
        servers.append(addr)
    if servers:
        if ctx.old:
            for addr in servers:
                cfg.line(f"sntp server {addr}")
        else:
            cfg.block("ntp", *[f"server {a}" for a in servers])
    if _truthy(s.get("mgmt_vrf")):
        ctx.warn("System", "A management VRF is not written for FastIron; the management port uses the main table.")
    addrs = _addresses(ctx, "System", "Management port", s.get("mgmt_address"))
    if addrs:
        cfg.block("interface management 1", *[_mask(a) for a in addrs if a.version == 4])
        gw = _s(s.get("mgmt_gateway"))
        if gw and (gw_ip := _ip(ctx, "System", "Management gateway", gw)):
            ctx.mgmt_gateway = str(gw_ip)
    elif _s(s.get("mgmt_gateway")):
        ctx.warn("System", "Management gateway is set but the management port has no address.")
    banner = (s.get("banner") or "").rstrip()
    if banner.strip():
        if "$" in banner:
            ctx.error("System", "The banner can't contain '$' (FastIron uses it to end the banner).", "system.banner")
        else:
            ctx.banner = banner


def _access(ctx: FiCtx) -> None:
    a, cfg = ctx.p["access"], ctx.cfg
    cfg.comment("Accounts and remote access")
    enable = _secret(ctx, "Access", "Enable (super-user) password", a.get("root_password"), "access.root_password")
    if enable:
        cfg.line(f"enable super-user-password 8 {enable}")
    names = set()
    for i, u in enumerate(a.get("users") or []):
        ctx.at("access.users", u)
        name = _s(u.get("name"))
        if not name:
            continue
        if not USERNAME.match(name) or len(name) > 48:
            ctx.error("Access", f"User '{name}': use lower-case letters, digits, '.', '_' or '-'.", "name")
            continue
        if name in names:
            ctx.error("Access", f"User '{name}' is listed twice.", "name")
            continue
        names.add(name)
        cls = u.get("class") or "read-only"
        if cls == "unauthorized":
            ctx.warn("Access", f"User '{name}' is 'unauthorized': skipped on FastIron.")
            continue
        hashed = _secret(ctx, "Access", f"User {name}", u.get("password"), f"access.users.{i}.password")
        if hashed:
            cfg.line(f"username {name} privilege {PRIV.get(cls, '5')} password 8 {hashed}")
        elif not _s(u.get("password")):
            ctx.error("Access", f"User '{name}' needs a password (FastIron SSH keys are loaded separately).", "password")
        if _s(u.get("ssh_keys")):
            ctx.warn("Access", f"User {name}: FastIron loads SSH public keys from a file ('ip ssh pub-key-file tftp ...'); "
                               "keys are not written into the config.")
    ctx.at("", None)
    if not any(u.get("class") == "super-user" and _s(u.get("name")) for u in a.get("users") or []):
        ctx.warn("Access", "No super-user (privilege 0) account.")
    cfg.line("aaa authentication login default local")
    cfg.line("aaa authentication enable default local")
    cfg.line("aaa authentication web-server default local")
    cfg.line("enable aaa console")
    cfg.line("ip ssh timeout 120")
    cfg.line("ip ssh authentication-retries 3")
    cfg.line("no telnet server")
    if _truthy(a.get("web")):
        cfg.line("web-management https")
        cfg.line("no web-management http")
    else:
        cfg.line("no web-management")
    if _truthy(a.get("netconf")):
        ctx.warn("Access", "NETCONF is not written for FastIron (use SSH, SNMP or the REST API on 09.x).")


def _snmp(ctx: FiCtx) -> None:
    s, cfg = ctx.p["snmp"], ctx.cfg
    comms = [c for c in s.get("communities") or [] if _s(c.get("name"))]
    users = [u for u in s.get("v3_users") or [] if _s(u.get("name"))]
    targets = _list(s.get("trap_targets"))
    if not (comms or users or targets or _s(s.get("location")) or _s(s.get("contact"))):
        return
    cfg.comment("SNMP")
    for key in ("location", "contact"):
        if _s(s.get(key)):
            cfg.line(f"snmp-server {key} {_s(s.get(key))}")
    for c in comms:
        ctx.at("snmp.communities", c)
        name = _s(c.get("name"))
        if not re.fullmatch(r"[A-Za-z0-9_.@#%+=-]{1,32}", name):
            ctx.error("SNMP", f"Community '{name}' may only use letters, digits and _ . @ # % + = - (max 32).", "name")
            continue
        if name.lower() in ("public", "private"):
            ctx.warn("SNMP", f"Community '{name}' is a well-known default; pick something harder to guess.")
        clients = [n for cl in _list(c.get("clients"))
                   if (n := _ip(ctx, "SNMP", f"Community {name} client", cl, allow_net=True)) and n.version == 4]
        acl = ""
        if clients:
            acl = f" SNMP-{name.upper()}"[:33]
            body = cfg.block(f"ip access-list standard{acl}")
            for net in clients:
                body.append(f"permit host {net.network_address}" if net.prefixlen == 32
                            else f"permit {net.network_address} {net.hostmask}")
        else:
            ctx.warn("SNMP", f"Community '{name}' accepts any source address. Add the allowed clients.")
        cfg.line(f"snmp-server community {name} {'rw' if c.get('access') == 'read-write' else 'ro'}{acl}")
    ctx.at("", None)
    if users:
        cfg.line("snmp-server view all iso included")
    for u in users:
        ctx.at("snmp.v3_users", u)
        name = _s(u.get("name"))
        apw, ppw = _s(u.get("auth_password")), _s(u.get("priv_password"))
        if len(apw) < 8:
            ctx.error("SNMP", f"SNMPv3 user {name}: the authentication password needs at least 8 characters.", "auth_password")
            continue
        if (u.get("auth") or "sha") not in ("md5", "sha"):
            ctx.warn("SNMP", f"SNMPv3 user {name}: FastIron does MD5 or SHA-1 only; using SHA.")
        line = f"snmp-server user {name} {name}-group v3 auth {SNMP_AUTH.get(u.get('auth') or 'sha', 'sha')} {apw}"
        priv = SNMP_PRIV.get(u.get("priv") or "")
        level = "auth"
        if priv:
            if len(ppw) < 8:
                ctx.error("SNMP", f"SNMPv3 user {name}: the privacy password needs at least 8 characters.", "priv_password")
                continue
            line += f" priv {priv} {ppw}"
            level = "priv"
        cfg.line(f"snmp-server group {name}-group v3 {level} read all")
        cfg.line(line)
    ctx.at("", None)
    if targets:
        comm = _s(s.get("trap_community")) or (comms[0]["name"] if comms else "traps")
        for t in targets:
            if _ip(ctx, "SNMP", "Trap target", t):
                cfg.line(f"snmp-server host {t} version v2c {comm}")


def _syslog(ctx: FiCtx) -> None:
    s, cfg = ctx.p["syslog"], ctx.cfg
    cfg.comment("Logging")
    cfg.line("logging buffered 1000")
    for h in s.get("hosts") or []:
        ctx.at("syslog.hosts", h)
        addr = _s(h.get("address"))
        if not addr or not _ip(ctx, "Logging", "Syslog server", addr):
            continue
        port = _s(h.get("port"))
        if port and port != "514" and not (port.isdigit() and 1 <= int(port) <= 65535):
            ctx.error("Logging", f"Syslog port '{port}' is not valid.", "port")
            continue
        cfg.line(f"logging host {addr}" + (f" udp-port {port}" if port and port != "514" else ""))
    ctx.at("", None)
    if _s(s.get("source_address")):
        ctx.warn("Logging", "FastIron sets the syslog source by interface ('ip syslog source-interface ve 10'); add it by hand.")


def _vlans(ctx: FiCtx) -> None:
    vlans = [v for v in ctx.p["vlans"] if _s(v.get("name")) or _s(v.get("id"))]
    if not vlans:
        ctx.warn("VLANs", "No VLANs yet: access ports will stay in the default VLAN 1.")
    for v in vlans:
        ctx.at("vlans", v)
        name, vid = _s(v.get("name")), _s(v.get("id"))
        if not NAME.match(name) or len(name) > 31:
            ctx.error("VLANs", f"VLAN name '{name}' must start with a letter, use letters, digits, '-', '_' or '.', max 31.", "name")
            continue
        if not vid.isdigit() or not 2 <= int(vid) <= 4090:
            ctx.error("VLANs", f"VLAN {name}: ID must be 2-4090 (4091-4095 are reserved on FastIron).", "id")
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
        addrs = _addresses(ctx, "VLANs", f"VLAN {name} VE", v.get("irb"))
        if addrs:
            ctx.svis[n] = addrs
            ctx.l3_ifaces.add(f"ve {n}")
        elif _truthy(v.get("dhcp_relay")):
            ctx.error("VLANs", f"VLAN {name}: DHCP relay needs a VE (layer 3) address.", "irb")
        if _s(v.get("vni")) or _s(v.get("vga")) or _s(v.get("vrf")):
            ctx.warn("VLANs", f"VLAN {name}: VXLAN and VRFs are not written for FastIron.")
    ctx.at("", None)


def _claim(ctx: FiCtx, section: str, label: str, names: list[str]) -> list[str]:
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
        elif info and info["kind"] == "stack":
            ctx.warn(section, f"{label}: {name} is a stacking port by default; free it from the stack first.")
        ctx.used[name] = label
        ok.append(name)
    if module:
        ctx.warn(section, f"{label}: {P.named_compact(module)} {'needs' if len(module) == 1 else 'need'} the optional module installed.")
    return ok


def _vlans_for(ctx: FiCtx, section: str, label: str, row: dict, refs: list[str], lines: list[str], is_lag=False) -> None:
    """Record VLAN membership for a port group or LAG and add per-port lines."""
    mode = row.get("mode") or "access"
    svc = ctx.p["services"]
    if mode == "access":
        vlan = _vlan_name(ctx, section, label, row.get("vlan"), "vlan")
        voice = _vlan_name(ctx, section, f"{label} voice", row.get("voice"), "voice")
        if not voice and not _s(row.get("voice")):
            voice = next((v["name"] for v in ctx.p["vlans"] if _truthy(v.get("voice")) and v["name"] != vlan
                          and v["name"] in ctx.vlan_by_name), "")
        if voice and voice == vlan:
            ctx.error(section, f"{label}: the voice VLAN must differ from the data VLAN.", "voice")
            voice = None
        if voice:
            vid = int(ctx.vlan_by_name[voice]["id"])
            for r in refs:
                _member(ctx, vid, r, True)
            lines.append(f"voice-vlan {vid}")
        if vlan:
            did = int(ctx.vlan_by_name[vlan]["id"])
            for r in refs:
                if voice and ctx.legacy:
                    _member(ctx, did, r, True)     # older releases: tagged + dual-mode
                else:
                    _member(ctx, did, r, False)
            if voice and ctx.legacy:
                lines.append(f"dual-mode {did}")
        elif not _s(row.get("vlan")):
            ctx.warn(section, f"{label}: no access VLAN, so the port stays in VLAN 1.")
        if _truthy(row.get("edge")) and _s(svc.get("stp")) != "none":
            lines.append("spanning-tree 802-1w admin-edge-port")
            if _truthy(svc.get("bpdu_block_on_edge")):
                lines.append("stp-bpdu-guard")
        limit = _s(row.get("mac_limit"))
        if limit:
            if limit.isdigit() and 1 <= int(limit) <= 64:
                action = _s(row.get("mac_action")) or "drop"
                lines.extend(["port security", " enable", f" maximum {limit}",
                              f" violation {'shutdown 0' if action == 'shutdown' else 'restrict'}"])
            else:
                ctx.error(section, f"{label}: MAC limit must be 1-64 on FastIron.", "mac_limit")
        if _truthy(row.get("sticky")):
            ctx.warn(section, f"{label}: sticky MAC is not written for FastIron; skipped.")
        if _truthy(row.get("dhcp_trusted")):
            lines.append("dhcp snooping trust")
            lines.append("arp inspection trust")
        if vlan and _truthy(ctx.vlan_by_name[vlan].get("ipsg")) and not _truthy(row.get("dhcp_trusted")):
            lines.append("source-guard enable")
        dot1x = _s(row.get("dot1x"))
        if dot1x:
            if ctx.old:
                ctx.error(section, f"{label}: 802.1X is not written for FGS/FLS (FastIron 07.x).", "dot1x")
            else:
                if dot1x in ("dot1x", "dot1x-mab"):
                    ctx.dot1x.extend(refs)
                if dot1x in ("mab", "dot1x-mab"):
                    ctx.mab.extend(refs)
    elif mode == "trunk":
        refs_v = _list(row.get("vlans"))
        if not refs_v:
            ctx.error(section, f"{label}: a trunk needs at least one VLAN (or 'all').", "vlans")
        if any(r.lower() == "all" for r in refs_v):
            vids = sorted(int(v["id"]) for v in ctx.vlan_by_name.values())
        else:
            vids = [int(ctx.vlan_by_name[n]["id"]) for r in refs_v if (n := _vlan_name(ctx, section, label, r, "vlans"))]
        native = _vlan_name(ctx, section, f"{label} native", row.get("native"), "native")
        nid = int(ctx.vlan_by_name[native]["id"]) if native else None
        for vid in vids:
            if vid != nid:
                for r in refs:
                    _member(ctx, vid, r, True)
        if nid:
            for r in refs:
                _member(ctx, nid, r, not not ctx.legacy)
            if ctx.legacy:
                lines.append(f"dual-mode {nid}")
        if _truthy(row.get("root_guard")):
            lines.append("spanning-tree root-protect")
        if _truthy(row.get("loop_protect")):
            lines.append("loop-detection")
        ctx.trunk_ports.extend(refs)
        if _s(row.get("voice")):
            ctx.warn(section, f"{label}: voice VLAN only applies to access ports; ignored on a trunk.")
    elif mode == "routed":
        addrs = _addresses(ctx, section, label, row.get("address"))
        if not addrs:
            ctx.error(section, f"{label}: a routed port needs an IP address with prefix (example 10.0.0.1/30).", "address")
        if len(refs) > 1:
            ctx.error(section, f"{label}: a routed port group can only hold one port (each needs its own address).")
        lines.append("route-only")
        lines.extend(_mask(a) for a in addrs)
        if addrs and len(refs) == 1:
            ctx.l3_ifaces.add(f"ethe {refs[0]}")
    elif mode != "disabled":
        ctx.error(section, f"{label}: unknown mode '{mode}'.", "mode")
    if _s(row.get("vlan_translate")):
        ctx.warn(section, f"{label}: FastIron has no per-port VLAN translation; the mapping is ignored.")
    if mode != "routed" and _s(row.get("address")):
        ctx.warn(section, f"{label}: the IP address is only used in routed mode. Use a VLAN VE for switch ports.")


def _common_lines(ctx: FiCtx, section: str, label: str, row: dict, phys: list[str], lines: list[str]) -> None:
    desc = _s(row.get("description"))
    if desc:
        lines.insert(0, f"port-name {desc[:63]}")
    if (row.get("mode") or "access") == "disabled":
        lines.append("disable")
        return
    speed = _s(row.get("speed")).lower()
    if speed:
        if speed in SPEEDS:
            lines.append(f"speed-duplex {SPEEDS[speed]}")
        else:
            ctx.error(section, f"{label}: speed must be one of {', '.join(SPEEDS)}.", "speed")
    if _s(row.get("mtu")):
        ctx.warn(section, f"{label}: FastIron sets jumbo frames for the whole switch ('jumbo', then a reload); MTU skipped.")
    poe, pmax = _s(row.get("poe")), _s(row.get("poe_max"))
    if poe or pmax:
        no_poe = [p for p in phys if p in ctx.known and not ctx.known[p].get("poe")]
        if no_poe:
            ctx.warn(section, f"{label}: {', '.join(no_poe[:3])}{'…' if len(no_poe) > 3 else ''} has no PoE; PoE setting skipped.")
        if len(no_poe) < len(phys):
            if poe == "off":
                lines.append("no inline power")
            elif poe in POE_PRIO:
                lines.append(f"inline power priority {POE_PRIO[poe]}")
            if pmax and poe != "off":
                try:
                    watts = float(pmax)
                except ValueError:
                    watts = -1
                if not 1 <= watts <= 90:
                    ctx.error(section, f"{label}: maximum PoE power must be 1-90 watts.", "poe_max")
                else:
                    lines.append(f"inline power power-limit {int(watts * 1000)}")


def _port_groups(ctx: FiCtx) -> None:
    rows = [r for r in ctx.p["ports"] if _s(r.get("ports"))]
    use_ranges = _truthy(ctx.p["services"].get("use_ranges"))
    for i, row in enumerate(rows):
        ctx.at("ports", row)
        label = _s(row.get("name")) or f"Port group {i + 1}"
        try:
            names = _ports(row.get("ports"))
        except ValueError as exc:
            ctx.error("Ports", f"{label}: {exc} (example: 1/1/1-24, 1/2/1).", "ports")
            continue
        names = _claim(ctx, "Ports", label, names)
        if not names:
            continue
        mode = row.get("mode") or "access"
        if mode == "routed" and len(names) > 1:
            ctx.error("Ports", f"{label}: a routed port group can only hold one port (each needs its own address).")
            continue
        lines: list[str] = []
        _vlans_for(ctx, "Ports", label, row, names, lines)
        _common_lines(ctx, "Ports", label, row, names, lines)
        if use_ranges and len(names) > 1:
            headers = [f"interface {_ethe(names)}"]
        else:
            headers = [f"interface ethernet {n}" for n in names]
        for h in headers:
            ctx.iface.setdefault(h, [])
            ctx.iface[h].extend(ln for ln in lines if ln not in ctx.iface[h] or ln.startswith(" "))
        if mode == "trunk":
            ctx.trunk_headers.extend(headers)
        for port in names:
            voice = mode == "access" and (bool(_s(row.get("voice"))) or any(
                _truthy(v.get("voice")) and v["name"] != _s(row.get("vlan")) for v in ctx.p["vlans"]))
            ctx.res.ports[port] = {"use": mode, "label": label, "voice": voice, "role": _s(row.get("role"))}
    ctx.at("", None)


def _lags(ctx: FiCtx) -> None:
    lags = [r for r in ctx.p["lags"] if _s(r.get("name")) or _s(r.get("members"))]
    seen = set()
    for row in lags:
        ctx.at("lags", row)
        raw = _s(row.get("name"))
        m = _LAG.fullmatch(raw) or re.fullmatch(r"(\d{1,3})", raw)
        num = int(m.group(1)) if m else -1
        if not 1 <= num <= 256:
            ctx.error("LAGs", f"LAG name '{raw}' must be lag1 to lag256.", "name")
            continue
        label = f"lag{num}"
        if num in seen:
            ctx.error("LAGs", f"{label} is listed twice.", "name")
            continue
        seen.add(num)
        try:
            members = _ports(row.get("members"))
        except ValueError as exc:
            ctx.error("LAGs", f"{label}: {exc}", "members")
            continue
        members = _claim(ctx, "LAGs", label, members)
        if not members:
            ctx.error("LAGs", f"{label}: add member ports.", "members")
            continue
        if len(members) == 1:
            ctx.warn("LAGs", f"{label}: only one member port, so there's no redundancy.")
        if (row.get("mode") or "trunk") == "routed":
            ctx.error("LAGs", f"{label}: routed LAGs are not written for FastIron; use a VE on a VLAN.", "mode")
            continue
        lacp = row.get("lacp") if row.get("lacp") in ("active", "passive", "static") else "active"
        primary = sorted(members, key=P.named_key)[0]
        desc = _s(row.get("description"))
        if ctx.old:
            # FastIron 07.x: LACP per port with a shared key; VLANs list every member.
            refs = members
            for mem in members:
                body = ctx.iface.setdefault(f"interface ethernet {mem}", [])
                if desc:
                    body.append(f"port-name {desc[:50]} (lag{num})")
                if lacp == "static":
                    ctx.error("LAGs", f"{label}: static trunks on FGS/FLS use 'trunk ethe ...'; not written here.", "lacp")
                    break
                body.extend([f"link-aggregate configure key {10000 + num}", f"link-aggregate {lacp}"])
        else:
            kind = "static" if lacp == "static" else "dynamic"
            body = ctx.cfg.block(f'lag "{(re.sub(r"[^A-Za-z0-9_-]", "-", desc) or f"LAG{num}")[:60]}" {kind} id {num}')
            body.append(f"ports {_ethe(members)}")
            if ctx.legacy:
                body.append(f"primary-port {primary}")
            if kind == "dynamic" and lacp == "passive":
                body.append(f"lacp-mode passive ethe {primary}")
            if kind == "dynamic" and _truthy(row.get("lacp_fast")):
                body.append(f"lacp-timeout short {_ethe(members)}")
            body.append("deploy")
            refs = [primary] if ctx.legacy else [f"lag {num}"]
            if not ctx.legacy and desc:
                ctx.iface.setdefault(f"interface lag {num}", []).append(f"port-name {desc[:63]}")
        ml = _s(row.get("min_links"))
        if ml:
            ctx.warn("LAGs", f"{label}: minimum links are not written for FastIron.")
        if _s(row.get("esi")):
            ctx.warn("LAGs", f"{label}: EVPN multihoming is not available on FastIron.")
        lines: list[str] = []
        _vlans_for(ctx, "LAGs", label, row, refs, lines, is_lag=True)
        if lines:
            target = f"interface ethernet {primary}" if ctx.legacy or ctx.old else f"interface lag {num}"
            ctx.iface.setdefault(target, []).extend(lines)
        if (row.get("mode") or "trunk") == "trunk":
            if ctx.legacy or ctx.old:
                ctx.trunk_headers.extend(f"interface ethernet {r}" for r in refs)
            else:
                ctx.trunk_headers.append(f"interface lag {num}")
        for mem in members:
            ctx.res.ports[mem] = {"use": "lag", "label": label}
    ctx.at("", None)


def _write_vlans(ctx: FiCtx) -> None:
    cfg = ctx.cfg
    if not ctx.vlan_by_id:
        return
    cfg.comment("VLANs and their ports")
    stp = _s(ctx.p["services"].get("stp")) or "rstp"
    prio = _s(ctx.p["services"].get("bridge_priority")).lower()
    prio_val = None
    if prio:
        m = re.fullmatch(r"(\d+)(k?)", prio)
        val = int(m.group(1)) * (1024 if m.group(2) else 1) if m else -1
        val = 4096 * round(val / 4096) if m and m.group(2) else val
        if 0 <= val <= 61440 and val % 4096 == 0:
            prio_val = val
        else:
            ctx.error("Services", "Bridge priority must be 0, 4k, 8k ... 60k (steps of 4k).", "services.bridge_priority")
    snoop, dai = [], []
    for vid, v in sorted(ctx.vlan_by_id.items()):
        body = cfg.block(f"vlan {vid} name {v['name']} by port")
        tagged = ctx.tagged.get(vid, [])
        untagged = ctx.untagged.get(vid, [])
        for kind, refs in (("tagged", tagged), ("untagged", untagged)):
            eth = [r for r in refs if not r.startswith("lag ")]
            lags = [r for r in refs if r.startswith("lag ")]
            if eth:
                body.append(f"{kind} {_ethe(eth)}")
            for lag in lags:
                body.append(f"{kind} {lag}")
        if vid in ctx.svis:
            body.append(f"router-interface ve {vid}")
        if stp == "rstp":
            body.append("spanning-tree 802-1w")
            if prio_val is not None:
                body.append(f"spanning-tree 802-1w priority {prio_val}")
        if _truthy(v.get("snooping")) or _truthy(v.get("dai")) or _truthy(v.get("ipsg")):
            snoop.append(vid)
        if _truthy(v.get("dai")):
            dai.append(vid)
    if stp == "none":
        ctx.warn("Services", "Spanning tree is off: a cabling loop will take the network down.")
    for vid in snoop:
        cfg.line(f"ip dhcp snooping vlan {vid}")
    for vid in dai:
        cfg.line(f"ip arp inspection vlan {vid}")
    if snoop or dai:
        for h in dict.fromkeys(ctx.trunk_headers):
            body = ctx.iface.setdefault(h, [])
            body.append("dhcp snooping trust")
            if dai:
                body.append("arp inspection trust")
        ctx.warn("Services", "DHCP snooping is on: trunk and LAG ports are trusted, access ports are not. "
                             "Tick 'DHCP trusted' on an access port that has a DHCP server behind it.")


def _write_interfaces(ctx: FiCtx) -> None:
    if ctx.iface:
        ctx.cfg.comment("Port settings")
    for header, lines in ctx.iface.items():
        if lines:
            ctx.cfg.block(header, *lines)


def _l3(ctx: FiCtx) -> None:
    r, cfg = ctx.p["routing"], ctx.cfg
    servers = [sv for sv in _list(r.get("dhcp_relay_servers")) if _ip(ctx, "Routing", "DHCP server", sv)]
    relay = {int(v["id"]) for v in ctx.vlan_by_name.values() if _truthy(v.get("dhcp_relay")) and _s(v.get("irb"))}
    if relay and not servers:
        ctx.error("Routing", "VLANs use DHCP relay but no DHCP server is set on the Routing tab.")
    if ctx.svis:
        cfg.comment("VLAN interfaces (VE)")
    for vid, addrs in sorted(ctx.svis.items()):
        body = cfg.block(f"interface ve {vid}")
        body.extend(_mask(a) for a in addrs)
        if vid in relay:
            body.extend(f"ip helper-address {i} {sv}" for i, sv in enumerate(servers, 1))
    lo = _s(r.get("loopback"))
    if lo:
        addrs = _addresses(ctx, "Routing", "Loopback", lo if "/" in lo else f"{lo}/32")
        if addrs:
            body = cfg.block("interface loopback 1")
            for a in addrs:
                body.append(_mask(a))
                if a.version == 4:
                    ctx.loopback_ip = str(a.ip)
            ctx.l3_ifaces.add("loopback 1")
    rid = _s(r.get("router_id")) or (ctx.loopback_ip or "")
    if rid:
        try:
            ipaddress.IPv4Address(rid)
            ctx.router_id = rid
            cfg.line(f"ip router-id {rid}")
        except ValueError:
            ctx.error("Routing", f"Router ID '{rid}' must be an IPv4 address.", "routing.router_id")
    asn = _s(r.get("asn"))
    if asn:
        if asn.isdigit() and 1 <= int(asn) <= 4294967295:
            ctx.asn = int(asn)
        else:
            ctx.error("Routing", "AS number must be 1-4294967295.", "routing.asn")
    routed = ctx.svis or lo or any(row.get("mode") == "routed" for row in ctx.p["ports"])
    if routed and any(m.family in ("FGS", "FLS") for _, m in ctx.fmodels):
        ctx.warn("Routing", "FGS/FLS need the Layer 3 software image for VE interfaces and routing.")


def _static(ctx: FiCtx) -> None:
    r, cfg = ctx.p["routing"], ctx.cfg
    routes = [x for x in r.get("static") or [] if _s(x.get("prefix"))]
    gw = getattr(ctx, "mgmt_gateway", None)
    if gw and not any(_s(x.get("prefix")) in ("0.0.0.0/0", "default") for x in routes):
        routes.append({"prefix": "0.0.0.0/0", "next_hop": gw, "preference": ""})
    if routes:
        cfg.comment("Static routes")
    for x in routes:
        ctx.at("routing.static", x)
        prefix = "0.0.0.0/0" if _s(x.get("prefix")) == "default" else _s(x.get("prefix"))
        net = _ip(ctx, "Routing", "Route", prefix, allow_net=True)
        if not net:
            continue
        nh = _s(x.get("next_hop"))
        if nh in ("discard", "reject"):
            target = "null0"
        else:
            nh_ip = _ip(ctx, "Routing", f"Route {net} next hop", nh) if nh else None
            if not nh_ip:
                if not nh:
                    ctx.error("Routing", f"Route {net}: add a next hop (an IP, 'discard' or 'reject').", "next_hop")
                continue
            target = nh
        pref = _s(x.get("preference"))
        if pref and not (pref.isdigit() and 1 <= int(pref) <= 255):
            ctx.error("Routing", f"Route {net}: preference (distance) must be 1-255.", "preference")
            continue
        cfg.line(f"{'ip' if net.version == 4 else 'ipv6'} route {net} {target}" + (f" distance {pref}" if pref else ""))
    ctx.at("", None)


def _fi_iface(text: str) -> str | None:
    t = _s(text)
    if m := re.fullmatch(r"(?:irb\.|vlan|ve)\s*(\d{1,4})", t, re.I):
        return f"ve {m.group(1)}"
    if re.fullmatch(r"(?:lo|loopback)\s*\d{0,4}(?:\.0)?", t, re.I):
        return "loopback 1"
    try:
        names = _ports(t)
    except ValueError:
        return None
    return f"ethernet {names[0]}" if len(names) == 1 else None


def _ospf(ctx: FiCtx) -> None:
    o = ctx.p["routing"].get("ospf") or {}
    if not _truthy(o.get("enabled")):
        return
    cfg = ctx.cfg
    cfg.comment("OSPF")
    body = cfg.block("router ospf")
    rb = _s(o.get("reference_bandwidth"))
    if rb:
        m = re.fullmatch(r"(\d+)\s*([gm]?)", rb.lower())
        if m:
            body.append(f"auto-cost reference-bandwidth {int(m.group(1)) * (1000 if m.group(2) == 'g' else 1)}")
        else:
            ctx.error("OSPF", "Reference bandwidth must look like 100g or 100000 (Mbps).", "routing.ospf.reference_bandwidth")
    if _s(o.get("export")):
        ctx.warn("OSPF", "Export policies are not written for FastIron yet; add 'redistribute' lines by hand.")
    for a in o.get("areas") or []:
        ctx.at("routing.ospf.areas", a)
        area = _s(a.get("area")) or "0"
        if not re.fullmatch(r"\d+|\d+\.\d+\.\d+\.\d+", area):
            ctx.error("OSPF", f"Area '{area}' must be a number or dotted (0.0.0.0).", "area")
            continue
        kind = a.get("type") or "normal"
        body.append(f"area {area}" + (f" {kind} 1" if kind == "stub" else " nssa 1" if kind == "nssa" else ""))
        key = _s(a.get("md5_key"))
        p2p = {_fi_iface(x) for x in _list(re.sub(r"\bethe?\s+", "", _s(a.get("p2p"))))}
        passive = P.iface_list(a.get("passive"))
        for raw in P.iface_list(a.get("interfaces")) + passive:
            name = _fi_iface(raw)
            if not name:
                ctx.error("OSPF", f"Area {area}: '{raw}' is not a FastIron interface (1/2/1, ve 20, loopback 1).", "interfaces")
                continue
            ib = cfg.block(f"interface {name}", f"ip ospf area {area}")
            if (raw in passive or name.startswith("loopback")) and "ip ospf passive" not in ib:
                ib.append("ip ospf passive")
            if name in p2p:
                ib.append("ip ospf network point-to-point")
            if key and f"ip ospf md5-authentication key-id 1 key {key}" not in ib:
                ib.append(f"ip ospf md5-authentication key-id 1 key {key}")
    ctx.at("", None)


def _bgp(ctx: FiCtx) -> None:
    groups = [g for g in ctx.p["routing"].get("bgp_groups") or [] if _s(g.get("name")) or _s(g.get("neighbors"))]
    if not groups:
        return
    if not ctx.asn:
        ctx.error("BGP", "BGP needs the switch's AS number (Routing tab).", "routing.asn")
        return
    cfg = ctx.cfg
    cfg.comment("BGP")
    body = cfg.block("router bgp", f"local-as {ctx.asn}")
    if any(_truthy(g.get("multipath")) for g in groups) or _truthy(ctx.p["routing"].get("ecmp")):
        body.append("maximum-paths 4")
    for g in groups:
        ctx.at("routing.bgp_groups", g)
        name = re.sub(r"[^A-Za-z0-9_-]", "-", _s(g.get("name")) or "PEERS")
        external = (g.get("type") or "external") == "external"
        peer_as = _s(g.get("peer_as"))
        neighbors = R._neighbors(ctx, "BGP", f"Group {name}", g.get("neighbors", ""))
        if not neighbors:
            ctx.error("BGP", f"Group {name} has no neighbors.", "neighbors")
            continue
        body.append(f"neighbor {name} peer-group")
        if not external:
            body.append(f"neighbor {name} remote-as {ctx.asn}")
        elif peer_as:
            body.append(f"neighbor {name} remote-as {peer_as}")
        if _s(g.get("local_address")) and ctx.loopback_ip and _s(g.get("local_address")) == ctx.loopback_ip:
            body.append(f"neighbor {name} update-source loopback 1")
        if _s(g.get("auth_key")):
            body.append(f"neighbor {name} password {_s(g.get('auth_key'))}")
        if _s(g.get("import")) or _s(g.get("export")):
            ctx.warn("BGP", f"Group {name}: import/export policies are not written for FastIron yet (use route-maps).")
        for ip, asn, desc in neighbors:
            if external and asn:
                body.append(f"neighbor {ip} remote-as {asn}")
            elif external and not peer_as:
                ctx.error("BGP", f"Group {name}: neighbor {ip} needs a peer AS (on the group or after the IP).", "neighbors")
            body.append(f"neighbor {ip} peer-group {name}")
            if desc:
                body.append(f"neighbor {ip} description \"{desc}\"")
    ctx.at("", None)
    if ctx.loopback_ip:
        body.extend(["address-family ipv4 unicast", f" network {ctx.loopback_ip}/32", " exit-address-family"])


def _services(ctx: FiCtx) -> None:
    s, cfg = ctx.p["services"], ctx.cfg
    cfg.comment("Switching services")
    if _truthy(s.get("lldp")):
        cfg.line("lldp run")
    else:
        cfg.line("no lldp run")
    if _truthy(s.get("storm_control")):
        ctx.warn("Services", "Storm control on FastIron is a rate per port ('broadcast limit ... kbps'); not written.")
    sec = ctx.p.get("security") or {}
    rt = _s(sec.get("recovery_timeout"))
    if rt:
        if rt.isdigit() and 10 <= int(rt) <= 65535:
            cfg.line("errdisable recovery cause bpduguard")
            cfg.line(f"errdisable recovery interval {rt}")
        else:
            ctx.error("Security", "Auto-recovery time must be 10-65535 seconds.", "security.recovery_timeout")
    if any(_truthy(s.get(k)) for k in ("poe_fast", "poe_perpetual")) or _s(s.get("poe_guard_band")):
        ctx.warn("Services", "Perpetual/fast PoE and guard band are Juniper options; not written for FastIron.")
    if ctx.dot1x or ctx.mab:
        servers = [x for x in sec.get("radius_servers") or [] if _s(x.get("address"))]
        if not servers:
            ctx.error("Security", "802.1X / MAB ports need at least one RADIUS server.")
        cfg.comment("802.1X and MAB (RADIUS)")
        cfg.line("aaa authentication dot1x default radius")
        for x in servers:
            ctx.at("security.radius_servers", x)
            addr = _s(x.get("address"))
            if not _ip(ctx, "Security", "RADIUS server", addr):
                continue
            if not _s(x.get("secret")):
                ctx.error("Security", f"RADIUS server {addr} needs a shared secret.", "secret")
                continue
            port = _s(x.get("port")) or "1812"
            cfg.line(f"radius-server host {addr} auth-port {port} acct-port 1813 default key {_s(x.get('secret'))} dot1x mac-auth")
        ctx.at("", None)
        body = cfg.block("authentication")
        vlans = sorted(ctx.vlan_by_id)
        body.append(f"auth-default-vlan {vlans[0] if vlans else 1}")
        if ctx.dot1x:
            ports = sorted(set(ctx.dot1x), key=P.named_key)
            body.extend(["dot1x enable", f"dot1x enable {_ethe(ports)}", f"dot1x port-control auto {_ethe(ports)}"])
        if ctx.mab:
            ports = sorted(set(ctx.mab), key=P.named_key)
            body.extend(["mac-authentication enable", f"mac-authentication enable {_ethe(ports)}"])
    if _truthy(s.get("disable_unused")) and ctx.known:
        unused = [n for n, info in ctx.known.items() if n not in ctx.used and info["kind"] in ("access", "uplink")]
        if unused:
            cfg.block(f"interface {_ethe(unused)}", "port-name Unused - disabled", "disable")
            for n in unused:
                ctx.res.ports.setdefault(n, {"use": "disabled", "label": "Unused"})


def _unsupported(ctx: FiCtx) -> None:
    p = ctx.p
    if _truthy((p.get("evpn") or {}).get("enabled")):
        ctx.warn("EVPN", "EVPN-VXLAN is not available on FastIron.")
    if any((p.get("policy") or {}).get(k) for k in ("prefix_lists", "communities", "terms")):
        ctx.warn("Policies", "Routing policies are not written for FastIron yet.")
    if _truthy((p.get("qos") or {}).get("enabled")):
        ctx.warn("QoS", "QoS is not written for FastIron yet.")


def header(p: dict) -> list[str]:
    name = _s(p.get("name")) or _s(p.get("system", {}).get("hostname")) or "switch"
    models = ", ".join(f"{_s(m.get('model'))} (unit {m.get('fpc', 1) or 1})" for m in p["switch"].get("members") or [])
    return [f"Brocade / Ruckus FastIron configuration for {name}", f"Hardware: {models}",
            f"Made by Multi-Vendor Switch Config Builder {__version__}. Review before you load it."]


def build(project: dict) -> Result:
    p = normalize(project)
    ctx = FiCtx(p)
    for t in header(p):
        ctx.cfg.comment(t)
    for step in (_switch, _system, _access, _snmp, _syslog, _vlans, _port_groups, _lags, _l3, _write_vlans,
                 _write_interfaces, _static, _ospf, _bgp, _services, _unsupported):
        step(ctx)
        ctx.row = None
    if ctx.p["system"].get("hostname"):
        ctx.cfg.comment("SSH host key (once, on a new switch)")
        ctx.cfg.line("crypto key generate" if ctx.old else "crypto key generate rsa modulus 2048")
    text = ctx.cfg.text()
    if ctx.banner:
        text = text[: -len("end\n")] + "banner motd $\n" + ctx.banner + "\n$\n!\nend\n"
    ctx.res.errors = _dedupe(ctx.res.errors)
    ctx.res.warnings = _dedupe(ctx.res.warnings)
    ctx.res.set_text = text
    ctx.res.hier_text = text
    ctx.res.hostname = _s(p["system"].get("hostname")) or "switch"
    return ctx.res
