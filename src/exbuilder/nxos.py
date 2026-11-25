"""Turn a project into Cisco NX-OS configuration (Nexus 9000 and 3000).

Uses the same project format as the Juniper builder (see generator.py), so a
project's VLANs, port groups, LAGs and routing mean the same thing here. Port
names are NX-OS names (Ethernet1/1, Ethernet1/49/1), LAGs are port-channels,
and every protocol the config uses gets its ``feature`` line at the top.
The out-of-band port mgmt0 always sits in the ``management`` VRF.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from zoneinfo import ZoneInfo

from . import __version__, nxos_models, vendors
from . import ports as P
from . import routing as R
from .cryptpw import is_hashed, sha256_crypt
from .generator import (DOMAIN, HOSTNAME, NAME, USERNAME, Ctx, Result, SSH_KEY_TYPES, _addresses, _ip, _list,
                        _s, _truthy, _vlan_name, normalize)
from .textcfg import Blocks

VENDOR = vendors.VENDORS["nexus"]
SPEEDS = {"100m": "100", "1g": "1000", "10g": "10000", "25g": "25000", "40g": "40000", "100g": "100000"}
SEVERITY = {"emergency": 0, "alert": 1, "critical": 2, "error": 3, "warning": 4, "notice": 5, "info": 6, "any": 7}
ROLES = {"super-user": "network-admin", "operator": "network-operator", "read-only": "network-operator"}
SNMP_AUTH = {"md5": "md5", "sha": "sha", "sha256": "sha-256"}
SNMP_PRIV = {"aes128": "aes-128", "des": ""}
FEATURE_ORDER = ("lacp", "interface-vlan", "dhcp", "ospf", "bgp", "dot1x", "port-security", "lldp",
                 "netconf", "nxapi")
_PO = re.compile(r"^(?:port-channel|po|ae|lag)\s*(\d{1,4})$", re.I)
_IN_VRF = " use-vrf management"


def _vid(ctx: Ctx, name: str) -> int:
    return int(ctx.vlan_by_name[name]["id"])


def _vid_list(ids) -> str:
    """[10, 11, 12, 20] -> '10-12,20'."""
    ids = sorted(set(ids))
    out, start = [], None
    for i, v in enumerate(ids):
        if start is None:
            start = v
        if i + 1 == len(ids) or ids[i + 1] != v + 1:
            out.append(str(start) if start == v else f"{start}-{v}")
            start = None
    return ",".join(out)


def _iface_name(text: str) -> str | None:
    """User text such as 'Vlan20', 'irb.20', 'lo0', 'Eth1/49', 'Po1' -> an NX-OS interface name."""
    t = _s(text)
    if not t:
        return None
    if m := re.fullmatch(r"(?:irb\.|vlan\s*)(\d{1,4})", t, re.I):
        return f"Vlan{m.group(1)}"
    if m := re.fullmatch(r"(?:lo|loopback)\s*(\d{0,4})(?:\.0)?", t, re.I):
        return f"loopback{m.group(1) or 0}"
    if m := _PO.fullmatch(t):
        return f"port-channel{m.group(1)}"
    try:
        names = P.expand_named(t, nxos_models.ALIASES)
    except ValueError:
        return None
    return names[0] if len(names) == 1 else None


class NxCtx(Ctx):
    def __init__(self, project: dict):
        super().__init__(project)
        self.cfg = Blocks()
        self.nmodels: list = []
        self.features: set[str] = set()
        self.svis: dict[int, list] = {}
        self.dot1x_ports: list[str] = []
        self.mgmt_route: str | None = None
        self.banner: str | None = None

    @property
    def vrf(self) -> str:
        """' use-vrf management' when services are reached through mgmt0."""
        return _IN_VRF if _truthy(self.p["system"].get("mgmt_vrf")) else ""

    @property
    def legacy(self) -> bool:
        return any(m.legacy for m in self.nmodels)


# ------------------------------------------------------------------ sections
def _switch(ctx: NxCtx) -> None:
    members = ctx.p["switch"].get("members") or []
    if len(members) > 1:
        ctx.error("Switch", "Nexus switches don't stack. Use one switch per project (a vPC pair is two projects).")
    for m in members[:1]:
        ctx.at("switch.members", m)
        model = nxos_models.get(m.get("model", ""))
        if model:
            ctx.nmodels.append(model)
            for port in model.ports:
                ctx.known[port["name"]] = port
        elif m.get("model") != nxos_models.CUSTOM:
            ctx.error("Switch", f"Unknown Nexus model '{m.get('model')}'. Pick one from the list or Custom.", "model")
    ctx.at("", None)
    try:
        for name in P.expand_named(ctx.p["switch"].get("custom_ports", ""), nxos_models.ALIASES):
            ctx.known.setdefault(name, {"name": name, "kind": "access", "speed": "", "poe": False})
    except ValueError as exc:
        ctx.error("Switch", f"Custom ports: {exc}")


def _password(ctx: NxCtx, section: str, label: str, value, key: str) -> str | None:
    value = _s(value)
    if not value:
        return None
    if is_hashed(value):
        if not value.startswith(("$5$", "$1$")):
            ctx.error(section, f"{label}: NX-OS takes a $5$ (SHA-256) or $1$ (MD5) hash; type the password instead.",
                      key if not ctx.row else key.rsplit(".", 1)[-1])
            return None
        return value
    if len(value) < 8:
        ctx.error(section, f"{label}: use at least 8 characters.", key if not ctx.row else key.rsplit(".", 1)[-1])
        return None
    hashed = sha256_crypt(value)
    ctx.res.hashed[key] = hashed
    return hashed


def _timezone(ctx: NxCtx, tz: str) -> None:
    """NX-OS wants a short name and a fixed offset ('clock timezone MST -7 0')."""
    try:
        zone = ZoneInfo(tz)
    except Exception:  # noqa: BLE001 - any bad zone name
        ctx.error("System", f"Time zone '{tz}' is not valid.", "system.timezone")
        return
    jan, jul = datetime(2026, 1, 15, 12, tzinfo=zone), datetime(2026, 7, 15, 12, tzinfo=zone)
    std = jan if not jan.dst() else jul
    offset = std.utcoffset() - (std.dst() or std.utcoffset() * 0)
    minutes = int(offset.total_seconds() // 60)
    sign = "-" if minutes < 0 else ""
    hours, mins = divmod(abs(minutes), 60)
    name = re.sub(r"[^A-Za-z]", "", std.tzname() or "")[:8] or "LOCAL"
    ctx.cfg.line(f"clock timezone {name} {sign}{hours} {mins}")
    if jan.dst() or jul.dst():
        ctx.warn("System", f"{tz} has summer time; NX-OS needs a 'clock summer-time' line for it, added by hand.")


def _system(ctx: NxCtx) -> None:
    s, cfg = ctx.p["system"], ctx.cfg
    cfg.comment("System")
    host = _s(s.get("hostname"))
    if not host:
        ctx.error("System", "Host name is required.", "system.hostname")
    elif not HOSTNAME.match(host):
        ctx.error("System", f"Host name '{host}' may only use letters, digits and hyphens (max 63).", "system.hostname")
    else:
        cfg.line(f"hostname {host}")
    vrf = ctx.vrf
    domain = _s(s.get("domain"))
    if domain:
        if DOMAIN.match(domain):
            cfg.line(f"ip domain-name {domain}{vrf}")
        else:
            ctx.error("System", f"Domain '{domain}' is not a valid domain name.", "system.domain")
    servers = [ns for ns in _list(s.get("name_servers")) if _ip(ctx, "System", "DNS server", ns)]
    if len(servers) > 3:
        ctx.warn("System", "NX-OS takes at most 3 DNS servers; the rest are left out.")
    if servers:
        cfg.line(f"ip name-server {' '.join(servers[:3])}{vrf}")
    for d in _list(s.get("domain_search")):
        if DOMAIN.match(d):
            cfg.line(f"ip domain-list {d}{vrf}")
    tz = _s(s.get("timezone"))
    if tz and tz != "UTC":
        _timezone(ctx, tz)
    ntp = [n for n in s.get("ntp_servers") or [] if _s(n.get("address"))]
    if not ntp:
        ctx.warn("System", "No NTP server: logs and certificates need the right time.")
    for n in ntp:
        addr = _s(n.get("address"))
        if not (re.match(r"^[A-Za-z0-9.-]+$", addr) or _ip(ctx, "System", "NTP server", addr)):
            continue
        cfg.line(f"ntp server {addr}" + (" prefer" if _truthy(n.get("prefer")) else "") + vrf)
    src = _s(s.get("ntp_source"))
    if src and _ip(ctx, "System", "NTP source", src):
        cfg.line(f"ntp source {src}")

    mif = _s(s.get("mgmt_interface")) or "mgmt0"
    if mif.lower() != "mgmt0":
        ctx.error("System", f"Management port '{mif}' should be mgmt0 on a Nexus.", "system.mgmt_interface")
    addrs = _addresses(ctx, "System", "Management (mgmt0)", s.get("mgmt_address"))
    if addrs:
        body = cfg.block("interface mgmt0", "vrf member management")
        for a in addrs:
            body.append(f"{'ip' if a.version == 4 else 'ipv6'} address {a.with_prefixlen}")
        gw = _s(s.get("mgmt_gateway"))
        if gw and (gw_ip := _ip(ctx, "System", "Management gateway", gw)):
            if not any(gw_ip in a.network for a in addrs if a.version == gw_ip.version):
                ctx.warn("System", f"Management gateway {gw} is not in the management subnet.")
            default = "0.0.0.0/0" if gw_ip.version == 4 else "::/0"
            ctx.mgmt_route = f"{'ip' if gw_ip.version == 4 else 'ipv6'} route {default} {gw}"
        if not vrf:
            ctx.warn("System", "mgmt0 is always in the management VRF on a Nexus. With 'Management VRF' off, "
                               "NTP, DNS, logging and SNMP go out through the switch ports instead.")
    elif _s(s.get("mgmt_gateway")):
        ctx.warn("System", "Management gateway is set but mgmt0 has no address.")
    banner = (s.get("banner") or "").rstrip()
    if banner.strip():
        delim = next((c for c in "#^%@~" if c not in banner), None)
        if not delim:
            ctx.error("System", "The banner uses every delimiter NX-OS allows (# ^ % @ ~); remove one of them.", "system.banner")
        else:
            ctx.banner = f"banner motd {delim}\n{banner}\n{delim}"


def _access(ctx: NxCtx) -> None:
    a, cfg = ctx.p["access"], ctx.cfg
    cfg.comment("Accounts and remote access")
    root = _password(ctx, "Access", "admin password", a.get("root_password"), "access.root_password")
    if root:
        cfg.line(f"username admin password 5 {root} role network-admin")
    names = set()
    for i, u in enumerate(a.get("users") or []):
        ctx.at("access.users", u)
        name = _s(u.get("name"))
        if not name:
            continue
        if not USERNAME.match(name) or name in ("root", "admin"):
            ctx.error("Access", f"User '{name}': use lower-case letters, digits, '.', '_' or '-' (not root or admin).", "name")
            continue
        if name in names:
            ctx.error("Access", f"User '{name}' is listed twice.", "name")
            continue
        names.add(name)
        cls = u.get("class") or "read-only"
        if cls == "unauthorized":
            ctx.warn("Access", f"User '{name}' is 'unauthorized': skipped on NX-OS.")
            continue
        role = ROLES.get(cls, ROLES["read-only"])
        hashed = _password(ctx, "Access", f"User {name}", u.get("password"), f"access.users.{i}.password")
        keys = [k.strip() for k in (u.get("ssh_keys") or "").splitlines() if k.strip()]
        if hashed:
            cfg.line(f"username {name} password 5 {hashed} role {role}")
        elif keys:
            cfg.line(f"username {name} role {role}")
        else:
            ctx.error("Access", f"User '{name}' needs a password or an SSH key.", "password")
        if len(keys) > 1:
            ctx.warn("Access", f"User {name}: NX-OS keeps one SSH key per user; only the first is written.")
        for k in keys[:1]:
            if k.split()[0] not in SSH_KEY_TYPES:
                ctx.error("Access", f"User {name}: SSH key must start with ssh-rsa, ssh-ed25519 or ecdsa-sha2-...")
            else:
                cfg.line(f"username {name} sshkey {k}")
    ctx.at("", None)
    if not root and not any(u.get("class") == "super-user" and _s(u.get("name")) for u in a.get("users") or []):
        ctx.warn("Access", "No super-user account: nobody can change the config after this one.")
    limit = _s(a.get("ssh_connection_limit"))
    if limit:
        if limit.isdigit() and 1 <= int(limit) <= 64:
            cfg.block("line vty", f"session-limit {limit}")
        else:
            ctx.error("Access", "SSH connection limit must be 1-64 on NX-OS.", "access.ssh_connection_limit")
    if _truthy(a.get("retry_options")):
        cfg.line("ssh login-attempts 3")
    if _truthy(a.get("netconf")):
        ctx.features.add("netconf")
    if _truthy(a.get("web")):
        ctx.features.add("nxapi")
        if ctx.vrf:
            cfg.line("nxapi use-vrf management")


def _snmp(ctx: NxCtx) -> None:
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
        group = "network-admin" if c.get("access") == "read-write" else "network-operator"
        cfg.line(f"snmp-server community {name} group {group}")
        clients = [cl for cl in _list(c.get("clients")) if _ip(ctx, "SNMP", f"Community {name} client", cl, allow_net=True)]
        if clients:
            acl = f"SNMP-{name.upper()}"[:64]
            body = cfg.block(f"ip access-list {acl}")
            for i, cl in enumerate(clients, 1):
                body.append(f"{i * 10} permit udp {cl if '/' in cl else cl + '/32'} any eq snmp")
            cfg.line(f"snmp-server community {name} use-ipv4acl {acl}")
        else:
            ctx.warn("SNMP", f"Community '{name}' accepts any source address. Add the allowed clients.")
    ctx.at("", None)
    for u in users:
        ctx.at("snmp.v3_users", u)
        name = _s(u.get("name"))
        apw, ppw = _s(u.get("auth_password")), _s(u.get("priv_password"))
        if len(apw) < 8:
            ctx.error("SNMP", f"SNMPv3 user {name}: the authentication password needs at least 8 characters.", "auth_password")
            continue
        auth_key = u.get("auth") or "sha"
        auth = SNMP_AUTH.get(auth_key)
        if not auth:
            ctx.warn("SNMP", f"SNMPv3 user {name}: NX-OS has no {auth_key}; SHA is used.")
            auth = "sha"
        line = f"snmp-server user {name} network-operator auth {auth} {apw}"
        priv_key = u.get("priv") or ""
        if priv_key:
            if priv_key not in SNMP_PRIV:
                ctx.warn("SNMP", f"SNMPv3 user {name}: NX-OS has no {priv_key}; AES-128 is used.")
            if len(ppw) < 8:
                ctx.error("SNMP", f"SNMPv3 user {name}: the privacy password needs at least 8 characters.", "priv_password")
                continue
            kind = SNMP_PRIV.get(priv_key, "aes-128")
            line += f" priv {kind + ' ' if kind else ''}{ppw}"
        else:
            ctx.warn("SNMP", f"SNMPv3 user {name} has no privacy (encryption); polls are readable on the wire.")
        cfg.line(line)
    ctx.at("", None)
    if targets:
        comm = _s(s.get("trap_community")) or (comms[0]["name"] if comms else "traps")
        for t in targets:
            if _ip(ctx, "SNMP", "Trap target", t):
                cfg.line(f"snmp-server host {t} traps version 2c {comm}")
                if ctx.vrf:
                    cfg.line(f"snmp-server host {t}{ctx.vrf}")
        cfg.line("snmp-server enable traps")


def _syslog(ctx: NxCtx) -> None:
    s, cfg = ctx.p["syslog"], ctx.cfg
    cfg.comment("Logging")
    cfg.line(f"logging logfile messages {SEVERITY.get(s.get('local_level') or 'notice', 5)}")
    for h in s.get("hosts") or []:
        ctx.at("syslog.hosts", h)
        addr = _s(h.get("address"))
        if not addr or not _ip(ctx, "Logging", "Syslog server", addr):
            continue
        port = _s(h.get("port"))
        if port and port != "514" and not (port.isdigit() and 1 <= int(port) <= 65535):
            ctx.error("Logging", f"Syslog port '{port}' is not valid.", "port")
            continue
        level = SEVERITY.get(h.get("level") or "info", 6)
        cfg.line(f"logging server {addr} {level}" + (f" port {port}" if port and port != "514" else "") + ctx.vrf)
    ctx.at("", None)
    if _s(s.get("source_address")):
        ctx.warn("Logging", "NX-OS sets the syslog source by interface; add 'logging source-interface' by hand if needed.")


def _vlans(ctx: NxCtx) -> None:
    cfg = ctx.cfg
    vlans = [v for v in ctx.p["vlans"] if _s(v.get("name")) or _s(v.get("id"))]
    if not vlans:
        ctx.warn("VLANs", "No VLANs yet: access ports will land in VLAN 1.")
        return
    cfg.comment("VLANs")
    snoop, dai = [], []
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
        if 3968 <= n <= 4094:
            ctx.error("VLANs", f"VLAN {name}: IDs 3968-4094 are reserved on NX-OS.", "id")
            continue
        if name.lower() in {x.lower() for x in ctx.vlan_by_name}:
            ctx.error("VLANs", f"VLAN name '{name}' is used twice.", "name")
            continue
        if n in ctx.vlan_by_id:
            ctx.error("VLANs", f"VLAN ID {n} is used by both {ctx.vlan_by_id[n]['name']} and {name}.", "id")
            continue
        ctx.vlan_by_name[name] = v
        ctx.vlan_by_id[n] = v
        cfg.block(f"vlan {n}", f"name {name}")
        addrs = _addresses(ctx, "VLANs", f"VLAN {name} SVI", v.get("irb"))
        if addrs:
            ctx.svis[n] = addrs
            ctx.l3_ifaces.add(f"Vlan{n}")
        elif _truthy(v.get("dhcp_relay")):
            ctx.error("VLANs", f"VLAN {name}: DHCP relay needs an SVI address.", "irb")
        if _truthy(v.get("snooping")):
            snoop.append(n)
        if _truthy(v.get("dai")):
            dai.append(n)
        if _truthy(v.get("ipsg")):
            ctx.warn("VLANs", f"VLAN {name}: IP source guard is set per port on NX-OS; not written.")
        if _s(v.get("vni")) or _s(v.get("vga")) or _s(v.get("vrf")):
            ctx.warn("VLANs", f"VLAN {name}: VNI, virtual gateway and VRF are not written for Nexus yet.")
    ctx.at("", None)
    if snoop or dai:
        ctx.features.add("dhcp")
    if snoop:
        cfg.line("ip dhcp snooping")
        cfg.line(f"ip dhcp snooping vlan {_vid_list(snoop)}")
    if dai:
        cfg.line(f"ip arp inspection vlan {_vid_list(dai)}")


def _claim(ctx: NxCtx, section: str, label: str, names: list[str]) -> list[str]:
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


def _translate(ctx: NxCtx, section: str, label: str, body: list, row: dict, allowed: list | None) -> None:
    spec = _s(row.get("vlan_translate"))
    if not spec:
        return
    if ctx.legacy:
        ctx.error(section, f"{label}: VLAN mapping needs a Nexus 9000; the Nexus 3000 can't do it.", "vlan_translate")
        return
    try:
        pairs = P.translations(spec)
    except ValueError as exc:
        ctx.error(section, f"{label}: VLAN translation: {exc}", "vlan_translate")
        return
    lines = []
    for wire, local in pairs:
        if wire in ctx.vlan_by_id:
            ctx.error(section, f"{label}: wire VLAN {wire} is also a VLAN on this switch; "
                               "pick a wire VLAN that is not on the VLANs tab.", "vlan_translate")
            continue
        if local not in ctx.vlan_by_id:
            ctx.error(section, f"{label}: switch VLAN {local} is not on the VLANs tab.", "vlan_translate")
            continue
        if allowed is not None and local not in allowed:
            ctx.warn(section, f"{label}: VLAN {local} is translated but not in the trunk's VLAN list; added it.")
            allowed.append(local)
        lines.append(f"switchport vlan mapping {wire} {local}")
    if lines:
        body.append("switchport vlan mapping enable")
        body.extend(lines)


def _port_body(ctx: NxCtx, section: str, label: str, body: list, row: dict, phys: list[str], is_lag=False) -> None:
    mode = row.get("mode") or "access"
    desc = _s(row.get("description"))
    if desc:
        body.append(f"description {desc}")
    if mode == "disabled":
        body.append("shutdown")
        return
    speed = _s(row.get("speed")).lower()
    if speed and not is_lag:
        if speed in SPEEDS:
            body.append(f"speed {SPEEDS[speed]}")
        else:
            ctx.error(section, f"{label}: speed must be one of {', '.join(SPEEDS)}.", "speed")
    mtu = _s(row.get("mtu"))
    if mtu:
        if mode == "routed":
            if mtu.isdigit() and 576 <= int(mtu) <= 9216:
                body.append(f"mtu {mtu}")
            else:
                ctx.error(section, f"{label}: MTU must be 576-9216 on a routed port.", "mtu")
        elif mtu in ("1500", "9216"):
            body.append(f"mtu {mtu}")
        else:
            ctx.error(section, f"{label}: a Nexus switch port takes MTU 1500 or 9216 (jumbo).", "mtu")
    svc = ctx.p["services"]
    storm = _truthy(svc.get("storm_control"))
    pct = _s(svc.get("storm_percent")) or "5"
    storm_lines = [f"storm-control broadcast level {pct}.00", f"storm-control unicast level {pct}.00"] \
        if pct.isdigit() else []
    edge_lines = ["spanning-tree port type edge"] + (["spanning-tree bpduguard enable"] if _truthy(svc.get("bpdu_block_on_edge")) else [])
    if mode == "access":
        body.extend(["switchport", "switchport mode access"])
        vlan = _vlan_name(ctx, section, label, row.get("vlan"), "vlan")
        if vlan:
            body.append(f"switchport access vlan {_vid(ctx, vlan)}")
        elif not _s(row.get("vlan")):
            ctx.warn(section, f"{label}: no access VLAN, so the port uses VLAN 1.")
        if _s(row.get("voice")):
            ctx.warn(section, f"{label}: Nexus switches have no voice VLAN; only the data VLAN is written.")
        if storm:
            body.extend(storm_lines)
        if _truthy(row.get("edge")):
            body.extend(edge_lines)
        limit = _s(row.get("mac_limit"))
        if limit:
            if limit.isdigit() and 1 <= int(limit) <= 1025:
                ctx.features.add("port-security")
                body.append("switchport port-security")
                body.append(f"switchport port-security maximum {limit}")
                action = _s(row.get("mac_action")) or "drop"
                body.append("switchport port-security violation " + ("protect" if action == "drop" else "restrict"))
            else:
                ctx.error(section, f"{label}: MAC limit must be 1-1025.", "mac_limit")
        if _truthy(row.get("sticky")):
            if limit:
                body.append("switchport port-security mac-address sticky")
            else:
                ctx.warn(section, f"{label}: sticky MAC needs a MAC limit; skipped.")
        if _truthy(row.get("dhcp_trusted")):
            ctx.features.add("dhcp")
            body.extend(["ip dhcp snooping trust", "ip arp inspection trust"])
        dot1x = _s(row.get("dot1x"))
        if dot1x:
            ctx.features.add("dot1x")
            body.append("dot1x port-control auto")
            if dot1x in ("dot1x-mab", "mab"):
                body.append("dot1x mac-auth-bypass")
            if dot1x == "mab":
                ctx.warn(section, f"{label}: NX-OS runs MAB as a fallback after 802.1X; devices that can't do 802.1X still get in by MAC.")
            ctx.dot1x_ports.extend(phys)
    elif mode == "trunk":
        body.extend(["switchport", "switchport mode trunk"])
        refs = _list(row.get("vlans"))
        if not refs:
            ctx.error(section, f"{label}: a trunk needs at least one VLAN (or 'all').", "vlans")
        allowed = None if any(r.lower() == "all" for r in refs) else \
            [_vid(ctx, n) for r in refs if (n := _vlan_name(ctx, section, label, r, "vlans"))]
        native = _vlan_name(ctx, section, f"{label} native", row.get("native"), "native")
        if native:
            body.append(f"switchport trunk native vlan {_vid(ctx, native)}")
            if allowed is not None and _vid(ctx, native) not in allowed:
                allowed.append(_vid(ctx, native))
        trans: list[str] = []
        _translate(ctx, section, label, trans, row, allowed)
        if allowed is not None and allowed:
            body.append(f"switchport trunk allowed vlan {_vid_list(allowed)}")
        body.extend(trans)
        if storm and svc.get("storm_scope") == "all":
            body.extend(storm_lines)
        if _truthy(row.get("root_guard")):
            body.append("spanning-tree guard root")
        if _truthy(row.get("loop_protect")):
            body.append("spanning-tree guard loop")
        if _s(row.get("voice")):
            ctx.warn(section, f"{label}: voice VLAN only applies to access ports; ignored on a trunk.")
    elif mode == "routed":
        addrs = _addresses(ctx, section, label, row.get("address"))
        if not addrs:
            ctx.error(section, f"{label}: a routed port needs an IP address with prefix (example 10.0.0.1/30).", "address")
        if len(phys) > 1:
            ctx.error(section, f"{label}: a routed port group can only hold one port (each needs its own address).")
        body.insert(1 if desc else 0, "no switchport")
        for a in addrs:
            body.append(f"{'ip' if a.version == 4 else 'ipv6'} address {a.with_prefixlen}")
        if addrs and len(phys) == 1:
            ctx.l3_ifaces.add(phys[0])
    else:
        ctx.error(section, f"{label}: unknown mode '{mode}'.", "mode")
        return
    if mode != "trunk" and _s(row.get("vlan_translate")):
        ctx.error(section, f"{label}: VLAN translation only works on trunk ports.", "vlan_translate")
    if mode != "routed" and _s(row.get("address")):
        ctx.warn(section, f"{label}: the IP address is only used in routed mode. Use a VLAN SVI for switch ports.")
    if not is_lag and (_s(row.get("poe")) or _s(row.get("poe_max"))):
        ctx.warn(section, f"{label}: Nexus switches have no PoE; PoE setting skipped.")
    body.append("no shutdown")


def _range(names: list[str], use_ranges: bool) -> list[str]:
    """Interface block headers for a port group."""
    if not use_ranges or len(names) == 1:
        return names
    return [", ".join(a if a == b else f"{a}-{P.named_key(b)[1][-1]}" for a, b in P.named_runs(names))]


def _ports(ctx: NxCtx) -> None:
    rows = [r for r in ctx.p["ports"] if _s(r.get("ports"))]
    if not rows:
        return
    ctx.cfg.comment("Switch ports")
    use_ranges = _truthy(ctx.p["services"].get("use_ranges"))
    for i, row in enumerate(rows):
        ctx.at("ports", row)
        label = _s(row.get("name")) or f"Port group {i + 1}"
        try:
            names = P.expand_named(row.get("ports"), nxos_models.ALIASES)
        except ValueError as exc:
            ctx.error("Ports", f"{label}: {exc} (example: Ethernet1/1-24, Eth1/49).", "ports")
            continue
        names = _claim(ctx, "Ports", label, names)
        if not names:
            continue
        mode = row.get("mode") or "access"
        if mode == "routed" and len(names) > 1:
            ctx.error("Ports", f"{label}: a routed port group can only hold one port (each needs its own address).")
            continue
        headers = _range(names, use_ranges and mode != "routed")
        for header in headers:
            body: list[str] = []
            _port_body(ctx, "Ports", label, body, row, names if len(headers) == 1 else [header])
            ctx.cfg.block(f"interface {header}", *body)
        for port in names:
            ctx.res.ports[port] = {"use": mode, "label": label, "voice": False, "role": _s(row.get("role"))}
    ctx.at("", None)


def _dedupe(items: list) -> list:
    seen, out = set(), []
    for m in items:
        key = tuple(sorted(m.items()))
        if key not in seen:
            seen.add(key)
            out.append(m)
    return out


_MEMBER_LINES = ("switchport", "no switchport", "mtu ")


def _lags(ctx: NxCtx) -> None:
    lags = [r for r in ctx.p["lags"] if _s(r.get("name")) or _s(r.get("members"))]
    if not lags:
        return
    ctx.cfg.comment("Port-channels (LACP)")
    seen = set()
    for row in lags:
        ctx.at("lags", row)
        raw = _s(row.get("name"))
        m = _PO.fullmatch(raw) or re.fullmatch(r"(\d{1,4})", raw)
        num = int(m.group(1)) if m else -1
        if not 1 <= num <= 4096:
            ctx.error("LAGs", f"LAG name '{raw}' must be port-channel1 to port-channel4096 (Po1 also works).", "name")
            continue
        name = f"port-channel{num}"
        label = name
        if num in seen:
            ctx.error("LAGs", f"{name} is listed twice.", "name")
            continue
        seen.add(num)
        try:
            members = P.expand_named(row.get("members"), nxos_models.ALIASES)
        except ValueError as exc:
            ctx.error("LAGs", f"{label}: {exc}", "members")
            continue
        members = _claim(ctx, "LAGs", label, members)
        if not members:
            ctx.error("LAGs", f"{label}: add member ports.", "members")
            continue
        if len(members) == 1:
            ctx.warn("LAGs", f"{label}: only one member port, so there's no redundancy.")
        lacp = row.get("lacp") if row.get("lacp") in ("active", "passive", "static") else "active"
        if lacp == "static":
            ctx.warn("LAGs", f"{label}: static LAG without LACP can't detect a mis-cabled member.")
        else:
            ctx.features.add("lacp")
        body: list[str] = []
        _port_body(ctx, "LAGs", label, body, row, [name], is_lag=True)
        ml = _s(row.get("min_links"))
        if ml:
            if ml.isdigit() and 1 <= int(ml) <= len(members):
                body.insert(-1, f"lacp min-links {ml}")
            else:
                ctx.error("LAGs", f"{label}: minimum links must be 1-{len(members)}.", "min_links")
        if _s(row.get("esi")):
            ctx.warn("LAGs", f"{label}: EVPN multihoming (ESI) is not written for Nexus (vPC is set up by hand).")
        ctx.cfg.block(f"interface {name}", *body)
        # Members carry the same layer-2/3 mode so they're compatible when they join.
        shared = [ln for ln in body if ln.startswith(_MEMBER_LINES)]
        for mem in members:
            mb = ctx.cfg.block(f"interface {mem}")
            if _s(row.get("description")):
                mb.append(f"description {_s(row.get('description'))} (member of {name})")
            mb.extend(shared)
            if lacp != "static" and _truthy(row.get("lacp_fast")):
                mb.append("lacp rate fast")
            mb.append(f"channel-group {num} mode {'on' if lacp == 'static' else lacp}")
            mb.append("shutdown" if (row.get("mode") == "disabled") else "no shutdown")
            ctx.res.ports[mem] = {"use": "lag", "label": name}
    ctx.at("", None)


def _l3(ctx: NxCtx) -> None:
    """SVIs, loopback, routing identity and DHCP relay."""
    r, cfg = ctx.p["routing"], ctx.cfg
    servers = [sv for sv in _list(r.get("dhcp_relay_servers")) if _ip(ctx, "Routing", "DHCP server", sv)]
    relay = {int(v["id"]) for v in ctx.vlan_by_name.values() if _truthy(v.get("dhcp_relay")) and _s(v.get("irb"))}
    if relay and not servers:
        ctx.error("Routing", "VLANs use DHCP relay but no DHCP server is set on the Routing tab.")
    if relay and servers:
        ctx.features.add("dhcp")
    if ctx.svis:
        ctx.features.add("interface-vlan")
        cfg.comment("VLAN interfaces (SVIs)")
    for vid, addrs in sorted(ctx.svis.items()):
        body = cfg.block(f"interface Vlan{vid}", "no shutdown")
        for a in addrs:
            body.append(f"{'ip' if a.version == 4 else 'ipv6'} address {a.with_prefixlen}")
        if vid in relay:
            body.extend(f"ip dhcp relay address {sv}" for sv in servers)
    lo = _s(r.get("loopback"))
    if lo:
        addrs = _addresses(ctx, "Routing", "Loopback", lo if "/" in lo else f"{lo}/32")
        if addrs:
            body = cfg.block("interface loopback0")
            for a in addrs:
                body.append(f"{'ip' if a.version == 4 else 'ipv6'} address {a.with_prefixlen}")
                if a.version == 4:
                    ctx.loopback_ip = str(a.ip)
            ctx.l3_ifaces.add("loopback0")
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


def _static(ctx: NxCtx) -> None:
    r, cfg = ctx.p["routing"], ctx.cfg
    routes = [x for x in r.get("static") or [] if _s(x.get("prefix"))]
    if routes or ctx.mgmt_route:
        cfg.comment("Static routes")
    if ctx.mgmt_route:
        cfg.block("vrf context management", ctx.mgmt_route)
    for x in routes:
        ctx.at("routing.static", x)
        prefix = "0.0.0.0/0" if _s(x.get("prefix")) == "default" else _s(x.get("prefix"))
        net = _ip(ctx, "Routing", "Route", prefix, allow_net=True)
        if not net:
            continue
        nh = _s(x.get("next_hop"))
        if nh in ("discard", "reject"):
            target = "Null0"
        else:
            nh_ip = _ip(ctx, "Routing", f"Route {net} next hop", nh) if nh else None
            if not nh_ip:
                if not nh:
                    ctx.error("Routing", f"Route {net}: add a next hop (an IP, 'discard' or 'reject').", "next_hop")
                continue
            if not any(nh_ip in iface.network for _, iface in ctx.l3_networks if iface.version == nh_ip.version):
                ctx.warn("Routing", f"Route {net}: next hop {nh} is not in any subnet on this switch.")
            target = nh
        pref = _s(x.get("preference"))
        if pref and not (pref.isdigit() and 1 <= int(pref) <= 255):
            ctx.error("Routing", f"Route {net}: preference (distance) must be 1-255.", "preference")
            continue
        cfg.line(f"{'ip' if net.version == 4 else 'ipv6'} route {net} {target}" + (f" {pref}" if pref else ""))
    ctx.at("", None)


def _ospf(ctx: NxCtx) -> None:
    o = ctx.p["routing"].get("ospf") or {}
    if not _truthy(o.get("enabled")):
        return
    ctx.features.add("ospf")
    cfg = ctx.cfg
    cfg.comment("OSPF")
    body = cfg.block("router ospf 1")
    if ctx.router_id:
        body.append(f"router-id {ctx.router_id}")
    else:
        ctx.warn("OSPF", "Set a router ID or loopback (Routing tab) so OSPF has a stable ID.")
    rb = _s(o.get("reference_bandwidth"))
    if rb:
        m = re.fullmatch(r"(\d+)\s*([gm]?)", rb.lower())
        if m:
            unit = "Gbps" if m.group(2) == "g" else "Mbps"
            body.append(f"auto-cost reference-bandwidth {int(m.group(1))} {unit}")
        else:
            ctx.error("OSPF", "Reference bandwidth must look like 100g or 100000 (Mbps).", "routing.ospf.reference_bandwidth")
    if _s(o.get("export")):
        ctx.warn("OSPF", "Export policies are not written for Nexus yet; add 'redistribute' lines by hand.")
    for a in o.get("areas") or []:
        ctx.at("routing.ospf.areas", a)
        area = _s(a.get("area")) or "0.0.0.0"
        if not re.fullmatch(r"\d+|\d+\.\d+\.\d+\.\d+", area):
            ctx.error("OSPF", f"Area '{area}' must be a number or dotted (0.0.0.0).", "area")
            continue
        if area.isdigit():
            area = str(ipaddress.IPv4Address(int(area)))
        kind = a.get("type") or "normal"
        if kind in ("stub", "nssa"):
            body.append(f"area {area} {kind}")
        key = _s(a.get("md5_key"))
        p2p = {_iface_name(x) for x in P.iface_list(a.get("p2p"))}
        passive = {_iface_name(x) for x in P.iface_list(a.get("passive"))}
        for raw in P.iface_list(a.get("interfaces")) + P.iface_list(a.get("passive")):
            name = _iface_name(raw)
            if not name:
                ctx.error("OSPF", f"Area {area}: '{raw}' is not an NX-OS interface (Ethernet1/49, Vlan20, loopback0).", "interfaces")
                continue
            ib = cfg.block(f"interface {name}", f"ip router ospf 1 area {area}")
            if name in passive or name.startswith("loopback"):
                if not name.startswith("loopback") and "ip ospf passive-interface" not in ib:
                    ib.append("ip ospf passive-interface")
            if name in p2p:
                ib.append("ip ospf network point-to-point")
            if key:
                if len(key) > 16:
                    ctx.error("OSPF", f"Area {area}: the MD5 key can be at most 16 characters.", "md5_key")
                elif "ip ospf authentication message-digest" not in ib:
                    ib.extend(["ip ospf authentication message-digest", f"ip ospf message-digest-key 1 md5 0 {key}"])
    ctx.at("", None)


def _bgp(ctx: NxCtx) -> None:
    groups = [g for g in ctx.p["routing"].get("bgp_groups") or [] if _s(g.get("name")) or _s(g.get("neighbors"))]
    if not groups:
        return
    cfg = ctx.cfg
    if not ctx.asn:
        ctx.error("BGP", "BGP needs the switch's AS number (Routing tab).", "routing.asn")
        return
    ctx.features.add("bgp")
    cfg.comment("BGP")
    body = cfg.block(f"router bgp {ctx.asn}")
    if ctx.router_id:
        body.append(f"router-id {ctx.router_id}")
    af = ["address-family ipv4 unicast"]
    if ctx.loopback_ip:
        af.append(f"   network {ctx.loopback_ip}/32")
    if any(_truthy(g.get("multipath")) for g in groups) or _truthy(ctx.p["routing"].get("ecmp")):
        af.append("   maximum-paths 4")
    body.extend(af)
    for g in groups:
        ctx.at("routing.bgp_groups", g)
        name = re.sub(r"[^A-Za-z0-9_-]", "-", _s(g.get("name")) or "PEERS")
        external = (g.get("type") or "external") == "external"
        peer_as = _s(g.get("peer_as"))
        if peer_as and not (peer_as.isdigit() and 1 <= int(peer_as) <= 4294967295):
            ctx.error("BGP", f"Group {name}: peer AS must be 1-4294967295.", "peer_as")
            continue
        neighbors = R._neighbors(ctx, "BGP", f"Group {name}", g.get("neighbors", ""))
        if not neighbors:
            ctx.error("BGP", f"Group {name} has no neighbors.", "neighbors")
            continue
        body.append(f"template peer {name}")
        tpl = []
        if not external:
            tpl.append(f"remote-as {ctx.asn}")
        elif peer_as:
            tpl.append(f"remote-as {peer_as}")
        if _s(g.get("description")):
            tpl.append(f"description {_s(g.get('description'))}")
        local = _s(g.get("local_address"))
        if local and ctx.loopback_ip and local == ctx.loopback_ip:
            tpl.append("update-source loopback0")
        elif local:
            ctx.warn("BGP", f"Group {name}: NX-OS sets the source by interface; only the loopback address is mapped.")
        if _s(g.get("auth_key")):
            tpl.append(f"password 0 {_s(g.get('auth_key'))}")
        if _s(g.get("bfd")):
            tpl.append("bfd")
            ctx.features.add("bfd")
        tpl.append("address-family ipv4 unicast")
        body.extend("   " + t for t in tpl)
        if _s(g.get("import")) or _s(g.get("export")):
            ctx.warn("BGP", f"Group {name}: import/export policies are not written for Nexus yet (use route-maps).")
        for ip, asn, desc in neighbors:
            body.append(f"neighbor {ip}")
            body.append(f"   inherit peer {name}")
            if external and asn:
                body.append(f"   remote-as {asn}")
            elif external and not peer_as:
                ctx.error("BGP", f"Group {name}: neighbor {ip} needs a peer AS (on the group or after the IP).", "neighbors")
            if desc:
                body.append(f"   description {desc}")
    ctx.at("", None)


def _services(ctx: NxCtx) -> None:
    s, cfg = ctx.p["services"], ctx.cfg
    cfg.comment("Switching services")
    if _truthy(s.get("lldp")):
        ctx.features.add("lldp")
    stp = s.get("stp")
    if stp == "rstp":
        cfg.line("spanning-tree mode rapid-pvst")
        prio = _s(s.get("bridge_priority")).lower()
        if prio:
            m = re.fullmatch(r"(\d+)(k?)", prio)
            val = int(m.group(1)) * (1024 if m.group(2) else 1) if m else -1
            val = 4096 * round(val / 4096) if m and m.group(2) else val
            if 0 <= val <= 61440 and val % 4096 == 0:
                cfg.line(f"spanning-tree vlan 1-3967 priority {val}")
            else:
                ctx.error("Services", "Bridge priority must be 0, 4k, 8k ... 60k (steps of 4k).", "services.bridge_priority")
    elif stp == "none":
        cfg.line("no spanning-tree vlan 1-3967")
        ctx.warn("Services", "Spanning tree is off: a cabling loop will take the network down.")
    pct = _s(s.get("storm_percent")) or "5"
    if _truthy(s.get("storm_control")) and not (pct.isdigit() and 1 <= int(pct) <= 100):
        ctx.error("Services", "Storm control percentage must be 1-100.", "services.storm_percent")
    if ctx.dot1x_ports:
        sec = ctx.p.get("security") or {}
        servers = [x for x in sec.get("radius_servers") or [] if _s(x.get("address"))]
        if not servers:
            ctx.error("Security", "802.1X / MAB ports need at least one RADIUS server.")
        group = cfg.block("aaa group server radius RADIUS")
        for x in servers:
            ctx.at("security.radius_servers", x)
            addr = _s(x.get("address"))
            if _ip(ctx, "Security", "RADIUS server", addr):
                if not _s(x.get("secret")):
                    ctx.error("Security", f"RADIUS server {addr} needs a shared secret.", "secret")
                    continue
                port = _s(x.get("port"))
                cfg.line(f"radius-server host {addr} key {_s(x.get('secret'))}"
                         + (f" auth-port {port}" if port else "") + " authentication accounting")
                group.append(f"server {addr}")
        ctx.at("", None)
        if ctx.vrf:
            group.append("use-vrf management")
        cfg.line("aaa authentication dot1x default group RADIUS")
    if _truthy(s.get("disable_unused")) and ctx.known:
        unused = [n for n, info in ctx.known.items() if n not in ctx.used and info["kind"] in ("access", "uplink")]
        if unused:
            for header in _range(unused, _truthy(s.get("use_ranges"))):
                cfg.block(f"interface {header}", "description Unused - disabled", "shutdown")
            for n in unused:
                ctx.res.ports.setdefault(n, {"use": "disabled", "label": "Unused"})


def _unsupported(ctx: NxCtx) -> None:
    p = ctx.p
    if _truthy((p.get("evpn") or {}).get("enabled")):
        ctx.warn("EVPN", "EVPN-VXLAN is not written for Nexus yet.")
    if any((p.get("policy") or {}).get(k) for k in ("prefix_lists", "communities", "terms")):
        ctx.warn("Policies", "Routing policies are not written for Nexus yet.")
    if _truthy((p.get("qos") or {}).get("enabled")):
        ctx.warn("QoS", "QoS is not written for Nexus yet.")
    s = p["services"]
    if any(_truthy(s.get(k)) for k in ("poe_fast", "poe_perpetual")) or _s(s.get("poe_guard_band")) or _s(s.get("poe_management")):
        ctx.warn("Services", "Nexus switches have no PoE; the PoE options are skipped.")


def header(p: dict) -> list[str]:
    name = _s(p.get("name")) or _s(p.get("system", {}).get("hostname")) or "switch"
    model = ", ".join(_s(m.get("model")) for m in (p["switch"].get("members") or [])[:1])
    return [f"Cisco NX-OS configuration for {name}", f"Hardware: {model}",
            f"Made by Multi-Vendor Switch Config Builder {__version__}. Review before you load it."]


def build(project: dict) -> Result:
    p = normalize(project)
    ctx = NxCtx(p)
    for step in (_switch, _system, _access, _snmp, _syslog, _vlans, _ports, _lags, _l3, _static, _ospf, _bgp,
                 _services, _unsupported):
        step(ctx)
        ctx.row = None
    head = [f"! {t}" for t in header(p)] + ["!", "! Features (switched on first, so the lines below load)"]
    feats = [f for f in FEATURE_ORDER if f in ctx.features] + sorted(ctx.features - set(FEATURE_ORDER))
    head += [f"feature {f}" for f in feats] + ["!"]
    text = "\n".join(head) + "\n" + ctx.cfg.text()
    if ctx.banner:
        text = text[: -len("end\n")] + ctx.banner + "\n!\nend\n"
    ctx.res.errors = _dedupe(ctx.res.errors)
    ctx.res.warnings = _dedupe(ctx.res.warnings)
    ctx.res.set_text = text
    ctx.res.hier_text = text
    ctx.res.hostname = _s(p["system"].get("hostname")) or "switch"
    return ctx.res
