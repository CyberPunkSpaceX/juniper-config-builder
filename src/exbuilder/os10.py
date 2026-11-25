"""Turn a project into Dell SmartFabric OS10 configuration.

Uses the same project format as the Juniper builder (see generator.py). Port
names are OS10 names (ethernet1/1/1), LAGs are port-channels, a VLAN is an
``interface vlan10`` that also holds its address, and a trunk's untagged VLAN
is its ``switchport access vlan``.
"""

from __future__ import annotations

import ipaddress
import re

from . import __version__, os10_models, vendors
from . import ports as P
from . import routing as R
from .cryptpw import is_hashed, sha512_crypt
from .generator import (DOMAIN, HOSTNAME, NAME, USERNAME, Ctx, Result, _addresses, _ip, _list,
                        _s, _truthy, _vlan_name, normalize)
from .textcfg import Blocks

VENDOR = vendors.VENDORS["dell"]
SPEEDS = {"100m": "100", "1g": "1000", "10g": "10000", "25g": "25000", "40g": "40000", "100g": "100000"}
SEVERITY = {"emergency": "log-emerg", "alert": "log-alert", "critical": "log-crit", "error": "log-err",
            "warning": "log-warning", "notice": "log-notice", "info": "log-info", "any": "log-debug"}
ROLES = {"super-user": "sysadmin priv-lvl 15", "operator": "netoperator", "read-only": "netoperator"}
SNMP_AUTH = {"md5": "md5", "sha": "sha"}
_PO = re.compile(r"^(?:port-channel|po|ae|lag)\s*(\d{1,3})$", re.I)


def _vid(ctx: Ctx, name: str) -> int:
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


def _iface_name(text: str) -> str | None:
    """'Vlan20', 'irb.20', 'lo0', 'eth1/1/49', 'Po1' -> an OS10 interface name."""
    t = _s(text)
    if not t:
        return None
    if m := re.fullmatch(r"(?:irb\.|vlan\s*)(\d{1,4})", t, re.I):
        return f"vlan{m.group(1)}"
    if m := re.fullmatch(r"(?:lo|loopback)\s*(\d{0,4})(?:\.0)?", t, re.I):
        return f"loopback{m.group(1) or 0}"
    if m := _PO.fullmatch(t):
        return f"port-channel{m.group(1)}"
    try:
        names = P.expand_named(t, os10_models.ALIASES)
    except ValueError:
        return None
    return names[0] if len(names) == 1 else None


class DellCtx(Ctx):
    def __init__(self, project: dict):
        super().__init__(project)
        self.cfg = Blocks(indent=" ")
        self.dmodels: list = []
        self.svis: dict[int, list] = {}
        self.dot1x_ports: list[str] = []
        self.banner: str | None = None


# ------------------------------------------------------------------ sections
def _switch(ctx: DellCtx) -> None:
    members = ctx.p["switch"].get("members") or []
    if len(members) > 1:
        ctx.error("Switch", "OS10 switches don't stack. Use one switch per project (a VLT pair is two projects).")
    for m in members[:1]:
        ctx.at("switch.members", m)
        model = os10_models.get(m.get("model", ""))
        if model:
            ctx.dmodels.append(model)
            for port in model.ports:
                ctx.known[port["name"]] = port
        elif m.get("model") != os10_models.CUSTOM:
            ctx.error("Switch", f"Unknown Dell model '{m.get('model')}'. Pick one from the list or Custom.", "model")
    ctx.at("", None)
    try:
        for name in P.expand_named(ctx.p["switch"].get("custom_ports", ""), os10_models.ALIASES):
            ctx.known.setdefault(name, {"name": name, "kind": "access", "speed": "", "poe": False})
    except ValueError as exc:
        ctx.error("Switch", f"Custom ports: {exc}")


def _password(ctx: DellCtx, section: str, label: str, value, key: str) -> str | None:
    value = _s(value)
    if not value:
        return None
    field = key if not ctx.row else key.rsplit(".", 1)[-1]
    if is_hashed(value):
        if not value.startswith("$6$"):
            ctx.error(section, f"{label}: OS10 takes a $6$ (SHA-512) hash; type the password instead.", field)
            return None
        return value
    if len(value) < 9:
        ctx.error(section, f"{label}: OS10 needs at least 9 characters.", field)
        return None
    hashed = sha512_crypt(value)
    ctx.res.hashed[key] = hashed
    return hashed


def _system(ctx: DellCtx) -> None:
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
            cfg.line(f"ip domain-name {domain}")
        else:
            ctx.error("System", f"Domain '{domain}' is not a valid domain name.", "system.domain")
    servers = [ns for ns in _list(s.get("name_servers")) if _ip(ctx, "System", "DNS server", ns)]
    if len(servers) > 3:
        ctx.warn("System", "OS10 takes at most 3 DNS servers; the rest are left out.")
    if servers:
        cfg.line(f"ip name-server {' '.join(servers[:3])}")
    search = [d for d in _list(s.get("domain_search")) if DOMAIN.match(d)]
    if search:
        cfg.line(f"ip domain-list {' '.join(search)}")
    tz = _s(s.get("timezone"))
    if tz and tz != "UTC":
        if re.fullmatch(r"[A-Za-z0-9_+\-/]+", tz):
            cfg.line(f"clock timezone standard-timezone {tz}")
        else:
            ctx.error("System", f"Time zone '{tz}' is not valid.", "system.timezone")
    ntp = [n for n in s.get("ntp_servers") or [] if _s(n.get("address"))]
    if not ntp:
        ctx.warn("System", "No NTP server: logs and certificates need the right time.")
    for n in ntp:
        addr = _s(n.get("address"))
        if not (re.match(r"^[A-Za-z0-9.-]+$", addr) or _ip(ctx, "System", "NTP server", addr)):
            continue
        cfg.line(f"ntp server {addr}" + (" prefer" if _truthy(n.get("prefer")) else ""))
    if _s(s.get("ntp_source")):
        ctx.warn("System", "OS10 sets the NTP source by interface; add 'ntp source' by hand if needed.")
    if _truthy(s.get("mgmt_vrf")):
        ctx.warn("System", "The management VRF is not written for OS10; mgmt1/1/1 uses its own 'management route' instead.")

    mif = _s(s.get("mgmt_interface")) or "mgmt1/1/1"
    if mif.lower() != "mgmt1/1/1":
        ctx.error("System", f"Management port '{mif}' should be mgmt1/1/1 on OS10.", "system.mgmt_interface")
    addrs = _addresses(ctx, "System", "Management (mgmt1/1/1)", s.get("mgmt_address"))
    if addrs:
        body = cfg.block("interface mgmt1/1/1", "no ip address dhcp")
        for a in addrs:
            body.append(f"{'ip' if a.version == 4 else 'ipv6'} address {a.with_prefixlen}")
        body.append("no shutdown")
        gw = _s(s.get("mgmt_gateway"))
        if gw and (gw_ip := _ip(ctx, "System", "Management gateway", gw)):
            if not any(gw_ip in a.network for a in addrs if a.version == gw_ip.version):
                ctx.warn("System", f"Management gateway {gw} is not in the management subnet.")
            ctx.mgmt_route = f"management route {'0.0.0.0/0' if gw_ip.version == 4 else '::/0'} {gw}"
    elif _s(s.get("mgmt_gateway")):
        ctx.warn("System", "Management gateway is set but mgmt1/1/1 has no address.")
    banner = (s.get("banner") or "").rstrip()
    if banner.strip():
        delim = next((c for c in "%#^@~" if c not in banner), None)
        if not delim:
            ctx.error("System", "The banner uses every delimiter OS10 allows (% # ^ @ ~); remove one of them.", "system.banner")
        else:
            ctx.banner = f"banner login {delim}\n{banner}\n{delim}"


def _access(ctx: DellCtx) -> None:
    a, cfg = ctx.p["access"], ctx.cfg
    cfg.comment("Accounts and remote access")
    root = _password(ctx, "Access", "admin password", a.get("root_password"), "access.root_password")
    if root:
        cfg.line(f"username admin password {root} role sysadmin priv-lvl 15")
    names = set()
    for i, u in enumerate(a.get("users") or []):
        ctx.at("access.users", u)
        name = _s(u.get("name"))
        if not name:
            continue
        if not USERNAME.match(name) or name in ("root", "admin", "linuxadmin"):
            ctx.error("Access", f"User '{name}': use lower-case letters, digits, '.', '_' or '-' (not root, admin or linuxadmin).", "name")
            continue
        if name in names:
            ctx.error("Access", f"User '{name}' is listed twice.", "name")
            continue
        names.add(name)
        cls = u.get("class") or "read-only"
        if cls == "unauthorized":
            ctx.warn("Access", f"User '{name}' is 'unauthorized': skipped on OS10.")
            continue
        hashed = _password(ctx, "Access", f"User {name}", u.get("password"), f"access.users.{i}.password")
        if hashed:
            cfg.line(f"username {name} password {hashed} role {ROLES.get(cls, ROLES['read-only'])}")
        elif not _s(u.get("password")):
            ctx.error("Access", f"User '{name}' needs a password on OS10.", "password")
        if _s(u.get("ssh_keys")):
            ctx.warn("Access", f"User {name}: OS10 loads SSH keys from a file ('username {name} sshkey filename'); "
                               "add the key by hand.")
    ctx.at("", None)
    if not root and not any(u.get("class") == "super-user" and _s(u.get("name")) for u in a.get("users") or []):
        ctx.warn("Access", "No super-user account: nobody can change the config after this one.")
    if _truthy(a.get("retry_options")):
        cfg.line("password-attributes max-retry 3 lockout-period 5")
    if _truthy(a.get("web")):
        cfg.line("rest api restconf")
    if _truthy(a.get("netconf")):
        ctx.warn("Access", "OS10 has no NETCONF; it offers RESTCONF (tick the web/API option) instead.")


def _snmp(ctx: DellCtx) -> None:
    s, cfg = ctx.p["snmp"], ctx.cfg
    comms = [c for c in s.get("communities") or [] if _s(c.get("name"))]
    users = [u for u in s.get("v3_users") or [] if _s(u.get("name"))]
    targets = _list(s.get("trap_targets"))
    if not (comms or users or targets or _s(s.get("location")) or _s(s.get("contact"))):
        return
    cfg.comment("SNMP")
    for key in ("location", "contact"):
        if _s(s.get(key)):
            cfg.line(f"snmp-server {key} \"{_s(s.get(key))}\"")
    for c in comms:
        ctx.at("snmp.communities", c)
        name = _s(c.get("name"))
        if not re.fullmatch(r"[A-Za-z0-9_.@#%+=-]{1,32}", name):
            ctx.error("SNMP", f"Community '{name}' may only use letters, digits and _ . @ # % + = - (max 32).", "name")
            continue
        if name.lower() in ("public", "private"):
            ctx.warn("SNMP", f"Community '{name}' is a well-known default; pick something harder to guess.")
        mode = "rw" if c.get("access") == "read-write" else "ro"
        clients = [cl for cl in _list(c.get("clients")) if _ip(ctx, "SNMP", f"Community {name} client", cl, allow_net=True)]
        if clients:
            acl = f"SNMP-{name.upper()}"[:64]
            body = cfg.block(f"ip access-list {acl}")
            for i, cl in enumerate(clients, 1):
                body.append(f"seq {i * 10} permit ip {cl if '/' in cl else cl + '/32'} any")
            cfg.line(f"snmp-server community {name} {mode} acl {acl}")
        else:
            ctx.warn("SNMP", f"Community '{name}' accepts any source address. Add the allowed clients.")
            cfg.line(f"snmp-server community {name} {mode}")
    ctx.at("", None)
    if users:
        cfg.line("snmp-server view ALL 1.3.6.1 included")
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
            ctx.warn("SNMP", f"SNMPv3 user {name}: OS10 has no {auth_key}; SHA is used.")
            auth = "sha"
        line = f"snmp-server user {name} {name}-group 3 auth {auth} {apw}"
        priv_key = u.get("priv") or ""
        level = "auth"
        if priv_key:
            if len(ppw) < 8:
                ctx.error("SNMP", f"SNMPv3 user {name}: the privacy password needs at least 8 characters.", "priv_password")
                continue
            kind = "des" if priv_key == "des" else "aes"
            if priv_key not in ("des", "aes128"):
                ctx.warn("SNMP", f"SNMPv3 user {name}: OS10 has no {priv_key}; AES is used.")
            line += f" priv {kind} {ppw}"
            level = "priv"
        else:
            ctx.warn("SNMP", f"SNMPv3 user {name} has no privacy (encryption); polls are readable on the wire.")
        cfg.line(f"snmp-server group {name}-group 3 {level} read ALL")
        cfg.line(line)
    ctx.at("", None)
    if targets:
        comm = _s(s.get("trap_community")) or (comms[0]["name"] if comms else "traps")
        for t in targets:
            if _ip(ctx, "SNMP", "Trap target", t):
                cfg.line(f"snmp-server host {t} traps version 2c {comm}")
        cfg.line("snmp-server enable traps")


def _syslog(ctx: DellCtx) -> None:
    s, cfg = ctx.p["syslog"], ctx.cfg
    hosts = [h for h in s.get("hosts") or [] if _s(h.get("address"))]
    if not hosts:
        return
    cfg.comment("Logging")
    for h in hosts:
        ctx.at("syslog.hosts", h)
        addr = _s(h.get("address"))
        if not _ip(ctx, "Logging", "Syslog server", addr):
            continue
        port = _s(h.get("port"))
        if port and port != "514" and not (port.isdigit() and 1 <= int(port) <= 65535):
            ctx.error("Logging", f"Syslog port '{port}' is not valid.", "port")
            continue
        level = SEVERITY.get(h.get("level") or "info", "log-info")
        cfg.line(f"logging server {addr} severity {level}" + (f" udp {port}" if port and port != "514" else ""))
    ctx.at("", None)
    if _s(s.get("source_address")):
        ctx.warn("Logging", "OS10 sets the syslog source by interface; add it by hand if needed.")


def _vlans(ctx: DellCtx) -> None:
    vlans = [v for v in ctx.p["vlans"] if _s(v.get("name")) or _s(v.get("id"))]
    if not vlans:
        ctx.warn("VLANs", "No VLANs yet: access ports will land in VLAN 1.")
        return
    snoop = False
    for v in vlans:
        ctx.at("vlans", v)
        name, vid = _s(v.get("name")), _s(v.get("id"))
        if not NAME.match(name) or len(name) > 32:
            ctx.error("VLANs", f"VLAN name '{name}' must start with a letter, use letters, digits, '-', '_' or '.', max 32.", "name")
            continue
        if not vid.isdigit() or not 1 <= int(vid) <= 4093:
            ctx.error("VLANs", f"VLAN {name}: ID must be 1-4093 on OS10.", "id")
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
        addrs = _addresses(ctx, "VLANs", f"VLAN {name} address", v.get("irb"))
        if addrs:
            ctx.svis[n] = addrs
            ctx.l3_ifaces.add(f"vlan{n}")
        elif _truthy(v.get("dhcp_relay")):
            ctx.error("VLANs", f"VLAN {name}: DHCP relay needs a VLAN address.", "irb")
        snoop = snoop or _truthy(v.get("snooping"))
        if _truthy(v.get("dai")) or _truthy(v.get("ipsg")):
            ctx.warn("VLANs", f"VLAN {name}: ARP inspection and IP source guard are not written for OS10 yet.")
        if _s(v.get("vni")) or _s(v.get("vga")) or _s(v.get("vrf")):
            ctx.warn("VLANs", f"VLAN {name}: VNI, virtual gateway and VRF are not written for OS10 yet.")
    ctx.at("", None)
    ctx.cfg.comment("VLANs")
    for n, v in sorted(ctx.vlan_by_id.items()):
        ctx.cfg.block(f"interface vlan{n}", f"description {v['name']}", "no shutdown")
    if snoop:
        ctx.cfg.line("ip dhcp snooping")
        ctx.warn("VLANs", "OS10 turns DHCP snooping on for the whole switch, not per VLAN.")


def _claim(ctx: DellCtx, section: str, label: str, names: list[str]) -> list[str]:
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


def _port_body(ctx: DellCtx, section: str, label: str, body: list, row: dict, phys: list[str], is_lag=False) -> None:
    mode = row.get("mode") or "access"
    desc = _s(row.get("description"))
    if desc:
        body.append(f"description \"{desc}\"")
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
        if mtu.isdigit() and 1312 <= int(mtu) <= 9216:
            body.append(f"mtu {mtu}")
        else:
            ctx.error(section, f"{label}: MTU must be 1312-9216 on OS10.", "mtu")
    svc = ctx.p["services"]
    edge = ["spanning-tree port type edge"] + (["spanning-tree bpduguard enable"] if _truthy(svc.get("bpdu_block_on_edge")) else [])
    if mode == "access":
        body.append("switchport mode access")
        vlan = _vlan_name(ctx, section, label, row.get("vlan"), "vlan")
        if vlan:
            body.append(f"switchport access vlan {_vid(ctx, vlan)}")
        elif not _s(row.get("vlan")):
            ctx.warn(section, f"{label}: no access VLAN, so the port uses VLAN 1.")
        if _s(row.get("voice")):
            ctx.warn(section, f"{label}: the voice VLAN is not written for OS10 yet; only the data VLAN is.")
        if _truthy(row.get("edge")):
            body.extend(edge)
        if _s(row.get("mac_limit")) or _truthy(row.get("sticky")):
            ctx.warn(section, f"{label}: port security (MAC limit, sticky MAC) is not written for OS10 yet.")
        if _truthy(row.get("dhcp_trusted")):
            body.append("ip dhcp snooping trust")
        dot1x = _s(row.get("dot1x"))
        if dot1x:
            body.append("dot1x port-control auto")
            if dot1x in ("dot1x-mab", "mab"):
                ctx.warn(section, f"{label}: MAB is not written for OS10 yet; only 802.1X is.")
            ctx.dot1x_ports.extend(phys)
    elif mode == "trunk":
        body.append("switchport mode trunk")
        refs = _list(row.get("vlans"))
        if not refs:
            ctx.error(section, f"{label}: a trunk needs at least one VLAN (or 'all').", "vlans")
        native = _vlan_name(ctx, section, f"{label} native", row.get("native"), "native")
        if any(r.lower() == "all" for r in refs):
            tagged = [n for n in ctx.vlan_by_id if not native or n != _vid(ctx, native)]
        else:
            tagged = [_vid(ctx, n) for r in refs if (n := _vlan_name(ctx, section, label, r, "vlans"))]
            if native:
                tagged = [t for t in tagged if t != _vid(ctx, native)]
        # On OS10 the untagged VLAN of a trunk is its access VLAN (VLAN 1 unless set).
        if native:
            body.append(f"switchport access vlan {_vid(ctx, native)}")
        if tagged:
            body.append(f"switchport trunk allowed vlan {_vid_list(tagged)}")
        if _truthy(row.get("root_guard")):
            body.append("spanning-tree guard root")
        if _truthy(row.get("loop_protect")):
            body.append("spanning-tree guard loop")
        if _s(row.get("voice")):
            ctx.warn(section, f"{label}: voice VLAN only applies to access ports; ignored on a trunk.")
        if _s(row.get("vlan_translate")):
            ctx.error(section, f"{label}: VLAN translation is not available on OS10.", "vlan_translate")
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
    if mode not in ("trunk",) and _s(row.get("vlan_translate")):
        ctx.error(section, f"{label}: VLAN translation is not available on OS10.", "vlan_translate")
    if mode != "routed" and _s(row.get("address")):
        ctx.warn(section, f"{label}: the IP address is only used in routed mode. Use a VLAN address for switch ports.")
    if not is_lag and (_s(row.get("poe")) or _s(row.get("poe_max"))):
        ctx.warn(section, f"{label}: PoE settings are not written for OS10 yet; PoE ports power up by default.")
    body.append("no shutdown")


def _range(names: list[str], use_ranges: bool) -> list[str]:
    """Interface block headers for a port group ('range ethernet1/1/1-1/1/24,ethernet1/1/30')."""
    if not use_ranges or len(names) == 1:
        return names
    runs = P.named_runs(names)
    if len(runs) == 1 and runs[0][0] == runs[0][1]:
        return [runs[0][0]]
    return ["range " + ",".join(a if a == b else f"{a}-{b[len('ethernet'):]}" for a, b in runs)]


def _ports(ctx: DellCtx) -> None:
    rows = [r for r in ctx.p["ports"] if _s(r.get("ports"))]
    if not rows:
        return
    ctx.cfg.comment("Switch ports")
    use_ranges = _truthy(ctx.p["services"].get("use_ranges"))
    for i, row in enumerate(rows):
        ctx.at("ports", row)
        label = _s(row.get("name")) or f"Port group {i + 1}"
        try:
            names = P.expand_named(row.get("ports"), os10_models.ALIASES)
        except ValueError as exc:
            ctx.error("Ports", f"{label}: {exc} (example: ethernet1/1/1-24, eth1/1/49).", "ports")
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


def _lags(ctx: DellCtx) -> None:
    lags = [r for r in ctx.p["lags"] if _s(r.get("name")) or _s(r.get("members"))]
    if not lags:
        return
    ctx.cfg.comment("Port-channels (LACP)")
    seen = set()
    for row in lags:
        ctx.at("lags", row)
        raw = _s(row.get("name"))
        m = _PO.fullmatch(raw) or re.fullmatch(r"(\d{1,3})", raw)
        num = int(m.group(1)) if m else -1
        if not 1 <= num <= 128:
            ctx.error("LAGs", f"LAG name '{raw}' must be port-channel1 to port-channel128 (Po1 also works).", "name")
            continue
        name = f"port-channel{num}"
        if num in seen:
            ctx.error("LAGs", f"{name} is listed twice.", "name")
            continue
        seen.add(num)
        try:
            members = P.expand_named(row.get("members"), os10_models.ALIASES)
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
        if lacp == "static":
            ctx.warn("LAGs", f"{name}: static LAG without LACP can't detect a mis-cabled member.")
        body: list[str] = []
        _port_body(ctx, "LAGs", name, body, row, [name], is_lag=True)
        ml = _s(row.get("min_links"))
        if ml:
            if ml.isdigit() and 1 <= int(ml) <= len(members):
                body.insert(-1, f"minimum-links {ml}")
            else:
                ctx.error("LAGs", f"{name}: minimum links must be 1-{len(members)}.", "min_links")
        if _s(row.get("esi")):
            ctx.warn("LAGs", f"{name}: EVPN multihoming (ESI) is not written for OS10 (VLT is set up by hand).")
        ctx.cfg.block(f"interface {name}", *body)
        for mem in members:
            mb = ctx.cfg.block(f"interface {mem}")
            if _s(row.get("description")):
                mb.append(f"description \"{_s(row.get('description'))} (member of {name})\"")
            mb.append("no switchport")
            if lacp != "static" and _truthy(row.get("lacp_fast")):
                mb.append("lacp rate fast")
            mb.append(f"channel-group {num}" + ("" if lacp == "static" else f" mode {lacp}"))
            mb.append("shutdown" if row.get("mode") == "disabled" else "no shutdown")
            ctx.res.ports[mem] = {"use": "lag", "label": name}
    ctx.at("", None)


def _l3(ctx: DellCtx) -> None:
    """VLAN addresses, loopback, routing identity and DHCP relay."""
    r, cfg = ctx.p["routing"], ctx.cfg
    servers = [sv for sv in _list(r.get("dhcp_relay_servers")) if _ip(ctx, "Routing", "DHCP server", sv)]
    relay = {int(v["id"]) for v in ctx.vlan_by_name.values() if _truthy(v.get("dhcp_relay")) and _s(v.get("irb"))}
    if relay and not servers:
        ctx.error("Routing", "VLANs use DHCP relay but no DHCP server is set on the Routing tab.")
    if ctx.svis:
        cfg.comment("VLAN addresses")
    for vid, addrs in sorted(ctx.svis.items()):
        body = cfg.block(f"interface vlan{vid}")
        for a in addrs:
            body.append(f"{'ip' if a.version == 4 else 'ipv6'} address {a.with_prefixlen}")
        if vid in relay:
            body.extend(f"ip helper-address {sv}" for sv in servers)
    lo = _s(r.get("loopback"))
    if lo:
        addrs = _addresses(ctx, "Routing", "Loopback", lo if "/" in lo else f"{lo}/32")
        if addrs:
            body = cfg.block("interface loopback0")
            for a in addrs:
                body.append(f"{'ip' if a.version == 4 else 'ipv6'} address {a.with_prefixlen}")
                if a.version == 4:
                    ctx.loopback_ip = str(a.ip)
            body.append("no shutdown")
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


def _static(ctx: DellCtx) -> None:
    r, cfg = ctx.p["routing"], ctx.cfg
    routes = [x for x in r.get("static") or [] if _s(x.get("prefix"))]
    mgmt = getattr(ctx, "mgmt_route", None)
    if routes or mgmt:
        cfg.comment("Static routes")
    if mgmt:
        cfg.line(mgmt)
    for x in routes:
        ctx.at("routing.static", x)
        prefix = "0.0.0.0/0" if _s(x.get("prefix")) == "default" else _s(x.get("prefix"))
        net = _ip(ctx, "Routing", "Route", prefix, allow_net=True)
        if not net:
            continue
        nh = _s(x.get("next_hop"))
        if nh in ("discard", "reject"):
            target = "interface null0"
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


def _ospf(ctx: DellCtx) -> None:
    o = ctx.p["routing"].get("ospf") or {}
    if not _truthy(o.get("enabled")):
        return
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
            body.append(f"auto-cost reference-bandwidth {int(m.group(1)) * (1000 if m.group(2) == 'g' else 1)}")
        else:
            ctx.error("OSPF", "Reference bandwidth must look like 100g or 100000 (Mbps).", "routing.ospf.reference_bandwidth")
    if _s(o.get("export")):
        ctx.warn("OSPF", "Export policies are not written for OS10 yet; add 'redistribute' lines by hand.")
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
        if _s(a.get("md5_key")):
            ctx.warn("OSPF", f"Area {area}: OSPF authentication is not written for OS10 yet.")
        p2p = {_iface_name(x) for x in P.iface_list(a.get("p2p"))}
        passive = {_iface_name(x) for x in P.iface_list(a.get("passive"))}
        for raw in P.iface_list(a.get("interfaces")) + P.iface_list(a.get("passive")):
            name = _iface_name(raw)
            if not name:
                ctx.error("OSPF", f"Area {area}: '{raw}' is not an OS10 interface (ethernet1/1/49, vlan20, loopback0).", "interfaces")
                continue
            ib = cfg.block(f"interface {name}", f"ip ospf 1 area {area}")
            if name in passive and not name.startswith("loopback") and "ip ospf passive" not in ib:
                ib.append("ip ospf passive")
            if name in p2p and "ip ospf network point-to-point" not in ib:
                ib.append("ip ospf network point-to-point")
    ctx.at("", None)


def _bgp(ctx: DellCtx) -> None:
    groups = [g for g in ctx.p["routing"].get("bgp_groups") or [] if _s(g.get("name")) or _s(g.get("neighbors"))]
    if not groups:
        return
    cfg = ctx.cfg
    if not ctx.asn:
        ctx.error("BGP", "BGP needs the switch's AS number (Routing tab).", "routing.asn")
        return
    cfg.comment("BGP")
    body = cfg.block(f"router bgp {ctx.asn}")
    if ctx.router_id:
        body.append(f"router-id {ctx.router_id}")
    af = ["address-family ipv4 unicast"]
    if ctx.loopback_ip:
        af.append(f" network {ctx.loopback_ip}/32")
    if any(_truthy(g.get("multipath")) for g in groups) or _truthy(ctx.p["routing"].get("ecmp")):
        af.append(" maximum-paths ebgp 4")
        af.append(" maximum-paths ibgp 4")
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
        body.append(f"template {name}")
        tpl = []
        if not external:
            tpl.append(f"remote-as {ctx.asn}")
        elif peer_as:
            tpl.append(f"remote-as {peer_as}")
        if _s(g.get("description")):
            tpl.append(f"description \"{_s(g.get('description'))}\"")
        local = _s(g.get("local_address"))
        if local and ctx.loopback_ip and local == ctx.loopback_ip:
            tpl.append("update-source loopback0")
        elif local:
            ctx.warn("BGP", f"Group {name}: OS10 sets the source by interface; only the loopback address is mapped.")
        if _s(g.get("auth_key")):
            tpl.append(f"password {_s(g.get('auth_key'))}")
        if _s(g.get("bfd")):
            tpl.append("bfd")
        body.extend(" " + t for t in tpl)
        if _s(g.get("import")) or _s(g.get("export")):
            ctx.warn("BGP", f"Group {name}: import/export policies are not written for OS10 yet (use route-maps).")
        for ip, asn, desc in neighbors:
            body.append(f"neighbor {ip}")
            body.append(f" inherit template {name}")
            if external and asn:
                body.append(f" remote-as {asn}")
            elif external and not peer_as:
                ctx.error("BGP", f"Group {name}: neighbor {ip} needs a peer AS (on the group or after the IP).", "neighbors")
            if desc:
                body.append(f" description \"{desc}\"")
            body.append(" no shutdown")
    ctx.at("", None)


def _services(ctx: DellCtx) -> None:
    s, cfg = ctx.p["services"], ctx.cfg
    cfg.comment("Switching services")
    if not _truthy(s.get("lldp")):
        cfg.line("no lldp enable")
    stp = s.get("stp")
    if stp == "rstp":
        cfg.line("spanning-tree mode rstp")
        prio = _s(s.get("bridge_priority")).lower()
        if prio:
            m = re.fullmatch(r"(\d+)(k?)", prio)
            val = int(m.group(1)) * (1024 if m.group(2) else 1) if m else -1
            val = 4096 * round(val / 4096) if m and m.group(2) else val
            if 0 <= val <= 61440 and val % 4096 == 0:
                cfg.line(f"spanning-tree rstp priority {val}")
            else:
                ctx.error("Services", "Bridge priority must be 0, 4k, 8k ... 60k (steps of 4k).", "services.bridge_priority")
    elif stp == "none":
        cfg.line("spanning-tree disable")
        ctx.warn("Services", "Spanning tree is off: a cabling loop will take the network down.")
    if _truthy(s.get("storm_control")):
        ctx.warn("Services", "OS10 sets storm control in packets per second, not a percentage; not written.")
    if ctx.dot1x_ports:
        sec = ctx.p.get("security") or {}
        servers = [x for x in sec.get("radius_servers") or [] if _s(x.get("address"))]
        if not servers:
            ctx.error("Security", "802.1X ports need at least one RADIUS server.")
        for x in servers:
            ctx.at("security.radius_servers", x)
            addr = _s(x.get("address"))
            if _ip(ctx, "Security", "RADIUS server", addr):
                if not _s(x.get("secret")):
                    ctx.error("Security", f"RADIUS server {addr} needs a shared secret.", "secret")
                    continue
                port = _s(x.get("port"))
                cfg.line(f"radius-server host {addr}" + (f" auth-port {port}" if port else "") + f" key {_s(x.get('secret'))}")
        ctx.at("", None)
        cfg.line("dot1x system-auth-control")
    if _truthy(s.get("disable_unused")) and ctx.known:
        unused = [n for n, info in ctx.known.items() if n not in ctx.used and info["kind"] in ("access", "uplink")]
        if unused:
            for header in _range(unused, _truthy(s.get("use_ranges"))):
                cfg.block(f"interface {header}", "description \"Unused - disabled\"", "shutdown")
            for n in unused:
                ctx.res.ports.setdefault(n, {"use": "disabled", "label": "Unused"})


def _unsupported(ctx: DellCtx) -> None:
    p = ctx.p
    if _truthy((p.get("evpn") or {}).get("enabled")):
        ctx.warn("EVPN", "EVPN-VXLAN is not written for OS10 yet.")
    if any((p.get("policy") or {}).get(k) for k in ("prefix_lists", "communities", "terms")):
        ctx.warn("Policies", "Routing policies are not written for OS10 yet.")
    if _truthy((p.get("qos") or {}).get("enabled")):
        ctx.warn("QoS", "QoS is not written for OS10 yet.")


def header(p: dict) -> list[str]:
    name = _s(p.get("name")) or _s(p.get("system", {}).get("hostname")) or "switch"
    model = ", ".join(_s(m.get("model")) for m in (p["switch"].get("members") or [])[:1])
    return [f"Dell SmartFabric OS10 configuration for {name}", f"Hardware: {model}",
            f"Made by Multi-Vendor Switch Config Builder {__version__}. Review before you load it."]


def build(project: dict) -> Result:
    p = normalize(project)
    ctx = DellCtx(p)
    ctx.mgmt_route = None
    for t in header(p):
        ctx.cfg.comment(t)
    for step in (_switch, _system, _access, _snmp, _syslog, _vlans, _ports, _lags, _l3, _static, _ospf, _bgp,
                 _services, _unsupported):
        step(ctx)
        ctx.row = None
    text = ctx.cfg.text()
    if ctx.banner:
        text = text[: -len("end\n")] + ctx.banner + "\n!\nend\n"
    ctx.res.errors = _dedupe(ctx.res.errors)
    ctx.res.warnings = _dedupe(ctx.res.warnings)
    ctx.res.set_text = text
    ctx.res.hier_text = text
    ctx.res.hostname = _s(p["system"].get("hostname")) or "switch"
    return ctx.res
