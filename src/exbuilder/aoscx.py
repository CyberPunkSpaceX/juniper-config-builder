"""Turn a project into HPE Aruba CX configuration (AOS-CX 10.x).

Uses the same project format as the other builders (see generator.py). Ports
are ``member/1/port`` (1/1/1), VSF stack members are 1-10, LAGs are
``lag N``, VLAN interfaces are ``interface vlan N`` and the out-of-band port
is ``interface mgmt`` in the ``mgmt`` VRF.

AOS-CX encrypts passwords with a key of its own, so the config carries them
as ``plaintext`` and the switch turns them into ``ciphertext`` when loaded.
"""

from __future__ import annotations

import ipaddress
import re
import zoneinfo

from . import __version__, aoscx_models as CX, vendors
from . import ports as P
from . import routing as R
from .eos import _dedupe, _vid_list
from .generator import (DOMAIN, HOSTNAME, NAME, USERNAME, Ctx, Result, _addresses, _ip, _list, _s, _truthy,
                        _vlan_name, normalize)
from .textcfg import Blocks

VENDOR = vendors.VENDORS["aruba"]
SPEEDS = {"10m": "10-full", "100m": "100-full", "1g": "1000-full"}
LEVELS = {"emergency": "emergency", "alert": "alert", "critical": "critical", "error": "error",
          "warning": "warning", "notice": "notice", "info": "info", "any": "debug"}
GROUPS = {"super-user": "administrators", "operator": "operators", "read-only": "operators"}
SNMP_AUTH = {"md5": "md5", "sha": "sha", "sha224": "sha", "sha256": "sha", "sha384": "sha", "sha512": "sha"}
SNMP_PRIV = {"aes128": "aes", "des": "des", "3des": "des"}
POE_PRIO = {"high": "high", "low": "low"}
_LAG = re.compile(r"^(?:lag|ae|po|port-channel)\s*(\d{1,3})$", re.I)
_SSH_KEY = re.compile(r"^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+)\s+[A-Za-z0-9+/=]+")


def _ports(spec) -> list[str]:
    """'1/1/1-1/1/24, 1/1/49' (AOS-CX style) or '1/1/1-24' -> port names."""
    text = re.sub(r"\b(\d+/\d+/)(\d+)\s*-\s*\1(\d+)\b", r"\1\2-\3", _s(spec))
    text = re.sub(r"\binterface\s+", "", text, flags=re.I)
    return P.expand_named(text, CX.ALIASES)


def _cx_range(names: list[str]) -> str:
    """Ports as an AOS-CX list: 1/1/1-1/1/24,1/1/30."""
    return ",".join(a if a == b else f"{a}-{b}" for a, b in P.named_runs(names))


def _vid(ctx: Ctx, name: str) -> int:
    return int(ctx.vlan_by_name[name]["id"])


def _iface_name(text: str) -> str | None:
    t = _s(text)
    if not t:
        return None
    if m := re.fullmatch(r"(?:irb\.|vlan\s*|ve\s*)(\d{1,4})", t, re.I):
        return f"vlan {m.group(1)}"
    if m := re.fullmatch(r"(?:lo|loopback)\s*(\d{0,3})(?:\.0)?", t, re.I):
        return f"loopback {m.group(1) or 0}"
    if m := _LAG.fullmatch(t):
        return f"lag {m.group(1)}"
    try:
        names = _ports(t)
    except ValueError:
        return None
    return names[0] if len(names) == 1 else None


def _timezone(tz: str) -> str | None:
    try:
        zoneinfo.ZoneInfo(tz)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        return None
    return tz.lower()


class CxCtx(Ctx):
    def __init__(self, project: dict):
        super().__init__(project)
        self.cfg = Blocks(indent="    ")
        self.cmodels: list = []
        self.svis: dict[int, list] = {}
        self.dot1x: dict[str, str] = {}       # interface header -> dot1x mode
        self.trunks: list[str] = []           # headers of trunk ports and LAGs (trusted for snooping/DAI)
        self.snoop: list[int] = []
        self.dai: list[int] = []
        self.port_security = False
        self.banner = None
        self.plaintext = False
        self.mgmt_gw = None


# ------------------------------------------------------------------ sections
def _switch(ctx: CxCtx) -> None:
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
            num = 1  # projects copied from Juniper start at member 0
        if not 1 <= num <= 10 or num in seen:
            ctx.error("Switch", f"VSF member number {m.get('fpc')} must be 1-10 and used once.", "fpc")
            continue
        seen.add(num)
        model = CX.get(m.get("model", ""))
        if model:
            ctx.cmodels.append((num, model))
            for port in model.ports(num):
                ctx.known[port["name"]] = port
            if len(members) > 1 and not model.stack:
                ctx.error("Switch", f"{model.name} doesn't stack with VSF. Use one switch per project.", "model")
        elif m.get("model") != CX.CUSTOM:
            ctx.error("Switch", f"Unknown Aruba CX model '{m.get('model')}'. Pick one from the list or Custom.", "model")
    ctx.at("", None)
    families = {mod.family for _, mod in ctx.cmodels}
    if len(families) > 1:
        ctx.error("Switch", f"A VSF stack can't mix {' and '.join(sorted(families))} switches.")
    if "6200" in families and len(members) > 8:
        ctx.error("Switch", "A 6200 VSF stack holds at most 8 switches.")
    if len(members) > 1:
        ctx.cfg.comment("VSF stack: set the links on each member ('link 1 <port>') before you join it")
        for num, mod in ctx.cmodels:
            if mod.vsf:
                ctx.cfg.block(f"vsf member {num}", f"type {mod.vsf}")
    try:
        for name in _ports(ctx.p["switch"].get("custom_ports", "")):
            ctx.known.setdefault(name, {"name": name, "kind": "access", "speed": "", "poe": False})
    except ValueError as exc:
        ctx.error("Switch", f"Custom ports: {exc}")


def _password(ctx: CxCtx, section: str, label: str, value, key: str) -> str | None:
    value = _s(value)
    if not value:
        return None
    short = key if not ctx.row else key.rsplit(".", 1)[-1]
    if value.startswith("$"):
        ctx.error(section, f"{label}: this password was hashed for another vendor; type it again for AOS-CX.", short)
        return None
    if len(value) < 8 or len(value) > 32 or re.search(r"[\s\"'?]", value):
        ctx.error(section, f"{label}: use 8-32 characters with no spaces, quotes or '?'.", short)
        return None
    ctx.plaintext = True
    return value


def _system(ctx: CxCtx) -> None:
    s, cfg = ctx.p["system"], ctx.cfg
    cfg.comment("System")
    host = _s(s.get("hostname"))
    if not host:
        ctx.error("System", "Host name is required.", "system.hostname")
    elif not HOSTNAME.match(host) or len(host) > 32:
        ctx.error("System", f"Host name '{host}' may only use letters, digits and hyphens (max 32).", "system.hostname")
    else:
        cfg.line(f"hostname {host}")
    vrf = "mgmt" if _truthy(s.get("mgmt_vrf")) else "default"
    domain = _s(s.get("domain"))
    if domain:
        if DOMAIN.match(domain):
            cfg.line(f"ip dns domain-name {domain}" + (" vrf mgmt" if vrf == "mgmt" else ""))
        else:
            ctx.error("System", f"Domain '{domain}' is not a valid domain name.", "system.domain")
    for d in _list(s.get("domain_search")):
        if DOMAIN.match(d):
            cfg.line(f"ip dns domain-list {d}" + (" vrf mgmt" if vrf == "mgmt" else ""))
    for ns in _list(s.get("name_servers"))[:3]:
        if _ip(ctx, "System", "DNS server", ns):
            cfg.line(f"ip dns server-address {ns}" + (" vrf mgmt" if vrf == "mgmt" else ""))
    tz = _s(s.get("timezone"))
    if tz and tz != "UTC":
        name = _timezone(tz)
        if name:
            cfg.line(f"clock timezone {name}")
        else:
            ctx.error("System", f"Time zone '{tz}' is not known.", "system.timezone")
    ntp = [n for n in s.get("ntp_servers") or [] if _s(n.get("address"))]
    if not ntp:
        ctx.warn("System", "No NTP server: logs and certificates need the right time.")
    for n in ntp:
        addr = _s(n.get("address"))
        if not (re.match(r"^[A-Za-z0-9.-]+$", addr) or _ip(ctx, "System", "NTP server", addr)):
            continue
        cfg.line(f"ntp server {addr} iburst" + (" prefer" if _truthy(n.get("prefer")) else ""))
    if ntp:
        cfg.line("ntp enable")
        if vrf == "mgmt":
            cfg.line("ntp vrf mgmt")
    if _s(s.get("ntp_source")):
        ctx.warn("System", "AOS-CX sets the NTP source by interface ('ntp source-interface ...'); add it by hand if needed.")
    has_mgmt = not ctx.cmodels or any(mod.has_mgmt for _, mod in ctx.cmodels)
    addrs = _addresses(ctx, "System", "Management port", s.get("mgmt_address"))
    if addrs and not has_mgmt:
        ctx.error("System", f"The {ctx.cmodels[0][1].name} has no out-of-band management port; "
                            "manage it through a VLAN interface instead.", "system.mgmt_address")
    elif addrs:
        if vrf != "mgmt":
            ctx.warn("System", "On AOS-CX the management port is always in the 'mgmt' VRF. Tick 'Management VRF' "
                               "so DNS, NTP, SSH and logging use it too.")
        body = cfg.block("interface mgmt", "no shutdown")
        for a in addrs:
            body.append(f"ip static {a.with_prefixlen}")
        gw = _s(s.get("mgmt_gateway"))
        if gw and (gw_ip := _ip(ctx, "System", "Management gateway", gw)):
            if not any(gw_ip in a.network for a in addrs if a.version == gw_ip.version):
                ctx.warn("System", f"Management gateway {gw} is not in the management subnet.")
            body.append(f"default-gateway {gw}")
    elif _s(s.get("mgmt_gateway")):
        ctx.warn("System", "Management gateway is set but the management port has no address.")
    banner = (s.get("banner") or "").rstrip()
    if banner.strip():
        if "^" in banner:
            ctx.error("System", "The banner can't contain '^' (it ends the banner).", "system.banner")
        else:
            ctx.banner = banner


def _access(ctx: CxCtx) -> None:
    a, s, cfg = ctx.p["access"], ctx.p["system"], ctx.cfg
    cfg.comment("Accounts and remote access")
    root = _password(ctx, "Access", "admin password (root password)", a.get("root_password"), "access.root_password")
    if root:
        cfg.line(f"user admin group administrators password plaintext {root}")
    names = set()
    for i, u in enumerate(a.get("users") or []):
        ctx.at("access.users", u)
        name = _s(u.get("name"))
        if not name:
            continue
        if not USERNAME.match(name) or name in ("root",) or len(name) > 32:
            ctx.error("Access", f"User '{name}': use lower-case letters, digits, '.', '_' or '-' (max 32).", "name")
            continue
        if name == "admin" and root:
            ctx.error("Access", "User 'admin' is already set by the root password; pick another name.", "name")
            continue
        if name in names:
            ctx.error("Access", f"User '{name}' is listed twice.", "name")
            continue
        names.add(name)
        cls = u.get("class") or "read-only"
        if cls == "unauthorized":
            ctx.warn("Access", f"User '{name}' is 'unauthorized': skipped on AOS-CX.")
            continue
        group = GROUPS.get(cls, "operators")
        pw = _password(ctx, "Access", f"User {name}", u.get("password"), f"access.users.{i}.password")
        keys = [k.strip() for k in (u.get("ssh_keys") or "").splitlines() if k.strip()]
        for k in keys:
            if not _SSH_KEY.match(k):
                ctx.error("Access", f"User {name}: '{k[:20]}…' is not an SSH public key.", "ssh_keys")
        keys = [k for k in keys if _SSH_KEY.match(k)]
        if pw:
            cfg.line(f"user {name} group {group} password plaintext {pw}")
        elif keys:
            cfg.line(f"user {name} group {group}")
        elif not _s(u.get("password")):
            ctx.error("Access", f"User '{name}' needs a password or an SSH key.", "password")
        for n, k in enumerate(keys[:5], 1):
            cfg.line(f"user {name} authorized-key {n} {k}")
    ctx.at("", None)
    if not root:
        ctx.warn("Access", "No root password: the built-in 'admin' account keeps whatever password it has now.")
    if ctx.plaintext:
        ctx.warn("Access", "AOS-CX takes passwords in plain text in a pasted config and encrypts them on the "
                           "switch. They stay readable in this project, so keep the project private.")
    vrf = "mgmt" if _truthy(s.get("mgmt_vrf")) else "default"
    cfg.line(f"ssh server vrf {vrf}")
    if vrf == "mgmt" and ctx.svis_planned:
        cfg.line("ssh server vrf default")
    cfg.line("ssh maximum-auth-attempts 3")
    if _truthy(a.get("web")):
        cfg.line(f"https-server vrf {vrf}")
    else:
        cfg.line(f"no https-server vrf {vrf}")
    if _truthy(a.get("netconf")):
        ctx.warn("Access", "NETCONF is not written for AOS-CX; use the REST API (https-server rest access-mode read-write).")
    if _truthy(a.get("retry_options")):
        cfg.line("aaa authentication limit-login-attempts 5 lockout-time 120")


def _snmp(ctx: CxCtx) -> None:
    s, cfg = ctx.p["snmp"], ctx.cfg
    comms = [c for c in s.get("communities") or [] if _s(c.get("name"))]
    users = [u for u in s.get("v3_users") or [] if _s(u.get("name"))]
    targets = _list(s.get("trap_targets"))
    if not (comms or users or targets or _s(s.get("location")) or _s(s.get("contact"))):
        return
    cfg.comment("SNMP")
    vrf = "mgmt" if _truthy(ctx.p["system"].get("mgmt_vrf")) else "default"
    cfg.line(f"snmp-server vrf {vrf}")
    if _s(s.get("location")):
        cfg.line(f"snmp-server system-location {_s(s.get('location'))}")
    if _s(s.get("contact")):
        cfg.line(f"snmp-server system-contact {_s(s.get('contact'))}")
    for c in comms:
        ctx.at("snmp.communities", c)
        name = _s(c.get("name"))
        if not re.fullmatch(r"[A-Za-z0-9_.@#%+=-]{1,32}", name):
            ctx.error("SNMP", f"Community '{name}' may only use letters, digits and _ . @ # % + = - (max 32).", "name")
            continue
        if name.lower() in ("public", "private"):
            ctx.warn("SNMP", f"Community '{name}' is a well-known default; pick something harder to guess.")
        clients = []
        for cl in _list(c.get("clients")):
            net = _ip(ctx, "SNMP", f"Community {name} client", cl, allow_net=True)
            if net and net.version == 4:
                clients.append(net)
        body = [f"access-level {'rw' if c.get('access') == 'read-write' else 'ro'}"]
        if clients:
            acl = f"SNMP-{name.upper()}"[:32]
            ab = cfg.block(f"access-list ip {acl}")
            for n, net in enumerate(clients, 1):
                ab.append(f"{n * 10} permit udp {net.network_address}/{net.netmask} any eq 161")
            body.append(f"access-list {acl}")
        else:
            ctx.warn("SNMP", f"Community '{name}' accepts any source address. Add the allowed clients.")
        cfg.block(f"snmp-server community {name}", *body)
    ctx.at("", None)
    for u in users:
        ctx.at("snmp.v3_users", u)
        name = _s(u.get("name"))
        apw, ppw = _s(u.get("auth_password")), _s(u.get("priv_password"))
        if len(apw) < 8:
            ctx.error("SNMP", f"SNMPv3 user {name}: the authentication password needs at least 8 characters.", "auth_password")
            continue
        line = f"snmpv3 user {name} auth {SNMP_AUTH.get(u.get('auth') or 'sha', 'sha')} auth-pass plaintext {apw}"
        priv = SNMP_PRIV.get(u.get("priv") or "")
        if priv:
            if len(ppw) < 8:
                ctx.error("SNMP", f"SNMPv3 user {name}: the privacy password needs at least 8 characters.", "priv_password")
                continue
            line += f" priv {priv} priv-pass plaintext {ppw}"
        else:
            ctx.warn("SNMP", f"SNMPv3 user {name} has no privacy (encryption); polls are readable on the wire.")
        cfg.line(line)
    ctx.at("", None)
    if targets:
        comm = _s(s.get("trap_community")) or (comms[0]["name"] if comms else "traps")
        for t in targets:
            if _ip(ctx, "SNMP", "Trap target", t):
                cfg.line(f"snmp-server host {t} trap version v2c community {comm}" + (" vrf mgmt" if vrf == "mgmt" else ""))


def _syslog(ctx: CxCtx) -> None:
    s, cfg = ctx.p["syslog"], ctx.cfg
    vrf = _truthy(ctx.p["system"].get("mgmt_vrf"))
    hosts = []
    for h in s.get("hosts") or []:
        ctx.at("syslog.hosts", h)
        addr = _s(h.get("address"))
        if not addr or not _ip(ctx, "Logging", "Syslog server", addr):
            continue
        port = _s(h.get("port"))
        if port and port != "514" and not (port.isdigit() and 1 <= int(port) <= 65535):
            ctx.error("Logging", f"Syslog port '{port}' is not valid.", "port")
            continue
        hosts.append(f"logging {addr}" + (f" udp {port}" if port and port != "514" else "")
                     + f" severity {LEVELS.get(h.get('level') or 'info', 'info')}" + (" vrf mgmt" if vrf else ""))
    ctx.at("", None)
    if hosts:
        cfg.comment("Logging")
        for ln in hosts:
            cfg.line(ln)
    if _s(s.get("source_address")):
        ctx.warn("Logging", "AOS-CX sets the syslog source by interface ('ip source-interface syslog ...'); add it by hand.")


def _vlans(ctx: CxCtx) -> None:
    cfg = ctx.cfg
    vlans = [v for v in ctx.p["vlans"] if _s(v.get("name")) or _s(v.get("id"))]
    if not vlans:
        ctx.warn("VLANs", "No VLANs yet: access ports will land in VLAN 1.")
        return
    cfg.comment("VLANs")
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
        body = cfg.block(f"vlan {n}", f"name {name}")
        if _truthy(v.get("voice")):
            body.append("voice")
        addrs = _addresses(ctx, "VLANs", f"VLAN {name} interface", v.get("irb"))
        if addrs:
            ctx.svis[n] = addrs
            ctx.l3_ifaces.add(f"vlan {n}")
        elif _truthy(v.get("dhcp_relay")):
            ctx.error("VLANs", f"VLAN {name}: DHCP relay needs a VLAN interface address.", "irb")
        if _truthy(v.get("snooping")) or _truthy(v.get("dai")):
            ctx.snoop.append(n)
            body.append("dhcpv4-snooping")
        if _truthy(v.get("dai")):
            ctx.dai.append(n)
            body.append("arp inspection")
        if _truthy(v.get("ipsg")):
            ctx.warn("VLANs", f"VLAN {name}: IP source guard ('ipv4 source-lockdown') is not written for AOS-CX yet.")
        if _s(v.get("vni")) or _s(v.get("vga")) or _s(v.get("vrf")):
            ctx.warn("VLANs", f"VLAN {name}: VNI, virtual gateway and VRF are not written for AOS-CX yet.")
    ctx.at("", None)
    ctx.svis_planned = bool(ctx.svis)


def _claim(ctx: CxCtx, section: str, label: str, names: list[str]) -> list[str]:
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


def _port_body(ctx: CxCtx, section: str, label: str, body: list, row: dict, phys: list[str], header: str,
               is_lag=False) -> None:
    mode = row.get("mode") or "access"
    desc = _s(row.get("description"))
    if desc:
        body.append(f"description {desc[:64]}")
    if mode == "disabled":
        body.append("shutdown")
        return
    body.append("no shutdown")
    speed = _s(row.get("speed")).lower()
    if speed and not is_lag:
        if speed in SPEEDS:
            body.append(f"speed {SPEEDS[speed]}")
        else:
            ctx.warn(section, f"{label}: on AOS-CX only 10m, 100m and 1g can be forced; faster ports follow the optic.")
    mtu = _s(row.get("mtu"))
    if mtu:
        if mtu.isdigit() and 68 <= int(mtu) <= 9198:
            body.append(f"mtu {mtu}")
        else:
            ctx.error(section, f"{label}: MTU must be 68-9198.", "mtu")
    svc = ctx.p["services"]
    if mode in ("access", "trunk"):
        body.append("no routing")
    if mode == "access":
        vlan = _vlan_name(ctx, section, label, row.get("vlan"), "vlan")
        voice = _vlan_name(ctx, section, f"{label} voice", row.get("voice"), "voice")
        if not voice and not _s(row.get("voice")):
            voice = next((v["name"] for v in ctx.p["vlans"] if _truthy(v.get("voice")) and v["name"] != vlan
                          and v["name"] in ctx.vlan_by_name), "")
        if voice and voice == vlan:
            ctx.error(section, f"{label}: the voice VLAN must differ from the data VLAN.", "voice")
            voice = ""
        if voice:
            # A phone port on AOS-CX: data untagged (native), voice tagged.
            data = _vid(ctx, vlan) if vlan else 1
            body.append(f"vlan trunk native {data}")
            body.append(f"vlan trunk allowed {_vid_list([data, _vid(ctx, voice)])}")
        elif vlan:
            body.append(f"vlan access {_vid(ctx, vlan)}")
        if not vlan and not _s(row.get("vlan")):
            ctx.warn(section, f"{label}: no access VLAN, so the port uses VLAN 1.")
        if _truthy(row.get("edge")):
            body.append("spanning-tree port-type admin-edge")
            if _truthy(svc.get("bpdu_block_on_edge")):
                body.append("spanning-tree bpdu-guard")
        limit = _s(row.get("mac_limit"))
        if limit:
            if limit.isdigit() and 1 <= int(limit) <= 64:
                ctx.port_security = True
                body.extend(["port-access port-security", "    enable", f"    client-limit {limit}"])
            else:
                ctx.error(section, f"{label}: MAC limit must be 1-64 on AOS-CX.", "mac_limit")
        if _truthy(row.get("sticky")):
            ctx.warn(section, f"{label}: sticky MAC is not written for AOS-CX; skipped.")
        if _truthy(row.get("dhcp_trusted")):
            body.append("dhcpv4-snooping trust")
        dot1x = _s(row.get("dot1x"))
        if dot1x:
            if dot1x in ("dot1x", "dot1x-mab"):
                body.extend(["aaa authentication port-access dot1x authenticator", "    enable"])
            if dot1x in ("mab", "dot1x-mab"):
                body.extend(["aaa authentication port-access mac-auth", "    enable"])
            ctx.dot1x[header] = dot1x
    elif mode == "trunk":
        refs = _list(row.get("vlans"))
        if not refs:
            ctx.error(section, f"{label}: a trunk needs at least one VLAN (or 'all').", "vlans")
        allowed = None if any(r.lower() == "all" for r in refs) else \
            [_vid(ctx, n) for r in refs if (n := _vlan_name(ctx, section, label, r, "vlans"))]
        native = _vlan_name(ctx, section, f"{label} native", row.get("native"), "native")
        if native:
            body.append(f"vlan trunk native {_vid(ctx, native)}")
            if allowed is not None and _vid(ctx, native) not in allowed:
                allowed.append(_vid(ctx, native))
        if allowed is None:
            body.append("vlan trunk allowed all")
        elif allowed:
            body.append(f"vlan trunk allowed {_vid_list(allowed)}")
        if _truthy(row.get("root_guard")):
            body.append("spanning-tree root-guard")
        if _truthy(row.get("loop_protect")):
            body.append("loop-protect")
        if _s(row.get("voice")):
            ctx.warn(section, f"{label}: voice VLAN only applies to access ports; ignored on a trunk.")
        ctx.trunks.append(header)
    elif mode == "routed":
        addrs = _addresses(ctx, section, label, row.get("address"))
        if not addrs:
            ctx.error(section, f"{label}: a routed port needs an IP address with prefix (example 10.0.0.1/30).", "address")
        body.append("routing")
        body.extend(f"ip address {a.with_prefixlen}" if a.version == 4 else f"ipv6 address {a.with_prefixlen}"
                    for a in addrs)
        if addrs and len(phys) == 1:
            ctx.l3_ifaces.add(phys[0])
    else:
        ctx.error(section, f"{label}: unknown mode '{mode}'.", "mode")
        return
    if _s(row.get("vlan_translate")):
        ctx.warn(section, f"{label}: per-port VLAN translation is not written for AOS-CX; the mapping is ignored.")
    if mode != "routed" and _s(row.get("address")):
        ctx.warn(section, f"{label}: the IP address is only used in routed mode. Use a VLAN interface for switch ports.")
    if is_lag:
        return
    poe, pmax = _s(row.get("poe")), _s(row.get("poe_max"))
    if poe or pmax:
        no_poe = [p for p in phys if p in ctx.known and not ctx.known[p].get("poe")]
        if no_poe:
            ctx.warn(section, f"{label}: {', '.join(no_poe[:3])}{'…' if len(no_poe) > 3 else ''} has no PoE; PoE setting skipped.")
        if len(no_poe) < len(phys):
            if poe == "off":
                body.append("no power-over-ethernet")
            elif poe in POE_PRIO:
                body.append(f"power-over-ethernet priority {POE_PRIO[poe]}")
            if pmax and poe != "off":
                ctx.warn(section, f"{label}: AOS-CX sets PoE by class or usage, not a watt limit; maximum power skipped.")


def _headers(names: list[str], use_ranges: bool) -> list[str]:
    if not use_ranges or len(names) == 1:
        return [f"interface {n}" for n in names]
    return [f"interface {_cx_range(names)}"]


def _port_groups(ctx: CxCtx) -> None:
    rows = [r for r in ctx.p["ports"] if _s(r.get("ports"))]
    if not rows:
        return
    ctx.cfg.comment("Switch ports")
    use_ranges = _truthy(ctx.p["services"].get("use_ranges"))
    for i, row in enumerate(rows):
        ctx.at("ports", row)
        label = _s(row.get("name")) or f"Port group {i + 1}"
        try:
            names = _ports(row.get("ports"))
        except ValueError as exc:
            ctx.error("Ports", f"{label}: {exc} (example: 1/1/1-1/1/24, 1/1/49).", "ports")
            continue
        names = _claim(ctx, "Ports", label, names)
        if not names:
            continue
        mode = row.get("mode") or "access"
        if mode == "routed" and len(names) > 1:
            ctx.error("Ports", f"{label}: a routed port group can only hold one port (each needs its own address).")
            continue
        for header in _headers(names, use_ranges):
            body: list[str] = []
            phys = names if header.count("/") > 2 or len(names) == 1 else [header.split(" ", 1)[1]]
            _port_body(ctx, "Ports", label, body, row, phys, header)
            ctx.cfg.block(header, *[]).extend(body)
        for port in names:
            voice = mode == "access" and (bool(_s(row.get("voice"))) or any(
                _truthy(v.get("voice")) and v["name"] != _s(row.get("vlan")) for v in ctx.p["vlans"]))
            ctx.res.ports[port] = {"use": mode, "label": label, "voice": voice, "role": _s(row.get("role"))}
    ctx.at("", None)


def _lags(ctx: CxCtx) -> None:
    lags = [r for r in ctx.p["lags"] if _s(r.get("name")) or _s(r.get("members"))]
    if not lags:
        return
    ctx.cfg.comment("LAGs (LACP)")
    seen = set()
    for row in lags:
        ctx.at("lags", row)
        raw = _s(row.get("name"))
        m = _LAG.fullmatch(raw) or re.fullmatch(r"(\d{1,3})", raw)
        num = int(m.group(1)) if m else -1
        if not 1 <= num <= 256:
            ctx.error("LAGs", f"LAG name '{raw}' must be lag1 to lag256.", "name")
            continue
        label = f"lag {num}"
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
        if len(members) > 8:
            ctx.error("LAGs", f"{label}: an AOS-CX LAG takes at most 8 members.", "members")
        lacp = row.get("lacp") if row.get("lacp") in ("active", "passive", "static") else "active"
        header = f"interface lag {num}"
        body: list[str] = []
        _port_body(ctx, "LAGs", label, body, row, [label], header, is_lag=True)
        if lacp == "static":
            ctx.warn("LAGs", f"{label}: static LAG without LACP can't detect a mis-cabled member.")
        else:
            body.append(f"lacp mode {lacp}")
            if _truthy(row.get("lacp_fast")):
                body.append("lacp rate fast")
        if _s(row.get("min_links")):
            ctx.warn("LAGs", f"{label}: minimum links are not written for AOS-CX.")
        if _s(row.get("esi")):
            ctx.warn("LAGs", f"{label}: EVPN multihoming is not written for AOS-CX; use VSX multi-chassis LAGs.")
        ctx.cfg.block(header).extend(body)
        for mem in members:
            mb = ctx.cfg.block(f"interface {mem}", "no shutdown")
            if _s(row.get("description")):
                mb.append(f"description {_s(row.get('description'))[:56]} (lag{num})")
            mb.append(f"lag {num}")
            ctx.res.ports[mem] = {"use": "lag", "label": f"lag{num}"}
    ctx.at("", None)


def _l3(ctx: CxCtx) -> None:
    r, cfg = ctx.p["routing"], ctx.cfg
    servers = [sv for sv in _list(r.get("dhcp_relay_servers")) if _ip(ctx, "Routing", "DHCP server", sv)]
    relay = {int(v["id"]) for v in ctx.vlan_by_name.values() if _truthy(v.get("dhcp_relay")) and _s(v.get("irb"))}
    if relay and not servers:
        ctx.error("Routing", "VLANs use DHCP relay but no DHCP server is set on the Routing tab.")
    if ctx.svis:
        cfg.comment("VLAN interfaces")
    for vid, addrs in sorted(ctx.svis.items()):
        body = cfg.block(f"interface vlan {vid}")
        body.extend(f"ip address {a.with_prefixlen}" if a.version == 4 else f"ipv6 address {a.with_prefixlen}"
                    for a in addrs)
        if vid in relay:
            body.extend(f"ip helper-address {sv}" for sv in servers)
    lo = _s(r.get("loopback"))
    if lo:
        addrs = _addresses(ctx, "Routing", "Loopback", lo if "/" in lo else f"{lo}/32")
        if addrs:
            body = cfg.block("interface loopback 0")
            for a in addrs:
                body.append(f"ip address {a.with_prefixlen}" if a.version == 4 else f"ipv6 address {a.with_prefixlen}")
                if a.version == 4:
                    ctx.loopback_ip = str(a.ip)
            ctx.l3_ifaces.add("loopback 0")
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


def _static(ctx: CxCtx) -> None:
    r, cfg = ctx.p["routing"], ctx.cfg
    routes = [x for x in r.get("static") or [] if _s(x.get("prefix"))]
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
            target = "blackhole" if nh == "discard" else "reject"
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
        cmd = "ip route" if net.version == 4 else "ipv6 route"
        cfg.line(f"{cmd} {net} {target}" + (f" distance {pref}" if pref else ""))
    ctx.at("", None)


def _ospf(ctx: CxCtx) -> None:
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
            body.append(f"reference-bandwidth {int(m.group(1)) * (1000 if m.group(2) == 'g' else 1)}")
        else:
            ctx.error("OSPF", "Reference bandwidth must look like 100g or 100000 (Mbps).", "routing.ospf.reference_bandwidth")
    if _s(o.get("export")):
        ctx.warn("OSPF", "Export policies are not written for AOS-CX yet; add 'redistribute' lines by hand.")
    for a in o.get("areas") or []:
        ctx.at("routing.ospf.areas", a)
        area = _s(a.get("area")) or "0.0.0.0"
        if not re.fullmatch(r"\d+|\d+\.\d+\.\d+\.\d+", area):
            ctx.error("OSPF", f"Area '{area}' must be a number or dotted (0.0.0.0).", "area")
            continue
        dotted = area if "." in area else str(ipaddress.IPv4Address(int(area)))
        kind = a.get("type") or "normal"
        body.append(f"area {dotted}" + (f" {kind}" if kind in ("stub", "nssa") else ""))
        key = _s(a.get("md5_key"))
        p2p = {_iface_name(x) for x in P.iface_list(a.get("p2p"))}
        passive = P.iface_list(a.get("passive"))
        for raw in P.iface_list(a.get("interfaces")) + passive:
            name = _iface_name(raw)
            if not name:
                ctx.error("OSPF", f"Area {area}: '{raw}' is not an AOS-CX interface (1/1/49, vlan 20, loopback 0).", "interfaces")
                continue
            ib = cfg.block(f"interface {name}", f"ip ospf 1 area {dotted}")
            if raw in passive or name.startswith("loopback"):
                if "ip ospf passive" not in ib:
                    ib.append("ip ospf passive")
            if name in p2p:
                ib.append("ip ospf network point-to-point")
            if key:
                if len(key) > 16:
                    ctx.error("OSPF", f"Area {area}: the MD5 key can be at most 16 characters.", "md5_key")
                else:
                    for ln in ("ip ospf authentication message-digest", f"ip ospf message-digest-key 1 md5 plaintext {key}"):
                        if ln not in ib:
                            ib.append(ln)
    ctx.at("", None)


def _bgp(ctx: CxCtx) -> None:
    groups = [g for g in ctx.p["routing"].get("bgp_groups") or [] if _s(g.get("name")) or _s(g.get("neighbors"))]
    if not groups:
        return
    if not ctx.asn:
        ctx.error("BGP", "BGP needs the switch's AS number (Routing tab).", "routing.asn")
        return
    cfg = ctx.cfg
    cfg.comment("BGP")
    body = cfg.block(f"router bgp {ctx.asn}")
    if ctx.router_id:
        body.append(f"bgp router-id {ctx.router_id}")
    if any(_truthy(g.get("multipath")) for g in groups) or _truthy(ctx.p["routing"].get("ecmp")):
        body.append("maximum-paths 4")
    activate: list[str] = []
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
        local = _s(g.get("local_address"))
        if local and not (ctx.loopback_ip and local == ctx.loopback_ip):
            ctx.warn("BGP", f"Group {name}: AOS-CX sets the source by interface; only the loopback address is mapped.")
        if _s(g.get("import")) or _s(g.get("export")):
            ctx.warn("BGP", f"Group {name}: import/export policies are not written for AOS-CX yet (use route-maps).")
        for ip, asn, desc in neighbors:
            remote = asn if external and asn else (peer_as if external else str(ctx.asn))
            if not remote:
                ctx.error("BGP", f"Group {name}: neighbor {ip} needs a peer AS (on the group or after the IP).", "neighbors")
                continue
            body.append(f"neighbor {ip} remote-as {remote}")
            d = desc or _s(g.get("description")) or name
            body.append(f"neighbor {ip} description {d[:80]}")
            if local and ctx.loopback_ip and local == ctx.loopback_ip:
                body.append(f"neighbor {ip} update-source loopback 0")
            if _s(g.get("auth_key")):
                body.append(f"neighbor {ip} password plaintext {_s(g.get('auth_key'))}")
            if _s(g.get("bfd")):
                body.append(f"neighbor {ip} fall-over bfd")
            activate.append(ip)
    ctx.at("", None)
    body.append("address-family ipv4 unicast")
    body.extend(f"    neighbor {ip} activate" for ip in activate)
    if ctx.loopback_ip:
        body.append(f"    network {ctx.loopback_ip}/32")
    body.append("exit-address-family")


def _services(ctx: CxCtx) -> None:
    s, cfg = ctx.p["services"], ctx.cfg
    cfg.comment("Switching services")
    if not _truthy(s.get("lldp")):
        cfg.line("no lldp")
    stp = s.get("stp")
    if stp == "rstp":
        cfg.line("spanning-tree")
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
    sec = ctx.p.get("security") or {}
    rt = _s(sec.get("recovery_timeout"))
    if rt:
        if rt.isdigit() and 10 <= int(rt) <= 65535:
            cfg.line(f"spanning-tree bpdu-guard timeout {rt}")
        else:
            ctx.error("Security", "Auto-recovery time must be 10-65535 seconds on AOS-CX.", "security.recovery_timeout")
    if _truthy(s.get("storm_control")):
        ctx.warn("Services", "Storm control on AOS-CX is a rate ('rate-limit broadcast ... kbps'), not a percentage; "
                             "not written.")
    if ctx.port_security:
        cfg.line("port-access port-security enable")
    if ctx.snoop:
        cfg.line("dhcpv4-snooping")
        for header in ctx.trunks:
            cfg.block(header, "dhcpv4-snooping trust")
        ctx.warn("Services", "DHCP snooping is on: trunk and LAG ports are trusted, access ports are not. "
                             "Tick 'DHCP trusted' on an access port that has a DHCP server behind it.")
    if ctx.dai:
        for header in ctx.trunks:
            cfg.block(header, "arp inspection trust")
    if any(_truthy(s.get(k)) for k in ("poe_fast", "poe_perpetual")) or _s(s.get("poe_guard_band")):
        ctx.warn("Services", "Perpetual/fast PoE and guard band are Juniper options; not written for AOS-CX.")
    if ctx.dot1x:
        servers = [x for x in sec.get("radius_servers") or [] if _s(x.get("address"))]
        if not servers:
            ctx.error("Security", "802.1X / MAB ports need at least one RADIUS server.")
        cfg.comment("802.1X and MAB (RADIUS)")
        vrf = " vrf mgmt" if _truthy(ctx.p["system"].get("mgmt_vrf")) and not ctx.svis else ""
        for x in servers:
            ctx.at("security.radius_servers", x)
            addr = _s(x.get("address"))
            if not _ip(ctx, "Security", "RADIUS server", addr):
                continue
            secret = _s(x.get("secret"))
            if not secret:
                ctx.error("Security", f"RADIUS server {addr} needs a shared secret.", "secret")
                continue
            port = _s(x.get("port")) or "1812"
            cfg.line(f"radius-server host {addr} key plaintext {secret}"
                     + (f" port {port}" if port != "1812" else "") + vrf)
        ctx.at("", None)
        modes = set(ctx.dot1x.values())
        if modes & {"dot1x", "dot1x-mab"}:
            cfg.block("aaa authentication port-access dot1x authenticator", "radius server-group radius", "enable")
        if modes & {"mab", "dot1x-mab"}:
            cfg.block("aaa authentication port-access mac-auth", "radius server-group radius", "enable")
    if _truthy(s.get("disable_unused")) and ctx.known:
        unused = [n for n, info in ctx.known.items() if n not in ctx.used and info["kind"] in ("access", "uplink")]
        if unused:
            for header in _headers(unused, _truthy(s.get("use_ranges"))):
                cfg.block(header, "description Unused - disabled", "shutdown")
            for n in unused:
                ctx.res.ports.setdefault(n, {"use": "disabled", "label": "Unused"})


def _unsupported(ctx: CxCtx) -> None:
    p = ctx.p
    if _truthy((p.get("evpn") or {}).get("enabled")):
        ctx.warn("EVPN", "EVPN-VXLAN is not written for AOS-CX yet.")
    if any((p.get("policy") or {}).get(k) for k in ("prefix_lists", "communities", "terms")):
        ctx.warn("Policies", "Routing policies are not written for AOS-CX yet.")
    if _truthy((p.get("qos") or {}).get("enabled")):
        ctx.warn("QoS", "QoS is not written for AOS-CX yet (it trusts DSCP with 'qos trust dscp').")


def header(p: dict) -> list[str]:
    name = _s(p.get("name")) or _s(p.get("system", {}).get("hostname")) or "switch"
    models = ", ".join(f"{_s(m.get('model'))} (member {m.get('fpc', 1) or 1})" for m in p["switch"].get("members") or [])
    return [f"HPE Aruba CX (AOS-CX) configuration for {name}", f"Hardware: {models}",
            f"Made by Multi-Vendor Switch Config Builder {__version__}. Review before you load it."]


def build(project: dict) -> Result:
    p = normalize(project)
    ctx = CxCtx(p)
    ctx.svis_planned = any(_s(v.get("irb")) for v in p["vlans"])
    for t in header(p):
        ctx.cfg.comment(t)
    for step in (_switch, _system, _access, _snmp, _syslog, _vlans, _port_groups, _lags, _l3, _static, _ospf, _bgp,
                 _services, _unsupported):
        step(ctx)
        ctx.row = None
    text = ctx.cfg.text()
    if ctx.banner:
        text = text[: -len("end\n")] + "banner motd ^\n" + ctx.banner + "\n^\n!\nend\n" \
            if text.endswith("end\n") else text + "banner motd ^\n" + ctx.banner + "\n^\n"
    ctx.res.errors = _dedupe(ctx.res.errors)
    ctx.res.warnings = _dedupe(ctx.res.warnings)
    ctx.res.set_text = text
    ctx.res.hier_text = text
    ctx.res.hostname = _s(p["system"].get("hostname")) or "switch"
    return ctx.res
