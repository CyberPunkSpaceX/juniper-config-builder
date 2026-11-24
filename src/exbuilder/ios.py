"""Turn a project into Cisco IOS-XE configuration (Catalyst 9000).

Uses the same project format as the other builders (see generator.py). Port
names are IOS-XE names (GigabitEthernet1/0/1, Te1/1/1), stack members are
switch numbers 1-8, and LAGs are Port-channels.
"""

from __future__ import annotations

import ipaddress
import re
import zoneinfo
from datetime import datetime

from . import __version__, ios_models, vendors
from . import ports as P
from . import routing as R
from .cryptpw import cisco_type8, is_type8
from .eos import _dedupe, _vid_list
from .generator import (DOMAIN, HOSTNAME, NAME, USERNAME, Ctx, Result, _addresses, _ip, _list, _s, _truthy,
                        _vlan_name, normalize)
from .textcfg import Blocks

VENDOR = vendors.VENDORS["cisco"]
SPEEDS = {"10m": "10", "100m": "100", "1g": "1000", "2.5g": "2500", "5g": "5000", "10g": "10000",
          "25g": "25000", "40g": "40000", "100g": "100000"}
LEVELS = {"emergency": "emergencies", "alert": "alerts", "critical": "critical", "error": "errors",
          "warning": "warnings", "notice": "notifications", "info": "informational", "any": "debugging"}
SNMP_AUTH = {"md5": "md5", "sha": "sha", "sha224": "sha-2 256", "sha256": "sha-2 256", "sha384": "sha-2 384",
             "sha512": "sha-2 512"}
SNMP_PRIV = {"aes128": "aes 128", "des": "des", "3des": "3des"}
MAC_ACTIONS = {"drop": "protect", "drop-and-log": "restrict", "log": "restrict", "shutdown": "shutdown"}
_PO = re.compile(r"^(?:port-channel|po|ae)\s*(\d{1,3})$", re.I)
_SSH_KEY = re.compile(r"^(ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp\d+)\s+([A-Za-z0-9+/=]+)")


def _ip_line(a) -> str:
    return f"ip address {a.ip} {a.netmask}" if a.version == 4 else f"ipv6 address {a.with_prefixlen}"


def _vid(ctx: Ctx, name: str) -> int:
    return int(ctx.vlan_by_name[name]["id"])


def _iface_name(text: str) -> str | None:
    t = _s(text)
    if not t:
        return None
    if m := re.fullmatch(r"(?:irb\.|vlan)\s*(\d{1,4})", t, re.I):
        return f"Vlan{m.group(1)}"
    if m := re.fullmatch(r"(?:lo|loopback)\s*(\d{0,4})(?:\.0)?", t, re.I):
        return f"Loopback{m.group(1) or 0}"
    if m := _PO.fullmatch(t):
        return f"Port-channel{m.group(1)}"
    try:
        names = P.expand_named(t, ios_models.ALIASES)
    except ValueError:
        return None
    return names[0] if len(names) == 1 else None


def _timezone(tz: str) -> list[str] | None:
    """'America/Edmonton' -> clock timezone/summer-time lines (IOS has no named zones)."""
    try:
        zone = zoneinfo.ZoneInfo(tz)
    except (zoneinfo.ZoneInfoNotFoundError, ValueError):
        return None
    year = datetime.now().year
    jan, jul = datetime(year, 1, 15, tzinfo=zone), datetime(year, 7, 15, tzinfo=zone)
    std, dst = (jan, jul) if jan.utcoffset() <= jul.utcoffset() else (jul, jan)
    off = std.utcoffset().total_seconds() / 60
    sign = "-" if off < 0 else ""
    h, m = divmod(abs(int(off)), 60)
    name = re.sub(r"[^A-Za-z]", "", std.tzname() or "") or "LOCAL"
    lines = [f"clock timezone {name[:7]} {sign}{h} {m}"]
    if dst.utcoffset() != std.utcoffset():
        dname = re.sub(r"[^A-Za-z]", "", dst.tzname() or "") or "SUMMER"
        lines.append(f"clock summer-time {dname[:7]} recurring")
    return lines


class IosCtx(Ctx):
    def __init__(self, project: dict):
        super().__init__(project)
        self.cfg = Blocks(indent=" ")
        self.imodels: list = []
        self.svis: dict[int, list] = {}
        self.dot1x_ports: list[str] = []
        self.trunks: list[str] = []     # block headers of trunk ports and LAGs (trusted for snooping/DAI)
        self.snoop: list[int] = []
        self.dai: list[int] = []
        self.ipsg: list[int] = []
        self.banner = None


# ------------------------------------------------------------------ sections
def _switch(ctx: IosCtx) -> None:
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
        if not 1 <= num <= 8 or num in seen:
            ctx.error("Switch", f"Stack member number {m.get('fpc')} must be 1-8 and used once.", "fpc")
            continue
        seen.add(num)
        model = ios_models.get(m.get("model", ""))
        if model:
            ctx.imodels.append((num, model))
            for port in model.ports(num):
                ctx.known[port["name"]] = port
            if len(members) > 1 and not model.stack:
                ctx.error("Switch", f"{model.name} doesn't stack (it uses StackWise Virtual). Use one switch per project.", "model")
        elif m.get("model") != ios_models.CUSTOM:
            ctx.error("Switch", f"Unknown Cisco model '{m.get('model')}'. Pick one from the list or Custom.", "model")
    ctx.at("", None)
    families = {mod.family for _, mod in ctx.imodels}
    if len(families) > 1:
        ctx.error("Switch", f"A stack can't mix {' and '.join(sorted(families))} switches.")
    if len(members) > 1:
        ctx.cfg.comment("Stack")
        for num, mod in ctx.imodels:
            if num != 1:
                ctx.cfg.line(f"switch {num} provision {mod.provision}")
    try:
        for name in P.expand_named(ctx.p["switch"].get("custom_ports", ""), ios_models.ALIASES):
            ctx.known.setdefault(name, {"name": name, "kind": "access", "speed": "", "poe": False})
    except ValueError as exc:
        ctx.error("Switch", f"Custom ports: {exc}")


def _secret(ctx: IosCtx, section: str, label: str, value, key: str) -> str | None:
    value = _s(value)
    if not value:
        return None
    if is_type8(value):
        return value
    if value.startswith("$"):
        ctx.error(section, f"{label}: this password was hashed for another vendor; type it again for Cisco.",
                  key if not ctx.row else key.rsplit(".", 1)[-1])
        return None
    if len(value) < 8:
        ctx.error(section, f"{label}: use at least 8 characters.", key if not ctx.row else key.rsplit(".", 1)[-1])
        return None
    if "?" in value:
        ctx.error(section, f"{label}: IOS can't take a '?' in a password.", key if not ctx.row else key.rsplit(".", 1)[-1])
        return None
    hashed = cisco_type8(value)
    ctx.res.hashed[key] = hashed
    return hashed


def _system(ctx: IosCtx) -> None:
    s, cfg = ctx.p["system"], ctx.cfg
    cfg.comment("System")
    cfg.line("service timestamps debug datetime msec localtime show-timezone")
    cfg.line("service timestamps log datetime msec localtime show-timezone")
    cfg.line("service password-encryption")
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
            cfg.line(f"ip domain name {domain}")
        else:
            ctx.error("System", f"Domain '{domain}' is not a valid domain name.", "system.domain")
    elif _s(host):
        ctx.warn("System", "Cisco needs a domain name to make the SSH key; add one.")
    vrf = _truthy(s.get("mgmt_vrf"))
    dns = [ns for ns in _list(s.get("name_servers")) if _ip(ctx, "System", "DNS server", ns)]
    if dns:
        cfg.line(f"ip name-server {'vrf Mgmt-vrf ' if vrf else ''}{' '.join(dns[:6])}")
    else:
        cfg.line("no ip domain lookup")
    for d in _list(s.get("domain_search")):
        if DOMAIN.match(d):
            cfg.line(f"ip domain list {d}")
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
    for n in ntp:
        addr = _s(n.get("address"))
        if not (re.match(r"^[A-Za-z0-9.-]+$", addr) or _ip(ctx, "System", "NTP server", addr)):
            continue
        cfg.line(f"ntp server {'vrf Mgmt-vrf ' if vrf else ''}{addr}" + (" prefer" if _truthy(n.get("prefer")) else ""))
    if _s(s.get("ntp_source")):
        ctx.warn("System", "Cisco picks the NTP source by interface ('ntp source Vlan10'); add it by hand if needed.")

    mif = _s(s.get("mgmt_interface")) or (ctx.imodels[0][1].mgmt if ctx.imodels else "GigabitEthernet0/0")
    addrs = _addresses(ctx, "System", f"Management ({mif})", s.get("mgmt_address"))
    if addrs:
        body = cfg.block(f"interface {mif}")
        if vrf:
            body.append("vrf forwarding Mgmt-vrf")
        body.extend(_ip_line(a) for a in addrs)
        body.append("no shutdown")
        gw = _s(s.get("mgmt_gateway"))
        if gw and (gw_ip := _ip(ctx, "System", "Management gateway", gw)):
            if not any(gw_ip in a.network for a in addrs if a.version == gw_ip.version):
                ctx.warn("System", f"Management gateway {gw} is not in the management subnet.")
            if vrf:
                ctx.mgmt_route = f"ip route vrf Mgmt-vrf 0.0.0.0 0.0.0.0 {gw}"
            else:
                ctx.mgmt_gateway = gw
    elif _s(s.get("mgmt_gateway")):
        ctx.warn("System", "Management gateway is set but the management port has no address.")
    banner = (s.get("banner") or "").rstrip()
    if banner.strip():
        if "^" in banner:
            ctx.error("System", "The banner can't contain '^' (Cisco uses it to end the banner).", "system.banner")
        else:
            ctx.banner = banner


def _access(ctx: IosCtx) -> None:
    a, cfg = ctx.p["access"], ctx.cfg
    cfg.comment("Accounts and remote access")
    enable = _secret(ctx, "Access", "Enable secret (root password)", a.get("root_password"), "access.root_password")
    if enable:
        cfg.line(f"enable secret 8 {enable}")
    names = set()
    keys_by_user: dict[str, list] = {}
    for i, u in enumerate(a.get("users") or []):
        ctx.at("access.users", u)
        name = _s(u.get("name"))
        if not name:
            continue
        if not USERNAME.match(name) or name in ("root",):
            ctx.error("Access", f"User '{name}': use lower-case letters, digits, '.', '_' or '-'.", "name")
            continue
        if name in names:
            ctx.error("Access", f"User '{name}' is listed twice.", "name")
            continue
        names.add(name)
        cls = u.get("class") or "read-only"
        if cls == "unauthorized":
            ctx.warn("Access", f"User '{name}' is 'unauthorized': skipped on Cisco.")
            continue
        priv = "15" if cls == "super-user" else "1"
        hashed = _secret(ctx, "Access", f"User {name}", u.get("password"), f"access.users.{i}.password")
        keys = []
        for k in (u.get("ssh_keys") or "").splitlines():
            k = k.strip()
            if not k:
                continue
            m = _SSH_KEY.match(k)
            if not m or m.group(1) != "ssh-rsa":
                ctx.error("Access", f"User {name}: Cisco IOS-XE takes RSA SSH keys (ssh-rsa ...) here.", "ssh_keys")
                continue
            keys.append(m.group(2))
        if hashed:
            cfg.line(f"username {name} privilege {priv} secret 8 {hashed}")
        elif keys:
            cfg.line(f"username {name} privilege {priv}")
        else:
            ctx.error("Access", f"User '{name}' needs a password or an SSH key.", "password")
        if keys:
            keys_by_user[name] = keys
    ctx.at("", None)
    if not any(u.get("class") == "super-user" and _s(u.get("name")) for u in a.get("users") or []):
        ctx.warn("Access", "No super-user (privilege 15) account: you'd need the enable secret for every change.")
    if not enable and not any(u.get("class") == "super-user" for u in a.get("users") or []):
        ctx.warn("Access", "No enable secret and no privilege 15 user.")
    cfg.line("aaa new-model")
    cfg.line("aaa authentication login default local")
    cfg.line("aaa authorization exec default local")
    cfg.line("ip ssh version 2")
    cfg.line("ip ssh time-out 60")
    cfg.line("ip ssh authentication-retries 3")
    if keys_by_user:
        body = cfg.block("ip ssh pubkey-chain")
        for user, keys in keys_by_user.items():
            body.append(f"username {user}")
            for key in keys:
                body.append(" key-string")
                for chunk in range(0, len(key), 72):
                    body.append(f"  {key[chunk:chunk + 72]}")
                body.append("  exit")
    if _truthy(a.get("retry_options")):
        cfg.line("login block-for 120 attempts 5 within 60")
        cfg.line("login on-failure log")
    if _truthy(a.get("netconf")):
        cfg.line("netconf-yang")
    cfg.line("no ip http server")
    if _truthy(a.get("web")):
        cfg.line("ip http secure-server")
        cfg.line("ip http authentication local")
    else:
        cfg.line("no ip http secure-server")
    limit = _s(a.get("ssh_connection_limit"))
    last = 15
    if limit:
        if limit.isdigit() and 1 <= int(limit) <= 16:
            last = int(limit) - 1
        else:
            ctx.error("Access", "SSH connection limit must be 1-16 on Cisco (vty lines).", "access.ssh_connection_limit")
    ctx.vty = ("line con 0", ["logging synchronous", "exec-timeout 15 0"],
               f"line vty 0 {last}", ["transport input ssh", "exec-timeout 15 0"])


def _snmp(ctx: IosCtx) -> None:
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
        if not re.fullmatch(r"[A-Za-z0-9_.@#%+=-]{1,64}", name):
            ctx.error("SNMP", f"Community '{name}' may only use letters, digits and _ . @ # % + = -.", "name")
            continue
        if name.lower() in ("public", "private"):
            ctx.warn("SNMP", f"Community '{name}' is a well-known default; pick something harder to guess.")
        clients = []
        for cl in _list(c.get("clients")):
            net = _ip(ctx, "SNMP", f"Community {name} client", cl, allow_net=True)
            if net and net.version == 4:
                clients.append(net)
        acl = ""
        if clients:
            acl = f" SNMP-{name.upper()}"[:40]
            body = cfg.block(f"ip access-list standard{acl}")
            for net in clients:
                body.append(f"permit host {net.network_address}" if net.prefixlen == 32
                            else f"permit {net.network_address} {net.hostmask}")
        else:
            ctx.warn("SNMP", f"Community '{name}' accepts any source address. Add the allowed clients.")
        cfg.line(f"snmp-server community {name} {'RW' if c.get('access') == 'read-write' else 'RO'}{acl}")
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
        auth = SNMP_AUTH.get(u.get("auth") or "sha", "sha")
        priv = SNMP_PRIV.get(u.get("priv") or "")
        line = f"snmp-server user {name} {name}-group v3 auth {auth} {apw}"
        level = "auth"
        if priv:
            if len(ppw) < 8:
                ctx.error("SNMP", f"SNMPv3 user {name}: the privacy password needs at least 8 characters.", "priv_password")
                continue
            line += f" priv {priv} {ppw}"
            level = "priv"
        else:
            ctx.warn("SNMP", f"SNMPv3 user {name} has no privacy (encryption); polls are readable on the wire.")
        cfg.line(f"snmp-server group {name}-group v3 {level} read all")
        cfg.line(line)
    ctx.at("", None)
    if targets:
        comm = _s(s.get("trap_community")) or (comms[0]["name"] if comms else "traps")
        for t in targets:
            if _ip(ctx, "SNMP", "Trap target", t):
                cfg.line(f"snmp-server host {t} version 2c {comm}")
        cfg.line("snmp-server enable traps")


def _syslog(ctx: IosCtx) -> None:
    s, cfg = ctx.p["syslog"], ctx.cfg
    cfg.comment("Logging")
    cfg.line(f"logging buffered 64000 {LEVELS.get(s.get('local_level') or 'notice', 'notifications')}")
    vrf = _truthy(ctx.p["system"].get("mgmt_vrf"))
    trap = None
    for h in s.get("hosts") or []:
        ctx.at("syslog.hosts", h)
        addr = _s(h.get("address"))
        if not addr or not _ip(ctx, "Logging", "Syslog server", addr):
            continue
        port = _s(h.get("port"))
        if port and port != "514" and not (port.isdigit() and 1 <= int(port) <= 65535):
            ctx.error("Logging", f"Syslog port '{port}' is not valid.", "port")
            continue
        cfg.line(f"logging host {addr}" + (" vrf Mgmt-vrf" if vrf else "")
                 + (f" transport udp port {port}" if port and port != "514" else ""))
        trap = LEVELS.get(h.get("level") or "info", "informational")
    ctx.at("", None)
    if trap:
        cfg.line(f"logging trap {trap}")
    if _truthy(s.get("log_commands")):
        cfg.block("archive", "log config", " logging enable", " notify syslog contenttype plaintext", " hidekeys")
    if _s(s.get("source_address")):
        ctx.warn("Logging", "Cisco sets the syslog source by interface ('logging source-interface Vlan10'); add it by hand.")


def _vlans(ctx: IosCtx) -> None:
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
        if 1002 <= n <= 1005:
            ctx.error("VLANs", f"VLAN {name}: IDs 1002-1005 are reserved on Cisco.", "id")
            continue
        if name.lower() in {x.lower() for x in ctx.vlan_by_name}:
            ctx.error("VLANs", f"VLAN name '{name}' is used twice.", "name")
            continue
        if n in ctx.vlan_by_id:
            ctx.error("VLANs", f"VLAN ID {n} is used by both {ctx.vlan_by_id[n]['name']} and {name}.", "id")
            continue
        ctx.vlan_by_name[name] = v
        ctx.vlan_by_id[n] = v
        if n != 1:
            cfg.block(f"vlan {n}", f"name {name}")
        addrs = _addresses(ctx, "VLANs", f"VLAN {name} SVI", v.get("irb"))
        if addrs:
            ctx.svis[n] = addrs
            ctx.l3_ifaces.add(f"Vlan{n}")
        elif _truthy(v.get("dhcp_relay")):
            ctx.error("VLANs", f"VLAN {name}: DHCP relay needs an SVI address.", "irb")
        if _truthy(v.get("snooping")) or _truthy(v.get("ipsg")):
            ctx.snoop.append(n)
        if _truthy(v.get("dai")):
            ctx.dai.append(n)
            if n not in ctx.snoop:
                ctx.snoop.append(n)
        if _truthy(v.get("ipsg")):
            ctx.ipsg.append(n)
        if _s(v.get("vni")) or _s(v.get("vga")) or _s(v.get("vrf")):
            ctx.warn("VLANs", f"VLAN {name}: VNI, virtual gateway and VRF are not written for Cisco yet.")
    ctx.at("", None)


def _claim(ctx: IosCtx, section: str, label: str, names: list[str]) -> list[str]:
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
        ctx.warn(section, f"{label}: {P.named_compact(module)} need the optional network module installed.")
    return ok


def _translate(ctx: IosCtx, section: str, label: str, body: list, row: dict, allowed: list | None) -> None:
    spec = _s(row.get("vlan_translate"))
    if not spec:
        return
    try:
        pairs = P.translations(spec)
    except ValueError as exc:
        ctx.error(section, f"{label}: VLAN translation: {exc}", "vlan_translate")
        return
    if any(mod.family == "C9200" for _, mod in ctx.imodels):
        ctx.warn(section, f"{label}: the Catalyst 9200 can't translate VLANs (switchport vlan mapping); "
                          "use a 9300 or 9500 for this port.")
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
        body.append(f"switchport vlan mapping {wire} {local}")


def _port_body(ctx: IosCtx, section: str, label: str, body: list, row: dict, phys: list[str], is_lag=False) -> None:
    mode = row.get("mode") or "access"
    desc = _s(row.get("description"))
    if desc:
        body.append(f"description {desc[:200]}")
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
        if not (mtu.isdigit() and 1500 <= int(mtu) <= 9198):
            ctx.error(section, f"{label}: MTU must be 1500-9198.", "mtu")
        elif mode == "routed":
            body.append(f"mtu {mtu}")
        else:
            ctx.warn(section, f"{label}: on Catalyst the switch-port MTU is global ('system mtu'); set it by hand if needed.")
    svc = ctx.p["services"]
    storm = _truthy(svc.get("storm_control"))
    pct = _s(svc.get("storm_percent")) or "5"
    storm_lines = [f"storm-control broadcast level {pct}.00", f"storm-control multicast level {pct}.00"]
    if mode == "access":
        body.append("switchport mode access")
        vlan = _vlan_name(ctx, section, label, row.get("vlan"), "vlan")
        if vlan:
            body.append(f"switchport access vlan {_vid(ctx, vlan)}")
        elif not _s(row.get("vlan")):
            ctx.warn(section, f"{label}: no access VLAN, so the port uses VLAN 1.")
        voice = _vlan_name(ctx, section, f"{label} voice", row.get("voice"), "voice")
        if not voice and not _s(row.get("voice")):
            voice = next((v["name"] for v in ctx.p["vlans"] if _truthy(v.get("voice")) and v["name"] != vlan
                          and v["name"] in ctx.vlan_by_name), "")
        if voice:
            if voice == vlan:
                ctx.error(section, f"{label}: the voice VLAN must differ from the data VLAN.", "voice")
            else:
                body.append(f"switchport voice vlan {_vid(ctx, voice)}")
        body.append("switchport nonegotiate")
        if storm:
            body.extend(storm_lines)
        if _truthy(row.get("edge")):
            body.append("spanning-tree portfast")
            if _truthy(svc.get("bpdu_block_on_edge")):
                body.append("spanning-tree bpduguard enable")
        limit = _s(row.get("mac_limit"))
        if limit or _truthy(row.get("sticky")):
            if limit and not (limit.isdigit() and 1 <= int(limit) <= 8192):
                ctx.error(section, f"{label}: MAC limit must be 1-8192.", "mac_limit")
            else:
                if limit:
                    body.append(f"switchport port-security maximum {limit}")
                body.append(f"switchport port-security violation {MAC_ACTIONS.get(_s(row.get('mac_action')) or 'drop', 'protect')}")
                if _truthy(row.get("sticky")):
                    body.append("switchport port-security mac-address sticky")
                body.append("switchport port-security")
        if _truthy(row.get("dhcp_trusted")):
            body.append("ip dhcp snooping trust")
        if vlan and _vid(ctx, vlan) in ctx.ipsg and not _truthy(row.get("dhcp_trusted")):
            body.append("ip verify source")
        dot1x = _s(row.get("dot1x"))
        if dot1x:
            if dot1x == "mab":
                body.extend(["authentication port-control auto", "mab"])
            else:
                body.extend(["authentication host-mode multi-auth", "authentication port-control auto"])
                if dot1x == "dot1x-mab":
                    body.extend(["authentication order dot1x mab", "authentication priority dot1x mab", "mab"])
                body.extend(["dot1x pae authenticator", "dot1x timeout tx-period 10"])
            ctx.dot1x_ports.extend(phys)
    elif mode == "trunk":
        body.append("switchport mode trunk")
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
        body.append("switchport nonegotiate")
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
        body.append("no switchport")
        body.extend(_ip_line(a) for a in addrs)
        if addrs and len(phys) == 1:
            ctx.l3_ifaces.add(phys[0])
    else:
        ctx.error(section, f"{label}: unknown mode '{mode}'.", "mode")
        return
    if mode != "trunk" and _s(row.get("vlan_translate")):
        ctx.error(section, f"{label}: VLAN translation only works on trunk ports.", "vlan_translate")
    if mode != "routed" and _s(row.get("address")):
        ctx.warn(section, f"{label}: the IP address is only used in routed mode. Use a VLAN SVI for switch ports.")
    if is_lag:
        return
    poe, pmax = _s(row.get("poe")), _s(row.get("poe_max"))
    if poe or pmax:
        no_poe = [p for p in phys if p in ctx.known and not ctx.known[p].get("poe")]
        if no_poe:
            ctx.warn(section, f"{label}: {', '.join(no_poe[:3])}{'…' if len(no_poe) > 3 else ''} has no PoE; PoE setting skipped.")
        if len(no_poe) < len(phys):
            if poe == "off":
                body.append("power inline never")
            elif poe in ("high", "low"):
                body.append(f"power inline port priority {poe}")
            if pmax and poe != "off":
                try:
                    watts = float(pmax)
                except ValueError:
                    watts = -1
                if not 4 <= watts <= 90:
                    ctx.error(section, f"{label}: maximum PoE power must be 4-90 watts on Cisco.", "poe_max")
                else:
                    body.append(f"power inline auto max {int(watts * 1000)}")


def _ranges(names: list[str], use_ranges: bool) -> list[str]:
    """Interface block headers for a port group."""
    if not use_ranges or len(names) == 1:
        return [f"interface {n}" for n in names]
    runs = [a if a == b else f"{a} - {P.named_key(b)[1][-1]}" for a, b in P.named_runs(names)]
    out = []
    for i in range(0, len(runs), 5):  # IOS takes up to 5 ranges per 'interface range'
        out.append("interface range " + ", ".join(runs[i:i + 5]))
    return out


def _ports(ctx: IosCtx) -> None:
    rows = [r for r in ctx.p["ports"] if _s(r.get("ports"))]
    if not rows:
        return
    ctx.cfg.comment("Switch ports")
    use_ranges = _truthy(ctx.p["services"].get("use_ranges"))
    for i, row in enumerate(rows):
        ctx.at("ports", row)
        label = _s(row.get("name")) or f"Port group {i + 1}"
        try:
            names = P.expand_named(row.get("ports"), ios_models.ALIASES)
        except ValueError as exc:
            ctx.error("Ports", f"{label}: {exc} (example: Gi1/0/1-24, Te1/1/1).", "ports")
            continue
        names = _claim(ctx, "Ports", label, names)
        if not names:
            continue
        mode = row.get("mode") or "access"
        if mode == "routed" and len(names) > 1:
            ctx.error("Ports", f"{label}: a routed port group can only hold one port (each needs its own address).")
            continue
        headers = _ranges(names, use_ranges and mode != "routed")
        for header in headers:
            body: list[str] = []
            _port_body(ctx, "Ports", label, body, row, names if header.startswith("interface range") or len(names) == 1
                       else [header.split(" ", 1)[1]])
            if mode != "disabled":
                body.append("no shutdown")
            ctx.cfg.block(header, *body)
            if mode == "trunk":
                ctx.trunks.append(header)
        for port in names:
            voice = mode == "access" and (bool(_s(row.get("voice"))) or any(
                _truthy(v.get("voice")) and v["name"] != _s(row.get("vlan")) for v in ctx.p["vlans"]))
            ctx.res.ports[port] = {"use": mode, "label": label, "voice": voice, "role": _s(row.get("role"))}
    ctx.at("", None)


def _lags(ctx: IosCtx) -> None:
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
            ctx.error("LAGs", f"LAG name '{raw}' must be Port-channel1 to Port-channel128 (Po1 also works).", "name")
            continue
        name = label = f"Port-channel{num}"
        if num in seen:
            ctx.error("LAGs", f"{name} is listed twice.", "name")
            continue
        seen.add(num)
        try:
            members = P.expand_named(row.get("members"), ios_models.ALIASES)
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
            ctx.error("LAGs", f"{label}: a Catalyst Port-channel takes at most 8 active members.", "members")
        lacp = row.get("lacp") if row.get("lacp") in ("active", "passive", "static") else "active"
        if lacp == "static":
            ctx.warn("LAGs", f"{label}: static LAG without LACP can't detect a mis-cabled member.")
        body: list[str] = []
        _port_body(ctx, "LAGs", label, body, row, [name], is_lag=True)
        ml = _s(row.get("min_links"))
        if ml:
            if ml.isdigit() and 1 <= int(ml) <= len(members):
                body.append(f"port-channel min-links {ml}")
            else:
                ctx.error("LAGs", f"{label}: minimum links must be 1-{len(members)}.", "min_links")
        if _s(row.get("esi")):
            ctx.warn("LAGs", f"{label}: EVPN multihoming (ESI) is not written for Cisco yet.")
        ctx.cfg.block(f"interface {name}", *body)
        if (row.get("mode") or "trunk") == "trunk":
            ctx.trunks.append(f"interface {name}")
        # Members copy the switchport settings, then join the channel.
        for mem in members:
            mb = ctx.cfg.block(f"interface {mem}")
            if _s(row.get("description")):
                mb.append(f"description {_s(row.get('description'))[:180]} ({name})")
            mb.extend(ln for ln in body if ln.startswith(("switchport", "no switchport")) and "port-security" not in ln)
            mb.append(f"channel-group {num} mode {'on' if lacp == 'static' else lacp}")
            if lacp != "static" and _truthy(row.get("lacp_fast")):
                mb.append("lacp rate fast")
            mb.append("no shutdown")
            ctx.res.ports[mem] = {"use": "lag", "label": name}
    ctx.at("", None)


def _l3(ctx: IosCtx) -> None:
    r, cfg = ctx.p["routing"], ctx.cfg
    servers = [sv for sv in _list(r.get("dhcp_relay_servers")) if _ip(ctx, "Routing", "DHCP server", sv)]
    relay = {int(v["id"]) for v in ctx.vlan_by_name.values() if _truthy(v.get("dhcp_relay")) and _s(v.get("irb"))}
    if relay and not servers:
        ctx.error("Routing", "VLANs use DHCP relay but no DHCP server is set on the Routing tab.")
    if ctx.svis:
        cfg.comment("VLAN interfaces (SVIs)")
    for vid, addrs in sorted(ctx.svis.items()):
        body = cfg.block(f"interface Vlan{vid}")
        body.extend(_ip_line(a) for a in addrs)
        if vid in relay:
            body.extend(f"ip helper-address {sv}" for sv in servers)
        body.append("no shutdown")
    lo = _s(r.get("loopback"))
    if lo:
        addrs = _addresses(ctx, "Routing", "Loopback", lo if "/" in lo else f"{lo}/32")
        if addrs:
            body = cfg.block("interface Loopback0")
            for a in addrs:
                body.append(_ip_line(a))
                if a.version == 4:
                    ctx.loopback_ip = str(a.ip)
            ctx.l3_ifaces.add("Loopback0")
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
    if ctx.svis or lo or any(row.get("mode") == "routed" for row in ctx.p["ports"] + ctx.p["lags"]):
        cfg.line("ip routing")
    if any(a.version == 6 for _, a in ctx.l3_networks):
        cfg.line("ipv6 unicast-routing")


def _static(ctx: IosCtx) -> None:
    r, cfg = ctx.p["routing"], ctx.cfg
    routes = [x for x in r.get("static") or [] if _s(x.get("prefix"))]
    gw = getattr(ctx, "mgmt_gateway", None)
    has_default = any(_s(x.get("prefix")) in ("0.0.0.0/0", "default") for x in routes)
    if gw and not has_default:
        routes.append({"prefix": "0.0.0.0/0", "next_hop": gw, "preference": ""})
    elif gw and has_default:
        ctx.warn("System", "You have a default route and a management gateway. Tick 'management VRF' to "
                           "keep management traffic separate, or the management gateway is ignored.")
    mgmt_route = getattr(ctx, "mgmt_route", None)
    if routes or mgmt_route:
        cfg.comment("Static routes")
    if mgmt_route:
        cfg.line(mgmt_route)
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
        dest = f"ip route {net.network_address} {net.netmask}" if net.version == 4 else f"ipv6 route {net}"
        cfg.line(f"{dest} {target}" + (f" {pref}" if pref else ""))
    ctx.at("", None)


def _ospf(ctx: IosCtx) -> None:
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
        ctx.warn("OSPF", "Export policies are not written for Cisco yet; add 'redistribute' lines by hand.")
    for a in o.get("areas") or []:
        ctx.at("routing.ospf.areas", a)
        area = _s(a.get("area")) or "0.0.0.0"
        if not re.fullmatch(r"\d+|\d+\.\d+\.\d+\.\d+", area):
            ctx.error("OSPF", f"Area '{area}' must be a number or dotted (0.0.0.0).", "area")
            continue
        kind = a.get("type") or "normal"
        if kind in ("stub", "nssa"):
            body.append(f"area {area} {kind}")
        key = _s(a.get("md5_key"))
        p2p = {_iface_name(x) for x in _list(a.get("p2p"))}
        passive = _list(a.get("passive"))
        for raw in _list(a.get("interfaces")) + passive:
            name = _iface_name(raw)
            if not name:
                ctx.error("OSPF", f"Area {area}: '{raw}' is not a Cisco interface (Gi1/0/49, Vlan20, Loopback0).", "interfaces")
                continue
            ib = cfg.block(f"interface {name}", f"ip ospf 1 area {area}")
            if (raw in passive or name.startswith("Loopback")) and f"passive-interface {name}" not in body:
                body.append(f"passive-interface {name}")
            if name in p2p:
                ib.append("ip ospf network point-to-point")
            if key:
                if len(key) > 16:
                    ctx.error("OSPF", f"Area {area}: the MD5 key can be at most 16 characters.", "md5_key")
                else:
                    for ln in ("ip ospf authentication message-digest", f"ip ospf message-digest-key 1 md5 {key}"):
                        if ln not in ib:
                            ib.append(ln)
    ctx.at("", None)


def _bgp(ctx: IosCtx) -> None:
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
    body.append("bgp log-neighbor-changes")
    if any(_truthy(g.get("multipath")) for g in groups) or _truthy(ctx.p["routing"].get("ecmp")):
        body.append("maximum-paths 4")
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
        body.append(f"neighbor {name} peer-group")
        if not external:
            body.append(f"neighbor {name} remote-as {ctx.asn}")
        elif peer_as:
            body.append(f"neighbor {name} remote-as {peer_as}")
        if _s(g.get("description")):
            body.append(f"neighbor {name} description {_s(g.get('description'))}")
        local = _s(g.get("local_address"))
        if local and ctx.loopback_ip and local == ctx.loopback_ip:
            body.append(f"neighbor {name} update-source Loopback0")
        elif local:
            ctx.warn("BGP", f"Group {name}: Cisco sets the source by interface; only the loopback address is mapped.")
        if _s(g.get("auth_key")):
            body.append(f"neighbor {name} password {_s(g.get('auth_key'))}")
        if _s(g.get("bfd")):
            body.append(f"neighbor {name} fall-over bfd")
        if _s(g.get("import")) or _s(g.get("export")):
            ctx.warn("BGP", f"Group {name}: import/export policies are not written for Cisco yet (use route-maps).")
        for ip, asn, desc in neighbors:
            if external and asn:
                body.append(f"neighbor {ip} remote-as {asn}")
            elif external and not peer_as:
                ctx.error("BGP", f"Group {name}: neighbor {ip} needs a peer AS (on the group or after the IP).", "neighbors")
            body.append(f"neighbor {ip} peer-group {name}")
            if desc:
                body.append(f"neighbor {ip} description {desc}")
    ctx.at("", None)
    if ctx.loopback_ip:
        body.append(f"network {ctx.loopback_ip} mask 255.255.255.255")


def _services(ctx: IosCtx) -> None:
    s, cfg = ctx.p["services"], ctx.cfg
    cfg.comment("Switching services")
    if _truthy(s.get("lldp")):
        cfg.line("lldp run")
    stp = s.get("stp")
    if stp == "rstp":
        cfg.line("spanning-tree mode rapid-pvst")
        cfg.line("spanning-tree extend system-id")
        prio = _s(s.get("bridge_priority")).lower()
        if prio:
            m = re.fullmatch(r"(\d+)(k?)", prio)
            val = int(m.group(1)) * (1024 if m.group(2) else 1) if m else -1
            val = 4096 * round(val / 4096) if m and m.group(2) else val
            if 0 <= val <= 61440 and val % 4096 == 0:
                cfg.line(f"spanning-tree vlan 1-4094 priority {val}")
            else:
                ctx.error("Services", "Bridge priority must be 0, 4k, 8k ... 60k (steps of 4k).", "services.bridge_priority")
    elif stp == "none":
        cfg.line("no spanning-tree vlan 1-4094")
        ctx.warn("Services", "Spanning tree is off: a cabling loop will take the network down.")
    pct = _s(s.get("storm_percent")) or "5"
    if _truthy(s.get("storm_control")) and not (pct.isdigit() and 1 <= int(pct) <= 100):
        ctx.error("Services", "Storm control percentage must be 1-100.", "services.storm_percent")
    sec = ctx.p.get("security") or {}
    rt = _s(sec.get("recovery_timeout"))
    if rt:
        if rt.isdigit() and 30 <= int(rt) <= 86400:
            cfg.line("errdisable recovery cause bpduguard")
            cfg.line("errdisable recovery cause psecure-violation")
            cfg.line(f"errdisable recovery interval {rt}")
        else:
            ctx.error("Security", "Auto-recovery time must be 30-86400 seconds on Cisco.", "security.recovery_timeout")
    if ctx.snoop:
        cfg.line("ip dhcp snooping")
        cfg.line(f"ip dhcp snooping vlan {_vid_list(ctx.snoop)}")
        cfg.line("no ip dhcp snooping information option")
        for header in ctx.trunks:
            cfg.block(header, "ip dhcp snooping trust")
        ctx.warn("Services", "DHCP snooping is on: trunk and LAG ports are trusted, access ports are not. "
                             "Tick 'DHCP trusted' on an access port that has a DHCP server behind it.")
    if ctx.dai:
        cfg.line(f"ip arp inspection vlan {_vid_list(ctx.dai)}")
        for header in ctx.trunks:
            cfg.block(header, "ip arp inspection trust")
    if any(_truthy(s.get(k)) for k in ("poe_fast", "poe_perpetual")) or _s(s.get("poe_guard_band")):
        ctx.warn("Services", "Perpetual/fast PoE and guard band are Juniper options; not written for Cisco.")
    if ctx.dot1x_ports:
        servers = [x for x in sec.get("radius_servers") or [] if _s(x.get("address"))]
        if not servers:
            ctx.error("Security", "802.1X / MAB ports need at least one RADIUS server.")
        cfg.comment("802.1X and MAB (RADIUS)")
        cfg.line("aaa authentication dot1x default group radius")
        cfg.line("aaa authorization network default group radius")
        cfg.line("aaa accounting dot1x default start-stop group radius")
        cfg.line("dot1x system-auth-control")
        for i, x in enumerate(servers, 1):
            ctx.at("security.radius_servers", x)
            addr = _s(x.get("address"))
            if not _ip(ctx, "Security", "RADIUS server", addr):
                continue
            if not _s(x.get("secret")):
                ctx.error("Security", f"RADIUS server {addr} needs a shared secret.", "secret")
                continue
            port = _s(x.get("port")) or "1812"
            cfg.block(f"radius server RADIUS-{i}", f"address ipv4 {addr} auth-port {port} acct-port 1813",
                      f"key {_s(x.get('secret'))}")
        ctx.at("", None)
    if _truthy(s.get("disable_unused")) and ctx.known:
        unused = [n for n, info in ctx.known.items() if n not in ctx.used and info["kind"] in ("access", "uplink")]
        if unused:
            for header in _ranges(unused, _truthy(s.get("use_ranges"))):
                cfg.block(header, "description Unused - disabled", "shutdown")
            for n in unused:
                ctx.res.ports.setdefault(n, {"use": "disabled", "label": "Unused"})


def _unsupported(ctx: IosCtx) -> None:
    p = ctx.p
    if _truthy((p.get("evpn") or {}).get("enabled")):
        ctx.warn("EVPN", "EVPN-VXLAN is not written for Cisco yet.")
    if any((p.get("policy") or {}).get(k) for k in ("prefix_lists", "communities", "terms")):
        ctx.warn("Policies", "Routing policies are not written for Cisco yet.")
    if _truthy((p.get("qos") or {}).get("enabled")):
        ctx.warn("QoS", "QoS is not written for Cisco yet (Catalyst 9000 trusts DSCP by default).")


def header(p: dict) -> list[str]:
    name = _s(p.get("name")) or _s(p.get("system", {}).get("hostname")) or "switch"
    models = ", ".join(f"{_s(m.get('model'))} (switch {m.get('fpc', 1) or 1})" for m in p["switch"].get("members") or [])
    return [f"Cisco IOS-XE configuration for {name}", f"Hardware: {models}",
            f"Made by Multi-Vendor Switch Config Builder {__version__}. Review before you load it."]


def build(project: dict) -> Result:
    p = normalize(project)
    ctx = IosCtx(p)
    for t in header(p):
        ctx.cfg.comment(t)
    for step in (_switch, _system, _access, _snmp, _syslog, _vlans, _ports, _lags, _l3, _static, _ospf, _bgp,
                 _services, _unsupported):
        step(ctx)
        ctx.row = None
    vty = getattr(ctx, "vty", None)
    if vty:
        ctx.cfg.comment("Console and SSH lines")
        ctx.cfg.block(vty[0], *vty[1])
        ctx.cfg.block(vty[2], *vty[3])
    if ctx.p["system"].get("domain") and _s(ctx.p["system"].get("hostname")):
        ctx.cfg.comment("SSH host key (on a switch that already has one, answer 'no' when asked to replace it)")
        ctx.cfg.line("crypto key generate rsa general-keys modulus 2048 label SSH-KEY")
        ctx.cfg.line("ip ssh rsa keypair-name SSH-KEY")
    text = ctx.cfg.text()
    if ctx.banner:
        text = text[: -len("end\n")] + "banner login ^\n" + ctx.banner + "\n^\n!\nend\n"
    ctx.res.errors = _dedupe(ctx.res.errors)
    ctx.res.warnings = _dedupe(ctx.res.warnings)
    ctx.res.set_text = text
    ctx.res.hier_text = text
    ctx.res.hostname = _s(p["system"].get("hostname")) or "switch"
    return ctx.res
