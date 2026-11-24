"""Turn a project into Arista EOS configuration.

Uses the same project format as the Juniper builder (see generator.py), so a
project's VLANs, port groups, LAGs and routing mean the same thing here. Port
names are EOS names (Ethernet1, Ethernet49/1) and LAGs are Port-Channels.
"""

from __future__ import annotations

import ipaddress
import re

from . import __version__, eos_models, vendors
from . import ports as P
from . import routing as R
from .cryptpw import is_hashed, sha512_crypt
from .generator import (DOMAIN, HOSTNAME, NAME, USERNAME, Ctx, Result, SSH_KEY_TYPES, _addresses, _ip, _list,
                        _s, _truthy, _vlan_name, normalize)
from .textcfg import Blocks

VENDOR = vendors.VENDORS["arista"]
SPEEDS = {"10m": "10full", "100m": "100full", "1g": "1g", "2.5g": "2.5g", "5g": "5g", "10g": "10g",
          "25g": "25g", "40g": "40g", "100g": "100g"}
LEVELS = {"emergency": "emergencies", "alert": "alerts", "critical": "critical", "error": "errors",
          "warning": "warnings", "notice": "notifications", "info": "informational", "any": "debugging"}
ROLES = {"super-user": ("15", "network-admin"), "operator": ("1", "network-operator"),
         "read-only": ("1", "network-operator")}
SNMP_AUTH = {"md5": "md5", "sha": "sha", "sha224": "sha224", "sha256": "sha256", "sha384": "sha384", "sha512": "sha512"}
SNMP_PRIV = {"aes128": "aes", "des": "des", "3des": "3des"}
_PO = re.compile(r"^(?:port-channel|po|ae)\s*(\d{1,4})$", re.I)


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
    """User text such as 'Vlan20', 'irb.20', 'lo0', 'Et49/1', 'Po1' -> an EOS interface name."""
    t = _s(text)
    if not t:
        return None
    if m := re.fullmatch(r"(?:irb\.|vlan)\s*(\d{1,4})", t, re.I):
        return f"Vlan{m.group(1)}"
    if m := re.fullmatch(r"(?:lo|loopback)\s*(\d{0,4})(?:\.0)?", t, re.I):
        return f"Loopback{m.group(1) or 0}"
    if m := _PO.fullmatch(t):
        return f"Port-Channel{m.group(1)}"
    try:
        names = P.expand_named(t, eos_models.ALIASES)
    except ValueError:
        return None
    return names[0] if len(names) == 1 else None


class EosCtx(Ctx):
    def __init__(self, project: dict):
        super().__init__(project)
        self.cfg = Blocks()
        self.vmodels: list = []
        self.svis: dict[int, list] = {}
        self.dot1x_ports: list[str] = []


# ------------------------------------------------------------------ sections
def _switch(ctx: EosCtx) -> None:
    members = ctx.p["switch"].get("members") or []
    if len(members) > 1:
        ctx.error("Switch", "Arista switches don't stack. Use one switch per project (MLAG pairs are two projects).")
    for m in members[:1]:
        ctx.at("switch.members", m)
        model = eos_models.get(m.get("model", ""))
        if model:
            ctx.vmodels.append(model)
            for port in model.ports:
                ctx.known[port["name"]] = port
        elif m.get("model") != eos_models.CUSTOM:
            ctx.error("Switch", f"Unknown Arista model '{m.get('model')}'. Pick one from the list or Custom.", "model")
    ctx.at("", None)
    try:
        for name in P.expand_named(ctx.p["switch"].get("custom_ports", ""), eos_models.ALIASES):
            ctx.known.setdefault(name, {"name": name, "kind": "access", "speed": "", "poe": False})
    except ValueError as exc:
        ctx.error("Switch", f"Custom ports: {exc}")


def _password(ctx: EosCtx, section: str, label: str, value, key: str) -> str | None:
    value = _s(value)
    if not value:
        return None
    if is_hashed(value):
        return value
    if len(value) < 8:
        ctx.error(section, f"{label}: use at least 8 characters.", key if not ctx.row else key.rsplit(".", 1)[-1])
        return None
    hashed = sha512_crypt(value)
    ctx.res.hashed[key] = hashed
    return hashed


def _system(ctx: EosCtx) -> None:
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
    vrf = " vrf MGMT" if _truthy(s.get("mgmt_vrf")) else ""
    for ns in _list(s.get("name_servers")):
        if _ip(ctx, "System", "DNS server", ns):
            cfg.line(f"ip name-server{vrf} {ns}")
    search = [d for d in _list(s.get("domain_search")) if DOMAIN.match(d)]
    if search:
        cfg.block("dns domain", *[f"domain-list {d}" for d in search])
    tz = _s(s.get("timezone"))
    if tz and tz != "UTC":
        if re.match(r"^[A-Za-z0-9_+\-/]+$", tz):
            cfg.line(f"clock timezone {tz}")
        else:
            ctx.error("System", f"Time zone '{tz}' is not valid.", "system.timezone")
    ntp = [n for n in s.get("ntp_servers") or [] if _s(n.get("address"))]
    if not ntp:
        ctx.warn("System", "No NTP server: logs and certificates need the right time.")
    for n in ntp:
        addr = _s(n.get("address"))
        if not (re.match(r"^[A-Za-z0-9.-]+$", addr) or _ip(ctx, "System", "NTP server", addr)):
            continue
        cfg.line(f"ntp server{vrf} {addr}" + (" prefer" if _truthy(n.get("prefer")) else ""))
    src = _s(s.get("ntp_source"))
    if src:
        ctx.warn("System", "Arista picks the NTP source by interface, not address; set 'ntp local-interface' by hand if needed.")

    mif = _s(s.get("mgmt_interface")) or (ctx.vmodels[0].mgmt if ctx.vmodels else "Management1")
    if not re.fullmatch(r"Management\d+(?:/\d+)?", mif):
        ctx.error("System", f"Management port '{mif}' should be Management1 (or Management0).", "system.mgmt_interface")
        mif = "Management1"
    addrs = _addresses(ctx, "System", f"Management ({mif})", s.get("mgmt_address"))
    if addrs:
        if vrf:
            cfg.block("vrf instance MGMT")
        body = cfg.block(f"interface {mif}")
        if vrf:
            body.append("vrf MGMT")
        for a in addrs:
            body.append(f"{'ip' if a.version == 4 else 'ipv6'} address {a.with_prefixlen}")
        gw = _s(s.get("mgmt_gateway"))
        if gw and (gw_ip := _ip(ctx, "System", "Management gateway", gw)):
            if not any(gw_ip in a.network for a in addrs if a.version == gw_ip.version):
                ctx.warn("System", f"Management gateway {gw} is not in the management subnet.")
            if vrf:
                ctx.mgmt_route = f"{'ip' if gw_ip.version == 4 else 'ipv6'} route vrf MGMT {'0.0.0.0/0' if gw_ip.version == 4 else '::/0'} {gw}"
            else:
                ctx.mgmt_gateway = gw
    elif _s(s.get("mgmt_gateway")):
        ctx.warn("System", "Management gateway is set but the management port has no address.")
    banner = (s.get("banner") or "").rstrip()
    if banner.strip():
        if any(ln.strip() == "EOF" for ln in banner.splitlines()):
            ctx.error("System", "The banner can't contain a line that is just EOF.", "system.banner")
        else:
            ctx.banner = banner


def _access(ctx: EosCtx) -> None:
    a, cfg = ctx.p["access"], ctx.cfg
    cfg.comment("Accounts and remote access")
    root = _password(ctx, "Access", "Root password", a.get("root_password"), "access.root_password")
    if root:
        cfg.line(f"aaa root secret sha512 {root}")
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
            ctx.warn("Access", f"User '{name}' is 'unauthorized': skipped on Arista.")
            continue
        priv, role = ROLES.get(cls, ROLES["read-only"])
        hashed = _password(ctx, "Access", f"User {name}", u.get("password"), f"access.users.{i}.password")
        keys = [k.strip() for k in (u.get("ssh_keys") or "").splitlines() if k.strip()]
        if hashed:
            cfg.line(f"username {name} privilege {priv} role {role} secret sha512 {hashed}")
        elif keys:
            cfg.line(f"username {name} privilege {priv} role {role} nopassword")
        else:
            ctx.error("Access", f"User '{name}' needs a password or an SSH key.", "password")
        for k in keys:
            if k.split()[0] not in SSH_KEY_TYPES:
                ctx.error("Access", f"User {name}: SSH key must start with ssh-rsa, ssh-ed25519 or ecdsa-sha2-...")
            else:
                cfg.line(f"username {name} ssh-key {k}")
    ctx.at("", None)
    if not any(u.get("class") == "super-user" and _s(u.get("name")) for u in a.get("users") or []):
        ctx.warn("Access", "No super-user account: nobody can change the config after this one.")
    ssh = cfg.block("management ssh")
    if _truthy(ctx.p["system"].get("mgmt_vrf")):
        cfg.block("management ssh", "vrf MGMT", "   no shutdown")
    limit = _s(a.get("ssh_connection_limit"))
    if limit:
        if limit.isdigit() and 1 <= int(limit) <= 100:
            ssh.append(f"connection limit {limit}")
        else:
            ctx.error("Access", "SSH connection limit must be 1-100.", "access.ssh_connection_limit")
    if _truthy(a.get("retry_options")):
        ssh.append("authentication protocol keyboard-interactive password public-key")
        cfg.line("aaa authentication policy lockout failure 3 duration 300")
    if _truthy(a.get("netconf")):
        cfg.block("management api netconf", "transport ssh default")
    if _truthy(a.get("web")):
        cfg.block("management api http-commands", "no shutdown")


def _snmp(ctx: EosCtx) -> None:
    s, cfg = ctx.p["snmp"], ctx.cfg
    comms = [c for c in s.get("communities") or [] if _s(c.get("name"))]
    users = [u for u in s.get("v3_users") or [] if _s(u.get("name"))]
    targets = _list(s.get("trap_targets"))
    if not (comms or users or targets or _s(s.get("location")) or _s(s.get("contact"))):
        return
    cfg.comment("SNMP")
    vrf = " vrf MGMT" if _truthy(ctx.p["system"].get("mgmt_vrf")) else ""
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
        clients = [cl for cl in _list(c.get("clients")) if _ip(ctx, "SNMP", f"Community {name} client", cl, allow_net=True)]
        acl = ""
        if clients:
            acl = f" SNMP-{name.upper()}"[:65]
            body = cfg.block(f"ip access-list standard{acl}")
            for i, cl in enumerate(clients, 1):
                body.append(f"{i * 10} permit {cl if '/' in cl else cl + '/32'}")
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
        auth = SNMP_AUTH.get(u.get("auth") or "sha", "sha")
        priv = SNMP_PRIV.get(u.get("priv") or "")
        level = "auth"
        line = f"snmp-server user {name} {name}-group v3 auth {auth} {apw}"
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
                cfg.line(f"snmp-server host {t}{vrf} version 2c {comm}")
        cfg.line("snmp-server enable traps")
    if vrf:
        cfg.line("snmp-server vrf MGMT")


def _syslog(ctx: EosCtx) -> None:
    s, cfg = ctx.p["syslog"], ctx.cfg
    cfg.comment("Logging")
    level = LEVELS.get(s.get("local_level") or "notice", "notifications")
    cfg.line(f"logging buffered 10000 {level}")
    vrf = " vrf MGMT" if _truthy(ctx.p["system"].get("mgmt_vrf")) else ""
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
        cfg.line(f"logging{vrf} host {addr}" + (f" {port}" if port and port != "514" else ""))
        trap = LEVELS.get(h.get("level") or "info", "informational")
    ctx.at("", None)
    if trap:
        cfg.line(f"logging trap {trap}")
    if _truthy(s.get("log_commands")):
        cfg.line("aaa accounting commands all default start-stop logging")
    if _s(s.get("source_address")):
        ctx.warn("Logging", "Arista sets the syslog source by interface; add 'logging source-interface' by hand if needed.")


def _vlans(ctx: EosCtx) -> None:
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
            ctx.warn("VLANs", f"VLAN {name}: IP source guard is set per port on Arista; not written.")
        if _s(v.get("vni")) or _s(v.get("vga")) or _s(v.get("vrf")):
            ctx.warn("VLANs", f"VLAN {name}: VNI, virtual gateway and VRF are not written for Arista yet.")
    ctx.at("", None)
    if snoop:
        cfg.line("ip dhcp snooping")
        cfg.line(f"ip dhcp snooping vlan {_vid_list(snoop)}")
    if dai:
        cfg.line(f"ip arp inspection vlan {_vid_list(dai)}")


def _claim(ctx: EosCtx, section: str, label: str, names: list[str]) -> list[str]:
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


def _translate(ctx: EosCtx, section: str, label: str, body: list, row: dict, allowed: list | None) -> None:
    spec = _s(row.get("vlan_translate"))
    if not spec:
        return
    try:
        pairs = P.translations(spec)
    except ValueError as exc:
        ctx.error(section, f"{label}: VLAN translation: {exc}", "vlan_translate")
        return
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
        body.append(f"switchport vlan translation {wire} {local}")


def _port_body(ctx: EosCtx, section: str, label: str, body: list, row: dict, phys: list[str], is_lag=False) -> None:
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
        if not (mtu.isdigit() and 68 <= int(mtu) <= 9214):
            ctx.error(section, f"{label}: MTU must be 68-9214.", "mtu")
        elif mode == "routed":
            body.append(f"mtu {mtu}")
        else:
            ctx.warn(section, f"{label}: Arista switch ports already pass jumbo frames; MTU only applies to routed ports.")
    svc = ctx.p["services"]
    storm = _truthy(svc.get("storm_control"))
    pct = _s(svc.get("storm_percent")) or "5"
    storm_lines = [f"storm-control broadcast level {pct}", f"storm-control unknown-unicast level {pct}"]
    edge_lines = ["spanning-tree portfast"] + (["spanning-tree bpduguard enable"] if _truthy(svc.get("bpdu_block_on_edge")) else [])
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
                body.remove("switchport mode access")
                if vlan:
                    body.remove(f"switchport access vlan {_vid(ctx, vlan)}")
                    body.append(f"switchport trunk native vlan {_vid(ctx, vlan)}")
                body.append("switchport mode trunk phone")
                body.append(f"switchport phone vlan {_vid(ctx, voice)}")
                body.append("switchport phone trunk tagged")
                if not any(m.family in ("720XP", "722XPM") for m in ctx.vmodels):
                    ctx.warn(section, f"{label}: phone VLANs need a 720XP or 722XPM (or a recent EOS on other models).")
        if storm:
            body.extend(storm_lines)
        if _truthy(row.get("edge")):
            body.extend(edge_lines)
        limit = _s(row.get("mac_limit"))
        if limit:
            if limit.isdigit() and 1 <= int(limit) <= 1000:
                body.append("switchport port-security")
                body.append(f"switchport port-security mac-address maximum {limit}")
                action = _s(row.get("mac_action")) or "drop"
                if action in ("drop", "drop-and-log", "log"):
                    body.append("switchport port-security violation protect" + (" log" if action != "drop" else ""))
            else:
                ctx.error(section, f"{label}: MAC limit must be 1-1000.", "mac_limit")
        if _truthy(row.get("sticky")):
            ctx.warn(section, f"{label}: sticky MAC is not available on Arista; skipped.")
        if _truthy(row.get("dhcp_trusted")):
            body.append("ip arp inspection trust")
        dot1x = _s(row.get("dot1x"))
        if dot1x:
            body.append("dot1x pae authenticator")
            body.append("dot1x port-control auto")
            if dot1x in ("dot1x-mab", "mab"):
                body.append("dot1x mac based authentication")
            if dot1x == "mab":
                ctx.warn(section, f"{label}: Arista runs MAB as a fallback after 802.1X; devices that can't do 802.1X still get in by MAC.")
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
    if is_lag:
        return
    poe, pmax = _s(row.get("poe")), _s(row.get("poe_max"))
    if poe or pmax:
        no_poe = [p for p in phys if p in ctx.known and not ctx.known[p].get("poe")]
        if no_poe:
            ctx.warn(section, f"{label}: {', '.join(no_poe[:3])}{'…' if len(no_poe) > 3 else ''} has no PoE; PoE setting skipped.")
        if len(no_poe) < len(phys):
            if poe == "off":
                body.append("poe disabled")
            elif poe in ("high", "low"):
                body.append(f"poe priority {poe}")
            if pmax and poe != "off":
                try:
                    watts = float(pmax)
                except ValueError:
                    watts = -1
                if not 0 < watts <= 90:
                    ctx.error(section, f"{label}: maximum PoE power must be 0.1-90 watts.", "poe_max")
                else:
                    body.append(f"poe limit {watts:.2f} watts")


def _range(names: list[str], use_ranges: bool) -> list[str]:
    """Interface block headers for a port group."""
    if not use_ranges or len(names) == 1:
        return names
    return [", ".join(a if a == b else f"{a}-{P.named_key(b)[1][-1]}" for a, b in P.named_runs(names))]


def _ports(ctx: EosCtx) -> None:
    rows = [r for r in ctx.p["ports"] if _s(r.get("ports"))]
    if not rows:
        return
    ctx.cfg.comment("Switch ports")
    use_ranges = _truthy(ctx.p["services"].get("use_ranges"))
    for i, row in enumerate(rows):
        ctx.at("ports", row)
        label = _s(row.get("name")) or f"Port group {i + 1}"
        try:
            names = P.expand_named(row.get("ports"), eos_models.ALIASES)
        except ValueError as exc:
            ctx.error("Ports", f"{label}: {exc} (example: Ethernet1-24, Et49/1).", "ports")
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
            voice = mode == "access" and (bool(_s(row.get("voice"))) or any(
                _truthy(v.get("voice")) and v["name"] != _s(row.get("vlan")) for v in ctx.p["vlans"]))
            ctx.res.ports[port] = {"use": mode, "label": label, "voice": voice, "role": _s(row.get("role"))}
    ctx.at("", None)


def _dedupe(items: list) -> list:
    seen, out = set(), []
    for m in items:
        key = tuple(sorted(m.items()))
        if key not in seen:
            seen.add(key)
            out.append(m)
    return out


def _lags(ctx: EosCtx) -> None:
    lags = [r for r in ctx.p["lags"] if _s(r.get("name")) or _s(r.get("members"))]
    if not lags:
        return
    ctx.cfg.comment("Port-Channels (LACP)")
    seen = set()
    for row in lags:
        ctx.at("lags", row)
        raw = _s(row.get("name"))
        m = _PO.fullmatch(raw) or re.fullmatch(r"(\d{1,4})", raw)
        num = int(m.group(1)) if m else -1
        if not 1 <= num <= 2000:
            ctx.error("LAGs", f"LAG name '{raw}' must be Port-Channel1 to Port-Channel2000 (Po1 also works).", "name")
            continue
        name = f"Port-Channel{num}"
        label = name
        if num in seen:
            ctx.error("LAGs", f"{name} is listed twice.", "name")
            continue
        seen.add(num)
        try:
            members = P.expand_named(row.get("members"), eos_models.ALIASES)
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
        for mem in members:
            body = ctx.cfg.block(f"interface {mem}")
            if _s(row.get("description")):
                body.append(f"description {_s(row.get('description'))} (member of {name})")
            body.append(f"channel-group {num} mode {'on' if lacp == 'static' else lacp}")
            if lacp != "static" and _truthy(row.get("lacp_fast")):
                body.append("lacp timer fast")
            ctx.res.ports[mem] = {"use": "lag", "label": name}
        body = []
        _port_body(ctx, "LAGs", label, body, row, [name], is_lag=True)
        ml = _s(row.get("min_links"))
        if ml:
            if ml.isdigit() and 1 <= int(ml) <= len(members):
                body.append(f"port-channel min-links {ml}")
            else:
                ctx.error("LAGs", f"{label}: minimum links must be 1-{len(members)}.", "min_links")
        if _s(row.get("esi")):
            ctx.warn("LAGs", f"{label}: EVPN multihoming (ESI) is not written for Arista yet.")
        ctx.cfg.block(f"interface {name}", *body)
    ctx.at("", None)


def _l3(ctx: EosCtx) -> None:
    """SVIs, loopback, routing identity and DHCP relay."""
    r, cfg = ctx.p["routing"], ctx.cfg
    servers = [sv for sv in _list(r.get("dhcp_relay_servers")) if _ip(ctx, "Routing", "DHCP server", sv)]
    relay = {int(v["id"]) for v in ctx.vlan_by_name.values() if _truthy(v.get("dhcp_relay")) and _s(v.get("irb"))}
    if relay and not servers:
        ctx.error("Routing", "VLANs use DHCP relay but no DHCP server is set on the Routing tab.")
    if ctx.svis:
        cfg.comment("VLAN interfaces (SVIs)")
    for vid, addrs in sorted(ctx.svis.items()):
        body = cfg.block(f"interface Vlan{vid}")
        for a in addrs:
            body.append(f"{'ip' if a.version == 4 else 'ipv6'} address {a.with_prefixlen}")
        if vid in relay:
            body.extend(f"ip helper-address {sv}" for sv in servers)
    lo = _s(r.get("loopback"))
    if lo:
        addrs = _addresses(ctx, "Routing", "Loopback", lo if "/" in lo else f"{lo}/32")
        if addrs:
            body = cfg.block("interface Loopback0")
            for a in addrs:
                body.append(f"{'ip' if a.version == 4 else 'ipv6'} address {a.with_prefixlen}")
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
    if ctx.svis or any((row.get("mode") == "routed") for row in ctx.p["ports"] + ctx.p["lags"]) or lo:
        cfg.line("ip routing")


def _static(ctx: EosCtx) -> None:
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
        cfg.line(f"{'ip' if net.version == 4 else 'ipv6'} route {net} {target}" + (f" {pref}" if pref else ""))
    ctx.at("", None)


def _ospf(ctx: EosCtx) -> None:
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
            mbps = int(m.group(1)) * (1000 if m.group(2) == "g" else 1)
            body.append(f"auto-cost reference-bandwidth {mbps}")
        else:
            ctx.error("OSPF", "Reference bandwidth must look like 100g or 100000 (Mbps).", "routing.ospf.reference_bandwidth")
    if _s(o.get("export")):
        ctx.warn("OSPF", "Export policies are not written for Arista yet; add 'redistribute' lines by hand.")
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
        passive = [x for x in _list(a.get("passive"))]
        for raw in _list(a.get("interfaces")) + passive:
            name = _iface_name(raw)
            if not name:
                ctx.error("OSPF", f"Area {area}: '{raw}' is not an Arista interface (Ethernet1, Vlan20, Loopback0).", "interfaces")
                continue
            ib = cfg.block(f"interface {name}", f"ip ospf area {area}")
            if (raw in passive or name.startswith("Loopback")) and f"passive-interface {name}" not in body:
                body.append(f"passive-interface {name}")
            if name in p2p:
                ib.append("ip ospf network point-to-point")
            if key:
                if len(key) > 16:
                    ctx.error("OSPF", f"Area {area}: the MD5 key can be at most 16 characters.", "md5_key")
                else:
                    ib.extend(["ip ospf authentication message-digest", f"ip ospf message-digest-key 1 md5 {key}"])
    ctx.at("", None)
    body.append("max-lsa 12000")


def _bgp(ctx: EosCtx) -> None:
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
    if any(_truthy(g.get("multipath")) for g in groups) or _truthy(ctx.p["routing"].get("ecmp")):
        body.append("maximum-paths 4 ecmp 4")
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
        body.append(f"neighbor {name} peer group")
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
            ctx.warn("BGP", f"Group {name}: Arista sets the source by interface; only the loopback address is mapped.")
        if _s(g.get("auth_key")):
            body.append(f"neighbor {name} password {_s(g.get('auth_key'))}")
        if _s(g.get("bfd")):
            body.append(f"neighbor {name} bfd")
        if _s(g.get("import")) or _s(g.get("export")):
            ctx.warn("BGP", f"Group {name}: import/export policies are not written for Arista yet (use route-maps).")
        for ip, asn, desc in neighbors:
            body.append(f"neighbor {ip} peer group {name}")
            if external and asn:
                body.append(f"neighbor {ip} remote-as {asn}")
            elif external and not peer_as:
                ctx.error("BGP", f"Group {name}: neighbor {ip} needs a peer AS (on the group or after the IP).", "neighbors")
            if desc:
                body.append(f"neighbor {ip} description {desc}")
    ctx.at("", None)
    if ctx.svis or ctx.loopback_ip:
        nets = []
        if ctx.loopback_ip:
            nets.append(f"network {ctx.loopback_ip}/32")
        body.extend(nets)


def _services(ctx: EosCtx) -> None:
    s, cfg = ctx.p["services"], ctx.cfg
    cfg.comment("Switching services")
    if not _truthy(s.get("lldp")):
        cfg.line("no lldp run")
    stp = s.get("stp")
    if stp == "rstp":
        cfg.line("spanning-tree mode rstp")
        prio = _s(s.get("bridge_priority")).lower()
        if prio:
            m = re.fullmatch(r"(\d+)(k?)", prio)
            val = int(m.group(1)) * (1024 if m.group(2) else 1) if m else -1
            val = 4096 * round(val / 4096) if m and m.group(2) else val
            if 0 <= val <= 61440 and val % 4096 == 0:
                cfg.line(f"spanning-tree priority {val}")
            else:
                ctx.error("Services", "Bridge priority must be 0, 4k, 8k ... 60k (steps of 4k).", "services.bridge_priority")
    elif stp == "none":
        cfg.line("spanning-tree mode none")
        ctx.warn("Services", "Spanning tree is off: a cabling loop will take the network down.")
    pct = _s(s.get("storm_percent")) or "5"
    if _truthy(s.get("storm_control")) and not (pct.isdigit() and 1 <= int(pct) <= 100):
        ctx.error("Services", "Storm control percentage must be 1-100.", "services.storm_percent")
    if not _truthy(s.get("igmp_snooping")):
        pass  # on by default on EOS
    if any(_truthy(s.get(k)) for k in ("poe_fast", "poe_perpetual")) or _s(s.get("poe_guard_band")) or _s(s.get("poe_management")):
        ctx.warn("Services", "Perpetual/fast PoE, guard band and power management are Juniper options; not written for Arista.")
    if ctx.dot1x_ports:
        sec = ctx.p.get("security") or {}
        servers = [x for x in sec.get("radius_servers") or [] if _s(x.get("address"))]
        if not servers:
            ctx.error("Security", "802.1X / MAB ports need at least one RADIUS server.")
        cfg.line("aaa authentication dot1x default group radius")
        cfg.line("dot1x system-auth-control")
        vrf = " vrf MGMT" if _truthy(ctx.p["system"].get("mgmt_vrf")) else ""
        for x in servers:
            ctx.at("security.radius_servers", x)
            if _ip(ctx, "Security", "RADIUS server", _s(x.get("address"))):
                if not _s(x.get("secret")):
                    ctx.error("Security", f"RADIUS server {_s(x.get('address'))} needs a shared secret.", "secret")
                    continue
                port = _s(x.get("port"))
                cfg.line(f"radius-server host {_s(x.get('address'))}{vrf}" + (f" auth-port {port}" if port else "")
                         + f" key {_s(x.get('secret'))}")
        ctx.at("", None)
    if _truthy(s.get("disable_unused")) and ctx.known:
        unused = [n for n, info in ctx.known.items() if n not in ctx.used and info["kind"] in ("access", "uplink")]
        if unused:
            for header in _range(unused, _truthy(s.get("use_ranges"))):
                cfg.block(f"interface {header}", "description Unused - disabled", "shutdown")
            for n in unused:
                ctx.res.ports.setdefault(n, {"use": "disabled", "label": "Unused"})


def _unsupported(ctx: EosCtx) -> None:
    p = ctx.p
    if _truthy((p.get("evpn") or {}).get("enabled")):
        ctx.warn("EVPN", "EVPN-VXLAN is not written for Arista yet.")
    if any((p.get("policy") or {}).get(k) for k in ("prefix_lists", "communities", "terms")):
        ctx.warn("Policies", "Routing policies are not written for Arista yet.")
    if _truthy((p.get("qos") or {}).get("enabled")):
        ctx.warn("QoS", "QoS is not written for Arista yet.")


def header(p: dict) -> list[str]:
    name = _s(p.get("name")) or _s(p.get("system", {}).get("hostname")) or "switch"
    model = ", ".join(_s(m.get("model")) for m in (p["switch"].get("members") or [])[:1])
    return [f"Arista EOS configuration for {name}", f"Hardware: {model}",
            f"Made by Multi-Vendor Switch Config Builder {__version__}. Review before you load it."]


def build(project: dict) -> Result:
    p = normalize(project)
    ctx = EosCtx(p)
    ctx.banner = None
    for t in header(p):
        ctx.cfg.comment(t)
    for step in (_switch, _system, _access, _snmp, _syslog, _vlans, _ports, _lags, _l3, _static, _ospf, _bgp,
                 _services, _unsupported):
        step(ctx)
        ctx.row = None
    text = ctx.cfg.text()
    if ctx.banner:
        text = text[: -len("end\n")] + "banner login\n" + ctx.banner + "\nEOF\n!\nend\n"
    ctx.res.errors = _dedupe(ctx.res.errors)
    ctx.res.warnings = _dedupe(ctx.res.warnings)
    ctx.res.set_text = text
    ctx.res.hier_text = text
    ctx.res.hostname = _s(p["system"].get("hostname")) or "switch"
    return ctx.res
