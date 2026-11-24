"""Turn a project (a plain dict, saved as JSON) into Junos ELS configuration.

``build(project)`` returns a Result with the `set` commands, the hierarchical
config, errors (the config would not commit or is unsafe), warnings and any
password hashes it made (the page writes those back so plain-text passwords
are never saved in a project file).
"""

from __future__ import annotations

import copy
import ipaddress
import re
from dataclasses import dataclass, field

from . import __version__, models, vendors
from . import qos as Q
from . import security as SEC
from . import routing as R
from . import ports as P
from .cryptpw import is_hashed, sha512_crypt
from .junos import Config, q

SCHEMA_VERSION = 1

DEFAULTS: dict = {
    "version": SCHEMA_VERSION,
    "vendor": vendors.DEFAULT,
    "name": "",
    "switch": {
        "members": [{"fpc": 0, "model": "EX2300-48P", "serial": "", "role": "routing-engine"}],
        "custom_ports": "",
        "vc_preprovisioned": False,
        "vc_no_split_detection": True,
    },
    "system": {
        "hostname": "", "domain": "", "timezone": "UTC",
        "name_servers": "", "domain_search": "",
        "ntp_servers": [], "ntp_source": "",
        "banner": "",
        "mgmt_interface": "", "mgmt_address": "", "mgmt_gateway": "", "mgmt_vrf": False,
        "ignore_mgmt_alarm": True,
        "auto_snapshot": False,
    },
    "access": {
        "root_password": "", "root_ssh_key": "",
        "users": [],
        "ssh_root_login": "deny", "ssh_connection_limit": "10", "ssh_rate_limit": "5",
        "netconf": False, "web": False,
        "retry_options": True,
    },
    "snmp": {"location": "", "contact": "", "communities": [], "v3_users": [], "trap_targets": "",
             "trap_community": ""},
    "syslog": {"hosts": [], "source_address": "", "local_level": "notice", "log_commands": True},
    "vlans": [],
    "ports": [],
    "lags": [],
    "routing": {"static": [], "dhcp_relay_servers": "", **R.ROUTING_DEFAULTS},
    "policy": R.POLICY_DEFAULTS,
    "evpn": R.EVPN_DEFAULTS,
    "qos": Q.QOS_DEFAULTS,
    "security": SEC.SECURITY_DEFAULTS,
    "services": {
        "lldp": True, "lldp_med": True,
        "stp": "rstp", "bridge_priority": "", "bpdu_block_on_edge": True,
        "storm_control": True, "storm_percent": "5", "storm_scope": "access",
        "igmp_snooping": False,
        "poe_all": True, "poe_management": "", "poe_guard_band": "", "poe_fast": False, "poe_perpetual": False,
        "disable_unused": False,
        "use_ranges": True,
        "delete_first": True,
    },
}

PORT_DEFAULTS = {"name": "", "ports": "", "mode": "access", "vlan": "", "vlans": "", "native": "",
                 "voice": "", "description": "", "role": "", "poe": "", "poe_max": "", "edge": True, "mac_limit": "",
                 "mac_action": "drop", "sticky": False, "dot1x": "", "root_guard": False, "loop_protect": False,
                 "dhcp_trusted": False, "address": "", "mtu": "", "speed": "",
                 "vlan_translate": ""}
LAG_DEFAULTS = {**PORT_DEFAULTS, "name": "ae0", "members": "", "lacp": "active", "lacp_fast": True,
                "min_links": "", "mode": "trunk", "edge": False, "esi": "", "lacp_system_id": ""}
VLAN_DEFAULTS = {"name": "", "id": "", "description": "", "irb": "", "dhcp_relay": False,
                 "snooping": False, "dai": False, "ipsg": False,
                 "vni": "", "vga": "", "vrf": "", "voice": False}

HOSTNAME = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
DOMAIN = re.compile(r"^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,62}$")
USERNAME = re.compile(r"^[a-z_][a-z0-9_.-]{0,63}$")
CLASSES = ("super-user", "operator", "read-only", "unauthorized")
LEVELS = ("emergency", "alert", "critical", "error", "warning", "notice", "info", "any")
FACILITIES = ("any", "authorization", "change-log", "conflict-log", "daemon", "firewall",
              "interactive-commands", "kernel", "user")
PRIORITIES = {"0": "0", "4k": "4k", "8k": "8k", "12k": "12k", "16k": "16k", "20k": "20k", "24k": "24k",
              "28k": "28k", "32k": "32k", "36k": "36k", "40k": "40k", "44k": "44k", "48k": "48k",
              "52k": "52k", "56k": "56k", "60k": "60k"}
SPEEDS = ("10m", "100m", "1g", "2.5g", "5g", "10g", "25g", "40g", "100g")
SNMP_AUTH = {"md5": "authentication-md5", "sha": "authentication-sha", "sha224": "authentication-sha224",
             "sha256": "authentication-sha256", "sha384": "authentication-sha384",
             "sha512": "authentication-sha512"}
SNMP_PRIV = {"aes128": "privacy-aes128", "des": "privacy-des", "3des": "privacy-3des"}
SSH_KEY_TYPES = {"ssh-rsa": "ssh-rsa", "ssh-ed25519": "ssh-ed25519", "ecdsa-sha2-nistp256": "ssh-ecdsa",
                 "ecdsa-sha2-nistp384": "ssh-ecdsa", "ecdsa-sha2-nistp521": "ssh-ecdsa"}


@dataclass
class Result:
    set_text: str = ""
    hier_text: str = ""
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    hashed: dict = field(default_factory=dict)
    ports: dict = field(default_factory=dict)  # port -> what uses it, for the page's port map

    def to_dict(self) -> dict:
        return {"set": self.set_text, "hierarchy": self.hier_text, "errors": self.errors,
                "warnings": self.warnings, "hashed": self.hashed, "ports": self.ports}


# ----------------------------------------------------------------- helpers
def _merge(base: dict, data: dict) -> dict:
    out = copy.deepcopy(base)
    for key, val in (data or {}).items():
        if isinstance(out.get(key), dict) and isinstance(val, dict):
            out[key] = _merge(out[key], val)
        else:
            out[key] = val
    return out


def normalize(project: dict) -> dict:
    """Fill in defaults so every key the generator reads exists."""
    p = _merge(DEFAULTS, project if isinstance(project, dict) else {})
    p["vlans"] = [_merge(VLAN_DEFAULTS, v) for v in p.get("vlans") or [] if isinstance(v, dict)]
    p["ports"] = [_merge(PORT_DEFAULTS, v) for v in p.get("ports") or [] if isinstance(v, dict)]
    p["lags"] = [_merge(LAG_DEFAULTS, v) for v in p.get("lags") or [] if isinstance(v, dict)]
    return p


def _s(value) -> str:
    return str(value if value is not None else "").strip()


def _list(value) -> list[str]:
    if isinstance(value, list):
        items = value
    else:
        items = re.split(r"[,\s]+", _s(value))
    return [_s(i) for i in items if _s(i)]


def _truthy(value) -> bool:
    return value is True or _s(value).lower() in ("1", "true", "yes", "on")


class Ctx:
    def __init__(self, project: dict):
        self.p = project
        self.cfg = Config()
        self.res = Result()
        self.known: dict[str, dict] = {}      # port name -> catalog entry
        self.used: dict[str, str] = {}        # port name -> label of what uses it
        self.vlan_by_name: dict[str, dict] = {}
        self.vlan_by_id: dict[int, dict] = {}
        self.access_ports: list[str] = []     # access-mode ports (logical: ge-0/0/1)
        self.edge_ports: list[str] = []
        self.trusted: dict[str, list[str]] = {}  # vlan -> ports with dhcp trust
        self.l3_networks: list = []           # (label, ip_interface)
        self.l3_ifaces: set[str] = set()      # logical interfaces with an address (for OSPF)
        self.policy_names: set[str] = set()
        self.asn = None
        self.router_id = None
        self.loopback_ip = None
        self.models: list = []
        self.row: str | None = None           # table row being checked, e.g. "ports.3"

    def at(self, table: str, item: dict | None) -> None:
        """Mark which table row the next errors belong to (None clears it).

        The page uses this to outline the row, and the field when one is named.
        """
        self.row = None
        if item is None:
            return
        rows = self.p
        for key in table.split("."):
            rows = rows.get(key) if isinstance(rows, dict) else None
        for i, r in enumerate(rows or []):
            if r is item:
                self.row = f"{table}.{i}"
                return

    def error(self, section: str, message: str, field: str | None = None) -> None:
        """Record an error. ``field`` is a key in the current row, or a full path outside tables."""
        msg = {"section": section, "message": message}
        if self.row:
            msg["row"] = self.row
        if field:
            msg["field"] = f"{self.row}.{field}" if self.row else field
        self.res.errors.append(msg)

    def warn(self, section: str, message: str) -> None:
        self.res.warnings.append({"section": section, "message": message})


def _addresses(ctx: Ctx, section: str, label: str, text) -> list:
    out = []
    for item in _list(text):
        try:
            iface = ipaddress.ip_interface(item)
        except ValueError:
            ctx.error(section, f"{label}: '{item}' is not an address with a prefix length (example 10.0.10.1/24).")
            continue
        if "/" not in item:
            ctx.error(section, f"{label}: '{item}' needs a prefix length (example {item}/24).")
            continue
        if iface.version == 4 and iface.network.prefixlen < 31 and iface.ip in (
                iface.network.network_address, iface.network.broadcast_address):
            ctx.error(section, f"{label}: {item} is the network or broadcast address of {iface.network}.")
            continue
        for other_label, other in ctx.l3_networks:
            if other.version == iface.version and other.network.overlaps(iface.network):
                ctx.warn(section, f"{label}: {iface.network} overlaps {other.network} on {other_label}.")
        ctx.l3_networks.append((label, iface))
        out.append(iface)
    return out


def _ip(ctx: Ctx, section: str, label: str, value: str, allow_net=False):
    try:
        return ipaddress.ip_network(value, strict=False) if allow_net else ipaddress.ip_address(value)
    except ValueError:
        ctx.error(section, f"{label}: '{value}' is not a valid {'network' if allow_net else 'IP address'}.")
        return None


def _family(addr) -> str:
    return "inet" if addr.version == 4 else "inet6"


# ----------------------------------------------------------------- sections
def _switch(ctx: Ctx) -> None:
    sw = ctx.p["switch"]
    members = sw.get("members") or []
    if not members:
        ctx.error("Switch", "Add at least one switch (member 0).")
    seen = set()
    for m in members:
        ctx.at("switch.members", m)
        try:
            fpc = int(m.get("fpc", 0))
        except (TypeError, ValueError):
            ctx.error("Switch", f"Member number '{m.get('fpc')}' must be a number from 0 to 9.", "fpc")
            continue
        if not 0 <= fpc <= 9 or fpc in seen:
            ctx.error("Switch", f"Member number {fpc} must be 0-9 and used once.", "fpc")
            continue
        seen.add(fpc)
        model = models.get(m.get("model", ""))
        if model:
            for port in model.ports(fpc):
                ctx.known[port["name"]] = port
        elif m.get("model") != models.CUSTOM:
            ctx.error("Switch", f"Unknown model '{m.get('model')}'.", "model")
    ctx.at("", None)
    try:
        for name in P.expand(sw.get("custom_ports", "")):
            ctx.known.setdefault(name, {"name": name, "kind": "access", "speed": "", "poe": False})
    except ValueError as exc:
        ctx.error("Switch", f"Custom ports: {exc}")

    if len(members) > 1:
        ctx.cfg.comment("Virtual Chassis")
        ctx.cfg.add(("system",), "commit synchronize")
        if len(members) == 2 and _truthy(sw.get("vc_no_split_detection")):
            ctx.cfg.add(("virtual-chassis",), "no-split-detection")
        if _truthy(sw.get("vc_preprovisioned")):
            ctx.cfg.add(("virtual-chassis",), "preprovisioned")
            for m in members:
                ctx.at("switch.members", m)
                serial = _s(m.get("serial"))
                if not serial:
                    ctx.error("Switch", f"Pre-provisioned Virtual Chassis needs the serial number of member {m.get('fpc')}.", "serial")
                    continue
                role = m.get("role") if m.get("role") in ("routing-engine", "line-card") else "line-card"
                path = ("virtual-chassis", f"member {int(m.get('fpc', 0))}")
                ctx.cfg.add(path, f"role {role}")
                ctx.cfg.add(path, f"serial-number {q(serial)}")
            ctx.at("", None)
            res = [m for m in members if m.get("role") == "routing-engine"]
            if len(res) > 2:
                ctx.error("Switch", "A Virtual Chassis has at most two routing-engine members.")


def _models(ctx: Ctx) -> list:
    return [models.get(m.get("model", "")) for m in ctx.p["switch"].get("members") or []
            if models.get(m.get("model", ""))]


def _system(ctx: Ctx) -> None:
    s, cfg = ctx.p["system"], ctx.cfg
    cfg.comment("System")
    host = _s(s.get("hostname"))
    if not host:
        ctx.error("System", "Host name is required.", "system.hostname")
    elif not HOSTNAME.match(host):
        ctx.error("System", f"Host name '{host}' may only use letters, digits and hyphens (max 63).", "system.hostname")
    else:
        cfg.add(("system",), f"host-name {host}")
    domain = _s(s.get("domain"))
    if domain:
        if DOMAIN.match(domain):
            cfg.add(("system",), f"domain-name {domain}")
        else:
            ctx.error("System", f"Domain '{domain}' is not a valid domain name.", "system.domain")
    tz = _s(s.get("timezone"))
    if tz and tz != "UTC":
        if re.match(r"^[A-Za-z0-9_+\-/]+$", tz):
            cfg.add(("system",), f"time-zone {tz}")
        else:
            ctx.error("System", f"Time zone '{tz}' is not valid.", "system.timezone")
    for ns in _list(s.get("name_servers")):
        if _ip(ctx, "System", "DNS server", ns):
            cfg.add(("system", "name-server"), ns)
    search = [d for d in _list(s.get("domain_search")) if DOMAIN.match(d) or ctx.warn("System", f"Skipped search domain '{d}'.")]
    if search:
        cfg.add_list(("system",), "domain-search", search)

    ntp = [n for n in s.get("ntp_servers") or [] if _s(n.get("address"))]
    if not ntp:
        ctx.warn("System", "No NTP server: logs and certificates need the right time.")
    for n in ntp:
        addr = _s(n.get("address"))
        if not (re.match(r"^[A-Za-z0-9.-]+$", addr) or _ip(ctx, "System", "NTP server", addr)):
            continue
        if not re.match(r"^[0-9a-fA-F:.]+$", addr) and not _list(s.get("name_servers")):
            ctx.warn("System", f"NTP server {addr} is a name, so the switch needs a DNS server.")
        cfg.add(("system", "ntp"), f"server {addr}" + (" prefer" if _truthy(n.get("prefer")) else ""))
    src = _s(s.get("ntp_source"))
    if src and _ip(ctx, "System", "NTP source address", src):
        cfg.add(("system", "ntp"), f"source-address {src}")

    banner = s.get("banner") or ""
    if banner.strip():
        cfg.add(("system", "login"), f"message {q(banner.rstrip())}")
    if _truthy(s.get("auto_snapshot")):
        cfg.add(("system",), "auto-snapshot")

    # Management port
    mif = _s(s.get("mgmt_interface")) or (_models(ctx)[0].mgmt if _models(ctx) else "me0")
    addrs = _addresses(ctx, "System", f"Management ({mif})", s.get("mgmt_address"))
    if addrs:
        cfg.comment("Management port")
        for a in addrs:
            cfg.add(("interfaces", mif, "unit 0", f"family {_family(a)}"), f"address {a.with_prefixlen}")
        gw = _s(s.get("mgmt_gateway"))
        if gw and (gw_ip := _ip(ctx, "System", "Management gateway", gw)):
            if not any(gw_ip in a.network for a in addrs if a.version == gw_ip.version):
                ctx.warn("System", f"Management gateway {gw} is not in the management subnet.")
            if _truthy(s.get("mgmt_vrf")):
                cfg.add(("system",), "management-instance")
                cfg.add(("routing-instances", "mgmt_junos", "routing-options", "static"),
                        f"route {'0.0.0.0/0' if gw_ip.version == 4 else '::/0'} next-hop {gw}")
            else:
                ctx.mgmt_gateway = gw  # added as a default route unless the user has one
    elif _s(s.get("mgmt_gateway")):
        ctx.warn("System", "Management gateway is set but the management port has no address.")
    if not addrs and _truthy(s.get("ignore_mgmt_alarm")):
        cfg.add(("chassis", "alarm", "management-ethernet"), "link-down ignore")


def _password(ctx: Ctx, section: str, label: str, value: str, key: str) -> str | None:
    value = _s(value)
    if not value:
        return None
    if is_hashed(value):
        return value
    if len(value) < 6:
        ctx.error(section, f"{label}: Junos needs at least 6 characters.", key if not ctx.row else key.rsplit(".", 1)[-1])
        return None
    if value.isalpha() or value.isdigit():
        ctx.warn(section, f"{label}: Junos may refuse a password without a mix of letters and digits or symbols.")
    hashed = sha512_crypt(value)
    ctx.res.hashed[key] = hashed
    return hashed


def _ssh_keys(ctx: Ctx, section: str, label: str, path: tuple, text: str) -> None:
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        kind = SSH_KEY_TYPES.get(line.split()[0])
        if not kind:
            ctx.error(section, f"{label}: SSH key must start with ssh-rsa, ssh-ed25519 or ecdsa-sha2-...")
            continue
        ctx.cfg.add(path, f"{kind} {q(line)}")


def _access(ctx: Ctx) -> None:
    a, cfg = ctx.p["access"], ctx.cfg
    cfg.comment("Accounts and remote access")
    root = _password(ctx, "Access", "Root password", a.get("root_password"), "access.root_password")
    if root:
        cfg.add(("system", "root-authentication"), f"encrypted-password {q(root)}")
    elif not _s(a.get("root_ssh_key")):
        ctx.error("Access", "A root password is required, or Junos refuses to commit.", "access.root_password")
    _ssh_keys(ctx, "Access", "Root", ("system", "root-authentication"), a.get("root_ssh_key", ""))

    names = set()
    for i, u in enumerate(a.get("users") or []):
        ctx.at("access.users", u)
        name = _s(u.get("name"))
        if not name:
            continue
        if not USERNAME.match(name) or name in ("root",):
            ctx.error("Access", f"User '{name}': use lower-case letters, digits, '.', '_' or '-' (not root).", "name")
            continue
        if name in names:
            ctx.error("Access", f"User '{name}' is listed twice.", "name")
            continue
        names.add(name)
        cls = u.get("class") if u.get("class") in CLASSES else "read-only"
        path = ("system", "login", f"user {name}")
        if _s(u.get("full_name")):
            cfg.add(path, f"full-name {q(_s(u.get('full_name')))}")
        cfg.add(path, f"class {cls}")
        hashed = _password(ctx, "Access", f"User {name}", u.get("password"), f"access.users.{i}.password")
        if hashed:
            cfg.add((*path, "authentication"), f"encrypted-password {q(hashed)}")
        _ssh_keys(ctx, "Access", f"User {name}", (*path, "authentication"), u.get("ssh_keys", ""))
        if not hashed and not _s(u.get("ssh_keys")):
            ctx.error("Access", f"User '{name}' needs a password or an SSH key.", "password")
    ctx.at("", None)
    if not any(u.get("class") == "super-user" and _s(u.get("name")) for u in a.get("users") or []):
        ctx.warn("Access", "No super-user account: you'd have to sign in as root to manage the switch.")

    ssh = ("system", "services", "ssh")
    cfg.add(("system", "services"), "ssh")
    root_login = a.get("ssh_root_login") if a.get("ssh_root_login") in ("deny", "allow", "deny-password") else "deny"
    cfg.add(ssh, f"root-login {root_login}")
    cfg.add(ssh, "protocol-version v2")
    for key, stmt, top in (("ssh_connection_limit", "connection-limit", 250), ("ssh_rate_limit", "rate-limit", 250)):
        val = _s(a.get(key))
        if val:
            if val.isdigit() and 1 <= int(val) <= top:
                cfg.add(ssh, f"{stmt} {val}")
            else:
                ctx.error("Access", f"SSH {stmt} must be a number from 1 to {top}.")
    if _truthy(a.get("netconf")):
        cfg.add(("system", "services", "netconf", "ssh"), "port 830")
    if _truthy(a.get("web")):
        cfg.add(("system", "services", "web-management", "https"), "system-generated-certificate")
    if _truthy(a.get("retry_options")):
        r = ("system", "login", "retry-options")
        cfg.add(r, "tries-before-disconnect 3")
        cfg.add(r, "backoff-threshold 2")
        cfg.add(r, "lockout-period 5")


def _snmp(ctx: Ctx) -> None:
    s, cfg = ctx.p["snmp"], ctx.cfg
    comms = [c for c in s.get("communities") or [] if _s(c.get("name"))]
    users = [u for u in s.get("v3_users") or [] if _s(u.get("name"))]
    if not (comms or users or _s(s.get("location")) or _s(s.get("contact"))):
        return
    cfg.comment("SNMP")
    for key in ("location", "contact"):
        if _s(s.get(key)):
            cfg.add(("snmp",), f"{key} {q(_s(s.get(key)))}")
    for c in comms:
        ctx.at("snmp.communities", c)
        name = _s(c.get("name"))
        if name.lower() in ("public", "private"):
            ctx.warn("SNMP", f"Community '{name}' is a well-known default; pick something harder to guess.")
        path = ("snmp", f"community {q(name)}")
        cfg.add(path, f"authorization {'read-write' if c.get('access') == 'read-write' else 'read-only'}")
        clients = _list(c.get("clients"))
        if not clients:
            ctx.warn("SNMP", f"Community '{name}' accepts any source address. Add the allowed clients.")
        for cl in clients:
            if _ip(ctx, "SNMP", f"Community {name} client", cl, allow_net=True):
                cfg.add((*path, "clients"), cl)
        if clients:
            cfg.add((*path, "clients"), "0.0.0.0/0 restrict")
    ctx.at("", None)
    if users:
        cfg.add(("snmp", "view all"), "oid .1 include")
    for u in users:
        ctx.at("snmp.v3_users", u)
        name = _s(u.get("name"))
        user_path = ("snmp", "v3", "usm", "local-engine", f"user {q(name)}")
        auth = SNMP_AUTH.get(u.get("auth") or "sha")
        apw, ppw = _s(u.get("auth_password")), _s(u.get("priv_password"))
        if len(apw) < 8:
            ctx.error("SNMP", f"SNMPv3 user {name}: the authentication password needs at least 8 characters.", "auth_password")
            continue
        cfg.add((*user_path, auth), f"authentication-password {q(apw)}")
        level = "authentication"
        priv = SNMP_PRIV.get(u.get("priv") or "")
        if priv:
            if len(ppw) < 8:
                ctx.error("SNMP", f"SNMPv3 user {name}: the privacy password needs at least 8 characters.", "priv_password")
            else:
                cfg.add((*user_path, priv), f"privacy-password {q(ppw)}")
                level = "privacy"
        else:
            ctx.warn("SNMP", f"SNMPv3 user {name} has no privacy (encryption); polls are readable on the wire.")
        group = f"{name}-group"
        cfg.add(("snmp", "v3", "vacm", "security-to-group", "security-model usm", f"security-name {q(name)}"),
                f"group {q(group)}")
        cfg.add(("snmp", "v3", "vacm", "access", f"group {q(group)}", "default-context-prefix",
                 "security-model usm", f"security-level {level}"), "read-view all")
    ctx.at("", None)
    targets = _list(s.get("trap_targets"))
    if targets:
        tg = ("snmp", "trap-group traps")
        cfg.add(tg, "version v2")
        for t in targets:
            if _ip(ctx, "SNMP", "Trap target", t):
                cfg.add((*tg, "targets"), t)
        if not comms:
            ctx.warn("SNMP", "Traps use the community name 'traps'; add a community so the receiver matches it.")


def _syslog(ctx: Ctx) -> None:
    s, cfg = ctx.p["syslog"], ctx.cfg
    cfg.comment("Logging")
    level = s.get("local_level") if s.get("local_level") in LEVELS else "notice"
    cfg.add(("system", "syslog", "file messages"), f"any {level}")
    cfg.add(("system", "syslog", "file messages"), "authorization info")
    if _truthy(s.get("log_commands")):
        cfg.add(("system", "syslog", "file interactive-commands"), "interactive-commands any")
    for h in s.get("hosts") or []:
        ctx.at("syslog.hosts", h)
        addr = _s(h.get("address"))
        if not addr or not _ip(ctx, "Logging", "Syslog server", addr):
            continue
        path = ("system", "syslog", f"host {addr}")
        fac = h.get("facility") if h.get("facility") in FACILITIES else "any"
        lvl = h.get("level") if h.get("level") in LEVELS else "info"
        cfg.add(path, f"{fac} {lvl}")
        port = _s(h.get("port"))
        if port and port != "514":
            if port.isdigit() and 1 <= int(port) <= 65535:
                cfg.add(path, f"port {port}")
            else:
                ctx.error("Logging", f"Syslog port '{port}' is not valid.", "port")
    ctx.at("", None)
    src = _s(s.get("source_address"))
    if src and _ip(ctx, "Logging", "Syslog source address", src):
        cfg.add(("system", "syslog"), f"source-address {src}")


def _vlans(ctx: Ctx) -> None:
    cfg = ctx.cfg
    vlans = [v for v in ctx.p["vlans"] if _s(v.get("name")) or _s(v.get("id"))]
    if not vlans:
        ctx.warn("VLANs", "No VLANs yet: access ports will land in the default VLAN.")
        return
    cfg.comment("VLANs")
    for v in vlans:
        ctx.at("vlans", v)
        name, vid = _s(v.get("name")), _s(v.get("id"))
        if not NAME.match(name):
            ctx.error("VLANs", f"VLAN name '{name}' must start with a letter and use letters, digits, '-', '_' or '.'.", "name")
            continue
        if not vid.isdigit() or not 1 <= int(vid) <= 4094:
            ctx.error("VLANs", f"VLAN {name}: ID must be 1-4094.", "id")
            continue
        vid_n = int(vid)
        if name.lower() in {n.lower() for n in ctx.vlan_by_name}:
            ctx.error("VLANs", f"VLAN name '{name}' is used twice.", "name")
            continue
        if vid_n in ctx.vlan_by_id:
            ctx.error("VLANs", f"VLAN ID {vid_n} is used by both {ctx.vlan_by_id[vid_n]['name']} and {name}.", "id")
            continue
        ctx.vlan_by_name[name] = v
        ctx.vlan_by_id[vid_n] = v
        path = ("vlans", name)
        if _s(v.get("description")):
            cfg.add(path, f"description {q(_s(v.get('description')))}")
        cfg.add(path, f"vlan-id {vid_n}")
        addrs = _addresses(ctx, "VLANs", f"VLAN {name} IRB", v.get("irb"))
        if addrs:
            ctx.l3_ifaces.add(f"irb.{vid_n}")
            cfg.add(path, f"l3-interface irb.{vid_n}")
            for a in addrs:
                ctx.cfg.add(("interfaces", "irb", f"unit {vid_n}", f"family {_family(a)}"),
                            f"address {a.with_prefixlen}")
        elif _truthy(v.get("dhcp_relay")):
            ctx.error("VLANs", f"VLAN {name}: DHCP relay needs an IRB address.", "irb")
        if _truthy(v.get("snooping")) or _truthy(v.get("dai")) or _truthy(v.get("ipsg")):
            sec = (*path, "forwarding-options")
            cfg.add(sec, "dhcp-security")
            if _truthy(v.get("dai")):
                cfg.add((*sec, "dhcp-security"), "arp-inspection")
            if _truthy(v.get("ipsg")):
                cfg.add((*sec, "dhcp-security"), "ip-source-guard")


def _vlan_name(ctx: Ctx, section: str, label: str, ref: str, field: str | None = None) -> str | None:
    ref = _s(ref)
    if not ref:
        return None
    if ref in ctx.vlan_by_name:
        return ref
    for name in ctx.vlan_by_name:
        if name.lower() == ref.lower():
            return name
    if ref.isdigit() and int(ref) in ctx.vlan_by_id:
        return ctx.vlan_by_id[int(ref)]["name"]
    ctx.error(section, f"{label}: VLAN '{ref}' is not defined on the VLANs tab.", field)
    return None


def _claim(ctx: Ctx, section: str, label: str, names: list[str]) -> list[str]:
    ok = []
    for name in names:
        if name in ctx.used:
            ctx.error(section, f"{label}: {name} is already used by {ctx.used[name]}.", "ports" if section == "Ports" else "members")
            continue
        info = ctx.known.get(name)
        if info is None:
            alt = name.replace("ge-", "xe-", 1) if name.startswith("ge-") else None
            if alt and ctx.known.get(alt, {}).get("kind") in ("uplink", "module"):
                info = ctx.known[alt]  # 1G optic in a 10G uplink
            elif ctx.known:
                ctx.warn(section, f"{label}: {name} is not a port on the selected model(s).")
        elif info["kind"] == "vcp":
            ctx.warn(section, f"{label}: {name} is a Virtual Chassis port by default. Run "
                     f"'request virtual-chassis vc-port delete pic-slot {P.split(name)[2]} port {P.split(name)[3]}"
                     f"{' member ' + str(P.split(name)[1]) if P.split(name)[1] else ''}' first.")
        elif info["kind"] == "module":
            ctx.warn(section, f"{label}: {name} only exists with the optional uplink module installed.")
        ctx.used[name] = label
        ok.append(name)
    return ok


def _iface_settings(ctx: Ctx, section: str, label: str, base: tuple, row: dict, phys: list[str]) -> None:
    """Mode, VLANs, addresses and per-port features for one port group or LAG.

    ``base`` is the interface path (an interface or interface-range);
    ``phys`` the logical ports the per-port statements are written for.
    """
    cfg = ctx.cfg
    mode = row.get("mode") or "access"
    desc = _s(row.get("description"))
    if desc:
        cfg.add(base, f"description {q(desc)}")
    if mode == "disabled":
        cfg.add(base, "disable")
        return
    mtu = _s(row.get("mtu"))
    if mtu:
        if mtu.isdigit() and 256 <= int(mtu) <= 9216:
            cfg.add(base, f"mtu {mtu}")
        else:
            ctx.error(section, f"{label}: MTU must be 256-9216.", "mtu")
    speed = _s(row.get("speed")).lower()
    if speed and not base[1].startswith("ae"):
        if speed in SPEEDS:
            cfg.add((*base, "ether-options"), f"speed {speed}")
        else:
            ctx.error(section, f"{label}: speed must be one of {', '.join(SPEEDS)}.", "speed")
    unit = (*base, "unit 0")
    sw = (*unit, "family ethernet-switching")
    sc = _truthy(ctx.p["services"].get("storm_control"))
    sc_scope = ctx.p["services"].get("storm_scope", "access")

    if mode == "access":
        cfg.add(sw, "interface-mode access")
        vlan = _vlan_name(ctx, section, label, row.get("vlan"), "vlan")
        if vlan:
            cfg.add_list((*sw, "vlan"), "members", [vlan])
        elif not _s(row.get("vlan")):
            ctx.warn(section, f"{label}: no access VLAN, so the port uses the default VLAN.")
        voice = _vlan_name(ctx, section, f"{label} voice", row.get("voice"), "voice")
        if not voice and not _s(row.get("voice")):
            # A VLAN ticked as "voice VLAN" is offered to every access port that has none of its own.
            voice = next((v["name"] for v in ctx.p["vlans"] if _truthy(v.get("voice")) and v["name"] != vlan), "")
        if voice:
            if not _truthy(ctx.p["services"].get("lldp_med")):
                ctx.warn(section, f"{label}: turn on LLDP-MED (Services tab) so phones learn voice VLAN {voice} by themselves.")
            if voice == vlan:
                ctx.error(section, f"{label}: the voice VLAN must differ from the data VLAN.", "voice")
            else:
                for port in phys:
                    cfg.add(("switch-options", "voip", f"interface {port}.0"), f"vlan {voice}")
                    cfg.add(("switch-options", "voip", f"interface {port}.0"), "forwarding-class expedited-forwarding")
        if sc:
            cfg.add(sw, "storm-control storm-default")
        ctx.access_ports.extend(phys)
        if _truthy(row.get("edge")):
            ctx.edge_ports.extend(phys)
        limit = _s(row.get("mac_limit"))
        if limit:
            if limit.isdigit() and 1 <= int(limit) <= 16383:
                for port in phys:
                    path = ("switch-options", f"interface {port}.0")
                    cfg.add(path, f"interface-mac-limit {limit}")
                    action = _s(row.get("mac_action")) or "drop"
                    cfg.add((*path, "interface-mac-limit"), f"packet-action {action if action in SEC.MAC_ACTIONS else 'drop'}")
            else:
                ctx.error(section, f"{label}: MAC limit must be 1-16383.", "mac_limit")
        if _truthy(row.get("sticky")):
            for port in phys:
                cfg.add(("switch-options", f"interface {port}.0"), "persistent-learning")
        if _truthy(row.get("dhcp_trusted")) and vlan:
            ctx.trusted.setdefault(vlan, []).extend(phys)
    elif mode == "trunk":
        cfg.add(sw, "interface-mode trunk")
        refs = _list(row.get("vlans"))
        if not refs:
            ctx.error(section, f"{label}: a trunk needs at least one VLAN (or 'all').", "vlans")
        members = []
        if any(r.lower() == "all" for r in refs):
            members = ["all"]
        else:
            members = [n for r in refs if (n := _vlan_name(ctx, section, label, r, "vlans"))]
        native = _vlan_name(ctx, section, f"{label} native", row.get("native"), "native")
        if native:
            nid = int(ctx.vlan_by_name[native]["id"])
            cfg.add(base, f"native-vlan-id {nid}")
            if members != ["all"] and native not in members:
                members.append(native)  # ELS needs the native VLAN in the member list too
        if members:
            cfg.add_list((*sw, "vlan"), "members", members)
        if sc and sc_scope == "all":
            cfg.add(sw, "storm-control storm-default")
        _vlan_translate(ctx, section, label, sw, row, members)
        if _s(row.get("voice")):
            ctx.warn(section, f"{label}: voice VLAN only applies to access ports; ignored on a trunk.")
    elif mode == "routed":
        addrs = _addresses(ctx, section, label, row.get("address"))
        if not addrs:
            ctx.error(section, f"{label}: a routed port needs an IP address with prefix (example 10.0.0.1/30).", "address")
        if len(phys) > 1 and base[1] == "interface-range":
            ctx.error(section, f"{label}: a routed port group can only hold one port (each needs its own address).")
        if addrs and base[1] != "interface-range":
            ctx.l3_ifaces.add(f"{base[1]}.0")
        for a in addrs:
            cfg.add((*unit, f"family {_family(a)}"), f"address {a.with_prefixlen}")
    else:
        ctx.error(section, f"{label}: unknown mode '{mode}'.", "mode")
        return
    if mode != "trunk" and _s(row.get("vlan_translate")):
        ctx.error(section, f"{label}: VLAN translation only works on trunk ports.", "vlan_translate")
    if mode in ("access", "trunk"):
        SEC.port(ctx, section, label, mode, base, phys, row)

    if mode != "routed":
        for key in ("address",):
            if _s(row.get(key)):
                ctx.warn(section, f"{label}: the IP address is only used in routed mode. Use a VLAN IRB for L2 ports.")
    poe = _s(row.get("poe"))
    if poe and not base[1].startswith("ae"):
        for port in phys:
            info = ctx.known.get(port)
            if info is not None and not info.get("poe"):
                ctx.warn(section, f"{label}: {port} has no PoE; PoE setting skipped.")
                continue
            if poe == "off":
                ctx.cfg.add(("poe", f"interface {port}"), "disable")
            elif poe in ("high", "low"):
                ctx.cfg.add(("poe", f"interface {port}"), f"priority {poe}")
    pmax = _s(row.get("poe_max"))
    if pmax and poe != "off" and not base[1].startswith("ae"):
        try:
            watts = float(pmax)
        except ValueError:
            watts = -1
        if not 0 < watts <= 90:
            ctx.error(section, f"{label}: maximum PoE power must be 0.1-90 watts.", "poe_max")
        else:
            for port in phys:
                info = ctx.known.get(port)
                if info is None or info.get("poe"):
                    ctx.cfg.add(("poe", f"interface {port}"), f"maximum-power {pmax}")


# EX families that cannot rewrite VLAN tags on a port.
NO_VLAN_REWRITE = ("EX2300", "EX3400")


def _vlan_translate(ctx: Ctx, section: str, label: str, sw: tuple, row: dict, members: list) -> None:
    """``vlan-rewrite translate`` on a trunk: frames tagged with the wire VLAN
    arrive in the switch VLAN, and leave tagged with the wire VLAN again."""
    spec = _s(row.get("vlan_translate"))
    if not spec:
        return
    try:
        pairs = P.translations(spec)
    except ValueError as exc:
        ctx.error(section, f"{label}: VLAN translation: {exc}", "vlan_translate")
        return
    bad = sorted({m.family for m in ctx.models if m.family in NO_VLAN_REWRITE})
    if bad:
        ctx.warn(section, f"{label}: {' and '.join(bad)} cannot translate VLANs (vlan-rewrite); "
                          "use an EX4100, EX4300 or EX4400 for this port.")
    for wire, local in pairs:
        if wire in ctx.vlan_by_id:
            ctx.error(section, f"{label}: wire VLAN {wire} is also a VLAN on this switch; "
                               "pick a wire VLAN that is not on the VLANs tab.", "vlan_translate")
            continue
        vlan = ctx.vlan_by_id.get(local)
        if vlan is None:
            ctx.error(section, f"{label}: switch VLAN {local} is not on the VLANs tab.", "vlan_translate")
            continue
        if members != ["all"] and vlan["name"] not in members:
            ctx.warn(section, f"{label}: VLAN {vlan['name']} ({local}) is translated but not in the trunk's VLAN list; "
                              "added it.")
            members.append(vlan["name"])
            ctx.cfg.add_list((*sw, "vlan"), "members", [vlan["name"]])
        ctx.cfg.add(sw, f"vlan-rewrite translate {wire} {local}")


def _range_name(row: dict, index: int) -> str:
    name = re.sub(r"[^A-Za-z0-9_-]+", "-", _s(row.get("name"))).strip("-")
    return (name or f"PORTS-{index + 1}")[:60]


def _ports(ctx: Ctx) -> None:
    rows = [r for r in ctx.p["ports"] if _s(r.get("ports"))]
    if not rows:
        return
    use_ranges = _truthy(ctx.p["services"].get("use_ranges"))
    ctx.cfg.comment("Switch ports")
    range_names = set()
    for i, row in enumerate(rows):
        ctx.at("ports", row)
        label = _s(row.get("name")) or f"Port group {i + 1}"
        try:
            names = P.expand(row.get("ports"))
        except ValueError as exc:
            ctx.error("Ports", f"{label}: {exc}", "ports")
            continue
        names = _claim(ctx, "Ports", label, names)
        if not names:
            continue
        if use_ranges and len(names) > 1 and row.get("mode") != "routed":
            rname = _range_name(row, i)
            while rname in range_names:
                rname += "-x"
            range_names.add(rname)
            base = ("interfaces", "interface-range", rname)
            for first, last in P.runs(names):
                if first == last:
                    ctx.cfg.add(base, f"member {first}")
                else:
                    ctx.cfg.add(base, f"member-range {first} to {last}")
            _iface_settings(ctx, "Ports", label, base, row, names)
        else:
            if len(names) > 1 and row.get("mode") == "routed":
                ctx.error("Ports", f"{label}: a routed port group can only hold one port (each needs its own address).")
                continue
            for port in names:
                _iface_settings(ctx, "Ports", label, ("interfaces", port), row, [port])
        for port in names:
            mode_ = row.get("mode") or "access"
            voice_ = mode_ == "access" and (bool(_s(row.get("voice"))) or any(
                _truthy(v.get("voice")) and v["name"] != _s(row.get("vlan")) for v in ctx.p["vlans"]))
            ctx.res.ports[port] = {"use": mode_, "label": label, "voice": voice_, "role": _s(row.get("role"))}
    ctx.at("", None)


def _lags(ctx: Ctx) -> None:
    lags = [r for r in ctx.p["lags"] if _s(r.get("name")) or _s(r.get("members"))]
    if not lags:
        return
    ctx.cfg.comment("Link aggregation (LACP)")
    highest = -1
    seen = set()
    for row in lags:
        ctx.at("lags", row)
        name = _s(row.get("name"))
        label = f"LAG {name or '?'}"
        if not P.is_ae(name) or int(name[2:]) > 127:
            ctx.error("LAGs", f"LAG name '{name}' must be ae0 to ae127.", "name")
            continue
        if name in seen:
            ctx.error("LAGs", f"{name} is listed twice.", "name")
            continue
        seen.add(name)
        highest = max(highest, int(name[2:]))
        try:
            members = P.expand(row.get("members"))
        except ValueError as exc:
            ctx.error("LAGs", f"{label}: {exc}", "members")
            continue
        members = _claim(ctx, "LAGs", label, members)
        if len(members) < 1:
            ctx.error("LAGs", f"{label}: add member ports.", "members")
            continue
        if len(members) == 1:
            ctx.warn("LAGs", f"{label}: only one member port, so there's no redundancy.")
        speeds = {ctx.known.get(m, {}).get("speed") for m in members if m in ctx.known}
        if len(speeds) > 1:
            ctx.warn("LAGs", f"{label}: members have different speeds ({', '.join(sorted(s for s in speeds if s))}).")
        for m in members:
            ctx.cfg.add(("interfaces", m, "ether-options"), f"802.3ad {name}")
            ctx.res.ports[m] = {"use": "lag", "label": name}
        opts = ("interfaces", name, "aggregated-ether-options")
        lacp = row.get("lacp") if row.get("lacp") in ("active", "passive", "static") else "active"
        if lacp != "static":
            ctx.cfg.add((*opts, "lacp"), lacp)
            if _truthy(row.get("lacp_fast")):
                ctx.cfg.add((*opts, "lacp"), "periodic fast")
        else:
            ctx.warn("LAGs", f"{label}: static LAG without LACP can't detect a mis-cabled member.")
        ml = _s(row.get("min_links"))
        if ml:
            if ml.isdigit() and 1 <= int(ml) <= len(members):
                ctx.cfg.add(opts, f"minimum-links {ml}")
            else:
                ctx.error("LAGs", f"{label}: minimum links must be 1-{len(members)}.", "min_links")
        R.esi_lag(ctx, row, name, label)
        _iface_settings(ctx, "LAGs", label, ("interfaces", name), row, [name])
    ctx.at("", None)
    if highest >= 0:
        ctx.cfg.add(("chassis", "aggregated-devices", "ethernet"), f"device-count {highest + 1}")


def _routing(ctx: Ctx) -> None:
    r, cfg = ctx.p["routing"], ctx.cfg
    routes = [x for x in r.get("static") or [] if _s(x.get("prefix"))]
    gw = getattr(ctx, "mgmt_gateway", None)
    has_default = any(_s(x.get("prefix")) in ("0.0.0.0/0", "default") for x in routes)
    if gw and not has_default:
        routes.append({"prefix": "0.0.0.0/0", "next_hop": gw, "preference": ""})
    elif gw and has_default:
        ctx.warn("System", "You have a default route and a management gateway. Tick 'management VRF' to "
                           "keep management traffic separate, or the management gateway is ignored.")
    if routes:
        cfg.comment("Static routes")
    for x in routes:
        ctx.at("routing.static", x)
        prefix = _s(x.get("prefix"))
        if prefix == "default":
            prefix = "0.0.0.0/0"
        net = _ip(ctx, "Routing", "Route", prefix, allow_net=True)
        if not net:
            continue
        nh = _s(x.get("next_hop"))
        pref = _s(x.get("preference"))
        if nh in ("discard", "reject"):
            target = nh
        else:
            nh_ip = _ip(ctx, "Routing", f"Route {net} next hop", nh) if nh else None
            if not nh_ip:
                if not nh:
                    ctx.error("Routing", f"Route {net}: add a next hop (an IP, 'discard' or 'reject').", "next_hop")
                continue
            if not any(nh_ip in iface.network for _, iface in ctx.l3_networks if iface.version == nh_ip.version):
                ctx.warn("Routing", f"Route {net}: next hop {nh} is not in any subnet on this switch.")
            target = f"next-hop {nh}"
        base = ("routing-options", "static") if net.version == 4 else ("routing-options", "rib inet6.0", "static")
        if pref:
            if pref.isdigit() and 0 <= int(pref) <= 255:
                cfg.add((*base, f"route {net}"), target)
                cfg.add((*base, f"route {net}"), f"preference {pref}")
            else:
                ctx.error("Routing", f"Route {net}: preference must be 0-255.", "preference")
        else:
            cfg.add(base, f"route {net} {target}")

    ctx.at("", None)
    servers = _list(r.get("dhcp_relay_servers"))
    relay_vlans = [v for v in ctx.vlan_by_name.values() if _truthy(v.get("dhcp_relay")) and _s(v.get("irb"))]
    if relay_vlans and not servers:
        ctx.error("Routing", "VLANs use DHCP relay but no DHCP server is set on the Routing tab.")
    if servers and relay_vlans:
        cfg.comment("DHCP relay")
        dr = ("forwarding-options", "dhcp-relay")
        for sv in servers:
            if _ip(ctx, "Routing", "DHCP server", sv):
                cfg.add((*dr, "server-group DHCP-SERVERS"), sv)
        cfg.add((*dr, "group RELAY"), "active-server-group DHCP-SERVERS")
        for v in relay_vlans:
            cfg.add((*dr, "group RELAY"), f"interface irb.{int(v['id'])}")


def _services(ctx: Ctx) -> None:
    s, cfg = ctx.p["services"], ctx.cfg
    cfg.comment("Switching services")
    if _truthy(s.get("lldp")):
        cfg.add(("protocols", "lldp"), "interface all")
    if _truthy(s.get("lldp_med")):
        cfg.add(("protocols", "lldp-med"), "interface all")
    stp = s.get("stp")
    if stp == "rstp":
        cfg.add(("protocols", "rstp"), "interface all")
        prio = _s(s.get("bridge_priority")).lower()
        if prio:
            if prio in PRIORITIES:
                cfg.add(("protocols", "rstp"), f"bridge-priority {prio}")
            else:
                ctx.error("Services", "Bridge priority must be 0, 4k, 8k ... 60k (steps of 4k).", "services.bridge_priority")
        for port in sorted(set(ctx.edge_ports), key=P.sort_key):
            cfg.add(("protocols", "rstp", f"interface {port}"), "edge")
        if _truthy(s.get("bpdu_block_on_edge")):
            cfg.add(("protocols", "rstp"), "bpdu-block-on-edge")
    elif stp == "none":
        ctx.warn("Services", "Spanning tree is off: a cabling loop will take the network down.")
    if _truthy(s.get("igmp_snooping")):
        cfg.add(("protocols", "igmp-snooping"), "vlan all")
    if _truthy(s.get("storm_control")):
        pct = _s(s.get("storm_percent")) or "5"
        if pct.isdigit() and 1 <= int(pct) <= 100:
            cfg.add(("forwarding-options", "storm-control-profiles storm-default", "all"), f"bandwidth-percentage {pct}")
        else:
            ctx.error("Services", "Storm control percentage must be 1-100.", "services.storm_percent")
    poe_models = any(m.poe for m in _models(ctx))
    if _truthy(s.get("poe_all")) and poe_models:
        cfg.add(("poe",), "interface all")
    if poe_models:
        mgmt = _s(s.get("poe_management"))
        if mgmt in ("class", "static"):
            cfg.add(("poe",), f"management {mgmt}")
        gb = _s(s.get("poe_guard_band"))
        if gb:
            if gb.isdigit() and 0 <= int(gb) <= 19:
                cfg.add(("poe",), f"guard-band {gb}")
            else:
                ctx.error("Services", "PoE guard band must be 0-19 watts.", "services.poe_guard_band")
        fpcs = sorted({int(m.get("fpc", 0)) for m in ctx.p["switch"].get("members") or []
                       if str(m.get("fpc", 0)).isdigit() and (models.get(m.get("model", "")) or models.Model("", "", ())).poe})
        for fpc in fpcs:
            if _truthy(s.get("poe_fast")):
                cfg.add(("poe", f"fpc {fpc}"), "fast-poe")
            if _truthy(s.get("poe_perpetual")):
                cfg.add(("poe", f"fpc {fpc}"), "perpetual-poe")
    elif any(_truthy(s.get(k)) for k in ("poe_fast", "poe_perpetual")) or _s(s.get("poe_guard_band")):
        ctx.warn("Services", "PoE settings skipped: no member of this switch has PoE.")
    for vlan, ports in ctx.trusted.items():
        v = ctx.vlan_by_name.get(vlan)
        if v and (_truthy(v.get("snooping")) or _truthy(v.get("dai")) or _truthy(v.get("ipsg"))):
            grp = ("vlans", vlan, "forwarding-options", "dhcp-security", "group trusted")
            cfg.add((*grp, "overrides"), "trusted")
            for port in ports:
                cfg.add(grp, f"interface {port}.0")
    if any(_truthy(v.get("snooping")) or _truthy(v.get("dai")) for v in ctx.vlan_by_name.values()):
        ctx.warn("Services", "DHCP snooping is on: trunk and LAG ports are trusted, access ports are not. "
                             "Tick 'DHCP trusted' on an access port that has a DHCP server behind it.")

    if _truthy(s.get("disable_unused")) and ctx.known:
        unused = [n for n, info in ctx.known.items() if n not in ctx.used and info["kind"] in ("access", "uplink")]
        if unused:
            base = ("interfaces", "interface-range", "UNUSED")
            for first, last in P.runs(unused):
                cfg.add(base, f"member {first}" if first == last else f"member-range {first} to {last}")
            cfg.add(base, f"description {q('Unused - disabled')}")
            cfg.add(base, "disable")
            for n in unused:
                ctx.res.ports.setdefault(n, {"use": "disabled", "label": "Unused"})


# ----------------------------------------------------------------- entry
def header(project: dict) -> list[str]:
    name = _s(project.get("name")) or _s(project.get("system", {}).get("hostname")) or "switch"
    members = ", ".join(f"{m.get('model')} (member {m.get('fpc', 0)})" for m in project["switch"].get("members") or [])
    return [f"Juniper EX configuration for {name}", f"Hardware: {members}",
            f"Made by Multi-Vendor Switch Config Builder {__version__}. Review before you commit."]


def build(project: dict) -> Result:
    vendor = vendors.get((project or {}).get("vendor") if isinstance(project, dict) else None)
    if vendor.key == "arista":
        from . import eos
        return eos.build(project)
    if vendor.key != "juniper":
        res = Result()
        res.errors.append({"section": "Switch", "message": f"{vendor.name} ({vendor.os}) configs are not ready yet."})
        return res
    p = normalize(project)
    ctx = Ctx(p)
    for i, title in enumerate(header(p)):
        ctx.cfg.comment(title, gap=i == 0)
    if _truthy(p["services"].get("delete_first")):
        ctx.cfg.comment("Start from clean interface and VLAN settings (removes the factory port config)")
        ctx.cfg.raw_set("delete interfaces")
        ctx.cfg.raw_set("delete vlans")
        ctx.cfg.raw_set("delete protocols rstp")
        ctx.cfg.raw_set("delete switch-options")
        ctx.cfg.raw_set("delete poe")
        if _truthy((p.get("qos") or {}).get("enabled")):
            ctx.cfg.raw_set("delete class-of-service")

    steps = (_switch, _models, _system, _access, _snmp, _syslog, _vlans, _ports, _lags, R.basics, R.policies,
             _routing, R.ospf, R.bgp, R.evpn, _services, SEC.apply, Q.apply)
    for step in steps:
        if step is _models:
            ctx.models = _models(ctx)
        else:
            step(ctx)
        ctx.row = None  # a step that stops early must not leave its row behind

    hostname = _s(p["system"].get("hostname")) or "switch"
    ctx.res.set_text = ctx.cfg.to_set()
    hier = ctx.cfg.to_hierarchy()
    ctx.res.hier_text = "".join(f"/* {line} */\n" for line in header(p)) + hier
    ctx.res.hostname = hostname
    return ctx.res
