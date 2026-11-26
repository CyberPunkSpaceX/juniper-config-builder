"""Port security: 802.1X / MAB with RADIUS, sticky MAC, root guard, loop
protection and auto-recovery. MAC limits, DHCP snooping, ARP inspection, IP
source guard, storm control and BPDU block live in generator.py."""

from __future__ import annotations

import ipaddress

SECURITY_DEFAULTS = {
    "radius_servers": [],        # {address, secret, port}
    "radius_source": "",
    "server_fail": "",           # "" | permit | deny | use-cache | vlan
    "server_fail_vlan": "",
    "guest_vlan": "",
    "reauth": "",                # seconds
    "recovery_timeout": "",      # seconds before a BPDU-blocked port comes back
}
PROFILE = "DOT1X"
DOT1X_MODES = ("dot1x", "dot1x-mab", "mab")
MAC_ACTIONS = ("drop", "log", "drop-and-log", "shutdown")


def port(ctx, section: str, label: str, mode: str, base: tuple, phys: list[str], row: dict) -> None:
    """Per port group settings. Called from the port/LAG code."""
    cfg = ctx.cfg
    targets = [base[1]] if base[1].startswith("ae") else phys
    if row.get("root_guard") in (True, "true", "on", "1"):
        if mode == "access":
            ctx.warn(section, f"{label}: root guard is meant for uplinks and ports to other switches.")
        for t in targets:
            cfg.add(("protocols", "rstp", f"interface {t}"), "no-root-port")
    if row.get("loop_protect") in (True, "true", "on", "1"):
        for t in targets:
            cfg.add(("protocols", "rstp", f"interface {t}"), "bpdu-timeout-action block")
    dot1x = str(row.get("dot1x") or "")
    if dot1x:
        if dot1x not in DOT1X_MODES:
            ctx.error(section, f"{label}: unknown 802.1X mode '{dot1x}'.", "dot1x")
            return
        if mode != "access" or base[1].startswith("ae"):
            ctx.error(section, f"{label}: 802.1X and MAB only work on access ports.", "dot1x")
            return
        ctx.dot1x_ports = getattr(ctx, "dot1x_ports", [])
        for p in phys:
            path = ("protocols", "dot1x", "authenticator", f"interface {p}.0")
            cfg.add(path, "supplicant multiple")
            if dot1x in ("dot1x-mab", "mab"):
                cfg.add(path, "mac-radius" if dot1x == "dot1x-mab" else "mac-radius restrict")
            ctx.dot1x_ports.append(p)


def apply(ctx) -> None:
    """Global settings, after all ports are done."""
    sec = {**SECURITY_DEFAULTS, **(ctx.p.get("security") or {})}
    cfg = ctx.cfg
    rt = str(sec.get("recovery_timeout") or "").strip()
    if rt:
        if rt.isdigit() and 10 <= int(rt) <= 3600:
            cfg.add(("protocols", "layer2-control"), f"recovery-timeout {rt}")
        else:
            ctx.error("Security", "Auto-recovery time must be 10-3600 seconds.", "security.recovery_timeout")
    ports = getattr(ctx, "dot1x_ports", [])
    servers = [s for s in sec.get("radius_servers") or [] if str(s.get("address") or "").strip()]
    if not ports:
        if servers:
            ctx.warn("Security", "RADIUS servers are set, but no port group uses 802.1X or MAB.")
        return
    if not servers:
        ctx.error("Security", "802.1X/MAB is on for some ports, but there is no RADIUS server.")
        return
    cfg.comment("802.1X / MAC authentication")
    prof = ("access", "profile", PROFILE)
    cfg.add(prof, "authentication-order radius")
    for s in servers:
        ctx.at("security.radius_servers", s)
        addr = str(s["address"]).strip()
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            ctx.error("Security", f"RADIUS server '{addr}' is not an IP address.", "address")
            continue
        secret = str(s.get("secret") or "")
        if not secret:
            ctx.error("Security", f"RADIUS server {addr} needs a shared secret.", "secret")
        else:
            cfg.add(("access", "radius-server", addr), f'secret "{secret}"')
        if str(s.get("port") or "").strip():
            cfg.add(("access", "radius-server", addr), f"port {str(s['port']).strip()}")
        src = str(sec.get("radius_source") or "").strip()
        if src:
            cfg.add(("access", "radius-server", addr), f"source-address {src}")
        cfg.add((*prof, "radius"), f"authentication-server {addr}")
    ctx.at("", None)
    auth = ("protocols", "dot1x", "authenticator")
    cfg.add(auth, f"authentication-profile-name {PROFILE}")
    fail = str(sec.get("server_fail") or "")
    vlan_names = {v["name"] for v in ctx.p.get("vlans") or []}
    reported = set()

    def once(message, field):
        # These settings apply to every 802.1X port: report a problem once, not per port.
        if message not in reported:
            reported.add(message)
            ctx.error("Security", message, field)

    for p in ports:
        path = (*auth, f"interface {p}.0")
        if fail in ("permit", "deny", "use-cache"):
            cfg.add((*path, "server-fail"), fail)
        elif fail == "vlan":
            v = str(sec.get("server_fail_vlan") or "")
            if v in vlan_names:
                cfg.add((*path, "server-fail"), f"vlan-name {v}")
            else:
                once("Pick the VLAN to use when RADIUS is down.", "security.server_fail_vlan")
        guest = str(sec.get("guest_vlan") or "")
        if guest:
            if guest in vlan_names:
                cfg.add(path, f"guest-vlan {guest}")
            else:
                once(f"Guest VLAN '{guest}' does not exist.", "security.guest_vlan")
        re_ = str(sec.get("reauth") or "").strip()
        if re_:
            if re_.isdigit() and 60 <= int(re_) <= 65535:
                cfg.add(path, f"reauthentication {re_}")
            else:
                once("Re-authentication must be 60-65535 seconds.", "security.reauth")
    if not fail:
        ctx.warn("Security", "When RADIUS is unreachable, 802.1X ports block everyone. Consider "
                             "'server fail: permit' or a fallback VLAN.")
    ctx.warn("Security", "The RADIUS secret is written in clear; Junos encrypts it when you commit. "
                         "Don't share this config file.")
