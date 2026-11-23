"""Dynamic routing for the builder: router ID / AS / loopback, OSPF, BGP,
routing policies and EVPN-VXLAN.

Called from generator.build() after interfaces and VLANs are known, so the
checks can tell which interfaces exist.
"""

from __future__ import annotations

import ipaddress
import re

from .junos import q

NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
AREA = re.compile(r"^(\d{1,10}|\d{1,3}(\.\d{1,3}){3})$")
COMMUNITY = re.compile(r"^(\d{1,10}:\d{1,10}|target:[\d.]+:\d+|origin:[\d.]+:\d+|no-export|no-advertise|no-export-subconfed)$")
ESI = re.compile(r"^([0-9a-fA-F]{2}:){9}[0-9a-fA-F]{2}$")
MAC = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
PROTOCOLS = ("direct", "static", "ospf", "bgp", "aggregate", "evpn", "local")
MATCHES = ("exact", "orlonger", "longer", "upto")
EVPN_MODELS = ("EX4400", "EX4100", "EX4100-F", "EX4300-48MP")

ROUTING_DEFAULTS = {
    "router_id": "", "asn": "", "loopback": "", "ecmp": False,
    "ospf": {"enabled": False, "reference_bandwidth": "", "export": "", "areas": []},
    "bgp_groups": [],
}
POLICY_DEFAULTS = {"prefix_lists": [], "communities": [], "terms": []}
EVPN_DEFAULTS = {"enabled": False, "role": "leaf", "overlay_type": "internal", "overlay_as": "", "route_reflector": False,
                 "peers": "", "vrf_target": "", "vrfs": []}
AREA_DEFAULTS = {"area": "0.0.0.0", "type": "normal", "interfaces": "", "passive": "", "p2p": "", "md5_key": ""}
BGP_DEFAULTS = {"name": "", "type": "external", "peer_as": "", "local_address": "", "neighbors": "",
                "import": "", "export": "", "multipath": False, "bfd": "", "auth_key": "", "description": ""}
TERM_DEFAULTS = {"policy": "", "term": "", "protocol": "", "prefix_list": "", "match": "exact", "route_filter": "",
                 "community": "", "action": "accept", "local_pref": "", "med": "", "community_add": "",
                 "next_hop_self": False}


def _s(v) -> str:
    return str(v if v is not None else "").strip()


def _list(v) -> list[str]:
    return [i for i in re.split(r"[,\s]+", _s(v)) if i]


def _true(v) -> bool:
    return v is True or _s(v).lower() in ("1", "true", "yes", "on")


def _asn(ctx, section, label, value) -> int | None:
    value = _s(value)
    if not value:
        return None
    if "." in value:  # asdot 1.10 -> 65546
        hi, _, lo = value.partition(".")
        if hi.isdigit() and lo.isdigit():
            value = str(int(hi) * 65536 + int(lo))
    if value.isdigit() and 1 <= int(value) <= 4294967294:
        return int(value)
    ctx.error(section, f"{label}: '{value}' is not a valid AS number (1-4294967294).")
    return None


def _iface_name(name: str) -> str:
    name = name.strip()
    return name if "." in name else f"{name}.0"


# ------------------------------------------------------------------ basics
def basics(ctx) -> None:
    """Loopback, router ID, AS number and ECMP."""
    r, cfg = ctx.p["routing"], ctx.cfg
    ctx.loopback_ip = None
    lo = _s(r.get("loopback"))
    if lo:
        try:
            iface = ipaddress.ip_interface(lo if "/" in lo else f"{lo}/32")
        except ValueError:
            ctx.error("Routing", f"Loopback '{lo}' is not a valid address.")
            iface = None
        if iface is not None:
            if iface.version == 4 and iface.network.prefixlen != 32:
                ctx.warn("Routing", "A loopback is normally a /32.")
            cfg.comment("Loopback and routing identity")
            cfg.add(("interfaces", "lo0", "unit 0", f"family {'inet' if iface.version == 4 else 'inet6'}"),
                    f"address {iface.with_prefixlen}")
            ctx.l3_ifaces.add("lo0.0")
            if iface.version == 4:
                ctx.loopback_ip = str(iface.ip)
    rid = _s(r.get("router_id")) or (ctx.loopback_ip or "")
    if rid:
        try:
            ipaddress.IPv4Address(rid)
            cfg.add(("routing-options",), f"router-id {rid}")
            ctx.router_id = rid
        except ValueError:
            ctx.error("Routing", f"Router ID '{rid}' must be an IPv4 address.")
    ctx.asn = _asn(ctx, "Routing", "AS number", r.get("asn"))
    if ctx.asn:
        cfg.add(("routing-options",), f"autonomous-system {ctx.asn}")
    if _true(r.get("ecmp")):
        cfg.add(("policy-options", "policy-statement ECMP-LOAD-BALANCE", "then"), "load-balance per-packet")
        cfg.add(("routing-options", "forwarding-table"), "export ECMP-LOAD-BALANCE")
        ctx.policy_names.add("ECMP-LOAD-BALANCE")


# ---------------------------------------------------------------- policies
def policies(ctx) -> None:
    p, cfg = ctx.p["policy"], ctx.cfg
    pls = [x for x in p.get("prefix_lists") or [] if _s(x.get("name"))]
    comms = [x for x in p.get("communities") or [] if _s(x.get("name"))]
    terms = [x for x in p.get("terms") or [] if _s(x.get("policy"))]
    if not (pls or comms or terms):
        return
    cfg.comment("Routing policies")
    pl_names, comm_names = set(), set()
    for pl in pls:
        ctx.at("policy.prefix_lists", pl)
        name = _s(pl.get("name"))
        if not NAME.match(name):
            ctx.error("Policies", f"Prefix list name '{name}' must start with a letter (letters, digits, - _ .).")
            continue
        prefixes = _list(pl.get("prefixes"))
        if not prefixes:
            ctx.error("Policies", f"Prefix list {name} is empty.")
        for pfx in prefixes:
            try:
                cfg.add(("policy-options", f"prefix-list {name}"), str(ipaddress.ip_network(pfx, strict=False)))
            except ValueError:
                ctx.error("Policies", f"Prefix list {name}: '{pfx}' is not a prefix.")
        pl_names.add(name)
    for c in comms:
        ctx.at("policy.communities", c)
        name = _s(c.get("name"))
        if not NAME.match(name):
            ctx.error("Policies", f"Community name '{name}' must start with a letter.")
            continue
        members = _list(c.get("members"))
        if not members:
            ctx.error("Policies", f"Community {name} has no members (example 65000:100).")
        for m in members:
            if COMMUNITY.match(m):
                cfg.add(("policy-options", f"community {name}"), f"members {m}")
            else:
                ctx.error("Policies", f"Community {name}: '{m}' is not a community value (example 65000:100).")
        comm_names.add(name)

    seen_terms = set()
    for t in terms:
        ctx.at("policy.terms", t)
        policy, term = _s(t.get("policy")), _s(t.get("term"))
        if not NAME.match(policy):
            ctx.error("Policies", f"Policy name '{policy}' must start with a letter.")
            continue
        if not term:
            term = f"t{sum(1 for k in seen_terms if k[0] == policy) + 1}"
        if not NAME.match(term) or (policy, term) in seen_terms:
            ctx.error("Policies", f"Policy {policy}: term '{term}' is invalid or used twice.")
            continue
        seen_terms.add((policy, term))
        ctx.policy_names.add(policy)
        base = ("policy-options", f"policy-statement {policy}", f"term {term}")
        proto = _s(t.get("protocol"))
        if proto:
            if proto in PROTOCOLS:
                cfg.add((*base, "from"), f"protocol {proto}")
            else:
                ctx.error("Policies", f"{policy}/{term}: unknown protocol '{proto}'.")
        pl = _s(t.get("prefix_list"))
        if pl:
            if pl not in pl_names:
                ctx.error("Policies", f"{policy}/{term}: prefix list '{pl}' is not defined.")
            match = t.get("match") if t.get("match") in ("exact", "orlonger", "longer") else "exact"
            cfg.add((*base, "from"), f"prefix-list {pl}" if match == "exact" else f"prefix-list-filter {pl} {match}")
        for rf in [x.strip() for x in _s(t.get("route_filter")).split(",") if x.strip()]:
            parts = rf.split()
            try:
                net = ipaddress.ip_network(parts[0], strict=False)
            except ValueError:
                ctx.error("Policies", f"{policy}/{term}: route filter '{rf}' needs a prefix (example 10.0.0.0/8 orlonger).")
                continue
            mode = " ".join(parts[1:]) or "exact"
            if mode.split()[0] not in MATCHES:
                ctx.error("Policies", f"{policy}/{term}: route filter match must be exact, orlonger, longer or upto /N.")
                continue
            cfg.add((*base, "from"), f"route-filter {net} {mode}")
        comm = _s(t.get("community"))
        if comm:
            if comm not in comm_names:
                ctx.error("Policies", f"{policy}/{term}: community '{comm}' is not defined.")
            cfg.add((*base, "from"), f"community {comm}")
        lp, med = _s(t.get("local_pref")), _s(t.get("med"))
        if lp:
            if lp.isdigit():
                cfg.add((*base, "then"), f"local-preference {lp}")
            else:
                ctx.error("Policies", f"{policy}/{term}: local preference must be a number.")
        if med:
            if med.isdigit():
                cfg.add((*base, "then"), f"metric {med}")
            else:
                ctx.error("Policies", f"{policy}/{term}: metric (MED) must be a number.")
        add = _s(t.get("community_add"))
        if add:
            if add not in comm_names:
                ctx.error("Policies", f"{policy}/{term}: community '{add}' is not defined.")
            cfg.add((*base, "then"), f"community add {add}")
        if _true(t.get("next_hop_self")):
            cfg.add((*base, "then"), "next-hop self")
        action = t.get("action") if t.get("action") in ("accept", "reject", "next") else "accept"
        if action == "next":
            if not (lp or med or add or _true(t.get("next_hop_self"))):
                ctx.warn("Policies", f"{policy}/{term}: the term changes nothing and passes on; it has no effect.")
            cfg.add((*base, "then"), "next term")
        else:
            cfg.add((*base, "then"), action)


def _policy_refs(ctx, section: str, label: str, text) -> list[str]:
    names = _list(text)
    for n in names:
        if n not in ctx.policy_names:
            ctx.error(section, f"{label}: policy '{n}' is not defined on the Policies tab.")
    return names


# -------------------------------------------------------------------- OSPF
def ospf(ctx) -> None:
    o, cfg = ctx.p["routing"]["ospf"], ctx.cfg
    if not _true(o.get("enabled")):
        return
    areas = [a for a in o.get("areas") or [] if _s(a.get("area")) or _s(a.get("interfaces"))]
    cfg.comment("OSPF")
    if not areas:
        ctx.error("OSPF", "OSPF is on but has no area. Add area 0.0.0.0 with its interfaces.")
    if not getattr(ctx, "router_id", None):
        ctx.warn("OSPF", "No router ID or loopback: Junos picks one itself, and it can change. Set a loopback.")
    ref = _s(o.get("reference_bandwidth")).lower()
    if ref:
        if re.match(r"^\d+[kmg]?$", ref):
            cfg.add(("protocols", "ospf"), f"reference-bandwidth {ref}")
        else:
            ctx.error("OSPF", "Reference bandwidth looks like 100g, 40g or 10g.")
    for pol in _policy_refs(ctx, "OSPF", "OSPF export", o.get("export")):
        cfg.add_list(("protocols", "ospf"), "export", [pol])
    seen_if = {}
    for a in areas:
        ctx.at("routing.ospf.areas", a)
        area = _s(a.get("area")) or "0.0.0.0"
        if not AREA.match(area):
            ctx.error("OSPF", f"Area '{area}' must look like 0.0.0.0 or a number.")
            continue
        base = ("protocols", "ospf", f"area {area}")
        kind = a.get("type")
        if kind in ("stub", "nssa"):
            if area in ("0", "0.0.0.0"):
                ctx.error("OSPF", "The backbone area 0 can't be a stub or NSSA.")
            else:
                cfg.add(base, kind)
        passive = {_iface_name(i) for i in _list(a.get("passive"))}
        p2p = {_iface_name(i) for i in _list(a.get("p2p"))}
        names = [_iface_name(i) for i in _list(a.get("interfaces"))]
        names += [i for i in sorted(passive | p2p) if i not in names]
        if not names:
            ctx.error("OSPF", f"Area {area} has no interfaces.", "interfaces")
        key = _s(a.get("md5_key"))
        for name in names:
            if name in seen_if:
                ctx.error("OSPF", f"{name} is in area {seen_if[name]} and area {area}.")
                continue
            seen_if[name] = area
            if name not in ctx.l3_ifaces:
                ctx.warn("OSPF", f"{name} has no IP address in this config (routed port, LAG, VLAN IRB or loopback).")
            path = (*base, f"interface {name}")
            if name in passive or name.startswith("lo0"):
                cfg.add(path, "passive")
                continue
            if name in p2p:
                cfg.add(path, "interface-type p2p")
            if key:
                cfg.add((*path, "authentication", "md5 1"), f"key {q(key)}")
            if name not in p2p and not key:
                cfg.add(base, f"interface {name}")


# --------------------------------------------------------------------- BGP
def _neighbors(ctx, section: str, label: str, text: str) -> list[tuple[str, int | None, str]]:
    out = []
    for line in (text or "").replace(";", "\n").splitlines():
        parts = [p for p in re.split(r"[,\s]+", line.strip(), maxsplit=2) if p]
        if not parts:
            continue
        try:
            ip = str(ipaddress.ip_address(parts[0]))
        except ValueError:
            ctx.error(section, f"{label}: '{parts[0]}' is not a neighbor IP address.")
            continue
        asn, desc = None, ""
        rest = parts[1:]
        if rest and re.match(r"^\d+(\.\d+)?$", rest[0]):
            asn = _asn(ctx, section, f"{label} neighbor {ip}", rest[0])
            rest = rest[1:]
        if rest:
            desc = " ".join(rest)
        out.append((ip, asn, desc))
    return out


def bgp(ctx) -> None:
    groups = [g for g in ctx.p["routing"].get("bgp_groups") or [] if _s(g.get("name")) or _s(g.get("neighbors"))]
    if not groups:
        return
    cfg = ctx.cfg
    cfg.comment("BGP")
    if not ctx.asn:
        ctx.error("BGP", "BGP needs the local AS number (Routing tab).")
    names = set()
    for g in groups:
        ctx.at("routing.bgp_groups", g)
        name = _s(g.get("name"))
        if not NAME.match(name) or name in names:
            ctx.error("BGP", f"BGP group name '{name}' must start with a letter and be unique.")
            continue
        names.add(name)
        _bgp_group(ctx, name, g)


def _bgp_group(ctx, name: str, g: dict, family: str | None = None) -> None:
    cfg = ctx.cfg
    section = "EVPN" if family == "evpn" else "BGP"
    base = ("protocols", "bgp", f"group {name}")
    kind = "internal" if g.get("type") == "internal" else "external"
    cfg.add(base, f"type {kind}")
    if _s(g.get("description")):
        cfg.add(base, f"description {q(_s(g.get('description')))}")
    la = _s(g.get("local_address"))
    if la:
        try:
            cfg.add(base, f"local-address {ipaddress.ip_address(la)}")
        except ValueError:
            ctx.error(section, f"Group {name}: local address '{la}' is not an IP address.")
    elif kind == "internal":
        ctx.warn(section, f"Group {name}: internal BGP normally peers between loopbacks; set the local address.")
    if family == "evpn":
        cfg.add((*base, "family evpn"), "signaling")
    group_as = _asn(ctx, section, f"Group {name} peer AS", g.get("peer_as"))
    if kind == "external" and group_as:
        cfg.add(base, f"peer-as {group_as}")
    if kind == "internal" and group_as and ctx.asn and group_as != ctx.asn:
        ctx.error(section, f"Group {name}: internal peers must be in our own AS {ctx.asn}.")
    if _true(g.get("multipath")):
        cfg.add(base, "multipath" if kind == "internal" else "multipath multiple-as")
    bfd = _s(g.get("bfd"))
    if bfd:
        if bfd.isdigit() and 50 <= int(bfd) <= 10000:
            cfg.add((*base, "bfd-liveness-detection"), f"minimum-interval {bfd}")
        else:
            ctx.error(section, f"Group {name}: BFD interval must be 50-10000 ms.")
    if _s(g.get("auth_key")):
        cfg.add(base, f"authentication-key {q(_s(g.get('auth_key')))}")
    for pol in _policy_refs(ctx, section, f"Group {name} import", g.get("import")):
        cfg.add_list(base, "import", [pol])
    for pol in _policy_refs(ctx, section, f"Group {name} export", g.get("export")):
        cfg.add_list(base, "export", [pol])
    if g.get("cluster"):
        cfg.add(base, f"cluster {g['cluster']}")
    if g.get("multihop"):
        cfg.add((*base, "multihop"), "no-nexthop-change")
    neighbors = _neighbors(ctx, section, f"Group {name}", g.get("neighbors", ""))
    if not neighbors:
        ctx.error(section, f"Group {name} has no neighbors.", "neighbors")
    for ip, asn, desc in neighbors:
        path = (*base, f"neighbor {ip}")
        if asn:
            if kind == "internal" and ctx.asn and asn != ctx.asn:
                ctx.error(section, f"Group {name}: neighbor {ip} AS {asn} differs from our AS in an internal group.")
            elif kind == "external":
                cfg.add(path, f"peer-as {asn}")
        elif kind == "external" and not group_as:
            ctx.error(section, f"Group {name}: neighbor {ip} needs a peer AS (on the group or after the IP).")
        if desc:
            cfg.add(path, f"description {q(desc)}")
        if not desc and not (asn and kind == "external"):
            cfg.add(base, f"neighbor {ip}")


# -------------------------------------------------------------- EVPN-VXLAN
def evpn(ctx) -> None:
    e, cfg = ctx.p["evpn"], ctx.cfg
    if not _true(e.get("enabled")):
        for v in ctx.vlan_by_name.values():
            if _s(v.get("vni")):
                ctx.warn("VLANs", f"VLAN {v['name']} has a VNI, but EVPN-VXLAN is off (EVPN-VXLAN tab).")
                break
        return
    families = {m.family for m in ctx.models} | {m.name for m in ctx.models}
    if ctx.models and not any(f in families for f in EVPN_MODELS):
        ctx.warn("EVPN", "EVPN-VXLAN runs on the EX4100, EX4400 and EX4300-48MP, not on the EX2300, EX3400 or other EX4300 models.")
    ctx.warn("EVPN", "EVPN-VXLAN and BGP need a feature license on EX switches. Check yours with 'show system license'.")
    role = e.get("role") if e.get("role") in ("leaf", "spine", "collapsed") else "leaf"
    lo = getattr(ctx, "loopback_ip", None)
    if not lo:
        ctx.error("EVPN", "EVPN-VXLAN needs an IPv4 loopback (Routing tab). It is the VTEP and BGP source.")
        return
    asn = _asn(ctx, "EVPN", "Overlay AS", e.get("overlay_as")) or ctx.asn
    if not asn:
        ctx.error("EVPN", "Set the AS number on the Routing tab (or an overlay AS here).")
        return
    if not (_true(ctx.p["routing"]["ospf"].get("enabled")) or ctx.p["routing"].get("bgp_groups")):
        ctx.warn("EVPN", "No underlay: turn on OSPF or add a BGP group so the switches can reach each other's loopbacks.")

    cfg.comment(f"EVPN-VXLAN overlay ({ {'leaf': 'leaf', 'spine': 'spine / route reflector', 'collapsed': 'collapsed core'}[role] })")
    overlay = {"type": e.get("overlay_type") if e.get("overlay_type") == "external" else "internal",
               "local_address": lo, "neighbors": e.get("peers", ""), "peer_as": "",
               "multipath": role != "spine", "description": "EVPN overlay"}
    if overlay["type"] == "internal":
        if asn != ctx.asn and ctx.asn:
            cfg.add(("protocols", "bgp", "group EVPN-OVERLAY"), f"local-as {asn}")
        if role == "spine" or _true(e.get("route_reflector")):
            overlay["cluster"] = lo
    else:
        overlay["multihop"] = True
    _bgp_group(ctx, "EVPN-OVERLAY", overlay, family="evpn")
    if role == "spine":
        ctx.warn("EVPN", "Spine role: this switch reflects EVPN routes only; VXLAN VLANs are configured on the leaves.")
        return

    cfg.add(("protocols", "evpn"), "encapsulation vxlan")
    cfg.add(("protocols", "evpn"), "extended-vni-list all")
    cfg.add(("switch-options",), "vtep-source-interface lo0.0")
    cfg.add(("switch-options",), f"route-distinguisher {lo}:1")
    target = _s(e.get("vrf_target")) or f"target:{asn}:1"
    if not re.match(r"^target:[\d.]+:\d+$", target):
        ctx.error("EVPN", "VRF target looks like target:65000:1.")
    cfg.add(("switch-options",), f"vrf-target {target}")

    vnis: dict[int, str] = {}
    any_vga = False
    vrfs = {_s(v.get("name")): v for v in e.get("vrfs") or [] if _s(v.get("name"))}
    vrf_irbs: dict[str, list[str]] = {n: [] for n in vrfs}
    for v in ctx.vlan_by_name.values():
        vni = _s(v.get("vni"))
        if not vni:
            ctx.warn("EVPN", f"VLAN {v['name']} has no VNI, so it stays local to this switch.")
            continue
        if not vni.isdigit() or not 1 <= int(vni) <= 16777214:
            ctx.error("EVPN", f"VLAN {v['name']}: VNI must be 1-16777214.")
            continue
        if int(vni) in vnis:
            ctx.error("EVPN", f"VNI {vni} is used by both {vnis[int(vni)]} and {v['name']}.")
            continue
        vnis[int(vni)] = v["name"]
        cfg.add(("vlans", v["name"], "vxlan"), f"vni {vni}")
        vga = _s(v.get("vga"))
        if vga:
            irb = [a for a in _list(v.get("irb"))]
            if not irb:
                ctx.error("EVPN", f"VLAN {v['name']}: the anycast gateway needs an IRB address on this switch too.")
                continue
            try:
                gw = ipaddress.ip_address(vga)
                own = next(ipaddress.ip_interface(a) for a in irb if ipaddress.ip_interface(a).version == gw.version)
                if gw not in own.network:
                    ctx.error("EVPN", f"VLAN {v['name']}: gateway {vga} is not in {own.network}.")
                    continue
                if gw == own.ip:
                    ctx.error("EVPN", f"VLAN {v['name']}: the gateway must differ from this switch's own IRB address.")
                    continue
            except (ValueError, StopIteration):
                ctx.error("EVPN", f"VLAN {v['name']}: '{vga}' is not a gateway address in the IRB subnet.")
                continue
            fam = "inet" if gw.version == 4 else "inet6"
            cfg.add(("interfaces", "irb", f"unit {int(v['id'])}", f"family {fam}", f"address {own.with_prefixlen}"),
                    f"virtual-gateway-address {gw}")
            any_vga = True
        vrf = _s(v.get("vrf"))
        if vrf:
            if vrf not in vrfs:
                ctx.error("EVPN", f"VLAN {v['name']}: VRF '{vrf}' is not defined below.")
            elif not _s(v.get("irb")):
                ctx.error("EVPN", f"VLAN {v['name']}: a VLAN in a VRF needs an IRB address.")
            else:
                vrf_irbs[vrf].append(f"irb.{int(v['id'])}")
    if any_vga:
        cfg.add(("protocols", "evpn", "default-gateway"), "no-gateway-community")
    if not vnis:
        ctx.warn("EVPN", "No VLAN has a VNI yet. Add VNIs on the VLANs tab.")

    for name, vrf in vrfs.items():
        if not NAME.match(name):
            ctx.error("EVPN", f"VRF name '{name}' must start with a letter.")
            continue
        rid, l3vni = _s(vrf.get("id")), _s(vrf.get("l3vni"))
        if not rid.isdigit() or not 1 <= int(rid) <= 16383:
            ctx.error("EVPN", f"VRF {name}: ID must be 1-16383 (used for the RD and lo0 unit).")
            continue
        if not l3vni.isdigit() or not 1 <= int(l3vni) <= 16777214:
            ctx.error("EVPN", f"VRF {name}: L3 VNI must be 1-16777214.")
            continue
        if int(l3vni) in vnis:
            ctx.error("EVPN", f"VRF {name}: L3 VNI {l3vni} is already used by VLAN {vnis[int(l3vni)]}.")
            continue
        vnis[int(l3vni)] = f"VRF {name}"
        base = ("routing-instances", name)
        cfg.add(base, "instance-type vrf")
        cfg.add(("interfaces", "lo0", f"unit {rid}"), "family inet")
        cfg.add(base, f"interface lo0.{rid}")
        for irb in vrf_irbs[name]:
            cfg.add(base, f"interface {irb}")
        if not vrf_irbs[name]:
            ctx.warn("EVPN", f"VRF {name} has no VLANs; pick it in the VRF column of a VLAN.")
        cfg.add(base, f"route-distinguisher {lo}:{rid}")
        cfg.add(base, f"vrf-target target:{asn}:{l3vni}")
        t5 = (*base, "protocols", "evpn", "ip-prefix-routes")
        cfg.add(t5, "advertise direct-nexthop")
        cfg.add(t5, "encapsulation vxlan")
        cfg.add(t5, f"vni {l3vni}")


def esi_lag(ctx, row: dict, name: str, label: str) -> None:
    """EVPN multihoming (ESI-LAG) settings on an ae interface."""
    esi, sysid = _s(row.get("esi")), _s(row.get("lacp_system_id"))
    if not esi and not sysid:
        return
    if not _true(ctx.p["evpn"].get("enabled")):
        ctx.warn("LAGs", f"{label}: ESI is set but EVPN-VXLAN is off; ignored.")
        return
    if esi:
        if ESI.match(esi):
            ctx.cfg.add(("interfaces", name), f"esi {esi.lower()}")
            ctx.cfg.add(("interfaces", name, "esi"), "all-active")
        else:
            ctx.error("LAGs", f"{label}: ESI is 10 bytes, like 00:01:01:01:01:01:01:01:01:01.")
    if sysid:
        if MAC.match(sysid):
            ctx.cfg.add(("interfaces", name, "aggregated-ether-options", "lacp"), f"system-id {sysid.lower()}")
        else:
            ctx.error("LAGs", f"{label}: LACP system ID is a MAC address, like 00:00:00:01:01:01.")
    if esi and not sysid:
        ctx.warn("LAGs", f"{label}: set the same LACP system ID on both switches so the other end sees one LAG.")
