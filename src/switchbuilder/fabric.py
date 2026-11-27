"""EVPN-VXLAN fabric wizard.

Takes a small fabric description (flavor, how many switches, which ports
connect them, address pools, VLANs and VRFs) and works out everything else:
loopbacks, /31 point-to-point links, AS numbers, VNIs, route distinguishers
and targets, anycast gateways and ESIs. Each switch then gets an ordinary
builder project, which generator.build() turns into its config, so every
check of the single-switch builder also runs on the fabric.

Flavors:

* ``collapsed``: two core switches do everything (gateways, VTEPs); access
  switches hang off both cores with ESI-LAG. No spines.
* ``erb``: spine-leaf, edge-routed bridging. Leaves are the gateways and
  VTEPs; spines only carry traffic and reflect EVPN routes.
* ``crb``: spine-leaf, centrally-routed bridging. Spines are the gateways;
  leaves only bridge (layer 2 VTEPs).
* ``bridged``: spine-leaf bridged overlay. Leaves stretch VLANs only; the
  default gateway lives outside the fabric (a firewall or router).
"""

from __future__ import annotations

import copy
import io
import ipaddress
import re
import zipfile

from . import models
from . import ports as P
from .generator import build

FLAVORS = {
    "collapsed": "Collapsed core: 2 core switches, access switches dual-homed with ESI-LAG",
    "erb": "Spine-leaf, edge-routed (ERB): gateways on every leaf",
    "crb": "Spine-leaf, centrally-routed (CRB): gateways on the spines",
    "bridged": "Spine-leaf, bridged overlay: layer 2 only, gateway outside the fabric",
}

DEFAULTS = {
    "flavor": "erb",
    "design": "ebgp",            # ebgp: eBGP underlay + eBGP overlay; ospf: OSPF underlay + iBGP overlay
    "prefix": "fabric",
    "spines": 2, "leaves": 2,
    "spine_model": "EX4400-24T", "leaf_model": "EX4400-48P", "core_model": "EX4400-48P",
    "spine_ports": "xe-0/2/0-3",     # spine downlinks, one per leaf, in leaf order
    "leaf_ports": "xe-0/2/0-1",      # leaf uplinks, one per spine, in spine order
    "core_links": "xe-0/2/0-1",      # collapsed core: links between the two cores
    "loopback_pool": "10.255.0.0/24",
    "p2p_pool": "10.254.0.0/24",
    "mgmt_pool": "", "mgmt_gateway": "",
    "asn_base": "65000",
    "vni_base": "10000",
    "vlans": [],                     # {name, id, subnet, vrf}
    "vrfs": [],                      # {name}
    "access_ports": "", "access_mode": "trunk", "access_vlan": "",
    "esi_links": "",                 # collapsed: ports used on BOTH cores for dual-homed access switches
    "bfd": True,
}

TEMPLATES = {
    "small-collapsed": {
        "title": "Small campus: collapsed core",
        "text": "Two core switches are the whole fabric. Each access switch connects to both cores with one LAG, "
                "so it keeps working if a core fails. Good for one building.",
        "fabric": {"flavor": "collapsed", "design": "ebgp", "prefix": "core", "core_model": "EX4400-48P",
                   "core_links": "xe-0/2/0-1", "esi_links": "ge-0/0/40-43",
                   "vlans": [{"name": "USERS", "id": "20", "subnet": "10.20.0.0/24", "vrf": "CORP"},
                             {"name": "VOICE", "id": "30", "subnet": "10.30.0.0/24", "vrf": "CORP"},
                             {"name": "GUEST", "id": "50", "subnet": "10.50.0.0/24", "vrf": "GUEST"}],
                   "vrfs": [{"name": "CORP"}, {"name": "GUEST"}]},
    },
    "campus-erb": {
        "title": "Campus fabric: 2 spines + 4 leaves (ERB)",
        "text": "Juniper's recommended campus design. Every leaf is the default gateway for its users, "
                "so traffic is routed at the edge and the spines only forward.",
        "fabric": {"flavor": "erb", "design": "ebgp", "prefix": "campus", "spines": 2, "leaves": 4,
                   "spine_model": "EX4400-24T", "leaf_model": "EX4400-48P",
                   "spine_ports": "xe-0/2/0-3", "leaf_ports": "xe-0/2/0-1",
                   "access_ports": "ge-0/0/0-39", "access_mode": "access", "access_vlan": "USERS",
                   "vlans": [{"name": "USERS", "id": "20", "subnet": "10.20.0.0/24", "vrf": "CORP"},
                             {"name": "VOICE", "id": "30", "subnet": "10.30.0.0/24", "vrf": "CORP"},
                             {"name": "IOT", "id": "40", "subnet": "10.40.0.0/24", "vrf": "IOT"}],
                   "vrfs": [{"name": "CORP"}, {"name": "IOT"}]},
    },
    "campus-crb": {
        "title": "Spine-leaf with gateways on the spines (CRB)",
        "text": "The two spines route between VLANs; leaves only switch. Easier to read, but all routed "
                "traffic goes through the spines.",
        "fabric": {"flavor": "crb", "design": "ospf", "prefix": "dc", "spines": 2, "leaves": 2,
                   "spine_model": "EX4400-24T", "leaf_model": "EX4400-48P",
                   "spine_ports": "xe-0/2/0-1", "leaf_ports": "xe-0/2/0-1",
                   "access_ports": "ge-0/0/0-47", "access_mode": "trunk",
                   "vlans": [{"name": "SERVERS", "id": "100", "subnet": "10.100.0.0/24", "vrf": ""},
                             {"name": "STORAGE", "id": "110", "subnet": "10.110.0.0/24", "vrf": ""}],
                   "vrfs": []},
    },
    "bridged": {
        "title": "Layer 2 stretch only (bridged overlay)",
        "text": "Stretch VLANs between buildings or racks without moving the gateway: your firewall or "
                "router keeps routing between VLANs.",
        "fabric": {"flavor": "bridged", "design": "ospf", "prefix": "l2", "spines": 2, "leaves": 2,
                   "spine_model": "EX4400-24T", "leaf_model": "EX4100-48P",
                   "spine_ports": "xe-0/2/0-1", "leaf_ports": "xe-0/2/0-1",
                   "access_ports": "ge-0/0/0-47", "access_mode": "trunk",
                   "vlans": [{"name": "USERS", "id": "20", "subnet": "", "vrf": ""},
                             {"name": "CAMERAS", "id": "60", "subnet": "", "vrf": ""}],
                   "vrfs": []},
    },
}

NAME = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,62}$")
COMMON_KEYS = ("system", "access", "snmp", "syslog", "services")


class FabricError(ValueError):
    pass


def _s(v) -> str:
    return str(v if v is not None else "").strip()


def _int(v, label, lo, hi) -> int:
    try:
        n = int(_s(v))
    except ValueError:
        raise FabricError(f"{label} must be a number.") from None
    if not lo <= n <= hi:
        raise FabricError(f"{label} must be {lo}-{hi}.")
    return n


def _pool(text, label):
    try:
        net = ipaddress.IPv4Network(_s(text), strict=False)
    except ValueError:
        raise FabricError(f"{label} '{text}' is not an IPv4 network (example 10.255.0.0/24).") from None
    return net


class Switch:
    def __init__(self, name, role, model, index):
        self.name, self.role, self.model, self.index = name, role, model, index
        self.loopback = None
        self.asn = None
        self.mgmt = ""
        self.ports: list[dict] = []       # builder port groups
        self.ospf_ifaces: list[str] = []
        self.underlay_peers: list[tuple[str, int]] = []
        self.overlay_peers: list["Switch"] = []
        self.gateway = False
        self.vtep = True


def plan(spec: dict) -> dict:
    """Work out the switches, links and addressing. Raises FabricError."""
    f = copy.deepcopy(DEFAULTS)
    f.update({k: v for k, v in (spec or {}).items() if v is not None})
    flavor = f["flavor"] if f["flavor"] in FLAVORS else "erb"
    design = "ospf" if f.get("design") == "ospf" else "ebgp"
    prefix = re.sub(r"[^A-Za-z0-9-]+", "-", _s(f["prefix"]) or "fabric").strip("-")[:40] or "fabric"
    lo_pool = _pool(f["loopback_pool"], "Loopback pool")
    p2p_pool = _pool(f["p2p_pool"], "Link pool")
    if lo_pool.overlaps(p2p_pool):
        raise FabricError("The loopback pool and the link pool overlap.")
    asn_base = _int(f["asn_base"], "Base AS number", 1, 4294967000)
    vni_base = _int(f["vni_base"], "VNI base", 1, 16000000)

    for key in ("spine_model", "leaf_model", "core_model"):
        if f[key] not in models.MODELS:
            raise FabricError(f"Unknown model '{f[key]}'.")

    switches: list[Switch] = []
    links: list[dict] = []
    if flavor == "collapsed":
        cores = [Switch(f"{prefix}-core{i + 1}", "core", f["core_model"], i) for i in range(2)]
        switches = cores
        spines, leaves = [], cores
        try:
            core_ports = P.expand(f["core_links"])
        except ValueError as exc:
            raise FabricError(f"Core interconnect ports: {exc}") from None
        if not core_ports:
            raise FabricError("Pick at least one port that connects the two cores (two is better).")
        pairs = [(cores[0], p, cores[1], p) for p in core_ports]
    else:
        n_sp = _int(f["spines"], "Number of spines", 1, 4)
        n_lf = _int(f["leaves"], "Number of leaves", 1, 32)
        spines = [Switch(f"{prefix}-spine{i + 1}", "spine", f["spine_model"], i) for i in range(n_sp)]
        leaves = [Switch(f"{prefix}-leaf{i + 1}", "leaf", f["leaf_model"], i) for i in range(n_lf)]
        switches = spines + leaves
        try:
            sp_ports, lf_ports = P.expand(f["spine_ports"]), P.expand(f["leaf_ports"])
        except ValueError as exc:
            raise FabricError(f"Fabric ports: {exc}") from None
        if len(sp_ports) < n_lf:
            raise FabricError(f"Each spine needs one downlink per leaf: {n_lf} leaves but only "
                              f"{len(sp_ports)} spine ports ({f['spine_ports']}).")
        if len(lf_ports) < n_sp:
            raise FabricError(f"Each leaf needs one uplink per spine: {n_sp} spines but only "
                              f"{len(lf_ports)} leaf ports ({f['leaf_ports']}).")
        pairs = [(sp, sp_ports[li], lf, lf_ports[si]) for li, lf in enumerate(leaves) for si, sp in enumerate(spines)]

    # Loopbacks and AS numbers
    hosts = list(lo_pool.hosts()) if lo_pool.prefixlen < 31 else list(lo_pool)
    if len(hosts) < len(switches):
        raise FabricError(f"The loopback pool is too small for {len(switches)} switches.")
    for sw, ip in zip(switches, hosts):
        sw.loopback = str(ip)
    if design == "ebgp":
        for sw in switches:
            if sw.role == "spine" and flavor != "crb":
                sw.asn = asn_base               # spines share one AS
            elif sw.role == "spine":
                sw.asn = asn_base + sw.index    # CRB spines peer each other, so each needs its own AS
            elif sw.role == "leaf":
                sw.asn = asn_base + (len(spines) if flavor == "crb" else 1) + sw.index
            else:
                sw.asn = asn_base + sw.index
    else:
        for sw in switches:
            sw.asn = asn_base

    # Management addresses (optional)
    if _s(f.get("mgmt_pool")):
        mp = ipaddress.IPv4Interface(_s(f["mgmt_pool"]))
        start = int(mp.ip)
        for i, sw in enumerate(switches):
            addr = ipaddress.IPv4Address(start + i)
            if addr not in mp.network or addr == mp.network.broadcast_address:
                raise FabricError("The management range runs out of addresses.")
            sw.mgmt = f"{addr}/{mp.network.prefixlen}"

    # Point-to-point /31 links
    subnets = list(p2p_pool.subnets(new_prefix=31)) if p2p_pool.prefixlen <= 31 else []
    if len(subnets) < len(pairs):
        raise FabricError(f"The link pool is too small for {len(pairs)} links (each needs a /31).")
    for (a, ap, b, bp), net in zip(pairs, subnets):
        a_ip, b_ip = net[0], net[1]
        for sw, port, ip, peer, peer_ip in ((a, ap, a_ip, b, b_ip), (b, bp, b_ip, a, a_ip)):
            sw.ports.append({"name": f"TO-{peer.name.upper()}"[:60], "ports": port, "mode": "routed",
                             "address": f"{ip}/31", "mtu": "9216", "description": f"Fabric link to {peer.name} {pp(peer, a, b, ap, bp)}",
                             "edge": False})
            sw.ospf_ifaces.append(port)
            sw.underlay_peers.append((str(peer_ip), peer.asn))
        links.append({"a": a.name, "a_port": ap, "a_ip": f"{a_ip}/31", "b": b.name, "b_port": bp, "b_ip": f"{b_ip}/31"})

    # Who is a gateway / VTEP, and who peers in the overlay
    for sw in switches:
        if flavor == "collapsed":
            sw.gateway = True
        elif flavor == "erb":
            sw.gateway = sw.role == "leaf"
            sw.vtep = sw.role == "leaf"
        elif flavor == "crb":
            sw.gateway = sw.role == "spine"
        else:  # bridged
            sw.gateway = False
            sw.vtep = sw.role == "leaf"
    if flavor == "collapsed":
        cores[0].overlay_peers, cores[1].overlay_peers = [cores[1]], [cores[0]]
    else:
        for sp in spines:
            sp.overlay_peers = list(leaves) + ([s for s in spines if s is not sp] if flavor == "crb" else [])
        for lf in leaves:
            lf.overlay_peers = list(spines)

    # VLANs and VRFs
    vrfs = []
    for i, v in enumerate(x for x in f.get("vrfs") or [] if _s(x.get("name"))):
        name = _s(v["name"])
        if not NAME.match(name):
            raise FabricError(f"VRF name '{name}' must start with a letter.")
        vrfs.append({"name": name, "id": str(i + 11),   # 11+: RD loopback:1 is the switch EVPN instance
                      "l3vni": str(vni_base - 1000 + i + 1 if vni_base > 1000 else 9000 + i + 1)})
    vrf_names = {v["name"] for v in vrfs}
    vlans = []
    seen = set()
    for v in f.get("vlans") or []:
        name, vid = _s(v.get("name")), _s(v.get("id"))
        if not name and not vid:
            continue
        if not NAME.match(name):
            raise FabricError(f"VLAN name '{name}' must start with a letter.")
        if not vid.isdigit() or not 1 <= int(vid) <= 4094 or vid in seen:
            raise FabricError(f"VLAN {name}: ID must be 1-4094 and unique.")
        seen.add(vid)
        subnet = _s(v.get("subnet"))
        net = None
        if subnet:
            try:
                net = ipaddress.IPv4Network(subnet, strict=False)
            except ValueError:
                raise FabricError(f"VLAN {name}: '{subnet}' is not a subnet (example 10.20.0.0/24).") from None
            if net.num_addresses < 8:
                raise FabricError(f"VLAN {name}: subnet {net} is too small (needs a /29 or larger).")
        vrf = _s(v.get("vrf"))
        if vrf and vrf not in vrf_names:
            raise FabricError(f"VLAN {name}: VRF '{vrf}' is not in the VRF list.")
        vlans.append({"name": name, "id": vid, "net": net, "vrf": vrf, "vni": str(vni_base + int(vid))})
    if not vlans:
        raise FabricError("Add at least one VLAN to stretch over the fabric.")

    return {"flavor": flavor, "design": design, "switches": switches, "links": links, "vlans": vlans,
            "vrfs": vrfs, "spec": f, "cores": switches if flavor == "collapsed" else []}


def pp(peer, a, b, ap, bp) -> str:
    return f"port {bp if peer is b else ap}"


def _project(fab: dict, sw: Switch, base: dict) -> dict:
    """The builder project for one switch."""
    f, flavor, design = fab["spec"], fab["flavor"], fab["design"]
    p = {k: copy.deepcopy(base.get(k, {})) for k in COMMON_KEYS}
    p["version"] = 1
    p["name"] = sw.name
    p["switch"] = {"members": [{"fpc": 0, "model": sw.model, "serial": "", "role": "routing-engine"}]}
    p["system"]["hostname"] = sw.name
    if sw.mgmt:
        p["system"]["mgmt_address"] = sw.mgmt
        p["system"]["mgmt_gateway"] = _s(f.get("mgmt_gateway"))
        p["system"]["mgmt_vrf"] = True
    p.setdefault("services", {})["delete_first"] = True

    # VLANs: lean spines carry no VLANs at all.
    p["vlans"] = []
    gw_switches = [s for s in fab["switches"] if s.gateway]
    if sw.vtep:
        for v in fab["vlans"]:
            row = {"name": v["name"], "id": v["id"], "vni": v["vni"], "description": f"VNI {v['vni']}"}
            if sw.gateway and v["net"] is not None:
                # Each gateway keeps its own address at the top of the subnet; .1 is the shared anycast gateway.
                pos = gw_switches.index(sw)
                own = v["net"].broadcast_address - 1 - pos
                row["irb"] = f"{own}/{v['net'].prefixlen}"
                row["vga"] = str(v["net"].network_address + 1)
                row["vrf"] = v["vrf"]
            p["vlans"].append(row)

    p["ports"] = list(sw.ports)
    access = _s(f.get("access_ports"))
    if access and sw.role in ("leaf", "core") and sw.vtep:
        names = ", ".join(v["name"] for v in fab["vlans"])
        if f.get("access_mode") == "access":
            p["ports"].append({"name": "ACCESS", "ports": access, "mode": "access",
                               "vlan": _s(f.get("access_vlan")) or fab["vlans"][0]["name"], "edge": True,
                               "description": "Access ports"})
        else:
            p["ports"].append({"name": "ACCESS", "ports": access, "mode": "trunk", "vlans": names, "edge": False,
                               "description": "Access ports"})

    # Collapsed core: dual-homed access switches with ESI-LAG (same ESI on both cores).
    p["lags"] = []
    if fab["flavor"] == "collapsed" and _s(f.get("esi_links")):
        for k, port in enumerate(P.expand(f["esi_links"]), start=1):
            p["lags"].append({"name": f"ae{k}", "members": port, "lacp": "active", "lacp_fast": True, "mode": "trunk",
                              "vlans": ", ".join(v["name"] for v in fab["vlans"]),
                              "description": f"Access switch {k} (dual-homed to both cores)",
                              "esi": f"00:10:00:00:00:00:00:00:00:{k:02x}", "lacp_system_id": f"00:00:00:10:00:{k:02x}"})

    routing = {"loopback": f"{sw.loopback}/32", "asn": str(sw.asn), "ecmp": True, "static": [],
               "ospf": {"enabled": False, "areas": []}, "bgp_groups": []}
    policy = {"prefix_lists": [], "communities": [], "terms": []}
    if design == "ospf":
        routing["ospf"] = {"enabled": True, "reference_bandwidth": "100g", "export": "",
                           "areas": [{"area": "0.0.0.0", "type": "normal",
                                      "interfaces": ", ".join([*sw.ospf_ifaces, "lo0"]),
                                      "passive": "lo0", "p2p": ", ".join(sw.ospf_ifaces), "md5_key": ""}]}
    else:
        policy["terms"] = [{"policy": "UNDERLAY-EXPORT", "term": "loopback", "protocol": "direct",
                            "route_filter": f"{sw.loopback}/32 exact", "action": "accept"}]
        routing["bgp_groups"] = [{"name": "UNDERLAY", "type": "external",
                                  "neighbors": "\n".join(f"{ip} {asn}" for ip, asn in sw.underlay_peers),
                                  "export": "UNDERLAY-EXPORT", "multipath": True,
                                  "bfd": "1000" if f.get("bfd", True) else "", "description": "Fabric underlay"}]
    p["routing"] = routing
    p["policy"] = policy

    if design == "ospf":
        peers = "\n".join(o.loopback for o in sw.overlay_peers)
    else:
        peers = "\n".join(f"{o.loopback} {o.asn}" for o in sw.overlay_peers)
    rr = design == "ospf" and sw.role == "spine"
    p["evpn"] = {"enabled": True,
                 "role": "spine" if not sw.vtep else ("collapsed" if sw.role == "core" else "leaf"),
                 "overlay_type": "internal" if design == "ospf" else "external",
                 "peers": peers, "route_reflector": rr and sw.vtep,
                 "vrf_target": f"target:{_int(f['asn_base'], 'Base AS', 1, 4294967000)}:1",
                 "vrfs": copy.deepcopy(fab["vrfs"]) if sw.gateway else []}
    return p


def generate(spec: dict, base: dict | None = None) -> dict:
    """Plan the fabric and build every switch. Returns a JSON-friendly dict."""
    try:
        fab = plan(spec)
    except FabricError as exc:
        return {"error": str(exc)}
    base = base or {}
    out = []
    for sw in fab["switches"]:
        project = _project(fab, sw, base)
        res = build(project)
        out.append({"name": sw.name, "role": sw.role, "model": sw.model, "loopback": sw.loopback, "asn": sw.asn,
                    "mgmt": sw.mgmt, "gateway": sw.gateway, "vtep": sw.vtep,
                    "set": res.set_text, "hierarchy": res.hier_text,
                    "errors": res.errors,
                    # The licence / model reminders repeat on every switch; keep them once at fabric level.
                    "warnings": [w for w in res.warnings if "feature license" not in w["message"]
                                 and not (not sw.vtep and w["message"].startswith("No VLANs yet"))
                                 # ESI-LAG: the second link is on the other core.
                                 and not (fab["flavor"] == "collapsed" and "only one member port" in w["message"])],
                    "hashed": res.hashed, "project": project})
    notes = [
        "EVPN-VXLAN and BGP need a feature license on EX switches. Check with 'show system license'.",
        "All fabric links use MTU 9216, because VXLAN adds 50 bytes to every frame.",
    ]
    if fab["flavor"] == "bridged":
        notes.append("Bridged overlay: connect your firewall or router to a leaf as a trunk; it stays the default gateway.")
    if fab["flavor"] == "collapsed":
        notes.append("Connect access switch N to port N of the dual-homed list on BOTH cores and bundle both "
                     "uplinks into one LACP LAG on the access switch.")
    return {
        "flavor": fab["flavor"], "design": fab["design"], "notes": notes,
        "switches": out, "links": fab["links"],
        "vlans": [{"name": v["name"], "id": v["id"], "vni": v["vni"], "subnet": str(v["net"]) if v["net"] else "",
                   "gateway": str(v["net"].network_address + 1) if v["net"] and fab["flavor"] != "bridged" else "",
                   "vrf": v["vrf"]} for v in fab["vlans"]],
        "vrfs": fab["vrfs"],
    }


def plan_markdown(result: dict) -> str:
    lines = [f"# Fabric plan ({FLAVORS.get(result['flavor'], result['flavor'])})", "",
             "## Switches", "", "| Switch | Role | Model | Loopback | AS | Management |", "|---|---|---|---|---|---|"]
    for s in result["switches"]:
        lines.append(f"| {s['name']} | {s['role']} | {s['model']} | {s['loopback']} | {s['asn']} | {s['mgmt'] or '-'} |")
    lines += ["", "## Cabling", "", "| From | Port | IP | To | Port | IP |", "|---|---|---|---|---|---|"]
    for link in result["links"]:
        lines.append(f"| {link['a']} | {link['a_port']} | {link['a_ip']} | {link['b']} | {link['b_port']} | {link['b_ip']} |")
    lines += ["", "## VLANs", "", "| VLAN | ID | VNI | Subnet | Gateway | VRF |", "|---|---|---|---|---|---|"]
    for v in result["vlans"]:
        lines.append(f"| {v['name']} | {v['id']} | {v['vni']} | {v['subnet'] or '-'} | {v['gateway'] or '-'} | {v['vrf'] or '-'} |")
    if result["vrfs"]:
        lines += ["", "## VRFs", "", "| VRF | L3 VNI |", "|---|---|"]
        lines += [f"| {v['name']} | {v['l3vni']} |" for v in result["vrfs"]]
    lines += ["", "## Notes", ""] + [f"- {n}" for n in result["notes"]]
    return "\n".join(lines) + "\n"


def to_zip(result: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("fabric-plan.md", plan_markdown(result))
        for s in result["switches"]:
            zf.writestr(f"{s['name']}.set", s["set"])
            zf.writestr(f"{s['name']}.conf", s["hierarchy"])
    return buf.getvalue()
