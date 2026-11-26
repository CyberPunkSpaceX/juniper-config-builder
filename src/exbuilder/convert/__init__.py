"""Convert a switch config from one vendor to another.

1. A reader turns the pasted config into a builder project (the same JSON every vendor's
   builder uses), listing every line it could not read.
2. ``retarget()`` moves that project to the target vendor: ports by position onto the
   target model, LAG and interface names, and features the target cannot do are taken out.
3. The target vendor's own builder writes the config and checks it.

The report says what was not read, what was changed and what to check, so nothing
disappears silently.
"""

from __future__ import annotations

import copy
import re

from .. import importer, vendors
from ..generator import build
from . import ios, portmap

# Vendors a config can be read from, and how to recognise their configs.
READERS = {"juniper": "Junos (set or curly-brace)", "cisco": "Cisco IOS / IOS-XE", "arista": "Arista EOS",
           "nexus": "Cisco NX-OS", "dell": "Dell OS10"}

_SIGNS = [
    ("mikrotik", r"^/(?:interface|ip|system)\b"),
    ("fortiswitch", r"^config (?:system|switch) "),
    ("juniper", r"^set (?:system|interfaces|vlans|protocols) |^(?:system|interfaces|vlans|protocols) \{"),
    ("extreme", r"^(?:create vlan|configure vlan|configure snmp|enable sharing)"),
    ("procurve", r"^; J\w+ Configuration Editor|^\s+(?:un)?tagged \d|^trunk \S+ trk\d"),
    ("ruckus", r"^ver \d+\.\d|^stack unit|^\s*(?:un)?tagged ethe|^ ?router-interface ve"),
    ("aruba", r"ArubaOS-CX|^\s+vlan (?:access|trunk) |^interface \d+/\d+/\d+\s*$"),
    ("dell", r"^! Version 10\.|^interface ethernet\d+/\d+/\d+|^interface mgmt1/1/1"),
    ("nexus", r"^feature |^!Command: show running-config|^vpc domain|^interface Ethernet\d+/\d+"),
    ("arista", r"^! device: |^interface Ethernet\d+\s*$|^interface Management1|^management api http"),
    ("cisco", r"^interface (?:GigabitEthernet|TenGigabitEthernet|FastEthernet|TwoGigabitEthernet)|"
              r"^switch \d+ provision|^spanning-tree mode (?:rapid-)?pvst"),
]


def detect(text: str) -> str:
    """The vendor whose config this looks like, or ''."""
    text = text or ""
    best, score = "", 0
    for key, pat in _SIGNS:
        n = len(re.findall(pat, text, re.M))
        if n > score:
            best, score = key, n
    return best


def read(text: str, source: str) -> dict:
    """Source config -> {project, unparsed, notes}."""
    if source == "juniper":
        det = importer.detect_models(text)
        res = importer.parse(text, "", det["members"])
        res["project"].pop("_facts", None)
        return res
    if source in ("cisco", "arista", "nexus", "dell"):
        return ios.parse(text, source)
    raise ValueError(f"Reading {vendors.get(source).name} configs is not ready yet.")


def _iface_ref(src: str, dst: str, raw: str, move: portmap.PortMove, lags: dict) -> str | None:
    raw = raw.strip()
    m = portmap._VLAN_IF.match(raw)
    if m:
        return portmap.vlan_iface(dst, m.group(1))
    if portmap._LOOP.match(raw):
        return portmap.loopback(dst)
    n = portmap.lag_number(src, raw)
    if n is not None:
        return lags.get(n) or portmap.lag_name(dst, n)
    try:
        names = portmap.expand(src, raw)
    except ValueError:
        return None
    if len(names) == 1 and names[0] in move.map:
        return move.map[names[0]]
    return None


def retarget(project: dict, src: str, dst: str, model: str = "", source_model: str = "") -> dict:
    """Move a project from vendor ``src`` to ``dst``. Returns {project, changes, ports, model}."""
    p = copy.deepcopy(project)
    p["vendor"] = dst
    v = vendors.get(dst)
    changes: list[dict] = []

    def note(section, text, level="changed"):
        changes.append({"section": section, "level": level, "text": text})

    used: list[str] = []
    for row in p.get("ports", []):
        try:
            used.extend(portmap.expand(src, row.get("ports")))
        except ValueError:
            pass
    for row in p.get("lags", []):
        try:
            used.extend(portmap.expand(src, row.get("members")))
        except ValueError:
            pass
    used = list(dict.fromkeys(used))
    members = p["switch"].get("members") or [{"fpc": portmap.first_member(src), "model": ""}]
    if source_model:
        members = [dict(m, model=source_model) for m in members]
    move = portmap.PortMove(src, members, dst, model, used, v.has("virtual_chassis"),
                            mgmt=bool(p["system"].get("mgmt_address")),
                            l3=any(x.get("irb") for x in p.get("vlans", [])) or any(
                                r.get("mode") == "routed" for r in p.get("ports", [])))
    for n in move.notes:
        note("Switch", n)
    for n in move.checks:
        note("Ports", n, "check")
    if move.unknown:
        note("Ports", f"{len(move.unknown)} port(s) are not on the source switch model and were left out: "
                      f"{', '.join(move.unknown[:6])}{'…' if len(move.unknown) > 6 else ''}.", "lost")
    p["switch"]["members"] = move.dst_members
    p["switch"]["custom_ports"] = ""
    p["system"]["mgmt_interface"] = ""

    kept = []
    for row in p.get("ports", []):
        spec, lost = move.spec(row.get("ports"), row.get("name"))
        lost = [x for x in lost if x not in move.unknown and x not in move.dropped]
        if lost:
            note("Ports", f"Port group {row.get('name')}: {', '.join(lost[:6])} had no free port on the "
                          f"{move.dst_model} and were left out.", "lost")
        if not spec:
            note("Ports", f"Port group {row.get('name')} has no ports left, so it was dropped.", "lost")
            continue
        row["ports"] = spec
        kept.append(row)
    p["ports"] = kept

    lag_names: dict[int, str] = {}
    for row in p.get("lags", []):
        n = portmap.lag_number(src, row.get("name")) or (len(lag_names) + 1)
        new = portmap.lag_name(dst, n)
        lag_names[n] = new
        row["name"] = new
        spec, lost = move.spec(row.get("members"), row.get("name"))
        lost = [x for x in lost if x not in move.dropped]
        if lost:
            note("LAGs", f"{new}: member(s) {', '.join(lost)} had no port on the {move.dst_model}.", "lost")
        row["members"] = spec

    # OSPF interface names
    for area in p["routing"].get("ospf", {}).get("areas", []):
        for key in ("interfaces", "passive", "p2p"):
            out = []
            from .. import ports as P
            for raw in P.iface_list(area.get(key)):
                new = _iface_ref(src, dst, raw, move, lag_names)
                if new is None:
                    note("OSPF", f"Area {area.get('area')}: interface {raw} could not be matched and was left out.", "lost")
                else:
                    out.append(new)
            area[key] = ", ".join(out)
        costs = []
        for item in [x.strip() for x in str(area.get("metrics") or "").split(",") if x.strip()]:
            raw, _, cost = item.rpartition(" ")
            new = _iface_ref(src, dst, raw, move, lag_names) if raw else None
            if new is None:
                note("OSPF", f"Area {area.get('area')}: cost on {raw or item} could not be matched and was left out.", "lost")
            else:
                costs.append(f"{new} {cost}")
        area["metrics"] = ", ".join(costs)
        if dst != "juniper":
            if area.get("metrics"):
                note("OSPF", f"Area {area.get('area')}: interface costs ({area['metrics']}) are only written for Juniper; set them by hand.", "lost")
            if area.get("ranges"):
                note("OSPF", f"Area {area.get('area')}: area ranges ({area['ranges']}) are only written for Juniper; set them by hand.", "lost")
            area["metrics"] = area["ranges"] = ""

    # Features the target can't do.
    def gone(feature, section, what):
        note(section, f"{what} is not available for {v.name} in the builder, so it was left out.", "lost")

    r = p["routing"]
    if r.get("ospf", {}).get("enabled") and not v.has("ospf"):
        r["ospf"]["enabled"] = False
        gone("ospf", "Routing", "OSPF")
    if r.get("bgp_groups") and not v.has("bgp"):
        r["bgp_groups"] = []
        gone("bgp", "Routing", "BGP")
    if p.get("evpn", {}).get("enabled") and not v.has("evpn_vxlan"):
        p["evpn"]["enabled"] = False
        gone("evpn", "EVPN-VXLAN", "EVPN-VXLAN")
    if any(p.get("policy", {}).get(k) for k in ("prefix_lists", "communities", "terms")) and not v.has("policies"):
        p["policy"] = {"prefix_lists": [], "communities": [], "terms": []}
        gone("policies", "Routing", "Routing policies")
    if p.get("qos", {}).get("enabled") and not v.has("qos"):
        p["qos"]["enabled"] = False
        gone("qos", "QoS", "QoS")
    for row in [*p.get("ports", []), *p.get("lags", [])]:
        label = f"Port group {row.get('name')}"
        if row.get("dot1x") and not v.has("dot1x"):
            row["dot1x"] = ""
            gone("dot1x", "Ports", f"{label}: 802.1X")
        if (row.get("poe") or row.get("poe_max")) and not v.has("poe"):
            row["poe"] = row["poe_max"] = ""
            gone("poe", "Ports", f"{label}: PoE settings")
        if row.get("vlan_translate") and not v.has("vlan_translation"):
            row["vlan_translate"] = ""
            gone("vlan_translation", "Ports", f"{label}: VLAN translation")
        if row.get("esi") and not v.has("evpn_vxlan"):
            row["esi"] = ""
    if p.get("access", {}).get("ssh_from") and dst != "juniper":
        note("Access", f"SSH was limited to {p['access']['ssh_from']} on the old switch; the builder only writes "
                       f"that filter for Juniper, so add it by hand.", "lost")
        p["access"]["ssh_from"] = ""
    if p["security"].get("radius_servers") and not v.has("dot1x"):
        p["security"]["radius_servers"] = []

    # Hashed passwords only work on the vendor that made them.
    if src != dst:
        a = p["access"]
        if str(a.get("root_password") or "").startswith("$"):
            a["root_password"] = ""
            note("Access", "The enable/root password was stored as a hash that can't be carried over. "
                           "Type a new one on the Access tab.", "check")
        for u in a.get("users", []):
            if str(u.get("password") or "").startswith("$"):
                u["password"] = ""
                note("Access", f"User {u.get('name')}: the password hash can't be carried over. Type a new one.", "check")
        if a.get("root_ssh_key") and dst != "juniper":
            pass
    if p["system"].get("timezone") and dst != "juniper" and "/" not in p["system"]["timezone"] and \
            p["system"]["timezone"] != "UTC":
        note("Switch", f"Time zone {p['system']['timezone']} may not exist on {v.name}; check it.", "check")
    return {"project": p, "changes": changes, "ports": move.table, "model": move.dst_model, "guessed": move.guessed,
            "source_models": move.src_models}


def convert(text: str, source: str = "", target: str = "juniper", model: str = "", source_model: str = "") -> dict:
    """Pasted config -> {source, target, project, config, report}."""
    source = source or detect(text)
    if not source:
        return {"error": "Couldn't tell which vendor this config is from. Pick the source vendor."}
    if source not in READERS:
        return {"error": f"Reading {vendors.get(source).name} configs is not ready yet. "
                         f"Ready now: {', '.join(vendors.get(k).name for k in READERS)}."}
    if not vendors.known(target):
        return {"error": "Pick a target vendor."}
    if model and portmap.model(target, model) is None:
        return {"error": f"'{model}' is not a {vendors.get(target).name} model."}
    try:
        got = read(text, source)
    except ValueError as e:
        return {"error": str(e)}
    if source_model and portmap.model(source, source_model) is None:
        source_model = ""
    moved = retarget(got["project"], source, target, model, source_model)
    p = moved["project"]
    res = build(p).to_dict()
    return {
        "source": source, "target": target, "model": moved["model"], "source_models": moved["source_models"],
        "project": p, "config": res.get("set", ""), "hierarchy": res.get("hierarchy", ""),
        "errors": res.get("errors", []), "warnings": res.get("warnings", []), "hashed": res.get("hashed", {}),
        "not_read": got.get("unparsed", []), "notes": got.get("notes", []), "changes": moved["changes"],
        "ports": moved["ports"], "source_models_guessed": bool(moved.get("guessed")),
        "stats": {"vlans": len(p["vlans"]), "port_groups": len(p["ports"]), "lags": len(p["lags"]),
                  "not_read": len(got.get("unparsed", []))},
    }
