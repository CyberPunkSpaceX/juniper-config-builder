"""Network map: read several switch configs, find the links between them and
check that both ends of each link agree.

Links are found in three ways, best first:

* LLDP: ``show lldp neighbors`` output pasted with (or after) a config names the
  remote switch and usually its port.
* Point-to-point addresses: two routed ports (or LAGs) whose addresses sit in the
  same /30 or /31 (/127 for IPv6).
* Descriptions: a port description that names another switch's host name, for
  example ``uplink to core-sw1 xe-0/1/0``.

Ports that belong to the same LAG on both ends are folded into one LAG link.
Everything is plain data so the web page can draw it.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from . import ports as P
from .importer import _words, detect_models, to_set_lines

IFACE = re.compile(r"^(?:ge|xe|mge|et|ae)-?\d")
PHYS = re.compile(r"^(?:ge|xe|mge|et)-\d{1,2}/\d{1,2}/\d{1,3}$")
MAC = re.compile(r"^(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
LLDP_LINE = re.compile(r"^\s*((?:ge|xe|mge|et)-\d{1,2}/\d{1,2}/\d{1,3}(?:\.\d+)?)\s+(.+)$")
MGMT = ("me0", "em0", "vme", "fxp0")
DEFAULT_MTU = 1514
MAX_SWITCHES = 60


def _iface(d: dict, name: str) -> dict:
    return d.setdefault(name, {"desc": "", "mode": "", "vlans": [], "native": "", "mtu": "", "addrs": [],
                               "lag": "", "disabled": False})


def _priority(value: str) -> int | None:
    v = value.lower().rstrip("k")
    if not v.isdigit():
        return None
    n = int(v)
    return n * 1024 if value.lower().endswith("k") else n


def _split_lldp(text: str) -> tuple[str, list[dict]]:
    """Pull 'show lldp neighbors' rows out of the text. Returns (rest, rows)."""
    rest, rows = [], []
    for line in (text or "").replace("\r\n", "\n").split("\n"):
        m = LLDP_LINE.match(line)
        if m and not line.lstrip().startswith(("set ", "interfaces")):
            toks = m.group(2).split()
            # Local Interface  [Parent Interface]  Chassis Id  Port info ...  System Name
            if len(toks) >= 3:
                parent = ""
                if not MAC.match(toks[0]) and len(toks) >= 4 and MAC.match(toks[1]):
                    parent = "" if toks[0] == "-" else toks[0]
                    toks = toks[1:]
                if MAC.match(toks[0]):
                    rows.append({"local": m.group(1).split(".")[0], "parent": parent, "chassis": toks[0].lower(),
                                 "port": " ".join(toks[1:-1]), "system": toks[-1]})
                    continue
        rest.append(line)
    return "\n".join(rest), rows


def read_switch(text: str, label: str = "", lldp: str = "") -> dict:
    """One switch config (set or curly-brace) -> the facts the map needs."""
    text, rows = _split_lldp(text)
    if lldp:
        rows += _split_lldp(lldp)[1]
    lines = to_set_lines(text)
    ifs: dict[str, dict] = {}
    ranges: dict[str, list[str]] = defaultdict(list)
    vlans: dict[str, int] = {}
    irb: dict[str, list[str]] = defaultdict(list)
    sw = {"hostname": "", "version": "", "mgmt": "", "loopback": [], "priority": None, "label": label}
    for line in lines:
        w = [x for x in _words(line) if x not in ("[", "]")]
        if len(w) < 2:
            continue
        if w[:2] == ["system", "host-name"] and len(w) > 2:
            sw["hostname"] = w[2]
        elif w[0] == "version":
            sw["version"] = w[1].rstrip(";")
        elif w[0] == "vlans" and len(w) >= 4 and w[2] == "vlan-id" and w[3].isdigit():
            vlans[w[1]] = int(w[3])
        elif w[0] == "protocols" and len(w) >= 4 and w[1] in ("rstp", "mstp", "stp") and w[2] == "bridge-priority":
            sw["priority"] = _priority(w[3])
        elif w[0] == "interfaces" and len(w) >= 3:
            name = w[1]
            if name == "interface-range":
                if len(w) >= 5 and w[3] == "member":
                    ranges[w[2]].append(w[4])
                    continue
                if len(w) >= 7 and w[3] == "member-range" and w[5] == "to":
                    first, last = w[4], w[6]
                    prefix = first.rsplit("/", 1)[0]
                    if last.startswith(prefix + "/"):
                        ranges[w[2]].append(f"{first}-{last.rsplit('/', 1)[1]}")
                    else:
                        ranges[w[2]] += [first, last]
                    continue
                name, rest = "range:" + w[2], w[3:]
            else:
                rest = w[2:]
            if name in MGMT or name == "lo0" or name == "irb":
                unit = rest[1] if len(rest) > 1 and rest[0] == "unit" else "0"
                if "address" in rest:
                    addr = rest[rest.index("address") + 1]
                    if name in MGMT and not sw["mgmt"]:
                        sw["mgmt"] = addr
                    elif name == "lo0":
                        sw["loopback"].append(addr)
                    elif name == "irb":
                        irb[unit].append(addr)
                continue
            d = _iface(ifs, name)
            if rest[0] == "description":
                d["desc"] = " ".join(rest[1:])
            elif rest[0] == "disable":
                d["disabled"] = True
            elif rest[0] == "mtu" and len(rest) > 1:
                d["mtu"] = rest[1]
            elif rest[0] == "native-vlan-id" and len(rest) > 1:
                d["native"] = rest[1]
            elif rest[0] in ("ether-options", "gigether-options") and len(rest) >= 3 and rest[1] == "802.3ad":
                d["lag"] = rest[2]
            elif rest[0] == "unit" and len(rest) >= 4:
                tail = rest[2:]
                if tail[:2] == ["family", "ethernet-switching"]:
                    t = tail[2:]
                    if len(t) >= 2 and t[0] in ("interface-mode", "port-mode"):
                        d["mode"] = t[1]
                    elif len(t) >= 3 and t[:2] == ["vlan", "members"]:
                        d["vlans"] += t[2:]
                elif tail[:1] == ["family"] and "address" in tail:
                    d["addrs"].append(tail[tail.index("address") + 1])
    # Interface ranges hand their settings to each member.
    for rname, members in ranges.items():
        settings = ifs.pop("range:" + rname, None)
        if not settings:
            continue
        try:
            names = P.expand(", ".join(members))
        except ValueError:
            names = [m for m in members if PHYS.match(m)]
        for n in names:
            d = _iface(ifs, n)
            for k, v in settings.items():
                if isinstance(v, list):
                    d[k] = d[k] + v if d[k] else list(v)
                elif v and not d[k]:
                    d[k] = v
    for d in ifs.values():
        if not d["mode"] and d["vlans"]:
            d["mode"] = "access"
        if d["addrs"]:
            d["mode"] = "routed"
    # The model from 'show version' / 'show virtual-chassis' output when it is there.
    # A guess from the port names only when enough ports are configured to tell models apart.
    seen = {n for n in ifs if PHYS.match(n)}
    det = detect_models(text)["members"]
    first = det.get(min(det)) if det else None
    model = ""
    if first and (first["how"] != "port names" or len(seen) >= 10):
        model = first["model"] + ("?" if first["how"] == "port names" else "")
        if len(det) > 1:
            model += f" +{len(det) - 1}"
    sw.update({"ifs": ifs, "vlans": vlans, "irb": dict(irb), "lldp": rows, "model": model, "lines": len(lines)})
    return sw


# ------------------------------------------------------------------ helpers
def _norm(host: str) -> str:
    return host.lower().split(".")[0]


def _vlan_ids(sw: dict, refs: list[str]) -> set[int] | None:
    """VLAN names/IDs/ranges -> IDs. None means 'all'."""
    out: set[int] = set()
    lower = {k.lower(): v for k, v in sw["vlans"].items()}
    for r in refs:
        if r.lower() == "all":
            return None
        if r.isdigit():
            out.add(int(r))
        elif re.match(r"^\d+-\d+$", r):
            a, b = map(int, r.split("-"))
            out.update(range(a, b + 1))
        elif r.lower() in lower:
            out.add(lower[r.lower()])
    return out


def _fmt_vlans(ids: set[int]) -> str:
    return ", ".join(str(i) for i in sorted(ids)[:12]) + (" …" if len(ids) > 12 else "")


def _side(sw: dict, name: str) -> dict:
    """The settings that matter for a port: its LAG's when it is a LAG member."""
    d = sw["ifs"].get(name, {})
    if d.get("lag") and d["lag"] in sw["ifs"]:
        merged = dict(sw["ifs"][d["lag"]])
        merged["disabled"] = d.get("disabled") or merged.get("disabled")
        return merged
    return d


def _p2p(addr: str):
    try:
        iface = ipaddress.ip_interface(addr)
    except ValueError:
        return None
    if (iface.version == 4 and iface.network.prefixlen in (30, 31)) or (iface.version == 6 and iface.network.prefixlen == 127):
        return iface
    return None


# -------------------------------------------------------------------- build
def analyze(items: list[dict]) -> dict:
    """items: [{"text": config, "name": optional label, "lldp": optional}] -> map data."""
    switches, checks = [], []
    for i, it in enumerate(items[:MAX_SWITCHES]):
        sw = read_switch(str(it.get("text") or ""), str(it.get("name") or ""), str(it.get("lldp") or ""))
        if not sw["lines"]:
            checks.append({"level": "error", "message": f"{sw['label'] or f'Config {i + 1}'}: no configuration found."})
            continue
        sw["id"] = len(switches)
        sw["hostname"] = sw["hostname"] or sw["label"] or f"switch-{i + 1}"
        switches.append(sw)
    if len(items) > MAX_SWITCHES:
        checks.append({"level": "warn", "message": f"Only the first {MAX_SWITCHES} configs are drawn."})

    by_host: dict[str, list[int]] = defaultdict(list)
    for sw in switches:
        by_host[_norm(sw["hostname"])].append(sw["id"])
    for host, ids in by_host.items():
        if len(ids) > 1:
            checks.append({"level": "error", "message": f"Host name {host} is used by {len(ids)} configs.", "switches": ids})

    links: dict[tuple, dict] = {}

    def add(a: int, ai: str, b: int, bi: str | None, how: str):
        if a == b:
            return
        if (b, bi) < (a, ai) and bi:
            a, ai, b, bi = b, bi, a, ai
        # A link already known for either end wins; fill in a missing remote port.
        for key, link in links.items():
            ends = {(link["a"], link["a_if"]), (link["b"], link["b_if"])}
            if (a, ai) in ends or (bi and (b, bi) in ends):
                other = (b, bi) if (a, ai) in ends else (a, ai)
                if link["b_if"] is None and link["b"] == other[0] and other[1]:
                    link["b_if"] = other[1]
                if link["a_if"] is None and link["a"] == other[0] and other[1]:
                    link["a_if"] = other[1]
                if how not in link["found"]:
                    link["found"].append(how)
                return
        links[(a, ai, b, bi)] = {"a": a, "a_if": ai, "b": b, "b_if": bi, "found": [how]}

    # 1. LLDP
    for sw in switches:
        for row in sw["lldp"]:
            ids = by_host.get(_norm(row["system"]))
            if not ids:
                continue
            other = switches[ids[0]]
            port = row["port"].split()[0] if row["port"] else ""
            remote = port.split(".")[0] if port.split(".")[0] in other["ifs"] or PHYS.match(port.split(".")[0]) else None
            if remote is None and row["port"]:
                hits = [n for n, d in other["ifs"].items() if d["desc"] and d["desc"] == row["port"]]
                remote = hits[0] if len(hits) == 1 else None
            add(sw["id"], row["local"], other["id"], remote, "LLDP")

    # 2. Point-to-point subnets
    nets: dict = defaultdict(list)
    for sw in switches:
        for name, d in sw["ifs"].items():
            for addr in d["addrs"]:
                if (iface := _p2p(addr)):
                    nets[iface.network].append((sw["id"], name, iface))
    for net, ends in nets.items():
        if len({e[0] for e in ends}) == 2 and len(ends) == 2:
            add(ends[0][0], ends[0][1], ends[1][0], ends[1][1], "addresses")

    # 3. Descriptions naming another switch
    hosts = {h: ids[0] for h, ids in by_host.items() if len(h) >= 3}
    for sw in switches:
        for name, d in sw["ifs"].items():
            if not d["desc"]:
                continue
            text = d["desc"].lower()
            for host, oid in hosts.items():
                if oid == sw["id"] or not re.search(rf"(?<![\w-]){re.escape(host)}(?![\w-])", text):
                    continue
                other = switches[oid]
                # A port on the other switch whose description names us, and the
                # remote port written in our description, pin down the far end.
                remote = None
                named = re.findall(r"\b((?:ge|xe|mge|et)-\d{1,2}/\d{1,2}/\d{1,3}|ae\d+)\b", d["desc"])
                named = [n for n in named if n in other["ifs"]]
                if len(named) == 1:
                    remote = named[0]
                else:
                    me = _norm(sw["hostname"])
                    back = [n for n, od in other["ifs"].items()
                            if od["desc"] and re.search(rf"(?<![\w-]){re.escape(me)}(?![\w-])", od["desc"].lower())]
                    if len(back) == 1:
                        remote = back[0]
                # A LAG member stands for its LAG: one link per LAG, not one per member.
                local = d["lag"] or name
                if remote and other["ifs"].get(remote, {}).get("lag"):
                    remote = other["ifs"][remote]["lag"]
                add(sw["id"], local, oid, remote, "description")

    # Fold LAG members into one link per LAG pair; drop member links that duplicate an 'ae' link.
    out, lag_links = [], {}
    for link in links.values():
        a, b = switches[link["a"]], switches[link["b"]]
        la = a["ifs"].get(link["a_if"], {}).get("lag", "") if link["a_if"] else ""
        lb = b["ifs"].get(link["b_if"], {}).get("lag", "") if link["b_if"] else ""
        if la and lb:
            key = (link["a"], la, link["b"], lb)
            lag = lag_links.get(key)
            if not lag:
                lag = lag_links[key] = {"a": link["a"], "a_if": la, "b": link["b"], "b_if": lb, "found": [],
                                        "members": []}
                out.append(lag)
            lag["members"].append([link["a_if"], link["b_if"]])
            lag["found"] = sorted(set(lag["found"]) | set(link["found"]))
        else:
            link["members"] = []
            out.append(link)
    # An ae-to-ae link found from addresses or descriptions merges into the member-built one.
    final = []

    def same(x, y):
        ex, ey = {(x["a"], x["a_if"]), (x["b"], x["b_if"])}, {(y["a"], y["a_if"]), (y["b"], y["b_if"])}
        if ex == ey:
            return True
        # One end unknown: the same known end towards the same switch is the same link.
        if {x["a"], x["b"]} != {y["a"], y["b"]}:
            return False
        known_x = {e for e in ex if e[1]}
        known_y = {e for e in ey if e[1]}
        return (len(known_x) == 1 or len(known_y) == 1) and bool(known_x & known_y)

    for link in sorted(out, key=lambda x: -(bool(x["a_if"]) + bool(x["b_if"]))):
        dup = next((x for x in final if same(x, link)), None)
        if dup:
            dup["found"] = sorted(set(dup["found"]) | set(link["found"]))
            dup["members"] += link["members"]
        else:
            final.append(link)

    # Several ports towards the same switch with the far end unknown: one line, not one per port.
    grouped, loose = [], defaultdict(list)
    for link in final:
        if link["a_if"] and not link["b_if"] and not link["members"]:
            loose[(link["a"], link["b"])].append(link)
        else:
            grouped.append(link)
    for (a, b), group in loose.items():
        if len(group) == 1:
            grouped.append(group[0])
            continue
        names = [x["a_if"] for x in group]
        grouped.append({"a": a, "a_if": P.compact(names) if all(PHYS.match(n) for n in names) else ", ".join(names),
                        "b": b, "b_if": None, "found": sorted({f for x in group for f in x["found"]}),
                        "members": [[n, "?"] for n in names], "ports": names})
    final = grouped

    for n, link in enumerate(final):
        _check_link(switches, link, n, checks)

    _check_network(switches, final, checks)
    return {
        "switches": [{"id": s["id"], "hostname": s["hostname"], "label": s["label"], "model": s["model"],
                      "version": s["version"], "mgmt": s["mgmt"], "loopback": s["loopback"][:1],
                      "priority": s["priority"], "vlans": len(s["vlans"]), "lldp": len(s["lldp"]),
                      "ports": sum(1 for k in s["ifs"] if PHYS.match(k))} for s in switches],
        "links": final,
        "checks": checks,
    }


def _kind(d: dict, name: str) -> str:
    if name and name.startswith("ae"):
        return "lag"
    return d.get("mode") or "unknown"


def _check_link(switches: list[dict], link: dict, n: int, checks: list[dict]) -> None:
    a, b = switches[link["a"]], switches[link["b"]]
    da = _side(a, (link.get("ports") or [link["a_if"]])[0]) if link["a_if"] else {}
    db = _side(b, link["b_if"]) if link["b_if"] else {}
    link["kind"] = _kind(da, (link.get("ports") or [link["a_if"]])[0]) if link["a_if"] else _kind(db, link["b_if"] or "")
    if link["kind"] == "lag":
        link["mode"] = da.get("mode") or db.get("mode") or ""
    issues = link["issues"] = []
    name_a = f"{a['hostname']} {link['a_if'] or '?'}"
    name_b = f"{b['hostname']} {link['b_if'] or '?'}"

    def issue(level, msg):
        issues.append({"level": level, "message": msg})
        checks.append({"level": level, "message": msg, "link": n, "switches": [a["id"], b["id"]]})

    if not (link["a_if"] and link["b_if"]):
        issue("info", f"{name_a} ↔ {name_b}: the far-end port is not known (found from {', '.join(link['found'])}). "
                      "Add 'show lldp neighbors' output to check both ends.")
        return
    for sw, port, d in ((a, link["a_if"], da), (b, link["b_if"], db)):
        if not sw["ifs"].get(port):
            issue("warn", f"{sw['hostname']} {port} is not in its config (LLDP sees it, but it has no settings).")
            return
        if d.get("disabled") or sw["ifs"][port].get("disabled"):
            issue("warn", f"{sw['hostname']} {port} is disabled, so this link is down.")
    # LAG on one side only
    pa, pb = a["ifs"].get(link["a_if"], {}), b["ifs"].get(link["b_if"], {})
    if bool(pa.get("lag")) != bool(pb.get("lag")) and not (link["a_if"].startswith("ae") and link["b_if"].startswith("ae")):
        lagged = name_a if pa.get("lag") else name_b
        issue("error", f"{lagged} is in a LAG but the other end ({name_b if pa.get('lag') else name_a}) is not.")
    ma, mb = da.get("mode") or "", db.get("mode") or ""
    if ma and mb and ma != mb:
        issue("error", f"{name_a} is {ma} but {name_b} is {mb}.")
        ma = mb = ""
    for sw, port, d in ((a, link["a_if"], da), (b, link["b_if"], db)):
        known = {k.lower() for k in sw["vlans"]}
        missing = [v for v in d.get("vlans", []) if not v.isdigit() and v.lower() != "all"
                   and not re.match(r"^\d+-\d+$", v) and v.lower() not in known]
        if missing:
            issue("error", f"{sw['hostname']} {port} uses VLAN {', '.join(missing)}, which is not defined on {sw['hostname']}.")
    if ma == mb == "trunk":
        va, vb = _vlan_ids(a, da.get("vlans", [])), _vlan_ids(b, db.get("vlans", []))
        all_a = set(a["vlans"].values()) if va is None else va
        all_b = set(b["vlans"].values()) if vb is None else vb
        if va is not None or vb is not None:
            only_a, only_b = all_a - all_b, all_b - all_a
            if only_a:
                issue("warn", f"VLAN {_fmt_vlans(only_a)} allowed on {name_a} but not on {name_b}.")
            if only_b:
                issue("warn", f"VLAN {_fmt_vlans(only_b)} allowed on {name_b} but not on {name_a}.")
        na, nb = da.get("native") or "", db.get("native") or ""
        if na != nb:
            issue("error", f"Native VLAN differs: {name_a} {na or 'none'}, {name_b} {nb or 'none'}.")
    elif ma == mb == "access":
        va, vb = _vlan_ids(a, da.get("vlans", [])), _vlan_ids(b, db.get("vlans", []))
        if va and vb and va != vb:
            issue("warn", f"Access VLAN differs: {name_a} {_fmt_vlans(va)}, {name_b} {_fmt_vlans(vb)}.")
    elif ma == mb == "routed":
        nets_a = {ipaddress.ip_interface(x).network for x in da.get("addrs", []) if _p2p(x)}
        nets_b = {ipaddress.ip_interface(x).network for x in db.get("addrs", []) if _p2p(x)}
        if nets_a and nets_b and not nets_a & nets_b:
            issue("error", f"{name_a} and {name_b} are routed but not in the same subnet.")
    mtu_a, mtu_b = int(da.get("mtu") or DEFAULT_MTU), int(db.get("mtu") or DEFAULT_MTU)
    if mtu_a != mtu_b:
        issue("warn", f"MTU differs: {name_a} {mtu_a}, {name_b} {mtu_b}.")


def _check_network(switches: list[dict], links: list[dict], checks: list[dict]) -> None:
    # Same address on two switches
    seen: dict[str, int] = {}
    for sw in switches:
        addrs = [sw["mgmt"]] + sw["loopback"] + [a for v in sw["irb"].values() for a in v] + \
                [a for d in sw["ifs"].values() for a in d["addrs"]]
        for addr in filter(None, addrs):
            ip = addr.split("/")[0]
            if ip in seen and seen[ip] != sw["id"]:
                checks.append({"level": "error", "message": f"Address {ip} is on both {switches[seen[ip]]['hostname']} and {sw['hostname']}.",
                               "switches": [seen[ip], sw["id"]]})
            seen.setdefault(ip, sw["id"])
    # VLAN IDs with different names
    names: dict[int, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    for sw in switches:
        for name, vid in sw["vlans"].items():
            names[vid][name].append(sw["hostname"])
    for vid, by in sorted(names.items()):
        if len(by) > 1:
            parts = "; ".join(f"{n} on {', '.join(h)}" for n, h in by.items())
            checks.append({"level": "info", "message": f"VLAN {vid} has different names: {parts}."})
    # Spanning tree root
    if len(switches) > 1:
        prios = [(s["priority"] if s["priority"] is not None else 32768, s) for s in switches]
        low = min(p for p, _ in prios)
        roots = [s for p, s in prios if p == low]
        if all(s["priority"] is None for s in switches):
            checks.append({"level": "warn", "message": "No switch sets a spanning-tree bridge priority, so the root is "
                           "whichever has the lowest MAC address. Give the core 4k (and a backup 8k)."})
        elif len(roots) > 1:
            checks.append({"level": "warn", "message": f"Spanning-tree root is a tie at priority {low}: "
                           f"{', '.join(s['hostname'] for s in roots)}. Give one of them a lower value.",
                           "switches": [s["id"] for s in roots]})
        else:
            checks.append({"level": "info", "message": f"Spanning-tree root: {roots[0]['hostname']} (priority {low}).",
                           "switches": [roots[0]["id"]]})
        linked = {x for link in links for x in (link["a"], link["b"])}
        for s in switches:
            if s["id"] not in linked:
                checks.append({"level": "info", "message": f"{s['hostname']}: no link to the other switches was found.",
                               "switches": [s["id"]]})
