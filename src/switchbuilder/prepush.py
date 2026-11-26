"""Pre-push checks: look at several builder projects together before they go on real switches.

A single project is checked by its own builder. These checks find what only shows up across switches:

* the same host name, or the same IP address (management, loopback, VLAN interface, routed port) on two
  switches, and one subnet used for different VLANs;
* a VLAN ID with different names, or a VLAN name with different IDs;
* links whose two ends disagree: access on one end and trunk on the other, a LAG on one end only, different
  native VLANs, VLANs allowed on one end only, both ends LACP passive, routed ends in different subnets, or
  different MTUs;
* VLANs used on a switch's ports that no uplink carries, so they cannot reach the rest of the network;
* spanning tree: different protocols, no bridge priority anywhere, or a tie for the root.

Links come from port-group and LAG descriptions that name another switch's host name (``To core-sw1``), and
from links the user adds by hand. Everything is plain data for the web page and for scripts.
"""

from __future__ import annotations

import ipaddress
import re
from collections import defaultdict

from .generator import build

MAX_SWITCHES = 100
LEVELS = ("error", "warn", "info")


def _s(v) -> str:
    return "" if v is None else str(v).strip()


def _list(v) -> list[str]:
    if isinstance(v, list):
        return [_s(x) for x in v if _s(x)]
    return [x.strip() for x in re.split(r"[,\s]+", _s(v)) if x.strip()]


def _iface(addr: str):
    try:
        return ipaddress.ip_interface(_s(addr))
    except ValueError:
        return None


class Switch:
    def __init__(self, idx: int, label: str, p: dict):
        self.idx = idx
        self.p = p
        sysd = p.get("system") or {}
        self.host = _s(sysd.get("hostname")) or label or f"switch-{idx + 1}"
        self.label = label or self.host
        self.vendor = _s(p.get("vendor")) or "juniper"
        self.vlan_id: dict[str, int] = {}   # lower-case name -> id
        self.vlan_name: dict[int, str] = {}
        self.irb: dict[int, list] = {}
        for v in p.get("vlans") or []:
            if not isinstance(v, dict):
                continue
            try:
                vid = int(_s(v.get("id")))
            except ValueError:
                continue
            name = _s(v.get("name")) or str(vid)
            self.vlan_id[name.lower()] = vid
            self.vlan_name[vid] = name
            addrs = [a for a in (_iface(x) for x in _list(v.get("irb"))) if a]
            if addrs:
                self.irb[vid] = addrs
        self.rows: dict[str, dict] = {}
        for kind, key in (("port", "ports"), ("lag", "lags")):
            for i, r in enumerate(p.get(key) or []):
                if not isinstance(r, dict):
                    continue
                name = _s(r.get("name")) or (_s(r.get("ports")) if kind == "port" else f"lag{i}")
                self.rows[name] = {"kind": kind, "name": name, "row": r, "mode": _s(r.get("mode")) or
                                   ("trunk" if kind == "lag" else "access"),
                                   "desc": _s(r.get("description")), "mtu": _s(r.get("mtu")),
                                   "ports": _s(r.get("members") if kind == "lag" else r.get("ports"))}
        services = p.get("services") or {}
        self.stp = _s(services.get("stp")) or "rstp"
        prio = _s(services.get("bridge_priority")).lower()
        self.priority = None
        if prio:
            try:
                self.priority = int(prio[:-1]) * 1024 if prio.endswith("k") else int(prio)
            except ValueError:
                self.priority = None
        self.mgmt = _iface(sysd.get("mgmt_address"))
        self.loopback = [a for a in (_iface(x) for x in _list((p.get("routing") or {}).get("loopback"))) if a]

    def ids(self, refs: list[str]) -> set[int] | None:
        """VLAN references (names, IDs, ranges, 'all') -> IDs; None means all VLANs."""
        out: set[int] = set()
        for r in refs:
            low = r.lower()
            if low == "all":
                return None
            if low in self.vlan_id:
                out.add(self.vlan_id[low])
            elif r.isdigit():
                out.add(int(r))
            elif (m := re.match(r"^(\d+)-(\d+)$", r)) and int(m.group(1)) <= int(m.group(2)) <= 4094:
                out.update(range(int(m.group(1)), int(m.group(2)) + 1))
        return out

    def one(self, ref) -> int | None:
        got = self.ids(_list(ref)) if _s(ref) else set()
        return next(iter(sorted(got)), None) if got else None

    def allowed(self, info: dict) -> set[int]:
        """VLAN IDs a row carries."""
        r = info["row"]
        if info["mode"] == "access":
            return {x for x in (self.one(r.get("vlan")), self.one(r.get("voice"))) if x is not None}
        if info["mode"] == "trunk":
            got = self.ids(_list(r.get("vlans")))
            got = set(self.vlan_name) if got is None else got
            native = self.one(r.get("native"))
            return got | ({native} if native is not None else set())
        return set()


def _fmt(ids) -> str:
    ids = sorted(ids)
    out, i = [], 0
    while i < len(ids):
        j = i
        while j + 1 < len(ids) and ids[j + 1] == ids[j] + 1:
            j += 1
        out.append(str(ids[i]) if i == j else f"{ids[i]}-{ids[j]}")
        i = j + 1
    return ", ".join(out)


def _mentions(text: str, host: str) -> bool:
    return bool(host) and bool(re.search(rf"(?<![\w-]){re.escape(host.lower())}(?![\w-])", text.lower()))


def find_links(switches: list[Switch]) -> list[dict]:
    """Links from descriptions that name another switch."""
    links, seen = [], set()
    for sw in switches:
        for name, info in sw.rows.items():
            if not info["desc"]:
                continue
            for other in switches:
                if other is sw or not _mentions(info["desc"], other.host):
                    continue
                back = [n for n, o in other.rows.items() if o["desc"] and _mentions(o["desc"], sw.host)]
                far = back[0] if len(back) == 1 else None
                key = frozenset({(sw.idx, name), (other.idx, far)}) if far else (sw.idx, name, other.idx)
                if key in seen:
                    continue
                seen.add(key)
                links.append({"a": sw.idx, "a_row": name, "b": other.idx, "b_row": far, "found": "description"})
    return links


def check(projects: list[dict], manual_links: list[dict] | None = None) -> dict:
    """projects: [{"name": label, "data": project}]; manual_links: [{a, a_row, b, b_row}] by host name or index."""
    checks: list[dict] = []
    switches = [Switch(i, _s(p.get("name")), p.get("data") or {}) for i, p in enumerate(projects[:MAX_SWITCHES])
                if isinstance(p, dict) and isinstance(p.get("data"), dict)]

    def add(level, message, sws=(), link=None):
        item = {"level": level, "message": message, "switches": sorted({s.host for s in sws})}
        if link is not None:
            item["link"] = link
        checks.append(item)

    if len(projects) > MAX_SWITCHES:
        add("warn", f"Only the first {MAX_SWITCHES} projects are checked.")

    # Each project on its own: the builder's own errors.
    built = {}
    for sw in switches:
        res = build(sw.p)
        built[sw.idx] = {"errors": len(res.errors), "warnings": len(res.warnings)}
        if res.errors:
            first = res.errors[0]
            add("error", f"{sw.host}: the builder reports {len(res.errors)} error(s), first: "
                         f"{first.get('section', '')}: {first.get('message', '')}", [sw])

    # Host names
    by_host = defaultdict(list)
    for sw in switches:
        by_host[sw.host.lower()].append(sw)
    for host, sws in by_host.items():
        if len(sws) > 1:
            add("error", f"Host name {sws[0].host} is used by {len(sws)} projects: "
                         f"{', '.join(s.label for s in sws)}.", sws)

    # Addresses
    owners: dict = defaultdict(list)
    for sw in switches:
        found = []
        if sw.mgmt:
            found.append((sw.mgmt, "management"))
        found += [(a, "loopback") for a in sw.loopback]
        found += [(a, f"VLAN {vid} interface") for vid, addrs in sw.irb.items() for a in addrs]
        for name, info in sw.rows.items():
            if info["mode"] == "routed":
                found += [(a, f"routed port {name}") for a in (_iface(x) for x in _list(info["row"].get("address"))) if a]
        for addr, what in found:
            owners[addr.ip].append((sw, what))
    for ip, where in owners.items():
        if len({s.idx for s, _ in where}) > 1:
            add("error", f"IP address {ip} is used more than once: " +
                "; ".join(f"{s.host} ({w})" for s, w in where) + ".", [s for s, _ in where])

    # One subnet, different VLANs
    nets: dict = defaultdict(set)
    for sw in switches:
        for vid, addrs in sw.irb.items():
            for a in addrs:
                nets[a.network].add((vid, sw.host))
    for net, uses in nets.items():
        vids = {v for v, _ in uses}
        if len(vids) > 1:
            add("warn", f"Subnet {net} is on different VLANs: " +
                "; ".join(f"VLAN {v} on {h}" for v, h in sorted(uses)) + ".",
                [s for s in switches if s.host in {h for _, h in uses}])

    # VLAN names and IDs
    names_by_id = defaultdict(lambda: defaultdict(list))
    ids_by_name = defaultdict(lambda: defaultdict(list))
    for sw in switches:
        for vid, name in sw.vlan_name.items():
            names_by_id[vid][name].append(sw.host)
            ids_by_name[name.lower()][vid].append(sw.host)
    for vid, by in sorted(names_by_id.items()):
        if len(by) > 1:
            add("info", f"VLAN {vid} has different names: " +
                "; ".join(f"{n} on {', '.join(h)}" for n, h in by.items()) + ".")
    for name, by in sorted(ids_by_name.items()):
        if len(by) > 1:
            add("warn", f"VLAN name {name} has different IDs: " +
                "; ".join(f"{v} on {', '.join(h)}" for v, h in sorted(by.items())) + ".")

    # Links
    index = {s.idx: s for s in switches}
    hosts = {s.host.lower(): s.idx for s in switches}

    def pick(v):
        if isinstance(v, int) and v in index:
            return v
        return hosts.get(_s(v).lower())

    links = find_links(switches)
    for m in manual_links or []:
        a, b = pick(m.get("a")), pick(m.get("b"))
        if a is None or b is None or a == b:
            add("warn", f"Link {m.get('a')} ↔ {m.get('b')}: pick two different switches from the list.")
            continue
        ar, br = _s(m.get("a_row")) or None, _s(m.get("b_row")) or None
        ends = {e for e in ((a, ar), (b, br)) if e[1]}
        links = [x for x in links if not ({(x["a"], x["a_row"]), (x["b"], x["b_row"])} & ends)]
        links.append({"a": a, "a_row": ar, "b": b, "b_row": br, "found": "added by hand"})

    uplinks = defaultdict(set)  # switch -> row names that link to another switch
    for n, link in enumerate(links):
        a, b = index[link["a"]], index[link["b"]]
        link["issues"] = []
        for sw, row in ((a, link["a_row"]), (b, link["b_row"])):
            if row:
                uplinks[sw.idx].add(row)
        na, nb = f"{a.host} {link['a_row'] or '?'}", f"{b.host} {link['b_row'] or '?'}"

        def issue(level, msg, _a=a, _b=b, _n=n, _link=link):
            _link["issues"].append({"level": level, "message": msg})
            add(level, msg, [_a, _b], _n)

        ra, rb = a.rows.get(link["a_row"] or ""), b.rows.get(link["b_row"] or "")
        if link["a_row"] and ra is None:
            issue("warn", f"{a.host} has no port group or LAG called {link['a_row']}.")
            continue
        if link["b_row"] and rb is None:
            issue("warn", f"{b.host} has no port group or LAG called {link['b_row']}.")
            continue
        if not (ra and rb):
            issue("info", f"{na} ↔ {nb}: the far end is not known. Name this switch in the far end's description, "
                          "or add the link by hand, to check both ends.")
            continue
        if ra["kind"] != rb["kind"]:
            lag, single = (na, nb) if ra["kind"] == "lag" else (nb, na)
            issue("error", f"{lag} is a LAG but {single} is not.")
        if ra["kind"] == rb["kind"] == "lag":
            la, lb = _s(ra["row"].get("lacp")) or "active", _s(rb["row"].get("lacp")) or "active"
            if la == lb == "passive":
                issue("error", f"{na} and {nb} are both LACP passive, so the LAG never comes up.")
            elif "none" in (la, lb) and la != lb:
                issue("error", f"{na} LACP {la} but {nb} LACP {lb}.")
        ma, mb = ra["mode"], rb["mode"]
        if ma != mb:
            issue("error", f"{na} is {ma} but {nb} is {mb}.")
        elif ma == "trunk":
            va, vb = a.allowed(ra), b.allowed(rb)
            if va - vb:
                issue("warn", f"VLAN {_fmt(va - vb)} allowed on {na} but not on {nb}.")
            if vb - va:
                issue("warn", f"VLAN {_fmt(vb - va)} allowed on {nb} but not on {na}.")
            nva, nvb = a.one(ra["row"].get("native")), b.one(rb["row"].get("native"))
            if nva != nvb:
                issue("error", f"Native VLAN differs: {na} {nva or 'none'}, {nb} {nvb or 'none'}.")
            for sw, other, vids, name in ((a, b, va, na), (b, a, vb, nb)):
                missing = {v for v in vids if v not in other.vlan_name}
                if missing:
                    issue("warn", f"{name} carries VLAN {_fmt(missing)}, which {other.host} does not have.")
        elif ma == "access":
            va, vb = a.allowed(ra), b.allowed(rb)
            if va != vb:
                issue("warn", f"Access VLAN differs: {na} {_fmt(va) or 'none'}, {nb} {_fmt(vb) or 'none'}.")
        elif ma == "routed":
            aa = [x for x in (_iface(y) for y in _list(ra["row"].get("address"))) if x]
            ab = [x for x in (_iface(y) for y in _list(rb["row"].get("address"))) if x]
            if aa and ab and not ({x.network for x in aa} & {x.network for x in ab}):
                issue("error", f"{na} and {nb} are routed but not in the same subnet.")
        if ra["mtu"] != rb["mtu"]:
            issue("warn", f"MTU differs: {na} {ra['mtu'] or 'default'}, {nb} {rb['mtu'] or 'default'}.")

    # VLANs used on a switch that no uplink carries
    for sw in switches:
        ups = [sw.rows[r] for r in uplinks.get(sw.idx, ()) if r in sw.rows]
        if not ups:
            continue
        carried = set().union(*(sw.allowed(u) for u in ups))
        used = set()
        for name, info in sw.rows.items():
            if name not in uplinks[sw.idx]:
                used |= sw.allowed(info)
        lost = {v for v in used - carried if v not in sw.irb}
        if lost:
            add("warn", f"{sw.host}: VLAN {_fmt(lost)} is used on its ports but no uplink carries it, so it cannot "
                        "reach the rest of the network.", [sw])

    # Spanning tree
    l2 = [s for s in switches if s.vlan_name]
    if len(l2) > 1:
        protos = defaultdict(list)
        for s in l2:
            protos[s.stp].append(s.host)
        if len(protos) > 1:
            add("warn", "Spanning-tree protocols differ: " +
                "; ".join(f"{p} on {', '.join(h)}" for p, h in protos.items()) + ".", l2)
        run = [s for s in l2 if s.stp not in ("none", "off", "")]
        if run:
            if all(s.priority is None for s in run):
                add("warn", "No switch sets a spanning-tree bridge priority, so the root is whichever has the lowest "
                            "MAC address. Give the core 4k (and a backup 8k).", run)
            else:
                low = min(s.priority if s.priority is not None else 32768 for s in run)
                roots = [s for s in run if (s.priority if s.priority is not None else 32768) == low]
                if len(roots) > 1:
                    add("warn", f"Spanning-tree root is a tie at priority {low}: {', '.join(s.host for s in roots)}. "
                                "Give one of them a lower value.", roots)
                else:
                    add("info", f"Spanning-tree root: {roots[0].host} (priority {low}).", roots)

    linked = {x for link in links for x in (link["a"], link["b"])}
    for sw in switches:
        if len(switches) > 1 and sw.idx not in linked:
            add("info", f"{sw.host}: no link to the other switches was found.", [sw])

    checks.sort(key=lambda c: LEVELS.index(c["level"]))
    counts = {lv: sum(1 for c in checks if c["level"] == lv) for lv in LEVELS}
    return {
        "switches": [{"host": s.host, "label": s.label, "vendor": s.vendor, "rows": list(s.rows),
                      **built.get(s.idx, {})} for s in switches],
        "links": [{**x, "a": index[x["a"]].host, "b": index[x["b"]].host} for x in links],
        "checks": checks,
        "counts": counts,
        "ready": counts["error"] == 0,
    }
