"""Shared parts of the vendor config readers: a neutral per-interface record and the step
that turns those records into a builder project (VLANs, port groups, LAGs).

A reader fills a ``Reader``: VLANs by ID, interfaces by their own name, and lines it did not
understand. ``Reader.project()`` then groups ports with the same settings into port groups,
the same way the Junos importer does.
"""

from __future__ import annotations

import copy
import ipaddress
import re

from ..generator import DEFAULTS, LAG_DEFAULTS, PORT_DEFAULTS, VLAN_DEFAULTS
from . import portmap

NAME_OK = re.compile(r"[^A-Za-z0-9_.-]+")


def vlan_name(raw: str, vid) -> str:
    """A VLAN name every builder takes: starts with a letter, letters/digits/-/_/., 32 at most."""
    name = NAME_OK.sub("-", str(raw or "").strip()).strip("-.")[:32]
    if not name or not name[0].isalpha():
        name = f"VLAN{vid}" if not name else f"V{name}"[:32]
    return name


def mask_to_prefix(addr: str, mask: str) -> str:
    try:
        return str(ipaddress.IPv4Interface(f"{addr}/{mask}").with_prefixlen)
    except ValueError:
        return f"{addr}/{mask}"


def net(prefix: str, mask: str) -> str:
    try:
        return str(ipaddress.IPv4Network(f"{prefix}/{mask}", strict=False))
    except ValueError:
        return f"{prefix}/{mask}"


def vid_list(text: str) -> list[int]:
    """'10,20-22' -> [10, 20, 21, 22]."""
    out: list[int] = []
    for part in re.split(r"[,\s]+", str(text or "").strip()):
        if not part:
            continue
        m = re.fullmatch(r"(\d+)-(\d+)", part)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            if b - a <= 4094:
                out.extend(range(a, b + 1))
        elif part.isdigit():
            out.append(int(part))
    return out


def blank() -> dict:
    """A project with the builder's opinions switched off, so only what the config had is set."""
    p = copy.deepcopy(DEFAULTS)
    sv = p["services"]
    sv.update(delete_first=False, storm_control=False, bpdu_block_on_edge=False, lldp=False, lldp_med=False,
              poe_all=False, stp="none")
    a = p["access"]
    a.update(retry_options=False, ssh_root_login="deny", ssh_connection_limit="", ssh_rate_limit="")
    p["syslog"]["log_commands"] = False
    p["system"]["ignore_mgmt_alarm"] = False
    return p


class Reader:
    """What a vendor reader collects before it becomes a project."""

    def __init__(self, vendor: str):
        self.vendor = vendor
        self.p = blank()
        self.p["vendor"] = vendor
        # No model yet: the port names decide (convert/portmap.py guesses it).
        self.p["switch"]["members"] = [{"fpc": portmap.first_member(vendor), "model": "", "serial": "",
                                        "role": "routing-engine"}]
        self.vlans: dict[int, dict] = {}
        self.ifs: dict[str, dict] = {}       # physical ports, by the vendor's full name
        self.lags: dict[int, dict] = {}      # LAG number (from 1) -> settings
        self.svis: dict[int, dict] = {}      # VLAN id -> {addr: [], relay: bool}
        self.relay: list[str] = []
        self.unparsed: list[str] = []
        self.notes: list[str] = []
        self.members: dict[int, str] = {}    # member number -> model
        self.used = 0
        self.vlan1_used = False
        self.ospf_if: dict[str, str] = {}    # interface -> OSPF area, from 'ip ospf 1 area 0'
        self.ospf_p2p: set[str] = set()
        self.later: list[str] = []           # notes for things read but not carried over

    def vlan(self, vid: int, name: str = "") -> dict:
        v = self.vlans.get(vid)
        if v is None:
            v = self.vlans[vid] = dict(VLAN_DEFAULTS, id=str(vid), name="")
        if name:
            v["name"] = vlan_name(name, vid)
        return v

    def iface(self, name: str) -> dict:
        return self.ifs.setdefault(name, {})

    def lag(self, n: int) -> dict:
        return self.lags.setdefault(n, {})

    def skip(self, line: str) -> None:
        self.unparsed.append(line)

    # ------------------------------------------------------------ building the project
    def _vname(self, vid) -> str:
        try:
            vid = int(vid)
        except (TypeError, ValueError):
            return str(vid)
        if vid == 1:
            self.vlan1_used = True
            if not self.vlan(1)["name"]:
                self.vlan(1, "default")
        return self.vlan(vid)["name"] or ""

    def _row(self, d: dict, base: dict) -> dict:
        row = copy.deepcopy(base)
        mode = d.get("mode") or ("routed" if d.get("addr") else "access")
        if d.get("shutdown"):
            mode = "disabled"
        row["mode"] = mode
        for k in ("description", "mtu", "speed", "poe", "poe_max", "mac_limit", "dot1x", "vlan_translate"):
            if d.get(k):
                row[k] = str(d[k])
        row["mac_action"] = d.get("mac_action", row["mac_action"])
        for k in ("sticky", "root_guard", "loop_protect", "dhcp_trusted"):
            row[k] = bool(d.get(k))
        row["edge"] = bool(d.get("edge"))
        if mode == "access":
            row["vlan"] = self._vname(d.get("vlan", 1))
            if d.get("voice"):
                row["voice"] = self._vname(d["voice"])
        elif mode == "trunk":
            allowed = d.get("allowed")
            if allowed is None or len(allowed) >= 4094:
                row["vlans"] = "all"
            else:
                row["vlans"] = ", ".join(self._vname(x) for x in sorted(set(allowed)))
            if d.get("native") and str(d["native"]) != "1":
                row["native"] = self._vname(d["native"])
        elif mode == "routed":
            row["address"] = ", ".join(d.get("addr", []))
        return row

    def project(self) -> dict:
        p = self.p
        # SVIs
        for vid, s in self.svis.items():
            v = self.vlan(vid)
            v["irb"] = ", ".join(s.get("addr", []))
            v["dhcp_relay"] = bool(s.get("relay"))
        if self.relay:
            p["routing"]["dhcp_relay_servers"] = ", ".join(dict.fromkeys(self.relay))
        # Ports, grouped by identical settings.
        groups: dict[tuple, list[str]] = {}
        rows: dict[tuple, dict] = {}
        for name, d in self.ifs.items():
            if d.get("lag"):
                continue
            if not d.get("touched"):
                continue
            row = self._row(d, PORT_DEFAULTS)
            key = tuple(sorted((k, str(v)) for k, v in row.items()))
            if row["mode"] == "routed":
                key += (("port", name),)
            groups.setdefault(key, []).append(name)
            rows[key] = row
        used: set[str] = set()
        for key, names in groups.items():
            row = rows[key]
            row["ports"] = portmap.compact(self.vendor, names)
            base = row["description"] or {"access": f"ACCESS-{row['vlan'] or 'DEFAULT'}", "trunk": "TRUNK",
                                          "routed": "ROUTED", "disabled": "DISABLED"}[row["mode"]]
            base = re.sub(r"[^A-Za-z0-9_-]+", "-", base).strip("-").upper()[:40] or "PORTS"
            nm, i = base, 2
            while nm in used:
                nm, i = f"{base}-{i}", i + 1
            used.add(nm)
            row["name"] = nm
            p["ports"].append(row)
        # LAGs
        members: dict[int, list[str]] = {}
        for name, d in self.ifs.items():
            if d.get("lag"):
                members.setdefault(d["lag"], []).append(name)
        for n in sorted(set(self.lags) | set(members)):
            d = self.lags.get(n, {})
            row = self._row({**d, "mode": d.get("mode") or "trunk"}, LAG_DEFAULTS)
            row["name"] = portmap.lag_name(self.vendor, n)
            mem = members.get(n, [])
            row["members"] = portmap.compact(self.vendor, mem)
            first = self.ifs.get(mem[0], {}) if mem else {}
            row["lacp"] = first.get("lacp", "active")
            row["lacp_fast"] = any(self.ifs[m].get("lacp_fast") for m in mem) or bool(d.get("lacp_fast"))
            if d.get("min_links"):
                row["min_links"] = str(d["min_links"])
            if not mem:
                self.notes.append(f"LAG {n} has no member ports in the config.")
            p["lags"].append(row)
        p["vlans"] = [v for _, v in sorted(self.vlans.items()) 
                     if not (v["id"] == "1" and not v["irb"] and not self.vlan1_used)]
        for v in p["vlans"]:
            if not v["name"]:
                v["name"] = f"VLAN{v['id']}"
        if self.members:
            p["switch"]["members"] = [{"fpc": n, "model": m, "serial": "", "role": "routing-engine" if i == 0 else "line-card"}
                                      for i, (n, m) in enumerate(sorted(self.members.items()))]
        p["name"] = p["system"]["hostname"] or "Converted switch"
        return p
