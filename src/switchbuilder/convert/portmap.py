"""Port names across vendors: expand and compact port lists, and move a project's ports
from one vendor's switch model to another's.

Ports are matched by position: the n-th front-panel (access) port of stack member m on the
old switch becomes the n-th access port of member m on the new one, and the same for
uplink ports. Anything that does not fit is reported, never dropped silently.
"""

from __future__ import annotations

import re

from .. import (aoscx_models, aoss_models, eos_models, exos_models, fastiron_models, fortiswitch_models, ios_models,
                models, nxos_models, os10_models, routeros_models, unifi_models)
from .. import ports as P
from .. import vendors

MODELS = {"juniper": models, "arista": eos_models, "cisco": ios_models, "nexus": nxos_models, "dell": os10_models,
          "extreme": exos_models, "fortiswitch": fortiswitch_models, "mikrotik": routeros_models,
          "unifi": unifi_models, "ruckus": fastiron_models, "aruba": aoscx_models, "procurve": aoss_models}
# The member number of the first (or only) switch in a project.
FIRST = {"juniper": 0, "arista": 0}


def first_member(vendor: str) -> int:
    return FIRST.get(vendor, 1)


def model(vendor: str, name: str):
    mod = MODELS.get(vendor)
    return mod.get(name) if mod and name else None


def model_names(vendor: str) -> list[str]:
    return [m["name"] for m in MODELS[vendor].catalog()]


def member_ports(vendor: str, name: str, member: int, stacked: bool) -> list[dict]:
    """The ports of one stack member, in front-panel order: [{name, kind, speed, poe}]."""
    m = model(vendor, name)
    if m is None:
        return []
    if not callable(m.ports):          # single switches: a fixed tuple of ports
        return [dict(x) for x in m.ports]
    if vendor == "unifi":
        return m.ports()
    if vendor == "extreme":
        return m.ports(member, stacked)
    return m.ports(member)


def expand(vendor: str, spec) -> list[str]:
    """A port list in the vendor's own spelling -> single port names. Raises ValueError."""
    spec = str(spec or "")
    if vendor == "juniper":
        return P.expand(spec)
    if vendor == "extreme":
        return exos_models.expand(spec)
    if vendor == "procurve":
        return aoss_models.expand(spec)
    return P.expand_named(spec, MODELS[vendor].ALIASES)


def compact(vendor: str, names: list[str]) -> str:
    if not names:
        return ""
    if vendor == "juniper":
        return P.compact(names)
    if vendor == "extreme":
        return exos_models.compact(names)
    if vendor == "procurve":
        return aoss_models.compact(names)
    return P.named_compact(names)


# ------------------------------------------------------------------ LAG and interface names
_LAG_NUM = re.compile(r"^(?:ae|po|port-?channel|lag|trk|bond(?:ing)?|trunk|sharing)\s*(\d{1,4})$", re.I)


def lag_number(vendor: str, name: str) -> int | None:
    """A LAG's number counted from 1 (Juniper's ae0 is LAG 1)."""
    m = _LAG_NUM.fullmatch(str(name or "").strip())
    if not m:
        return None
    n = int(m.group(1))
    return n + 1 if vendor == "juniper" else n


def lag_name(vendor: str, n: int) -> str:
    return {"juniper": f"ae{n - 1}", "cisco": f"Port-channel{n}", "arista": f"Port-Channel{n}",
            "nexus": f"port-channel{n}", "dell": f"port-channel{n}", "procurve": f"Trk{n}",
            "mikrotik": f"bond{n}"}.get(vendor, f"lag{n}")


_VLAN_IF = re.compile(r"^(?:irb\.|vlan\s*|ve\s*|interface-vlan\s*)(\d{1,4})$", re.I)
_LOOP = re.compile(r"^(?:lo|loopback)\s*(\d{0,4})(?:\.\d+)?$", re.I)


def vlan_iface(vendor: str, vid) -> str:
    return {"juniper": f"irb.{vid}", "cisco": f"Vlan{vid}", "arista": f"Vlan{vid}", "nexus": f"Vlan{vid}",
            "dell": f"vlan{vid}", "ruckus": f"ve {vid}"}.get(vendor, f"vlan {vid}")


def loopback(vendor: str) -> str:
    return {"juniper": "lo0.0", "cisco": "Loopback0", "arista": "Loopback0", "nexus": "loopback0",
            "dell": "loopback0", "ruckus": "loopback 1", "aruba": "loopback 0"}.get(vendor, "loopback")


# ------------------------------------------------------------------ ports of unknown models
_FAST_WORDS = ("tengig", "twentyfive", "forty", "hundred", "sfp", "qsfp", "xe-", "et-", "te", "fo", "hu")


def _nums(name: str) -> list[int]:
    return [int(x) for x in re.findall(r"\d+", name)]


def guess_place(vendor: str, name: str) -> tuple[int, str]:
    """For a port no catalog model has: (member number, 'access' or 'uplink'), from the name alone.

    Cisco Gi1/0/5 is member 1, Gi1/1/1 is an uplink (slot 1); older Gi0/5 is a single switch.
    Juniper ge-1/0/5 is member 1; xe-/et- and PIC 1/2 are uplinks. Faster port words are uplinks.
    """
    low = name.lower()
    nums = _nums(name)
    member, kind = 0, "access"
    word = re.match(r"[a-z-]*", low).group(0)
    if vendor == "juniper" and len(nums) == 3:
        member = nums[0]
        kind = "uplink" if word in ("xe-", "et-") or nums[1] > 0 else "access"
    elif len(nums) == 3:
        member = nums[0]
        kind = "uplink" if nums[1] > 0 else "access"
    if word and any(word.startswith(w) for w in _FAST_WORDS) and word not in ("", "ethernet"):
        kind = "uplink"
    return member, kind


# ------------------------------------------------------------------ guessing a model
def _classes(ports: list[dict]) -> dict[str, list[dict]]:
    out = {"access": [], "uplink": []}
    for p in ports:
        out["access" if p["kind"] == "access" else "uplink"].append(p)
    return out


def guess_model(vendor: str, names: set[str], member: int, stacked: bool) -> str:
    """The catalog model of ``vendor`` that holds the most of ``names`` (the smallest on a tie)."""
    best, best_score = "", (0, 0)
    for nm in model_names(vendor):
        ports = {p["name"] for p in member_ports(vendor, nm, member, stacked)}
        hit = len(names & ports)
        if hit and (hit, -len(ports)) > best_score:
            best, best_score = nm, (hit, -len(ports))
    return best


def _can_stack(m) -> bool:
    for attr in ("stack", "vsf"):
        if hasattr(m, attr):
            return bool(getattr(m, attr))
    return not isinstance(getattr(m, "ports", None), tuple)


def _has_mgmt(m) -> bool:
    for attr in ("has_mgmt", "has_oobm"):
        if hasattr(m, attr):
            return bool(getattr(m, attr))
    return bool(getattr(m, "mgmt", True))


def pick_target_model(vendor: str, need: dict, poe: bool, stack: bool = False, mgmt: bool = False,
                      l3: bool = False) -> str:
    """The best model of ``vendor``: enough access and uplink ports, then PoE, stacking, a management
    port and routing when the old switch had them, current over legacy, and the smallest of those."""
    rows = []
    for nm in model_names(vendor):
        m = model(vendor, nm)
        if nm == "Custom" or m is None:
            continue
        cl = _classes(member_ports(vendor, nm, first_member(vendor), False))
        acc, up = len(cl["access"]), len(cl["uplink"])
        has_poe = any(p["poe"] for p in cl["access"])
        short = max(0, need["access"] - acc) + max(0, need["uplink"] - up)
        legacy = any(getattr(m, a, False) for a in ("legacy", "old", "classic")) or "lab" in str(m.notes).lower()[:60] \
            or "virtual" in str(m.notes).lower()[:60]
        rows.append((short, poe and not has_poe, stack and not _can_stack(m), legacy,
                     l3 and hasattr(m, "layer3") and not m.layer3, mgmt and not _has_mgmt(m), acc + up, nm))
    rows.sort()
    return rows[0][-1] if rows else ""


# ------------------------------------------------------------------ the move
class PortMove:
    """Maps the ports a source project uses onto the target vendor's model, member by member."""

    def __init__(self, src_vendor: str, src_members: list[dict], dst_vendor: str, dst_model: str, used: list[str],
                 dst_stacks: bool, mgmt: bool = False, l3: bool = False):
        self.src, self.dst = src_vendor, dst_vendor
        self.notes: list[str] = []
        self.checks: list[str] = []
        self.table: list[dict] = []          # [{from, to}] for the report
        self.map: dict[str, str] = {}
        stacked = len(src_members) > 1
        used_set = set(used)
        # Where each source port sits: (member index, class, position).
        where: dict[str, tuple[int, str, int]] = {}
        need: dict[int, dict] = {}
        self.src_models: list[str] = []
        for i, m in enumerate(src_members):
            name = m.get("model", "")
            ports = member_ports(src_vendor, name, int(m.get("fpc", 0)), stacked)
            if not ports or not used_set & {p["name"] for p in ports}:
                guess = guess_model(src_vendor, used_set, int(m.get("fpc", 0)), stacked)
                if guess:
                    if name and name != guess:
                        self.notes.append(f"Source member {m.get('fpc')}: model {name or '?'} did not match the port "
                                          f"names, so the ports were read as a {guess}.")
                    name = guess
                    ports = member_ports(src_vendor, name, int(m.get("fpc", 0)), stacked)
            self.src_models.append(name)
            cl = _classes(ports)
            for kind, lst in cl.items():
                for pos, p in enumerate(lst):
                    where.setdefault(p["name"], (i, kind, pos))
            need[i] = {"access": len(cl["access"]), "uplink": len(cl["uplink"]),
                       "poe": any(p["poe"] for p in cl["access"])}
        # Only count what is actually used when picking a target model.
        used_need = {"access": 0, "uplink": 0}
        for n in used:
            if n in where:
                _, kind, pos = where[n]
                used_need[kind] = max(used_need[kind], pos + 1)
        # Ports no catalog model has (older switches such as a 2960 or 3560 with Gi0/1): match them by
        # their order instead, member by member, so they are never all dropped.
        self.guessed = [n for n in used if n not in where]
        if self.guessed:
            by_member = sorted({guess_place(src_vendor, n)[0] for n in self.guessed})
            count: dict[tuple, int] = {}
            for n in sorted(self.guessed, key=lambda x: (guess_place(src_vendor, x), P.named_key(x), _nums(x))):
                mem, kind = guess_place(src_vendor, n)
                i = by_member.index(mem)
                pos = count.get((i, kind), 0)
                count[(i, kind)] = pos + 1
                where[n] = (i, kind, pos)
                used_need[kind] = max(used_need[kind], pos + 1)
            if len(by_member) > len(src_members):
                src_members = src_members + [{"fpc": m, "model": ""} for m in by_member[len(src_members):]]
            self.checks.append(f"{len(self.guessed)} port(s) like {self.guessed[0]} are not on any "
                              f"{vendors.get(src_vendor).name} model the builder knows, so they were matched by order (the first port "
                              "becomes the new switch's first port). Pick the old switch model if that's wrong.")
        self.unknown: list[str] = []
        members = src_members if dst_stacks else src_members[:1]
        if len(src_members) > len(members):
            self.notes.append(f"{len(src_members)} stacked switches, but the target doesn't stack: only the first "
                              "switch's ports were converted. Make one project per extra switch.")
        poe = any(need.get(i, {}).get("poe") for i in range(len(members)))
        if not dst_model and src_vendor == dst_vendor and self.src_models and model(dst_vendor, self.src_models[0]):
            dst_model = self.src_models[0]
        self.dst_model = dst_model or pick_target_model(dst_vendor, used_need, poe, len(members) > 1, mgmt, l3)
        self.dropped = {n for n in used if n in where and where[n][0] >= len(members)}
        self.dst_members = [{"fpc": first_member(dst_vendor) + i, "model": self.dst_model, "serial": "",
                             "role": "routing-engine" if i == 0 else "line-card"} for i in range(len(members))]
        dst_stacked = len(members) > 1
        dst_classes = [_classes(member_ports(dst_vendor, self.dst_model, m["fpc"], dst_stacked))
                       for m in self.dst_members]
        taken: set[str] = set()
        overflow: list[str] = []
        for n in sorted(used, key=lambda x: where.get(x, (99, "", 0))):
            if n not in where:
                continue
            i, kind, pos = where[n]
            if i >= len(dst_classes):
                self.table.append({"from": n, "to": ""})
                continue
            lst = dst_classes[i][kind]
            if pos < len(lst) and lst[pos]["name"] not in taken:
                self.map[n] = lst[pos]["name"]
                taken.add(lst[pos]["name"])
            else:
                overflow.append(n)
        for n in overflow:  # an uplink the new switch lacks: use a free port of the other kind, from the end
            i, kind, _ = where[n]
            other = dst_classes[i]["uplink" if kind == "access" else "access"]
            spare = next((p["name"] for p in reversed(other) if p["name"] not in taken), "")
            if spare:
                self.map[n] = spare
                taken.add(spare)
                self.notes.append(f"{n}: the {self.dst_model} has no matching {kind} port, so it moved to {spare}.")
        for n in used:
            if n in where and where[n][0] < len(dst_classes):
                self.table.append({"from": n, "to": self.map.get(n, "")})
        for n in self.unknown:
            self.table.append({"from": n, "to": ""})

    def spec(self, spec, what: str) -> tuple[str, list[str]]:
        """A source port list -> the target's port list, and the source ports that had no place."""
        try:
            names = expand(self.src, spec)
        except ValueError:
            return "", [str(spec)]
        out = [self.map[n] for n in names if n in self.map]
        lost = [n for n in names if n not in self.map]
        return compact(self.dst, out), lost
