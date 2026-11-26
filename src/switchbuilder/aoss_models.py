"""HPE Aruba / ProCurve switches running AOS-S (ProVision), and older ProCurve.

Port names are AOS-S names: ``1`` to ``48`` on a standalone switch, ``A1`` for
a module port, and ``2/1`` or ``2/A1`` for stack member 2 on the 2930M and
3810M (which number their ports ``1/1`` even when standalone). These are the
common layouts; check the hardware guide for anything unusual.

``stack`` is the part number used in 'stacking / member N type ...'.
``legacy`` marks older ProCurve software (K/R/N/W releases before 16.x),
which uses SNTP instead of NTP.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Group:
    kind: str     # access | uplink | module
    first: int
    last: int
    speed: str
    poe: bool = False
    letter: str = ""


@dataclass(frozen=True)
class SModel:
    name: str
    family: str
    groups: tuple
    stack: str = ""        # 'member N type <part>' for backplane stacking; empty = no stacking
    member_ports: bool = False  # ports are named member/port (2930M, 3810M)
    legacy: bool = False
    has_oobm: bool = False
    notes: str = ""

    @property
    def poe(self) -> bool:
        return any(g.poe for g in self.groups)

    @property
    def mgmt(self) -> str:
        return "oobm" if self.has_oobm else ""

    def ports(self, member: int = 1) -> list[dict]:
        pre = f"{member}/" if self.member_ports else ""
        return [{"name": f"{pre}{g.letter}{n}", "kind": g.kind, "speed": g.speed, "poe": g.poe}
                for g in self.groups for n in range(g.first, g.last + 1)]

    def to_dict(self) -> dict:
        return {"name": self.name, "family": self.family, "mgmt": self.mgmt, "poe": self.poe, "notes": self.notes,
                "ports": self.ports(1), "stack": bool(self.stack)}


_M: list[SModel] = []


def _add(name, family, groups, notes="", stack="", member_ports=False, legacy=False, oobm=False):
    _M.append(SModel(name, family, tuple(groups), stack, member_ports, legacy, oobm, notes))


def g(first, last, speed, kind="access", poe=False, letter=""):
    return Group(kind, first, last, speed, poe, letter)


# ------------------------------------------------------------------ AOS-S 16.x
_add("2530-24G-PoE+", "2530", [g(1, 24, "1G", poe=True), g(25, 28, "1G SFP", "uplink")],
     "J9773A. PoE+. No stacking.")
_add("2530-48G-PoE+", "2530", [g(1, 48, "1G", poe=True), g(49, 52, "1G SFP", "uplink")],
     "J9772A. PoE+. No stacking.")
_add("2540-48G-PoE+-4SFP+", "2540", [g(1, 48, "1G", poe=True), g(49, 52, "1/10G SFP+", "uplink")],
     "JL357A. PoE+. No stacking.")
_add("2920-48G-PoE+", "2920", [g(1, 48, "1G", poe=True), g(1, 2, "10G module", "module", letter="A")],
     "J9729A. PoE+. 45-48 are shared with SFP slots. A1-A2 need a 10G module. Stacking with the stacking module is "
     "not written here.")
_add("2930F-24G-PoE+-4SFP+", "2930F", [g(1, 24, "1G", poe=True), g(25, 28, "1/10G SFP+", "uplink")],
     "JL255A. PoE+. VSF stacking renames the ports; not written here.")
_add("2930F-48G-PoE+-4SFP+", "2930F", [g(1, 48, "1G", poe=True), g(49, 52, "1/10G SFP+", "uplink")],
     "JL256A. PoE+. VSF stacking renames the ports; not written here.")
_add("2930M-24G-PoE+", "2930M", [g(1, 24, "1G", poe=True), g(1, 4, "10G module", "module", letter="A")],
     "JL320A. PoE+. Ports are 1/1 even standalone. Uplinks need a module (A1-A4). Backplane stacking, up to 10.",
     stack="JL320A", member_ports=True)
_add("2930M-48G-PoE+", "2930M", [g(1, 48, "1G", poe=True), g(1, 4, "10G module", "module", letter="A")],
     "JL322A. PoE+. Ports are 1/1 even standalone. Uplinks need a module (A1-A4). Backplane stacking, up to 10.",
     stack="JL322A", member_ports=True)
_add("3810M-48G-PoE+-1-slot", "3810M", [g(1, 48, "1G", poe=True), g(1, 4, "10G module", "module", letter="A")],
     "JL074A. PoE+. Ports are 1/1 even standalone. Uplinks need a module (A1-A4). Backplane stacking, up to 10.",
     stack="JL074A", member_ports=True, oobm=True)
_add("5406R-zl2 (2x 24-port PoE+)", "5400R", [g(1, 24, "1G", poe=True, letter="A"), g(1, 24, "1G", poe=True, letter="B")],
     "J9850A chassis with two J9986A 24-port PoE+ modules in slots A and B. Add more slots under Custom ports.",
     oobm=True)
# ------------------------------------------------------------------ older ProCurve
_add("ProCurve 2610-48-PWR", "2610", [g(1, 48, "100M", poe=True), g(49, 50, "1G", "uplink"),
                                      g(51, 52, "1G SFP", "uplink")],
     "J9089A. Fast Ethernet with PoE, older ProCurve (R.11). SNTP only.", legacy=True)
_add("ProCurve 2810-48G", "2810", [g(1, 48, "1G")],
     "J9022A. 45-48 are shared with SFP slots. Older ProCurve (N.11). SNTP only.", legacy=True)
_add("ProCurve 2910al-48G-PoE+", "2910al", [g(1, 48, "1G", poe=True), g(1, 4, "10G module", "module", letter="A")],
     "J9148A. PoE+. A1-A4 need a 10G module. Older ProCurve (W.15). SNTP only.", legacy=True)

MODELS: dict[str, SModel] = {m.name: m for m in _M}
CUSTOM = "Custom"
# The page's port map reads port names with these words; AOS-S names have none.
ALIASES = {"": "", "a": "A", "b": "B", "c": "C", "d": "D", "e": "E", "f": "F"}

_TOKEN = re.compile(r"^(?:(\d+)/)?([A-Fa-f]?)(\d+)$")
_RANGE = re.compile(r"^(?:(\d+)/)?([A-Fa-f]?)(\d+)\s*-\s*(?:(\d+)/)?([A-Fa-f]?)(\d+)$")


def expand(spec: str) -> list[str]:
    """``1-3, A1, 2/1-2/4, 1/A1-A2`` -> AOS-S port names. Raises ValueError."""
    out: list[str] = []
    text = re.sub(r"\s*-\s*", "-", re.sub(r"\s+to\s+", "-", (spec or "").strip()))
    for part in re.split(r"[,;\s]+", text):
        if not part:
            continue
        m = _TOKEN.match(part)
        if m:
            out.append(f"{m.group(1) + '/' if m.group(1) else ''}{m.group(2).upper()}{int(m.group(3))}")
            continue
        m = _RANGE.match(part)
        if not m:
            raise ValueError(f"'{part}' is not a port or port range")
        mem, let, a, mem2, let2, b = m.groups()
        if (mem2 and mem2 != mem) or (let2 and let2.upper() != let.upper()):
            raise ValueError(f"'{part}': a range must stay on one member and one module")
        a, b = int(a), int(b)
        if b < a or b - a > 1024:
            raise ValueError(f"'{part}': the range runs backwards or is too long")
        out.extend(f"{mem + '/' if mem else ''}{let.upper()}{n}" for n in range(a, b + 1))
    return out


def key(name: str):
    m = _TOKEN.match(name)
    if not m:
        return (999, "~", 0)
    return (int(m.group(1) or 0), m.group(2), int(m.group(3)))


def compact(names: list[str]) -> str:
    """Port names as an AOS-S list: 1-40,47,A1-A2,2/1-2/4."""
    runs: list[list[str]] = []
    for n in sorted(set(names), key=key):
        if runs:
            pm, pl, pn = key(runs[-1][1])
            m, letter, num = key(n)
            if (pm, pl) == (m, letter) and num == pn + 1:
                runs[-1][1] = n
                continue
        runs.append([n, n])
    return ",".join(a if a == b else f"{a}-{b}" for a, b in runs)


def get(name: str) -> SModel | None:
    return MODELS.get(name)


def catalog() -> list[dict]:
    return [m.to_dict() for m in _M]
