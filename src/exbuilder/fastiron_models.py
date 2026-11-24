"""Brocade / Ruckus FastIron switch models: ICX 7000, ICX 6000, FCX, FGS and FLS.

Ports are ``unit/module/port`` (1/1/1 is the first copper port of stack unit 1).
FGS and FLS switches number their single unit 0 (0/1/1). These are the common
layouts; module ports and stacking ports vary with options, so check the
hardware guide for anything unusual.

``legacy`` marks families on older FastIron releases (07.x and 08.0.30 and
earlier): they get ``dual-mode`` for untagged-plus-tagged ports and VLAN
membership by LAG primary port. ``old`` marks FGS/FLS (07.x): no 'lag'
command, no 'ntp' (SNTP only) and no new-style 802.1X.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Group:
    kind: str      # access | uplink | module | stack
    module: int
    first: int
    last: int
    speed: str
    poe: bool = False


@dataclass(frozen=True)
class FiModel:
    name: str
    family: str
    groups: tuple
    legacy: bool = False
    old: bool = False
    stack: bool = True
    notes: str = ""

    @property
    def poe(self) -> bool:
        return any(g.poe for g in self.groups)

    @property
    def mgmt(self) -> str:
        return "management 1"

    def ports(self, unit: int = 1) -> list[dict]:
        unit = 0 if self.old else unit
        return [{"name": f"{unit}/{g.module}/{n}", "kind": g.kind, "speed": g.speed, "poe": g.poe}
                for g in self.groups for n in range(g.first, g.last + 1)]

    def to_dict(self) -> dict:
        return {"name": self.name, "family": self.family, "mgmt": self.mgmt, "poe": self.poe, "notes": self.notes,
                "ports": self.ports(1), "stack": self.stack}


_M: list[FiModel] = []


def _add(name, family, groups, notes="", legacy=False, old=False, stack=True):
    _M.append(FiModel(name, family, tuple(groups), legacy, old, stack, notes))


def g(kind, module, last, speed, poe=False, first=1):
    return Group(kind, module, first, last, speed, poe)


# ------------------------------------------------------------- ICX 7000 (FastIron 08.0.95+ / 09.x)
_add("ICX7150-C12P", "ICX7150", [g("access", 1, 12, "1G", True), g("uplink", 2, 2, "1G"), g("uplink", 3, 2, "1/10G SFP+")],
     "Compact, fanless, PoE+.")
_add("ICX7150-24", "ICX7150", [g("access", 1, 24, "1G"), g("uplink", 2, 2, "1G"), g("uplink", 3, 4, "1/10G SFP+")],
     "10G on 1/3/x needs the upgrade licence.")
_add("ICX7150-24P", "ICX7150", [g("access", 1, 24, "1G", True), g("uplink", 2, 2, "1G"), g("uplink", 3, 4, "1/10G SFP+")],
     "PoE+. 10G on 1/3/x needs the upgrade licence.")
_add("ICX7150-48", "ICX7150", [g("access", 1, 48, "1G"), g("uplink", 2, 2, "1G"), g("uplink", 3, 4, "1/10G SFP+")],
     "10G on 1/3/x needs the upgrade licence.")
_add("ICX7150-48P", "ICX7150", [g("access", 1, 48, "1G", True), g("uplink", 2, 2, "1G"), g("uplink", 3, 4, "1/10G SFP+")],
     "PoE+. 10G on 1/3/x needs the upgrade licence.")
_add("ICX7250-24P", "ICX7250", [g("access", 1, 24, "1G", True), g("uplink", 2, 8, "1/10G SFP+")], "PoE+.")
_add("ICX7250-48P", "ICX7250", [g("access", 1, 48, "1G", True), g("uplink", 2, 8, "1/10G SFP+")], "PoE+.")
_add("ICX7450-48P", "ICX7450", [g("access", 1, 48, "1G", True), g("module", 2, 4, "10G SFP+")],
     "PoE+. Uplinks need a module (ICX7400-4X10GF shown).")
_add("ICX7550-48ZP", "ICX7550", [g("access", 1, 48, "mGig", True), g("module", 2, 4, "10/25G SFP28")],
     "Multi-gig PoE. Uplinks need a module.")
_add("ICX7650-48ZP", "ICX7650", [g("access", 1, 48, "mGig", True), g("uplink", 2, 2, "40/100G QSFP"),
                                 g("module", 3, 4, "10G SFP+")], "Multi-gig PoE.")
_add("ICX7850-48FS", "ICX7850", [g("access", 1, 48, "10/25G SFP28"), g("uplink", 2, 8, "40/100G QSFP28")],
     "Aggregation/core.")
# ------------------------------------------------------------- ICX 6000 (FastIron 08.0.30 and earlier)
_add("ICX6430-24P", "ICX6430", [g("access", 1, 24, "1G", True), g("uplink", 2, 4, "1G SFP")],
     "PoE+. 1/2/x can be stacking ports.", legacy=True)
_add("ICX6430-48P", "ICX6430", [g("access", 1, 48, "1G", True), g("uplink", 2, 4, "1G SFP")],
     "PoE+. 1/2/x can be stacking ports.", legacy=True)
_add("ICX6450-24P", "ICX6450", [g("access", 1, 24, "1G", True), g("uplink", 2, 4, "1/10G SFP+")],
     "PoE+. 1/2/1 and 1/2/3 are stacking ports by default.", legacy=True)
_add("ICX6450-48P", "ICX6450", [g("access", 1, 48, "1G", True), g("uplink", 2, 4, "1/10G SFP+")],
     "PoE+. 1/2/1 and 1/2/3 are stacking ports by default.", legacy=True)
_add("ICX6610-48P", "ICX6610", [g("access", 1, 48, "1G", True), g("stack", 2, 8, "40G QSFP stacking"),
                                g("uplink", 3, 8, "1/10G SFP+")], "PoE+. 1/2/x are stacking ports.", legacy=True)
# ------------------------------------------------------------- FCX (FastIron 07.x-08.0.30)
_add("FCX624S", "FCX", [g("access", 1, 24, "1G"), g("stack", 2, 2, "16G CX4 stacking"), g("module", 3, 4, "10G SFP+")],
     "1/2/x are stacking ports. 1/3/x needs the 10G module.", legacy=True)
_add("FCX624S-HPOE", "FCX", [g("access", 1, 24, "1G", True), g("stack", 2, 2, "16G CX4 stacking"),
                             g("module", 3, 4, "10G SFP+")],
     "PoE+. 1/2/x are stacking ports. 1/3/x needs the 10G module.", legacy=True)
_add("FCX648S", "FCX", [g("access", 1, 48, "1G"), g("stack", 2, 2, "16G CX4 stacking"), g("module", 3, 4, "10G SFP+")],
     "1/2/x are stacking ports. 1/3/x needs the 10G module.", legacy=True)
_add("FCX648S-HPOE", "FCX", [g("access", 1, 48, "1G", True), g("stack", 2, 2, "16G CX4 stacking"),
                             g("module", 3, 4, "10G SFP+")],
     "PoE+. 1/2/x are stacking ports. 1/3/x needs the 10G module.", legacy=True)
# ------------------------------------------------------------- FGS / FLS (FastIron 07.x)
_add("FGS624P", "FGS", [g("access", 1, 24, "1G", True), g("module", 2, 2, "10G XFP")],
     "PoE. Single unit (ports 0/1/x). 0/2/x needs the 10G module.", legacy=True, old=True, stack=False)
_add("FGS648P", "FGS", [g("access", 1, 48, "1G", True), g("module", 2, 2, "10G XFP")],
     "PoE. Single unit (ports 0/1/x). 0/2/x needs the 10G module.", legacy=True, old=True, stack=False)
_add("FLS624", "FLS", [g("access", 1, 24, "1G"), g("module", 2, 2, "10G XFP")],
     "Single unit (ports 0/1/x). 0/2/x needs the 10G module.", legacy=True, old=True, stack=False)
_add("FLS648", "FLS", [g("access", 1, 48, "1G"), g("module", 2, 2, "10G XFP")],
     "Single unit (ports 0/1/x). 0/2/x needs the 10G module.", legacy=True, old=True, stack=False)

MODELS: dict[str, FiModel] = {m.name: m for m in _M}
CUSTOM = "Custom"
# Port words people type before a FastIron port ('ethe 1/1/1'); the canonical form has none.
ALIASES = {"": "", "e": "", "eth": "", "ethe": "", "ethernet": ""}


def get(name: str) -> FiModel | None:
    return MODELS.get(name)


def catalog() -> list[dict]:
    return [m.to_dict() for m in _M]
