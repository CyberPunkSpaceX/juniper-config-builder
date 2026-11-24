"""HPE Aruba CX (AOS-CX) switch models and their front-panel ports.

Ports are ``member/slot/port``: 1/1/1 is the first port of VSF member 1.
These are the common layouts; check the hardware guide for anything unusual.
``vsf`` is the part number used in 'vsf member N / type ...' for models that
stack with VSF (6200 and 6300); the others don't stack.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Group:
    kind: str     # access | uplink
    first: int
    last: int
    speed: str
    poe: bool = False


@dataclass(frozen=True)
class CxModel:
    name: str
    family: str
    groups: tuple
    vsf: str = ""          # VSF member type (part number), empty = no stacking
    has_mgmt: bool = True
    notes: str = ""

    @property
    def poe(self) -> bool:
        return any(g.poe for g in self.groups)

    @property
    def stack(self) -> bool:
        return bool(self.vsf)

    @property
    def mgmt(self) -> str:
        return "mgmt" if self.has_mgmt else ""

    def ports(self, member: int = 1) -> list[dict]:
        return [{"name": f"{member}/1/{n}", "kind": g.kind, "speed": g.speed, "poe": g.poe}
                for g in self.groups for n in range(g.first, g.last + 1)]

    def to_dict(self) -> dict:
        return {"name": self.name, "family": self.family, "mgmt": self.mgmt, "poe": self.poe, "notes": self.notes,
                "ports": self.ports(1), "stack": self.stack}


_M: list[CxModel] = []


def _add(name, family, groups, notes="", vsf="", mgmt=True):
    _M.append(CxModel(name, family, tuple(groups), vsf, mgmt, notes))


def g(first, last, speed, kind="access", poe=False):
    return Group(kind, first, last, speed, poe)


# ------------------------------------------------------------------ access
_add("6000-24G-CL4-4SFP", "6000", [g(1, 24, "1G", poe=True), g(25, 28, "1G SFP", "uplink")],
     "R8N87A. PoE (class 4). No stacking and no out-of-band management port.", mgmt=False)
_add("6000-48G-CL4-4SFP", "6000", [g(1, 48, "1G", poe=True), g(49, 52, "1G SFP", "uplink")],
     "R8N85A. PoE (class 4). No stacking and no out-of-band management port.", mgmt=False)
_add("6100-24G-CL4-4SFP+", "6100", [g(1, 24, "1G", poe=True), g(25, 28, "1/10G SFP+", "uplink")],
     "JL677A. PoE (class 4). No stacking and no out-of-band management port.", mgmt=False)
_add("6100-48G-CL4-4SFP+", "6100", [g(1, 48, "1G", poe=True), g(49, 52, "1/10G SFP+", "uplink")],
     "JL675A. PoE (class 4). No stacking and no out-of-band management port.", mgmt=False)
_add("6200F-24G-CL4-4SFP+", "6200", [g(1, 24, "1G", poe=True), g(25, 28, "1/10G SFP+", "uplink")],
     "JL724A. PoE (class 4). Stacks with VSF (up to 8).", vsf="jl724a")
_add("6200F-48G-CL4-4SFP+", "6200", [g(1, 48, "1G", poe=True), g(49, 52, "1/10G SFP+", "uplink")],
     "JL725A. PoE (class 4). Stacks with VSF (up to 8).", vsf="jl725a")
_add("6300M-24G-CL4-4SFP56", "6300", [g(1, 24, "1G", poe=True), g(25, 28, "1/10/25/50G SFP56", "uplink")],
     "JL662A. PoE (class 4). Stacks with VSF (up to 10).", vsf="jl662a")
_add("6300M-48G-CL4-4SFP56", "6300", [g(1, 48, "1G", poe=True), g(49, 52, "1/10/25/50G SFP56", "uplink")],
     "JL661A. PoE (class 4). Stacks with VSF (up to 10).", vsf="jl661a")
_add("6300F-48G-CL4-4SFP56", "6300", [g(1, 48, "1G", poe=True), g(49, 52, "1/10/25/50G SFP56", "uplink")],
     "JL665A. PoE (class 4), fixed power supply. Stacks with VSF (up to 10).", vsf="jl665a")
_add("6300M-48SR5-CL6-4SFP56", "6300", [g(1, 36, "1G", poe=True), g(37, 48, "mGig 5G", poe=True),
                                        g(49, 52, "1/10/25/50G SFP56", "uplink")],
     "JL659A. Class 6 PoE, 12 multi-gig ports. Stacks with VSF (up to 10).", vsf="jl659a")
# ------------------------------------------------------------------ aggregation / core
_add("8320-48SFP+6QSFP+", "8320", [g(1, 48, "1/10G SFP+"), g(49, 54, "40G QSFP+", "uplink")],
     "JL479A. Aggregation/core. Uses VSX for redundancy instead of stacking.")
_add("8325-48Y8C", "8325", [g(1, 48, "10/25G SFP28"), g(49, 56, "40/100G QSFP28", "uplink")],
     "JL624A. Aggregation/core. Uses VSX for redundancy instead of stacking.")
_add("8360-48Y6C", "8360", [g(1, 48, "10/25G SFP28"), g(49, 54, "40/100G QSFP28", "uplink")],
     "JL700A. Aggregation/core. Uses VSX for redundancy instead of stacking.")
# ------------------------------------------------------------------ lab
_add("AOS-CX simulator", "CX-SIM", [g(1, 52, "1G")], "Virtual AOS-CX switch for labs (EVE-NG, GNS3).")

MODELS: dict[str, CxModel] = {m.name: m for m in _M}
CUSTOM = "Custom"
# Port words people may type before an AOS-CX port; the canonical form has none.
ALIASES = {"": "", "interface": "", "int": "", "port": ""}


def get(name: str) -> CxModel | None:
    return MODELS.get(name)


def catalog() -> list[dict]:
    return [m.to_dict() for m in _M]
