"""Ubiquiti UniFi switches (managed by the UniFi Network application).

Ports are numbered 1 to N, as on the switch and in the app's Port Manager.
``layer3`` marks the models that can route between VLANs themselves.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class UModel:
    name: str
    family: str
    groups: tuple          # (first, last, kind, speed, poe)
    layer3: bool = False
    notes: str = ""

    @property
    def poe(self) -> bool:
        return any(g[4] for g in self.groups)

    @property
    def mgmt(self) -> str:
        return ""

    @property
    def ports(self) -> list[dict]:
        return [{"name": str(n), "kind": kind, "speed": speed, "poe": poe}
                for first, last, kind, speed, poe in self.groups for n in range(first, last + 1)]

    def to_dict(self) -> dict:
        return {"name": self.name, "family": self.family, "mgmt": "", "poe": self.poe, "layer3": self.layer3,
                "notes": self.notes, "ports": self.ports}


_M: list[UModel] = []


def _add(name, family, groups, layer3=False, notes=""):
    _M.append(UModel(name, family, tuple(groups), layer3, notes))


_add("USW-Lite-8-PoE", "Lite", [(1, 4, "access", "1G", True), (5, 8, "access", "1G", False)],
     notes="8x 1G, ports 1-4 PoE+.")
_add("USW-Lite-16-PoE", "Lite", [(1, 8, "access", "1G", True), (9, 16, "access", "1G", False)],
     notes="16x 1G, ports 1-8 PoE+.")
_add("USW-24-PoE", "Standard", [(1, 16, "access", "1G", True), (17, 24, "access", "1G", False),
                                (25, 26, "uplink", "1G SFP", False)],
     notes="24x 1G (1-16 PoE+) + 2x 1G SFP.")
_add("USW-48-PoE", "Standard", [(1, 32, "access", "1G", True), (33, 48, "access", "1G", False),
                                (49, 52, "uplink", "1G SFP", False)],
     notes="48x 1G (1-32 PoE+) + 4x 1G SFP.")
_add("USW-Pro-24-PoE", "Pro", [(1, 24, "access", "1G", True), (25, 26, "uplink", "10G SFP+", False)], True,
     "24x 1G PoE+ (17-24 PoE++) + 2x 10G SFP+. Layer 3.")
_add("USW-Pro-48-PoE", "Pro", [(1, 48, "access", "1G", True), (49, 52, "uplink", "10G SFP+", False)], True,
     "48x 1G PoE+ (41-48 PoE++) + 4x 10G SFP+. Layer 3.")
_add("USW-Pro-Max-24-PoE", "Pro Max", [(1, 16, "access", "1G", True), (17, 24, "access", "2.5G", True),
                                       (25, 26, "uplink", "10G SFP+", False)], True,
     "16x 1G + 8x 2.5G, all PoE, + 2x 10G SFP+. Layer 3.")
_add("USW-Aggregation", "Aggregation", [(1, 8, "uplink", "10G SFP+", False)],
     notes="8x 10G SFP+.")
_add("USW-Pro-Aggregation", "Aggregation", [(1, 28, "uplink", "10G SFP+", False), (29, 32, "uplink", "25G SFP28", False)],
     True, "28x 10G SFP+ + 4x 25G SFP28. Layer 3.")

MODELS: dict[str, UModel] = {m.name: m for m in _M}
CUSTOM = "Custom"
ALIASES = {"": "", "port": "", "p": ""}


def get(name: str) -> UModel | None:
    return MODELS.get(name)


def catalog() -> list[dict]:
    return [m.to_dict() for m in _M]
