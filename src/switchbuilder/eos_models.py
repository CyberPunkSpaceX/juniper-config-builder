"""Arista EOS switch models and their front-panel ports.

Port names are EOS names: ``Ethernet1`` for fixed ports, ``Ethernet49/1``
for the first lane of a QSFP port. These are the common layouts; check the
hardware guide for anything unusual (breakouts add /2, /3 and /4).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VModel:
    name: str
    family: str
    ports: tuple          # ({"name", "kind", "speed", "poe"}, ...)
    mgmt: str = "Management1"
    notes: str = ""

    @property
    def poe(self) -> bool:
        return any(p["poe"] for p in self.ports)

    def to_dict(self) -> dict:
        return {"name": self.name, "family": self.family, "mgmt": self.mgmt, "poe": self.poe,
                "notes": self.notes, "ports": [dict(p) for p in self.ports]}


def _run(first, last, kind, speed, poe=False, lanes=False):
    return [{"name": f"Ethernet{n}/1" if lanes else f"Ethernet{n}", "kind": kind, "speed": speed, "poe": poe}
            for n in range(first, last + 1)]


_M: list[VModel] = []


def _add(name, family, groups, notes="", mgmt="Management1"):
    ports = tuple(p for g in groups for p in g)
    _M.append(VModel(name, family, ports, mgmt, notes))


_add("720XP-24Y6", "720XP", [_run(1, 24, "access", "1G", True), _run(25, 30, "uplink", "25G SFP")],
     "24x 1G PoE + 6x 25G SFP.")
_add("720XP-48Y6", "720XP", [_run(1, 48, "access", "1G", True), _run(49, 54, "uplink", "25G SFP")],
     "48x 1G PoE + 6x 25G SFP.")
_add("720XP-24ZY4", "720XP", [_run(1, 24, "access", "mGig", True), _run(25, 28, "uplink", "25G SFP")],
     "24x multi-gig PoE + 4x 25G SFP.")
_add("720XP-48ZC2", "720XP", [_run(1, 48, "access", "mGig", True), _run(49, 50, "uplink", "100G QSFP", lanes=True)],
     "48x multi-gig PoE + 2x 100G QSFP.")
_add("722XPM-48Y4", "722XPM", [_run(1, 48, "access", "1G", True), _run(49, 52, "uplink", "25G SFP")],
     "48x 1G PoE + 4x 25G SFP.")
_add("7010TX-48", "7010", [_run(1, 48, "access", "1G"), _run(49, 52, "uplink", "10G SFP+")],
     "48x 1G + 4x 10G SFP+.")
_add("7050SX3-48YC8", "7050X3", [_run(1, 48, "access", "25G SFP"), _run(49, 56, "uplink", "100G QSFP", lanes=True)],
     "48x 25G SFP + 8x 100G QSFP.")
_add("7050TX3-48C8", "7050X3", [_run(1, 48, "access", "10G"), _run(49, 56, "uplink", "100G QSFP", lanes=True)],
     "48x 10GBASE-T + 8x 100G QSFP.")
_add("vEOS-lab", "vEOS", [_run(1, 12, "access", "1G")], "Virtual switch for labs (EVE-NG, GNS3).")
_add("cEOS-lab", "cEOS", [_run(1, 12, "access", "1G")], "Container switch for labs (containerlab).", mgmt="Management0")

MODELS: dict[str, VModel] = {m.name: m for m in _M}
CUSTOM = "Custom"
ALIASES = {"et": "Ethernet", "eth": "Ethernet", "ethernet": "Ethernet"}


def get(name: str) -> VModel | None:
    return MODELS.get(name)


def catalog() -> list[dict]:
    return [m.to_dict() for m in _M]
