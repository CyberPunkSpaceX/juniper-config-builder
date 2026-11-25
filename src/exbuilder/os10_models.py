"""Dell PowerSwitch models running Dell SmartFabric OS10, and their ports.

Port names are OS10 names: ``ethernet1/1/1`` (node/slot/port). The uplinks
continue the numbering (``ethernet1/1/49``); breakout lanes add ``:1`` to ``:4``
and are left out here. The out-of-band port is ``mgmt1/1/1``. These are the
common layouts; check the hardware guide for anything unusual.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DModel:
    name: str
    family: str
    ports: tuple          # ({"name", "kind", "speed", "poe"}, ...)
    mgmt: str = "mgmt1/1/1"
    notes: str = ""

    @property
    def poe(self) -> bool:
        return any(p["poe"] for p in self.ports)

    def to_dict(self) -> dict:
        return {"name": self.name, "family": self.family, "mgmt": self.mgmt, "poe": self.poe,
                "notes": self.notes, "ports": [dict(p) for p in self.ports]}


def _run(first, last, kind, speed, poe=False):
    return [{"name": f"ethernet1/1/{n}", "kind": kind, "speed": speed, "poe": poe} for n in range(first, last + 1)]


_M: list[DModel] = []


def _add(name, family, groups, notes=""):
    _M.append(DModel(name, family, tuple(p for g in groups for p in g), "mgmt1/1/1", notes))


_add("N3248TE-ON", "N3200", [_run(1, 48, "access", "1G"), _run(49, 52, "uplink", "10G SFP+"),
                             _run(53, 54, "uplink", "100G QSFP28")],
     "48x 1G + 4x 10G SFP+ + 2x 100G QSFP28 (stacking ports used as uplinks).")
_add("N3248P-ON", "N3200", [_run(1, 48, "access", "1G", True), _run(49, 52, "uplink", "10G SFP+"),
                            _run(53, 54, "uplink", "100G QSFP28")],
     "48x 1G PoE+ + 4x 10G SFP+ + 2x 100G QSFP28. PoE settings are not written yet.")
_add("N3248PXE-ON", "N3200", [_run(1, 48, "access", "mGig", True), _run(49, 52, "uplink", "25G SFP28"),
                              _run(53, 54, "uplink", "100G QSFP28")],
     "48x multi-gig PoE + 4x 25G SFP28 + 2x 100G QSFP28. PoE settings are not written yet.")
_add("N2248PX-ON", "N2200", [_run(1, 48, "access", "1G", True), _run(49, 52, "uplink", "25G SFP28"),
                             _run(53, 54, "uplink", "100G QSFP28")],
     "48x 1G/2.5G PoE + 4x 25G SFP28 + 2x 100G QSFP28. PoE settings are not written yet.")
_add("S5248F-ON", "S5200", [_run(1, 48, "access", "25G SFP28"), _run(49, 52, "uplink", "100G QSFP28-DD"),
                            _run(53, 56, "uplink", "100G QSFP28")],
     "48x 25G SFP28 + 2x 200G QSFP28-DD (as 49-52) + 4x 100G QSFP28.")
_add("S5232F-ON", "S5200", [_run(1, 32, "uplink", "100G QSFP28")], "32x 100G QSFP28 (spine or aggregation).")
_add("OS10 virtual (lab)", "OS10 VM", [_run(1, 16, "access", "virtual")],
     "Dell OS10 virtual appliance for labs (GNS3, EVE-NG).")

MODELS: dict[str, DModel] = {m.name: m for m in _M}
CUSTOM = "Custom"
ALIASES = {"e": "ethernet", "et": "ethernet", "eth": "ethernet", "ethernet": "ethernet"}


def get(name: str) -> DModel | None:
    return MODELS.get(name)


def catalog() -> list[dict]:
    return [m.to_dict() for m in _M]
