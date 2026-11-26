"""Cisco Nexus switches running NX-OS, and their front-panel ports.

Port names are NX-OS names: ``Ethernet1/1`` to ``Ethernet1/48`` for the fixed
ports and ``Ethernet1/49`` and up for the uplinks (breakout lanes add
``/1`` to ``/4``, as in ``Ethernet1/49/1``). The out-of-band port is ``mgmt0``
and always sits in the ``management`` VRF. These are the common layouts;
check the hardware guide for anything unusual.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class NModel:
    name: str
    family: str
    ports: tuple          # ({"name", "kind", "speed", "poe"}, ...)
    mgmt: str = "mgmt0"
    legacy: bool = False  # NX-OS 7.x and older (Nexus 3000): no VLAN mapping
    notes: str = ""

    @property
    def poe(self) -> bool:
        return False

    def to_dict(self) -> dict:
        return {"name": self.name, "family": self.family, "mgmt": self.mgmt, "poe": False,
                "notes": self.notes, "ports": [dict(p) for p in self.ports]}


def _run(first, last, kind, speed):
    return [{"name": f"Ethernet1/{n}", "kind": kind, "speed": speed, "poe": False} for n in range(first, last + 1)]


_M: list[NModel] = []


def _add(name, family, groups, notes="", legacy=False):
    _M.append(NModel(name, family, tuple(p for g in groups for p in g), "mgmt0", legacy, notes))


_add("N9K-C93180YC-FX", "Nexus 9300", [_run(1, 48, "access", "10/25G SFP28"), _run(49, 54, "uplink", "40/100G QSFP28")],
     "48x 10/25G SFP28 + 6x 40/100G QSFP28.")
_add("N9K-C93180YC-FX3", "Nexus 9300", [_run(1, 48, "access", "10/25G SFP28"), _run(49, 54, "uplink", "40/100G QSFP28")],
     "48x 10/25G SFP28 + 6x 40/100G QSFP28.")
_add("N9K-C93108TC-FX", "Nexus 9300", [_run(1, 48, "access", "10GBASE-T"), _run(49, 54, "uplink", "40/100G QSFP28")],
     "48x 100M/1/10GBASE-T + 6x 40/100G QSFP28.")
_add("N9K-C9348GC-FXP", "Nexus 9300", [_run(1, 48, "access", "1G"), _run(49, 52, "uplink", "10/25G SFP28"),
                                        _run(53, 54, "uplink", "40/100G QSFP28")],
     "48x 100M/1G copper + 4x 10/25G SFP28 + 2x 40/100G QSFP28. Built for out-of-band management networks.")
_add("N9K-C92348GC-X", "Nexus 9200", [_run(1, 48, "access", "1G"), _run(49, 52, "uplink", "10/25G SFP28"),
                                       _run(53, 54, "uplink", "40/100G QSFP28")],
     "48x 100M/1G copper + 4x 10/25G SFP28 + 2x 40/100G QSFP28.")
_add("N9K-C9336C-FX2", "Nexus 9300", [_run(1, 36, "uplink", "40/100G QSFP28")],
     "36x 40/100G QSFP28 (spine or aggregation).")
_add("N3K-C3048TP-1GE", "Nexus 3000", [_run(1, 48, "access", "1G"), _run(49, 52, "uplink", "10G SFP+")],
     "48x 1G copper + 4x 10G SFP+. Older NX-OS (6.x/7.x): no VLAN mapping.", legacy=True)
_add("N3K-C3064PQ-10GX", "Nexus 3000", [_run(1, 48, "access", "10G SFP+"), _run(49, 52, "uplink", "40G QSFP+")],
     "48x 10G SFP+ + 4x 40G QSFP+. Older NX-OS (6.x/7.x): no VLAN mapping.", legacy=True)
_add("N9K-C9300v (Nexus 9000v lab)", "Nexus 9000v", [_run(1, 16, "access", "virtual")],
     "Virtual Nexus for labs (EVE-NG, CML, containerlab). Up to 64 ports; only the first 16 are listed.")

MODELS: dict[str, NModel] = {m.name: m for m in _M}
CUSTOM = "Custom"
ALIASES = {"e": "Ethernet", "et": "Ethernet", "eth": "Ethernet", "ethernet": "Ethernet"}


def get(name: str) -> NModel | None:
    return MODELS.get(name)


def catalog() -> list[dict]:
    return [m.to_dict() for m in _M]
