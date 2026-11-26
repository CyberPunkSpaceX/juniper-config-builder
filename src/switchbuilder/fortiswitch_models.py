"""Fortinet FortiSwitch models in standalone mode (FortiSwitchOS), and their ports.

Port names are FortiSwitchOS names: ``port1`` to ``port52``. The out-of-band
port is ``mgmt``. A FortiSwitch managed by a FortiGate (FortiLink) is set up on
the FortiGate instead; this writes the standalone switch's own CLI.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FModel:
    name: str
    family: str
    ports: tuple
    mgmt: str = "mgmt"
    notes: str = ""

    @property
    def poe(self) -> bool:
        return any(p["poe"] for p in self.ports)

    def to_dict(self) -> dict:
        return {"name": self.name, "family": self.family, "mgmt": self.mgmt, "poe": self.poe,
                "notes": self.notes, "ports": [dict(p) for p in self.ports]}


def _run(first, last, kind, speed, poe=False):
    return [{"name": f"port{n}", "kind": kind, "speed": speed, "poe": poe} for n in range(first, last + 1)]


_M: list[FModel] = []


def _add(name, family, groups, notes="", mgmt="mgmt"):
    _M.append(FModel(name, family, tuple(p for g in groups for p in g), mgmt, notes))


_add("FS-108F-FPOE", "100F", [_run(1, 8, "access", "1G", True), _run(9, 10, "uplink", "1G SFP")],
     "8x 1G PoE+ + 2x 1G SFP. No out-of-band port: manage it through a VLAN address.", mgmt="")
_add("FS-124F-POE", "100F", [_run(1, 24, "access", "1G", True), _run(25, 28, "uplink", "10G SFP+")],
     "24x 1G PoE+ + 4x 10G SFP+. No out-of-band port: manage it through a VLAN address.", mgmt="")
_add("FS-148F-FPOE", "100F", [_run(1, 48, "access", "1G", True), _run(49, 52, "uplink", "10G SFP+")],
     "48x 1G PoE+ + 4x 10G SFP+. No out-of-band port: manage it through a VLAN address.", mgmt="")
_add("FS-248E-FPOE", "200E", [_run(1, 48, "access", "1G", True), _run(49, 52, "uplink", "1G SFP")],
     "48x 1G PoE+ + 4x 1G SFP.")
_add("FS-424E-FPOE", "400E", [_run(1, 24, "access", "1G", True), _run(25, 28, "uplink", "10G SFP+")],
     "24x 1G PoE+ + 4x 10G SFP+.")
_add("FS-448E-FPOE", "400E", [_run(1, 48, "access", "1G", True), _run(49, 52, "uplink", "10G SFP+")],
     "48x 1G PoE+ + 4x 10G SFP+.")
_add("FS-1048E", "1000E", [_run(1, 48, "access", "10G SFP+"), _run(49, 54, "uplink", "100G QSFP28")],
     "48x 10G SFP+ + 6x 40/100G QSFP28.")

MODELS: dict[str, FModel] = {m.name: m for m in _M}
CUSTOM = "Custom"
# Plain numbers mean portN, so '1-24' works as well as 'port1-24'.
ALIASES = {"": "port", "port": "port", "p": "port"}


def get(name: str) -> FModel | None:
    return MODELS.get(name)


def catalog() -> list[dict]:
    return [m.to_dict() for m in _M]
