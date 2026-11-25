"""MikroTik switches running RouterOS v7 (CRS3xx with bridge VLAN filtering).

Port names are RouterOS names: ``ether1``, ``sfp-sfpplus1``. There is no
separate out-of-band port on most CRS models: manage the switch through a VLAN
address, or name a port as the management port to take it out of the bridge.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RModel:
    name: str
    family: str
    ports: tuple
    notes: str = ""

    @property
    def poe(self) -> bool:
        return any(p["poe"] for p in self.ports)

    @property
    def mgmt(self) -> str:
        return ""

    def to_dict(self) -> dict:
        return {"name": self.name, "family": self.family, "mgmt": "", "poe": self.poe,
                "notes": self.notes, "ports": [dict(p) for p in self.ports]}


def _run(word, first, last, kind, speed, poe=False):
    return [{"name": f"{word}{n}", "kind": kind, "speed": speed, "poe": poe} for n in range(first, last + 1)]


_M: list[RModel] = []


def _add(name, family, groups, notes=""):
    _M.append(RModel(name, family, tuple(p for g in groups for p in g), notes))


_add("CRS326-24G-2S+", "CRS3xx", [_run("ether", 1, 24, "access", "1G"), _run("sfp-sfpplus", 1, 2, "uplink", "10G SFP+")],
     "24x 1G + 2x 10G SFP+.")
_add("CRS328-24P-4S+", "CRS3xx", [_run("ether", 1, 24, "access", "1G", True), _run("sfp-sfpplus", 1, 4, "uplink", "10G SFP+")],
     "24x 1G PoE + 4x 10G SFP+.")
_add("CRS354-48P-4S+2Q+", "CRS3xx", [_run("ether", 1, 48, "access", "1G", True), _run("sfp-sfpplus", 1, 4, "uplink", "10G SFP+")],
     "48x 1G PoE + 4x 10G SFP+ (the 2x 40G QSFP+ ports, qsfpplus1-1 and qsfpplus2-1, go under Custom ports).")
_add("CRS310-8G+2S+", "CRS3xx", [_run("ether", 1, 8, "access", "2.5G"), _run("sfp-sfpplus", 1, 2, "uplink", "10G SFP+")],
     "8x 2.5G + 2x 10G SFP+.")
_add("CRS317-1G-16S+", "CRS3xx", [_run("ether", 1, 1, "access", "1G"), _run("sfp-sfpplus", 1, 16, "uplink", "10G SFP+")],
     "1x 1G + 16x 10G SFP+.")
_add("CHR (lab)", "CHR", [_run("ether", 1, 8, "access", "virtual")],
     "Cloud Hosted Router for labs (EVE-NG, GNS3). Bridging is done in software.")

MODELS: dict[str, RModel] = {m.name: m for m in _M}
CUSTOM = "Custom"
ALIASES = {"ether": "ether", "eth": "ether", "e": "ether", "sfp-sfpplus": "sfp-sfpplus", "sfpplus": "sfp-sfpplus",
           "sfp": "sfp", "combo": "combo", "qsfpplus": "qsfpplus"}


def get(name: str) -> RModel | None:
    return MODELS.get(name)


def catalog() -> list[dict]:
    return [m.to_dict() for m in _M]
