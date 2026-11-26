"""Extreme Networks switches running ExtremeXOS / Switch Engine, and their ports.

Port names are EXOS names: ``1`` to ``52`` on a standalone switch and
``slot:port`` (``2:1``) once switches are stacked (SummitStack). These are
the common layouts; check the hardware guide for anything unusual.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class XModel:
    name: str
    family: str
    groups: tuple          # (first, last, kind, speed, poe)
    stack: bool = True
    notes: str = ""

    @property
    def poe(self) -> bool:
        return any(g[4] for g in self.groups)

    @property
    def mgmt(self) -> str:
        return "Mgmt"

    def ports(self, slot: int = 1, stacked: bool = False) -> list[dict]:
        pre = f"{slot}:" if stacked else ""
        return [{"name": f"{pre}{n}", "kind": kind, "speed": speed, "poe": poe}
                for first, last, kind, speed, poe in self.groups for n in range(first, last + 1)]

    def to_dict(self) -> dict:
        return {"name": self.name, "family": self.family, "mgmt": self.mgmt, "poe": self.poe, "notes": self.notes,
                "ports": self.ports(), "stack": self.stack}


_M: list[XModel] = []


def _add(name, family, groups, notes="", stack=True):
    _M.append(XModel(name, family, tuple(groups), stack, notes))


_add("X440-G2-24p-10GE4", "X440-G2", [(1, 24, "access", "1G", True), (25, 28, "uplink", "10G SFP+", False)],
     "24x 1G PoE+ + 4x 10G SFP+ (the 10G ports need the license upgrade on some versions).")
_add("X440-G2-48p-10GE4", "X440-G2", [(1, 48, "access", "1G", True), (49, 52, "uplink", "10G SFP+", False)],
     "48x 1G PoE+ + 4x 10G SFP+.")
_add("X450-G2-48p-10GE4", "X450-G2", [(1, 48, "access", "1G", True), (49, 52, "uplink", "10G SFP+", False)],
     "48x 1G PoE+ + 4x 10G SFP+, plus rear stacking ports.")
_add("X460-G2-48p-10GE4", "X460-G2", [(1, 48, "access", "1G", True), (49, 52, "uplink", "10G SFP+", False)],
     "48x 1G PoE+ + 4x 10G SFP+, plus a VIM slot.")
_add("5320-48P-8XE", "5320", [(1, 48, "access", "1G", True), (49, 56, "uplink", "10G SFP+", False)],
     "48x 1G PoE+ + 8x 10G SFP+. Universal switch: runs Switch Engine (EXOS) or Fabric Engine; this writes Switch Engine.")
_add("5420F-48P-4XE", "5420", [(1, 48, "access", "1G", True), (49, 52, "uplink", "10G SFP+", False)],
     "48x 1G PoE+ + 4x 10G SFP+. Universal switch, Switch Engine (EXOS) persona.")
_add("EXOS VM (lab)", "EXOS VM", [(1, 8, "access", "virtual", False)],
     "ExtremeXOS virtual machine for labs (GNS3, EVE-NG).", stack=False)

MODELS: dict[str, XModel] = {m.name: m for m in _M}
CUSTOM = "Custom"
ALIASES = {"": ""}

_TOKEN = re.compile(r"^(?:(\d+):)?(\d+)$")
_RANGE = re.compile(r"^(?:(\d+):)?(\d+)-(?:(\d+):)?(\d+)$")


def expand(spec: str) -> list[str]:
    """``1-3, 49, 2:1-24, 2:1-2:4`` -> EXOS port names. Raises ValueError."""
    out: list[str] = []
    text = re.sub(r"\s*-\s*", "-", re.sub(r"\s+to\s+", "-", (spec or "").strip()))
    for part in re.split(r"[,;\s]+", text):
        if not part:
            continue
        m = _TOKEN.match(part)
        if m:
            out.append(f"{m.group(1) + ':' if m.group(1) else ''}{int(m.group(2))}")
            continue
        m = _RANGE.match(part)
        if not m:
            raise ValueError(f"'{part}' is not a port or port range")
        slot, a, slot2, b = m.groups()
        if slot2 and slot2 != slot:
            raise ValueError(f"'{part}': a range must stay on one stack slot")
        a, b = int(a), int(b)
        if b < a or b - a > 1024:
            raise ValueError(f"'{part}': the range runs backwards or is too long")
        out.extend(f"{slot + ':' if slot else ''}{n}" for n in range(a, b + 1))
    return out


def key(name: str):
    m = _TOKEN.match(name)
    return (int(m.group(1) or 0), int(m.group(2))) if m else (999, 0)


def compact(names: list[str]) -> str:
    """Port names as an EXOS port list: 1-40,47 or 1:1-24,2:1-24."""
    runs: list[list[str]] = []
    for n in sorted(set(names), key=key):
        if runs:
            ps, pn = key(runs[-1][1])
            s, num = key(n)
            if ps == s and num == pn + 1:
                runs[-1][1] = n
                continue
        runs.append([n, n])
    return ",".join(a if a == b else f"{a}-{key(b)[1]}" for a, b in runs)


def get(name: str) -> XModel | None:
    return MODELS.get(name)


def catalog() -> list[dict]:
    return [m.to_dict() for m in _M]
