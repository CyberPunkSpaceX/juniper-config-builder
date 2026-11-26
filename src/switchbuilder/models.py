"""EX switch models and their port layout.

Port names follow the Junos convention ``type-FPC/PIC/port``. FPC is the
Virtual Chassis member number (0 on a standalone switch). The layouts below
are the common factory layouts; check your hardware guide for anything
unusual (for example a 1G SFP in a 10G uplink shows up as ge- instead of xe-).

Port kinds:

* ``access``: front-panel ports.
* ``uplink``: built-in uplink ports.
* ``module``: ports that exist only with an optional uplink module.
* ``vcp``: ports that are Virtual Chassis ports out of the box. They need
  ``request virtual-chassis vc-port delete ...`` before they can carry traffic.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class PortGroup:
    kind: str          # access | uplink | module | vcp
    prefix: str        # ge | xe | mge | et
    pic: int
    first: int
    last: int
    speed: str
    poe: bool = False


@dataclass(frozen=True)
class Model:
    name: str
    family: str
    groups: tuple
    mgmt: str = "me0"
    poe: bool = False
    notes: str = ""
    alt_uplink: dict = field(default_factory=dict)  # xe pic -> also accept ge on that pic

    def ports(self, fpc: int = 0) -> list[dict]:
        out = []
        for g in self.groups:
            for n in range(g.first, g.last + 1):
                out.append({"name": f"{g.prefix}-{fpc}/{g.pic}/{n}", "kind": g.kind,
                            "speed": g.speed, "poe": g.poe})
        return out


def _ge(last, poe=False, first=0):
    return PortGroup("access", "ge", 0, first, last, "1G", poe)


def _mge(last, poe=True, first=0, speed="mGig"):
    return PortGroup("access", "mge", 0, first, last, speed, poe)


SFP10 = "10G SFP+"
_M = []


def _add(name, family, groups, mgmt="me0", notes=""):
    poe = any(g.poe for g in groups)
    _M.append(Model(name, family, tuple(groups), mgmt, poe, notes))


# ---------------------------------------------------------------- EX2300
_ex2300_up = lambda n=4: PortGroup("uplink", "xe", 1, 0, n - 1, SFP10)  # noqa: E731
_add("EX2300-C-12T", "EX2300", [_ge(11), _ex2300_up(2)], notes="Compact, fanless.")
_add("EX2300-C-12P", "EX2300", [_ge(11, True), _ex2300_up(2)], notes="Compact, fanless, PoE+.")
_add("EX2300-24T", "EX2300", [_ge(23), _ex2300_up()])
_add("EX2300-24P", "EX2300", [_ge(23, True), _ex2300_up()], notes="PoE+ on all 24 ports.")
_add("EX2300-24MP", "EX2300", [_ge(15, True), _mge(23, first=16, speed="1/2.5G"), _ex2300_up(6)],
     notes="Ports 16-23 are multigigabit (mge). PoE+ on all.")
_add("EX2300-48T", "EX2300", [_ge(47), _ex2300_up()])
_add("EX2300-48P", "EX2300", [_ge(47, True), _ex2300_up()], notes="PoE+ on all 48 ports.")
_add("EX2300-48MP", "EX2300", [_ge(31, True), _mge(47, first=32, speed="1/2.5G"), _ex2300_up(6)],
     notes="Ports 32-47 are multigigabit (mge). PoE+ on all.")

# ---------------------------------------------------------------- EX3400
_ex3400 = lambda: [PortGroup("uplink", "xe", 2, 0, 3, SFP10), PortGroup("vcp", "et", 1, 0, 1, "40G QSFP+")]  # noqa: E731
_add("EX3400-24T", "EX3400", [_ge(23), *_ex3400()], notes="et-0/1/0-1 are VC ports by default.")
_add("EX3400-24P", "EX3400", [_ge(23, True), *_ex3400()], notes="PoE+. et-0/1/0-1 are VC ports by default.")
_add("EX3400-48T", "EX3400", [_ge(47), *_ex3400()], notes="et-0/1/0-1 are VC ports by default.")
_add("EX3400-48P", "EX3400", [_ge(47, True), *_ex3400()], notes="PoE+. et-0/1/0-1 are VC ports by default.")
_add("EX3400-48MP", "EX3400", [_mge(23, speed="1/2.5/5/10G"), _ge(47, True, first=24), *_ex3400()],
     notes="Ports 0-23 are multigigabit (mge). PoE+. et-0/1/0-1 are VC ports by default.")

# ---------------------------------------------------------------- EX4100
# 4x 10G SFP+ uplinks (xe-0/2/x) and 4x 25G SFP28 (et-0/1/x) that are
# Virtual Chassis ports out of the box. The EX4100-F (fanless/compact) has
# 4x 1/10G SFP+ uplinks only.
_ex4100 = lambda: [PortGroup("vcp", "et", 1, 0, 3, "25G SFP28"), PortGroup("uplink", "xe", 2, 0, 3, SFP10)]  # noqa: E731
_ex4100f = lambda: [PortGroup("uplink", "xe", 2, 0, 3, SFP10)]  # noqa: E731
_N41 = "et-0/1/0-3 (25G) are VC ports by default."
_add("EX4100-24T", "EX4100", [_ge(23), *_ex4100()], mgmt="em0", notes=_N41)
_add("EX4100-24P", "EX4100", [_ge(23, True), *_ex4100()], mgmt="em0", notes="PoE+. " + _N41)
_add("EX4100-48T", "EX4100", [_ge(47), *_ex4100()], mgmt="em0", notes=_N41)
_add("EX4100-48P", "EX4100", [_ge(47, True), *_ex4100()], mgmt="em0", notes="PoE+. " + _N41)
_add("EX4100-24MP", "EX4100", [_mge(7, speed="1-10G"), _ge(23, True, first=8), *_ex4100()], mgmt="em0",
     notes="Ports 0-7 are multigigabit (mge), 8-23 are 1G. PoE++. " + _N41)
_add("EX4100-48MP", "EX4100", [_mge(15, speed="1-10G"), _ge(47, True, first=16), *_ex4100()], mgmt="em0",
     notes="Ports 0-15 are multigigabit (mge), 16-47 are 1G. PoE++. " + _N41)
_add("EX4100-F-12T", "EX4100-F", [_ge(11), *_ex4100f()], mgmt="em0", notes="Compact, fanless.")
_add("EX4100-F-12P", "EX4100-F", [_ge(11, True), *_ex4100f()], mgmt="em0", notes="Compact, fanless, PoE+.")
_add("EX4100-F-24T", "EX4100-F", [_ge(23), *_ex4100f()], mgmt="em0")
_add("EX4100-F-24P", "EX4100-F", [_ge(23, True), *_ex4100f()], mgmt="em0", notes="PoE+.")
_add("EX4100-F-48T", "EX4100-F", [_ge(47), *_ex4100f()], mgmt="em0")
_add("EX4100-F-48P", "EX4100-F", [_ge(47, True), *_ex4100f()], mgmt="em0", notes="PoE+.")

# ---------------------------------------------------------------- EX4300
_ex4300 = lambda: [PortGroup("vcp", "et", 1, 0, 3, "40G QSFP+"), PortGroup("module", "xe", 2, 0, 3, "10G SFP+ (module)")]  # noqa: E731
_add("EX4300-24T", "EX4300", [_ge(23), *_ex4300()], notes="Rear et-0/1/0-3 are VC ports. xe-0/2/x needs an uplink module.")
_add("EX4300-24P", "EX4300", [_ge(23, True), *_ex4300()], notes="PoE+. Rear et-0/1/0-3 are VC ports. xe-0/2/x needs an uplink module.")
_add("EX4300-48T", "EX4300", [_ge(47), *_ex4300()], notes="Rear et-0/1/0-3 are VC ports. xe-0/2/x needs an uplink module.")
_add("EX4300-48P", "EX4300", [_ge(47, True), *_ex4300()], notes="PoE+. Rear et-0/1/0-3 are VC ports. xe-0/2/x needs an uplink module.")
_add("EX4300-48MP", "EX4300", [_mge(23, speed="100M-10G"), _ge(47, True, first=24), *_ex4300()],
     notes="Ports 0-23 are multigigabit (mge). PoE. Rear et-0/1/0-3 are VC ports.")

# ---------------------------------------------------------------- EX4400
_ex4400 = lambda: [PortGroup("vcp", "et", 1, 0, 1, "100G QSFP28"), PortGroup("module", "xe", 2, 0, 3, "10/25G (module)")]  # noqa: E731
_add("EX4400-24T", "EX4400", [_ge(23), *_ex4400()], mgmt="em0", notes="Rear et-0/1/0-1 are VC ports. xe-0/2/x needs an uplink module.")
_add("EX4400-24P", "EX4400", [_ge(23, True), *_ex4400()], mgmt="em0", notes="PoE++ (90W). Rear et-0/1/0-1 are VC ports.")
_add("EX4400-48T", "EX4400", [_ge(47), *_ex4400()], mgmt="em0", notes="Rear et-0/1/0-1 are VC ports. xe-0/2/x needs an uplink module.")
_add("EX4400-48P", "EX4400", [_ge(47, True), *_ex4400()], mgmt="em0", notes="PoE++ (90W). Rear et-0/1/0-1 are VC ports.")
_add("EX4400-24MP", "EX4400", [_mge(23, speed="1-10G"), *_ex4400()], mgmt="em0", notes="Multigigabit PoE++. Rear et-0/1/0-1 are VC ports.")
_add("EX4400-48MP", "EX4400", [_mge(47, speed="1-10G"), *_ex4400()], mgmt="em0",
     notes="Multigigabit PoE++ (36x 2.5G + 12x 10G). Rear et-0/1/0-1 are VC ports.")

MODELS: dict[str, Model] = {m.name: m for m in _M}
CUSTOM = "Custom"


def get(name: str) -> Model | None:
    return MODELS.get(name)


def catalog() -> list[dict]:
    """The model list for the web page."""
    return [{"name": m.name, "family": m.family, "mgmt": m.mgmt, "poe": m.poe, "notes": m.notes,
             "ports": m.ports(0)} for m in _M]
