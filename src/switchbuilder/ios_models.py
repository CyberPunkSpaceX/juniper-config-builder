"""Cisco Catalyst models and their front-panel ports.

Catalyst 9000 and the older 3650/3850 run IOS-XE; the 2960-X runs classic IOS
(``classic``), which takes type 5 (MD5) secrets, has no management VRF, no
VLAN mapping and only static routing.

Port names are IOS-XE names: ``GigabitEthernet1/0/1`` is switch 1 of a stack,
slot 0, port 1. Uplink module ports are on slot 1 (``TenGigabitEthernet1/1/1``).
These are the common layouts; check the hardware guide for anything unusual.
"""

from __future__ import annotations

from dataclasses import dataclass

GI, TW, FI, TE, TWE, FO, HU = ("GigabitEthernet", "TwoGigabitEthernet", "FiveGigabitEthernet", "TenGigabitEthernet",
                               "TwentyFiveGigE", "FortyGigabitEthernet", "HundredGigE")


@dataclass(frozen=True)
class Group:
    kind: str     # access | uplink | module
    word: str
    slot: int
    first: int
    last: int
    speed: str
    poe: bool = False


@dataclass(frozen=True)
class IosModel:
    name: str
    family: str
    groups: tuple
    provision: str        # 'switch N provision <type>'
    mgmt: str = "GigabitEthernet0/0"
    notes: str = ""
    stack: bool = True
    classic: bool = False  # classic IOS (2960-X): type 5 secrets, no Mgmt-vrf, no VLAN mapping, static routes only

    @property
    def poe(self) -> bool:
        return any(g.poe for g in self.groups)

    def ports(self, member: int = 1) -> list[dict]:
        return [{"name": f"{g.word}{member}/{g.slot}/{n}", "kind": g.kind, "speed": g.speed, "poe": g.poe}
                for g in self.groups for n in range(g.first, g.last + 1)]

    def to_dict(self) -> dict:
        return {"name": self.name, "family": self.family, "mgmt": self.mgmt, "poe": self.poe, "notes": self.notes,
                "ports": self.ports(1), "stack": self.stack}


_M: list[IosModel] = []


def _add(name, family, groups, notes="", stack=True, mgmt="GigabitEthernet0/0", classic=False, provision=None):
    _M.append(IosModel(name, family, tuple(groups), provision or name.lower(), mgmt, notes, stack, classic))


def _acc(word, last, speed, poe=False, first=1):
    return Group("access", word, 0, first, last, speed, poe)


def _up(word, last, speed, kind="uplink"):
    return Group(kind, word, 1, 1, last, speed)


# ------------------------------------------------------------------ 2960-X (classic IOS 15.2)
_FA0 = "FastEthernet0"
_add("WS-C2960X-24PS-L", "C2960X", [_acc(GI, 24, "1G", True), Group("uplink", GI, 0, 25, 28, "1G SFP")],
     "PoE+, classic IOS 15.2. FlexStack (needs the stack module), up to 8.", mgmt=_FA0, classic=True)
_add("WS-C2960X-48LPS-L", "C2960X", [_acc(GI, 48, "1G", True), Group("uplink", GI, 0, 49, 52, "1G SFP")],
     "PoE+ (370 W), classic IOS 15.2. FlexStack (needs the stack module), up to 8.", mgmt=_FA0, classic=True)
_add("WS-C2960X-48FPS-L", "C2960X", [_acc(GI, 48, "1G", True), Group("uplink", GI, 0, 49, 52, "1G SFP")],
     "PoE+ (740 W), classic IOS 15.2. FlexStack (needs the stack module), up to 8.", mgmt=_FA0, classic=True)
_add("WS-C2960X-48FPD-L", "C2960X", [_acc(GI, 48, "1G", True), Group("uplink", TE, 0, 1, 2, "10G SFP+")],
     "PoE+ (740 W), 2x 10G SFP+ (Te1/0/1-2), classic IOS 15.2. FlexStack, up to 8.", mgmt=_FA0, classic=True)
_add("WS-C2960X-48TS-L", "C2960X", [_acc(GI, 48, "1G"), Group("uplink", GI, 0, 49, 52, "1G SFP")],
     "Classic IOS 15.2. FlexStack (needs the stack module), up to 8.", mgmt=_FA0, classic=True)
# ------------------------------------------------------------------ 3650 / 3850 (IOS-XE 16.x)
_add("WS-C3650-24PS", "C3650", [_acc(GI, 24, "1G", True), _up(GI, 4, "1G SFP")],
     "PoE+, IOS-XE 16. Fixed 4x 1G SFP uplinks. StackWise-160 with the stack kit.")
_add("WS-C3650-48PS", "C3650", [_acc(GI, 48, "1G", True), _up(GI, 4, "1G SFP")],
     "PoE+, IOS-XE 16. Fixed 4x 1G SFP uplinks. StackWise-160 with the stack kit.")
_add("WS-C3650-48PD", "C3650", [_acc(GI, 48, "1G", True), _up(GI, 2, "1G SFP"), Group("uplink", TE, 1, 3, 4, "10G SFP+")],
     "PoE+, IOS-XE 16. Uplinks Gi1/1/1-2 and Te1/1/3-4.")
_add("WS-C3850-24P", "C3850", [_acc(GI, 24, "1G", True), _up(TE, 4, "10G SFP+", "module")],
     "PoE+, IOS-XE 16. Uplinks need a network module (C3850-NM-4-10G shown).")
_add("WS-C3850-48P", "C3850", [_acc(GI, 48, "1G", True), _up(TE, 4, "10G SFP+", "module")],
     "PoE+, IOS-XE 16. Uplinks need a network module (C3850-NM-4-10G shown).")
_add("WS-C3850-48U", "C3850", [_acc(GI, 48, "1G", True), _up(TE, 4, "10G SFP+", "module")],
     "UPOE, IOS-XE 16. Uplinks need a network module (C3850-NM-4-10G shown).")
# ------------------------------------------------------------------ 9200
_add("C9200L-24T-4G", "C9200", [_acc(GI, 24, "1G"), _up(GI, 4, "1G SFP")], "Fixed 4x 1G SFP uplinks.")
_add("C9200L-24P-4G", "C9200", [_acc(GI, 24, "1G", True), _up(GI, 4, "1G SFP")], "PoE+. Fixed 4x 1G SFP uplinks.")
_add("C9200L-48P-4G", "C9200", [_acc(GI, 48, "1G", True), _up(GI, 4, "1G SFP")], "PoE+. Fixed 4x 1G SFP uplinks.")
_add("C9200L-48P-4X", "C9200", [_acc(GI, 48, "1G", True), _up(TE, 4, "10G SFP+")], "PoE+. Fixed 4x 10G SFP+ uplinks.")
_add("C9200-24P", "C9200", [_acc(GI, 24, "1G", True), _up(TE, 4, "10G SFP+", "module")],
     "PoE+. Uplinks need a network module (C9200-NM-4X shown).")
_add("C9200-48P", "C9200", [_acc(GI, 48, "1G", True), _up(TE, 4, "10G SFP+", "module")],
     "PoE+. Uplinks need a network module (C9200-NM-4X shown).")
# ------------------------------------------------------------------ 9300
_add("C9300-24T", "C9300", [_acc(GI, 24, "1G"), _up(TE, 8, "10G SFP+", "module")],
     "Uplinks need a network module (C9300-NM-8X shown).")
_add("C9300-24P", "C9300", [_acc(GI, 24, "1G", True), _up(TE, 8, "10G SFP+", "module")],
     "PoE+. Uplinks need a network module (C9300-NM-8X shown).")
_add("C9300-48T", "C9300", [_acc(GI, 48, "1G"), _up(TE, 8, "10G SFP+", "module")],
     "Uplinks need a network module (C9300-NM-8X shown).")
_add("C9300-48P", "C9300", [_acc(GI, 48, "1G", True), _up(TE, 8, "10G SFP+", "module")],
     "PoE+. Uplinks need a network module (C9300-NM-8X shown).")
_add("C9300-48UXM", "C9300", [_acc(TW, 36, "2.5G", True), _acc(TE, 48, "mGig 10G", True, first=37),
                              _up(TE, 8, "10G SFP+", "module")],
     "UPOE: 36x 2.5G + 12x 10G mGig. Uplinks need a network module.")
_add("C9300L-24P-4G", "C9300L", [_acc(GI, 24, "1G", True), _up(GI, 4, "1G SFP")], "PoE+. Fixed uplinks.")
_add("C9300L-48P-4G", "C9300L", [_acc(GI, 48, "1G", True), _up(GI, 4, "1G SFP")], "PoE+. Fixed uplinks.")
_add("C9300L-48P-4X", "C9300L", [_acc(GI, 48, "1G", True), _up(TE, 4, "10G SFP+")], "PoE+. Fixed uplinks.")
# ------------------------------------------------------------------ 9500
_add("C9500-16X", "C9500", [_acc(TE, 16, "10G SFP+")], "Core/aggregation. StackWise Virtual instead of stacking.",
     stack=False)
_add("C9500-24Y4C", "C9500", [_acc(TWE, 24, "25G SFP28"), _acc(HU, 28, "100G QSFP28", first=25)],
     "Core/aggregation. StackWise Virtual instead of stacking.", stack=False)
_add("C9500-48Y4C", "C9500", [_acc(TWE, 48, "25G SFP28"), _acc(HU, 52, "100G QSFP28", first=49)],
     "Core/aggregation. StackWise Virtual instead of stacking.", stack=False)
# ------------------------------------------------------------------ lab
_add("Cat9kv", "C9KV", [_acc(GI, 8, "1G")], "Catalyst 9000 virtual switch for labs (EVE-NG, CML).", stack=False,
     mgmt="GigabitEthernet0/0")

MODELS: dict[str, IosModel] = {m.name: m for m in _M}
CUSTOM = "Custom"
CUSTOM_MODEL = IosModel(CUSTOM, "Custom", (), "")
ALIASES = {
    "gi": GI, "gig": GI, "gigabitethernet": GI,
    "tw": TW, "two": TW, "twogigabitethernet": TW,
    "fa": "FastEthernet", "fastethernet": "FastEthernet",
    "fi": FI, "fivegigabitethernet": FI,
    "te": TE, "ten": TE, "tengigabitethernet": TE,
    "twe": TWE, "twentyfivegige": TWE,
    "fo": FO, "fortygigabitethernet": FO,
    "hu": HU, "hundredgige": HU,
}


def get(name: str) -> IosModel | None:
    return MODELS.get(name)


def catalog() -> list[dict]:
    return [m.to_dict() for m in _M]
