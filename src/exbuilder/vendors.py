"""Switch vendors the builder knows, and which builder features each supports.

A project carries ``"vendor"`` (one of the keys below; old projects without
it are Juniper). The shared parts of a project (VLANs, port groups, LAGs,
routing, services) mean the same thing for every vendor; each vendor has its
own config writer and its own model catalog. ``features`` lists what the
page may offer for that vendor, so options a platform cannot do are hidden
instead of producing config that will not load.
"""

from __future__ import annotations

from dataclasses import dataclass

# Every feature name the page can switch on or off per vendor.
FEATURES = (
    "basics", "vlans", "ports", "lags", "static_routes", "ospf", "bgp", "policies", "evpn_vxlan",
    "qos", "dot1x", "poe", "vlan_translation", "virtual_chassis", "ssh_fetch", "model_detect",
    "network_map", "eve_ng", "backups", "import",
)


@dataclass(frozen=True)
class Vendor:
    key: str
    name: str          # shown on the vendor screen
    os: str            # network OS the config is written for
    blurb: str         # one line under the name on the vendor screen
    features: frozenset
    ready: bool = False  # False: shown on the vendor screen as "coming soon"

    def has(self, feature: str) -> bool:
        return feature in self.features

    def to_dict(self) -> dict:
        return {"key": self.key, "name": self.name, "os": self.os, "blurb": self.blurb,
                "features": sorted(self.features), "ready": self.ready}


_ALL = frozenset(FEATURES)

VENDORS: dict[str, Vendor] = {
    "juniper": Vendor(
        "juniper", "Juniper", "Junos (ELS)", "EX2300, EX3400, EX4100, EX4300, EX4400",
        _ALL, ready=True),
    "arista": Vendor(
        "arista", "Arista", "EOS", "720XP, 722XPM, 7010, 7050X3, vEOS and cEOS lab",
        # What the Arista builder writes today. EVPN-VXLAN, policies, QoS, SSH fetch, import,
        # the network map and EVE-NG labs come later.
        frozenset({"basics", "vlans", "ports", "lags", "static_routes", "ospf", "bgp", "dot1x", "poe",
                   "vlan_translation"}),
        ready=True),
    "cisco": Vendor(
        "cisco", "Cisco", "IOS-XE and IOS", "Catalyst 9200, 9300, 9500, older 2960-X, 3650, 3850, and Cat9kv lab",
        # What the Cisco builder writes today; EVPN, policies, QoS and the tools come later.
        frozenset({"basics", "vlans", "ports", "lags", "static_routes", "ospf", "bgp", "dot1x", "poe",
                   "vlan_translation", "virtual_chassis"}),
        ready=True),
    "nexus": Vendor(
        "nexus", "Cisco Nexus", "NX-OS", "Nexus 9200, 9300, older 3000, and the Nexus 9000v lab",
        # What the NX-OS builder writes today. Nexus has no PoE, no voice VLAN and no stacking (vPC pairs
        # are two projects); EVPN, policies, QoS and the tools come later.
        frozenset({"basics", "vlans", "ports", "lags", "static_routes", "ospf", "bgp", "dot1x", "vlan_translation"}),
        ready=True),
    "dell": Vendor(
        "dell", "Dell", "SmartFabric OS10", "N3200, N2200, S5200 and the OS10 virtual lab",
        # What the OS10 builder writes today. No stacking (VLT pairs are two projects) and no VLAN
        # translation; PoE, port security, EVPN, policies, QoS and the tools come later.
        frozenset({"basics", "vlans", "ports", "lags", "static_routes", "ospf", "bgp", "dot1x"}),
        ready=True),
    "extreme": Vendor(
        "extreme", "Extreme Networks", "EXOS / Switch Engine", "X440-G2, X450-G2, X460-G2, 5320, 5420 and the EXOS VM",
        # What the EXOS builder writes today. No routed ports and no VLAN translation; 802.1X (netlogin),
        # EVPN, policies, QoS and the tools come later.
        frozenset({"basics", "vlans", "ports", "lags", "static_routes", "ospf", "bgp", "poe", "virtual_chassis"}),
        ready=True),
    "fortiswitch": Vendor(
        "fortiswitch", "Fortinet FortiSwitch", "FortiSwitchOS (standalone)", "FS-100F, 200E, 400E, 1000E",
        # What the FortiSwitchOS builder writes today. Standalone switches only (FortiLink-managed ones are set
        # up on the FortiGate). No routed ports, stacking or VLAN translation; EVPN, policies, QoS and the
        # tools come later.
        frozenset({"basics", "vlans", "ports", "lags", "static_routes", "ospf", "bgp", "dot1x", "poe"}),
        ready=True),
    "ruckus": Vendor(
        "ruckus", "Brocade / Ruckus", "FastIron", "ICX 7000 and 6000, and older FCX, FGS and FLS",
        # What the FastIron builder writes today. FastIron has no EVPN-VXLAN and no per-port
        # VLAN translation; policies, QoS and the tools come later.
        frozenset({"basics", "vlans", "ports", "lags", "static_routes", "ospf", "bgp", "dot1x", "poe",
                   "virtual_chassis"}),
        ready=True),
    "aruba": Vendor(
        "aruba", "HPE Aruba CX", "AOS-CX", "CX 6000, 6100, 6200, 6300, 8320, 8325, 8360 and the CX simulator",
        # What the AOS-CX builder writes today; EVPN, policies, QoS, VLAN translation and the tools come later.
        frozenset({"basics", "vlans", "ports", "lags", "static_routes", "ospf", "bgp", "dot1x", "poe",
                   "virtual_chassis"}),
        ready=True),
    "procurve": Vendor(
        "procurve", "HPE Aruba / ProCurve", "AOS-S", "2530, 2540, 2920, 2930F, 2930M, 3810M, 5400R and older ProCurve",
        # What the AOS-S builder writes today. AOS-S has no routed ports, no VLAN translation and no EVPN;
        # BGP, policies, QoS and the tools are not written.
        frozenset({"basics", "vlans", "ports", "lags", "static_routes", "ospf", "dot1x", "poe", "virtual_chassis"}),
        ready=True),
}

DEFAULT = "juniper"


def get(key: str | None) -> Vendor:
    """The vendor for a key; unknown or missing keys fall back to Juniper."""
    return VENDORS.get((key or "").strip().lower(), VENDORS[DEFAULT])


def known(key: str | None) -> bool:
    return (key or "").strip().lower() in VENDORS


def catalog() -> list[dict]:
    return [v.to_dict() for v in VENDORS.values()]
