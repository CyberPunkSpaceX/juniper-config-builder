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
        "cisco", "Cisco", "IOS-XE", "Catalyst 9200, 9300, 9500 and Cat9kv lab",
        # What the Cisco builder writes today; EVPN, policies, QoS and the tools come later.
        frozenset({"basics", "vlans", "ports", "lags", "static_routes", "ospf", "bgp", "dot1x", "poe",
                   "vlan_translation", "virtual_chassis"}),
        ready=True),
    "ruckus": Vendor(
        "ruckus", "Brocade / Ruckus", "FastIron (ICX)", "ICX 7150, 7250, 7450, 7550, 7650, 7850",
        # No EVPN-VXLAN on ICX, no ICX image for EVE-NG, and no per-port VLAN translation.
        _ALL - {"evpn_vxlan", "eve_ng", "vlan_translation"}),
}

DEFAULT = "juniper"


def get(key: str | None) -> Vendor:
    """The vendor for a key; unknown or missing keys fall back to Juniper."""
    return VENDORS.get((key or "").strip().lower(), VENDORS[DEFAULT])


def known(key: str | None) -> bool:
    return (key or "").strip().lower() in VENDORS


def catalog() -> list[dict]:
    return [v.to_dict() for v in VENDORS.values()]
