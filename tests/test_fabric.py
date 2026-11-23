import io
import zipfile

import pytest

from exbuilder.cryptpw import sha512_crypt
from exbuilder.fabric import TEMPLATES, generate, plan, FabricError, to_zip

HASH = sha512_crypt("Juniper123!", "fixedsalt")
BASE = {"system": {"ntp_servers": [{"address": "10.0.0.1"}]},
        "access": {"root_password": HASH, "users": [{"name": "admin1", "class": "super-user", "password": HASH}]}}


def by_name(res):
    return {s["name"]: s for s in res["switches"]}


def lines(sw, needle):
    return [x for x in sw["set"].splitlines() if needle in x]


@pytest.mark.parametrize("key", sorted(TEMPLATES))
def test_every_template_builds_without_errors(key):
    res = generate(TEMPLATES[key]["fabric"], BASE)
    assert "error" not in res, res.get("error")
    for sw in res["switches"]:
        assert sw["errors"] == [], (sw["name"], sw["errors"])
        assert sw["set"].startswith("#") and "set system host-name " + sw["name"] in sw["set"]


def test_erb_ebgp_addressing():
    res = generate(TEMPLATES["campus-erb"]["fabric"], BASE)
    sw = by_name(res)
    assert len(res["switches"]) == 6 and len(res["links"]) == 8
    # Spines share an AS, every leaf has its own.
    assert sw["campus-spine1"]["asn"] == sw["campus-spine2"]["asn"] == 65000
    assert [sw[f"campus-leaf{i}"]["asn"] for i in range(1, 5)] == [65001, 65002, 65003, 65004]
    leaf = sw["campus-leaf1"]
    assert "set interfaces xe-0/2/0 unit 0 family inet address 10.254.0.1/31" in leaf["set"]
    assert "set protocols bgp group UNDERLAY neighbor 10.254.0.0 peer-as 65000" in leaf["set"]
    assert "set protocols bgp group EVPN-OVERLAY neighbor 10.255.0.1 peer-as 65000" in leaf["set"]
    assert "set vlans USERS vxlan vni 10020" in leaf["set"]
    assert any("virtual-gateway-address 10.20.0.1" in x for x in lines(leaf, "irb unit 20"))
    assert "set routing-instances CORP protocols evpn ip-prefix-routes vni 9001" in leaf["set"]
    # Leaves get different IRB addresses in the same subnet.
    assert "10.20.0.254/24" in leaf["set"] and "10.20.0.253/24" in sw["campus-leaf2"]["set"]
    # Lean spines: no VLANs, no VTEP.
    spine = sw["campus-spine1"]
    assert not lines(spine, "set vlans") and not lines(spine, "vtep-source-interface")
    assert "set interfaces xe-0/2/3 unit 0 family inet address 10.254.0.12/31" in spine["set"]


def test_crb_ebgp_spines_get_their_own_as():
    spec = dict(TEMPLATES["campus-crb"]["fabric"], design="ebgp")
    sw = by_name(generate(spec, BASE))
    assert sw["dc-spine1"]["asn"] != sw["dc-spine2"]["asn"]
    assert "neighbor 10.255.0.2 peer-as 65001" in sw["dc-spine1"]["set"]
    assert lines(sw["dc-spine1"], "virtual-gateway-address")
    assert not lines(sw["dc-leaf1"], "virtual-gateway-address") and lines(sw["dc-leaf1"], "vxlan vni")


def test_ospf_design_spines_reflect_routes():
    sw = by_name(generate(TEMPLATES["bridged"]["fabric"], BASE))
    spine, leaf = sw["l2-spine1"], sw["l2-leaf1"]
    assert "set protocols bgp group EVPN-OVERLAY cluster 10.255.0.1" in spine["set"]
    assert "set protocols ospf area 0.0.0.0 interface lo0.0 passive" in leaf["set"]
    assert not lines(leaf, "irb unit") and lines(leaf, "vxlan vni 10020")


def test_collapsed_core_esi_lags():
    sw = by_name(generate(TEMPLATES["small-collapsed"]["fabric"], BASE))
    c1, c2 = sw["core-core1"], sw["core-core2"]
    for c in (c1, c2):
        assert "set interfaces ae1 esi 00:10:00:00:00:00:00:00:00:01" in c["set"]
        assert "set interfaces ae1 esi all-active" in c["set"]
    assert c1["asn"] != c2["asn"]


def test_mgmt_addresses_and_errors():
    spec = dict(TEMPLATES["campus-erb"]["fabric"], mgmt_pool="10.0.0.11/24", mgmt_gateway="10.0.0.1")
    res = generate(spec, BASE)
    assert [s["mgmt"] for s in res["switches"]][:2] == ["10.0.0.11/24", "10.0.0.12/24"]
    assert "Each spine needs one downlink per leaf" in generate(dict(spec, leaves=6), BASE)["error"]
    assert "overlap" in generate(dict(spec, p2p_pool="10.255.0.0/25"), BASE)["error"]
    with pytest.raises(FabricError):
        plan(dict(spec, vlans=[]))


def test_zip_has_plan_and_configs():
    res = generate(TEMPLATES["campus-erb"]["fabric"], BASE)
    zf = zipfile.ZipFile(io.BytesIO(to_zip(res)))
    names = zf.namelist()
    assert "fabric-plan.md" in names and "campus-leaf1.set" in names and "campus-spine2.conf" in names
    assert "| campus-leaf1 | leaf |" in zf.read("fabric-plan.md").decode()
