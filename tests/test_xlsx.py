import json
from pathlib import Path

import pytest

pytest.importorskip("openpyxl")

from exbuilder import xlsx  # noqa: E402
from exbuilder.generator import build  # noqa: E402

EX = Path(__file__).parent.parent / "examples"


def sets(text):
    return {x for x in text.splitlines() if x.startswith("set ")}


def test_office_round_trip():
    proj = json.load(open(EX / "office-switch.json"))
    again = xlsx.read(xlsx.workbook(proj))
    assert sets(build(again).set_text) == sets(build(proj).set_text)


def test_template_is_empty_and_readable():
    p = xlsx.read(xlsx.workbook())
    assert p["vlans"] == [] and p["ports"] == [] and p["system"]["hostname"] == ""


def test_filled_template():
    from io import BytesIO

    from openpyxl import load_workbook
    wb = load_workbook(BytesIO(xlsx.workbook()))
    st = wb["Settings"]
    for row in st.iter_rows(min_row=2):
        if row[0].value == "Host name":
            row[1].value = "sw-xl-01"
        if row[0].value == "NTP servers":
            row[1].value = "10.0.0.1, 10.0.0.2"
        if row[0].value == "Default gateway":
            row[1].value = "10.0.10.1"
    wb["VLANs"].append(["USERS", 20, "Staff", "", "no", "yes", "no"])
    wb["Ports"].append(["DESKS", "ge-0/0/0-23", "access", "pc", "USERS", "", "", "", "", "Desks", "", "", "", "yes", ""])
    buf = BytesIO()
    wb.save(buf)
    p = xlsx.read(buf.getvalue())
    assert p["system"]["hostname"] == "sw-xl-01"
    assert [x["address"] for x in p["system"]["ntp_servers"]] == ["10.0.0.1", "10.0.0.2"]
    assert p["vlans"][0]["id"] == "20" and p["vlans"][0]["snooping"] is True
    out = build(p).set_text
    assert "set vlans USERS vlan-id 20" in out
    assert "set routing-options static route 0.0.0.0/0 next-hop 10.0.10.1" in out
    assert "set interfaces interface-range DESKS unit 0 family ethernet-switching vlan members USERS" in out


def test_bad_file():
    with pytest.raises(xlsx.WorkbookError):
        xlsx.read(b"not a workbook")
