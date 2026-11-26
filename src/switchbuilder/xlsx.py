"""Excel workbook in and out.

``workbook(project)`` writes a filled-in (or empty) template with one sheet
per part of the config and drop-down lists. ``read(data)`` turns a filled-in
workbook back into a builder project. Passwords typed in the sheet are hashed
by the builder the first time it generates the config.
"""

from __future__ import annotations

import copy
import io

from . import models
from .generator import DEFAULTS, LAG_DEFAULTS, PORT_DEFAULTS, VLAN_DEFAULTS, _merge

YESNO = ["yes", "no"]

# (sheet, title, intro, columns). A column is (header, key, kind, choices, width, help).
# kind: text | bool | choice
SETTINGS = [
    # header, path, kind, choices, help
    ("Project name", "name", "text", None, "Any name, used when saving the project."),
    ("Switch model", "switch.members.0.model", "choice", "models", "Pick from the list."),
    ("Host name", "system.hostname", "text", None, "For example sw-office-01."),
    ("Domain name", "system.domain", "text", None, "For example example.lan."),
    ("Time zone", "system.timezone", "text", None, "For example America/Edmonton or UTC."),
    ("DNS servers", "system.name_servers", "text", None, "Comma separated."),
    ("NTP servers", "@ntp", "text", None, "Comma separated. The first one is preferred."),
    ("Login banner", "system.banner", "text", None, "Shown before login."),
    ("Management interface", "system.mgmt_interface", "choice", ["", "me0", "em0", "vme", "irb"], "Leave empty for the model default."),
    ("Management address", "system.mgmt_address", "text", None, "For example 10.0.0.11/24."),
    ("Management gateway", "system.mgmt_gateway", "text", None, "For example 10.0.0.1."),
    ("Root password", "access.root_password", "text", None, "Typed in clear here; the builder hashes it. Delete the sheet afterwards."),
    ("SSH root login", "access.ssh_root_login", "choice", ["deny", "deny-password", "allow"], "deny is safest."),
    ("NETCONF over SSH", "access.netconf", "bool", None, "For automation tools."),
    ("Web management (HTTPS)", "access.web", "bool", None, "J-Web on HTTPS."),
    ("SNMP location", "snmp.location", "text", None, "For example Head office, rack 2."),
    ("SNMP contact", "snmp.contact", "text", None, "For example noc@example.lan."),
    ("Syslog servers", "@syslog", "text", None, "Comma separated."),
    ("Default gateway", "@gateway", "text", None, "Adds a static route 0.0.0.0/0 to this address."),
    ("DHCP relay servers", "routing.dhcp_relay_servers", "text", None, "Comma separated. Tick DHCP relay on the VLANs sheet."),
    ("Spanning tree", "services.stp", "choice", ["rstp", "none"], "rstp is recommended."),
    ("Bridge priority", "services.bridge_priority", "choice", ["", "0", "4k", "8k", "16k", "32k"], "Lower wins root. Leave empty on access switches."),
    ("LLDP", "services.lldp", "bool", None, "Shows neighbours on each port."),
    ("Storm control", "services.storm_control", "bool", None, "Limits broadcast storms."),
    ("BPDU block on edge ports", "services.bpdu_block_on_edge", "bool", None, "Shuts a user port that sends spanning tree."),
    ("PoE on all ports", "services.poe_all", "bool", None, "PoE models only."),
    ("Perpetual PoE", "services.poe_perpetual", "bool", None, "Keeps phones and access points powered while the switch reboots."),
    ("Fast PoE", "services.poe_fast", "bool", None, "Powers devices straight after power-on, before Junos boots."),
    ("RADIUS server", "@radius_addr", "text", None, "For 802.1X / MAB ports. IP address."),
    ("RADIUS secret", "@radius_secret", "text", None, "Shared secret for that RADIUS server."),
    ("When RADIUS is down", "security.server_fail", "choice", ["", "permit", "use-cache", "deny"], "Empty blocks everyone; permit lets everyone in."),
    ("QoS for voice and video", "@qos", "choice", ["off", "voice", "voice-video"], "voice-video is recommended when you have IP phones or video."),
    ("Disable unused ports", "services.disable_unused", "bool", None, "Turns off every port not listed on the Ports sheet."),
]

TABLES = [
    ("Users", "access.users", "Local accounts. Passwords are hashed by the builder.", [
        ("User name", "name", "text", None, 16), ("Full name", "full_name", "text", None, 22),
        ("Class", "class", "choice", ["super-user", "operator", "read-only"], 14),
        ("Password", "password", "text", None, 18), ("SSH public key", "ssh_keys", "text", None, 50)],
     {"name": "", "full_name": "", "class": "super-user", "password": "", "ssh_keys": ""}),
    ("SNMP", "snmp.communities", "SNMP v2c communities. Never use public.", [
        ("Community", "name", "text", None, 22), ("Access", "access", "choice", ["read-only", "read-write"], 14),
        ("Allowed clients", "clients", "text", None, 30)],
     {"name": "", "access": "read-only", "clients": ""}),
    ("SNMPv3", "snmp.v3_users", "SNMP v3 users (safer than communities). Passwords need 8+ characters.", [
        ("User", "name", "text", None, 16), ("Authentication", "auth", "choice", ["sha", "sha256", "sha384", "sha512", "md5"], 15),
        ("Auth password", "auth_password", "text", None, 18), ("Privacy", "priv", "choice", ["aes128", "des", ""], 10),
        ("Privacy password", "priv_password", "text", None, 18)],
     {"name": "", "auth": "sha", "auth_password": "", "priv": "aes128", "priv_password": ""}),
    ("VLANs", "vlans", "One row per VLAN. An IRB address makes the switch route for that VLAN.", [
        ("Name", "name", "text", None, 16), ("VLAN ID", "id", "text", None, 9), ("Description", "description", "text", None, 26),
        ("IRB address", "irb", "text", None, 18), ("DHCP relay", "dhcp_relay", "bool", None, 11),
        ("DHCP snooping", "snooping", "bool", None, 14), ("ARP inspection", "dai", "bool", None, 14),
        ("Voice VLAN", "voice", "bool", None, 11)],
     VLAN_DEFAULTS),
    ("Ports", "ports", "One row per group of ports with the same settings. Ports like ge-0/0/0-23, xe-0/1/0.", [
        ("Name", "name", "text", None, 14), ("Ports", "ports", "text", None, 20),
        ("Mode", "mode", "choice", ["access", "trunk", "routed", "disabled"], 10),
        ("Devices", "role", "choice", ["", "pc", "phone", "ap", "camera", "printer", "server", "uplink"], 10),
        ("Access VLAN", "vlan", "text", None, 13), ("Voice VLAN", "voice", "text", None, 12),
        ("Trunk VLANs", "vlans", "text", None, 22), ("Native VLAN", "native", "text", None, 12),
        ("IP address", "address", "text", None, 16), ("Description", "description", "text", None, 22),
        ("PoE", "poe", "choice", ["", "high", "low", "off"], 7), ("Max PoE (W)", "poe_max", "text", None, 11), ("Speed", "speed", "choice", ["", "10m", "100m", "1g", "2.5g", "10g"], 7),
        ("MTU", "mtu", "text", None, 7), ("Edge port", "edge", "bool", None, 10), ("MAC limit", "mac_limit", "text", None, 10),
        ("802.1X / MAB", "dot1x", "choice", ["", "dot1x", "dot1x-mab", "mab"], 13)],
     PORT_DEFAULTS),
    ("LAGs", "lags", "Link aggregation (ae) bundles.", [
        ("Name", "name", "text", None, 8), ("Member ports", "members", "text", None, 20),
        ("LACP", "lacp", "choice", ["active", "passive", "static"], 9), ("Fast LACP", "lacp_fast", "bool", None, 10),
        ("Mode", "mode", "choice", ["trunk", "access", "routed", "disabled"], 9),
        ("Access VLAN", "vlan", "text", None, 13), ("Trunk VLANs", "vlans", "text", None, 22),
        ("Native VLAN", "native", "text", None, 12), ("IP address", "address", "text", None, 16),
        ("Description", "description", "text", None, 22), ("MTU", "mtu", "text", None, 7)],
     LAG_DEFAULTS),
    ("Static routes", "routing.static", "Static routes. 0.0.0.0/0 is the default route.", [
        ("Destination", "prefix", "text", None, 18), ("Next hop", "next_hop", "text", None, 18),
        ("Preference", "preference", "text", None, 11)],
     {"prefix": "", "next_hop": "", "preference": ""}),
]


def _get(p, path):
    for k in path.split("."):
        p = p[int(k)] if isinstance(p, list) else p.get(k, "")
    return p


def _set(p, path, value):
    keys = path.split(".")
    for k in keys[:-1]:
        p = p[int(k)] if isinstance(p, list) else p.setdefault(k, {})
    p[keys[-1]] = value


def _cell(v, kind):
    if kind == "bool":
        return "yes" if v else "no"
    return "" if v is None else str(v)


def _value(v, kind):
    if v is None:
        v = ""
    if kind == "bool":
        return str(v).strip().lower() in ("yes", "y", "true", "1", "x", "on")
    if isinstance(v, float) and v.is_integer():
        v = int(v)
    return str(v).strip()


def workbook(project: dict | None = None) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Alignment, Font, PatternFill
    from openpyxl.worksheet.datavalidation import DataValidation

    p = _merge(DEFAULTS, project or {})
    wb = Workbook()
    head = Font(bold=True, color="FFFFFF")
    fill = PatternFill("solid", fgColor="2F6FDF")
    note = Font(italic=True, color="666666")

    ws = wb.active
    ws.title = "Read me"
    for row in [["Multi-Vendor Switch Config Builder workbook"], [],
                ["1. Fill in the Settings sheet and the table sheets (Users, SNMP, SNMPv3, VLANs, Ports, LAGs, Static routes)."],
                ["2. Use the drop-down lists where a cell has one. yes/no cells take yes or no."],
                ["3. Leave a row empty to skip it. Add as many rows as you need."],
                ["4. In the builder, click Import, choose this file, check the result and load it."],
                ["5. Passwords are typed in clear here and hashed by the builder. Delete them from the file afterwards."],
                [], ["Port names look like ge-0/0/0 (1G), mge-0/0/0 (multigig), xe-0/1/0 (10G) or ranges like ge-0/0/0-23."],
                ["VLANs on the Ports and LAGs sheets are VLAN names from the VLANs sheet, comma separated for trunks."],
                ["OSPF, BGP, policies and EVPN-VXLAN are set in the builder itself (Advanced mode), not in this workbook."]]:
        ws.append(row)
    ws["A1"].font = Font(bold=True, size=14)
    ws.column_dimensions["A"].width = 110

    lists = wb.create_sheet("Lists")
    model_names = [m for m in models.MODELS] + [models.CUSTOM]
    for i, m in enumerate(model_names, start=1):
        lists.cell(row=i, column=1, value=m)
    lists.sheet_state = "hidden"

    st = wb.create_sheet("Settings", 1)
    st.append(["Setting", "Value", "Help"])
    for c in st[1]:
        c.font, c.fill = head, fill
    ntp = ", ".join(x.get("address", "") for x in p["system"].get("ntp_servers") or [])
    syslog = ", ".join(x.get("address", "") for x in p["syslog"].get("hosts") or [])
    gw = next((x.get("next_hop", "") for x in p["routing"].get("static") or [] if x.get("prefix") == "0.0.0.0/0"), "")
    for i, (label, path, kind, choices, help_) in enumerate(SETTINGS, start=2):
        if path == "@ntp":
            v = ntp
        elif path == "@syslog":
            v = syslog
        elif path == "@gateway":
            v = gw
        elif path in ("@radius_addr", "@radius_secret"):
            rs = (p.get("security", {}).get("radius_servers") or [{}])[0] if p.get("security", {}).get("radius_servers") else {}
            v = rs.get("address" if path == "@radius_addr" else "secret", "")
        elif path == "@qos":
            v = p["qos"].get("preset", "voice-video") if p.get("qos", {}).get("enabled") else "off"
        else:
            try:
                v = _get(p, path)
            except (IndexError, KeyError, AttributeError):
                v = ""
        st.append([label, _cell(v, kind), help_])
        st.cell(row=i, column=3).font = note
        if kind == "bool" or choices:
            if choices == "models":
                dv = DataValidation(type="list", formula1=f"=Lists!$A$1:$A${len(model_names)}", allow_blank=True)
            else:
                opts = YESNO if kind == "bool" else [c or " " for c in choices]
                dv = DataValidation(type="list", formula1='"' + ",".join(opts) + '"', allow_blank=True)
            st.add_data_validation(dv)
            dv.add(f"B{i}")
    st.column_dimensions["A"].width = 26
    st.column_dimensions["B"].width = 40
    st.column_dimensions["C"].width = 70
    st.freeze_panes = "A2"

    for sheet, path, intro, cols, defaults in TABLES:
        ws = wb.create_sheet(sheet)
        ws.append([intro])
        ws["A1"].font = note
        ws.append([c[0] for c in cols])
        for c in ws[2]:
            c.font, c.fill = head, fill
            c.alignment = Alignment(wrap_text=True)
        rows = _get(p, path) or []
        if path == "routing.static":
            rows = [r for r in rows if r.get("prefix") != "0.0.0.0/0"] if gw else rows
        for r in rows:
            r = {**defaults, **r}
            ws.append([_cell(r.get(c[1], ""), c[2]) for c in cols])
        last = max(200, len(rows) + 50)
        for idx, (_h, _k, kind, choices, width) in enumerate(cols, start=1):
            col = ws.cell(row=2, column=idx).column_letter
            ws.column_dimensions[col].width = width
            if kind == "bool" or choices:
                opts = YESNO if kind == "bool" else [c or " " for c in choices]
                dv = DataValidation(type="list", formula1='"' + ",".join(opts) + '"', allow_blank=True)
                ws.add_data_validation(dv)
                dv.add(f"{col}3:{col}{last}")
        ws.freeze_panes = "A3"

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


class WorkbookError(ValueError):
    pass


def read(data: bytes) -> dict:
    """A filled-in workbook -> builder project. Raises WorkbookError."""
    from openpyxl import load_workbook

    try:
        wb = load_workbook(io.BytesIO(data), data_only=True, read_only=True)
    except Exception as exc:  # noqa: BLE001 - any parse failure is the user's file
        raise WorkbookError(f"That is not an Excel workbook this builder can read ({exc.__class__.__name__}).") from None
    p = copy.deepcopy(DEFAULTS)
    names = {n.lower(): n for n in wb.sheetnames}
    if "settings" not in names:
        raise WorkbookError("The workbook has no Settings sheet. Download the template from the builder and fill that in.")

    by_label = {s[0].lower(): s for s in SETTINGS}
    for row in wb[names["settings"]].iter_rows(min_row=2, values_only=True):
        if not row or row[0] is None:
            continue
        spec = by_label.get(str(row[0]).strip().lower())
        if not spec:
            continue
        _label, path, kind, _choices, _help = spec
        v = _value(row[1] if len(row) > 1 else "", kind)
        if path == "@ntp":
            items = [x.strip() for x in str(v).split(",") if x.strip()]
            p["system"]["ntp_servers"] = [{"address": x, "prefer": i == 0} for i, x in enumerate(items)]
        elif path == "@syslog":
            p["syslog"]["hosts"] = [{"address": x.strip(), "facility": "any", "level": "info", "port": "514"}
                                    for x in str(v).split(",") if x.strip()]
        elif path == "@gateway":
            if v:
                p["routing"]["static"].append({"prefix": "0.0.0.0/0", "next_hop": v, "preference": ""})
        elif path in ("@radius_addr", "@radius_secret"):
            if v:
                rs = p["security"]["radius_servers"] or [{"address": "", "secret": "", "port": ""}]
                rs[0]["address" if path == "@radius_addr" else "secret"] = v
                p["security"]["radius_servers"] = rs
        elif path == "@qos":
            if v and v != "off":
                p["qos"].update(enabled=True, preset=v if v in ("voice", "voice-video") else "voice-video")
        elif kind == "bool" and (row[1] is None or str(row[1]).strip() == ""):
            continue    # keep the builder default
        else:
            _set(p, path, v)

    for sheet, path, _intro, cols, defaults in TABLES:
        if sheet.lower() not in names:
            continue
        rows = list(wb[names[sheet.lower()]].iter_rows(values_only=True))
        hdr_i = next((i for i, r in enumerate(rows[:5]) if r and any(str(c or "").strip().lower() == cols[0][0].lower() for c in r)), None)
        if hdr_i is None:
            continue
        header = [str(c or "").strip().lower() for c in rows[hdr_i]]
        out = []
        for r in rows[hdr_i + 1:]:
            if not r or all(c is None or str(c).strip() == "" for c in r):
                continue
            item = copy.deepcopy(defaults)
            for label, key, kind, _ch, _w in cols:
                if label.lower() in header:
                    i = header.index(label.lower())
                    raw = r[i] if i < len(r) else None
                    if kind == "bool" and (raw is None or str(raw).strip() == ""):
                        continue
                    item[key] = _value(raw, kind)
            out.append(item)
        if path == "routing.static":
            p["routing"]["static"].extend(out)
        else:
            _set(p, path, out)
    if not p.get("name"):
        p["name"] = p["system"].get("hostname") or "From Excel"
    return p
