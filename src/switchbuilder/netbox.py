"""NetBox sync in both directions.

* **Pull** (NetBox -> builder): the devices of a NetBox site become builder projects. Each gets its host name,
  model, serial, management IP (the device's primary IPv4), the site as SNMP location, the site's VLANs and the
  VLAN interface addresses NetBox has for it. A saved project can be the template, so ports and services come
  from your own standard.
* **Push** (builder -> NetBox): projects become NetBox data. Missing VLANs are added to the site, missing IP
  addresses (management and VLAN interfaces) are added and assigned when the device has that interface, devices
  that are missing are created when their model is a NetBox device type, and serial numbers are filled in.
  Nothing in NetBox is deleted, and nothing is changed before the plan is shown.

The NetBox address must be inside the networks this server may reach (the same rule as SSH and EVE-NG).
"""

from __future__ import annotations

import copy
import ipaddress
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request

from . import eveng, vendors
from .convert import portmap

MAX_DEVICES = 300
PAGE = 1000


class NetboxError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never follow NetBox somewhere else
        return None


def check_url(url: str) -> str:
    try:
        base, _host = eveng.check_url(url)
    except eveng.EveError as exc:
        raise NetboxError(str(exc).replace("EVE-NG", "NetBox")) from None
    return re.sub(r"/api$", "", base)


def auth_header(token: str) -> str:
    """NetBox 4.5+ v2 tokens (nbt_...) use Bearer; older ones use Token."""
    token = token.strip()
    return f"Bearer {token}" if token.startswith("nbt_") else f"Token {token}"


class Netbox:
    def __init__(self, url: str, token: str, verify_tls: bool = True, timeout: float = 30):
        self.base = check_url(url)
        self.token = token
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), _NoRedirect())
        self.timeout = timeout

    def call(self, method: str, path: str, data=None, params: dict | None = None):
        url = self.base + path + ("?" + urllib.parse.urlencode(params, doseq=True) if params else "")
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(url, data=body, method=method, headers={
            "Authorization": auth_header(self.token), "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read(30_000_000)
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read(100_000) or b"{}")
            except ValueError:
                detail = {}
            msg = detail.get("detail") if isinstance(detail, dict) else None
            msg = msg or (json.dumps(detail)[:300] if detail else exc.reason)
            if exc.code in (401, 403):
                raise NetboxError(f"NetBox refused the token ({exc.code}: {msg}). Check the token and its permissions.") from None
            raise NetboxError(f"NetBox {method} {path}: {exc.code} {msg}") from None
        except (urllib.error.URLError, OSError) as exc:
            raise NetboxError(f"Could not reach NetBox at {self.base}: {getattr(exc, 'reason', exc)}") from None
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            raise NetboxError(f"NetBox {path} did not answer with JSON. Is the address right?") from None

    def list(self, path: str, **params) -> list[dict]:
        out, offset = [], 0
        while True:
            page = self.call("GET", path, params={**params, "limit": PAGE, "offset": offset}) or {}
            out += page.get("results") or []
            if not page.get("next") or len(out) >= 5000:
                return out
            offset += PAGE

    def status(self) -> dict:
        return self.call("GET", "/api/status/") or {}


# ------------------------------------------------------------------ mapping
def vendor_for(manufacturer: str, model: str) -> str | None:
    """A NetBox manufacturer (name or slug) and model -> builder vendor key, or None."""
    m, mod = (manufacturer or "").lower(), (model or "").upper()
    if "juniper" in m:
        return "juniper"
    if "arista" in m:
        return "arista"
    if "cisco" in m:
        return "nexus" if re.match(r"^(N[3579]K|NEXUS|N9K)", mod.replace("-", "")) or mod.startswith("N9K") else "cisco"
    if "dell" in m:
        return "dell"
    if "extreme" in m:
        return "extreme"
    if "fortinet" in m:
        return "fortiswitch"
    if "mikrotik" in m:
        return "mikrotik"
    if "ubiquiti" in m or "ubnt" in m or "unifi" in m:
        return "unifi"
    if any(x in m for x in ("ruckus", "brocade", "commscope", "foundry")):
        return "ruckus"
    if any(x in m for x in ("aruba", "hpe", "hewlett", "procurve", "hp ")) or m == "hp":
        return "aruba" if re.match(r"^(CX|[68]\d{3}|JL\d+.*CX)", mod) or "CX" in mod.split() else "procurve"
    return None


def _norm(text: str) -> str:
    return re.sub(r"[^A-Z0-9+]", "", (text or "").upper())


def match_model(vendor: str, *names: str) -> str:
    """The builder's model name for a NetBox model or part number, or '' when none fits."""
    catalog = [n for n in portmap.model_names(vendor) if n != "Custom"]
    by = {_norm(n): n for n in catalog}
    for name in names:
        n = _norm(name)
        if not n:
            continue
        if n in by:
            return by[n]
        for strip in ("CATALYST", "WSC", "C", "DCS", "EX", "JL"):
            if n.startswith(strip) and n[len(strip):] in by:
                return by[n[len(strip):]]
        hits = [v for k, v in by.items() if len(k) >= 5 and (k in n or n in k)]
        if len(hits) == 1:
            return hits[0]
    return ""


VLAN_IF = re.compile(r"^(?:vlan|irb\.|vlan\.|ve|svi|vl)\s*(\d{1,4})$", re.I)


def _addr(ip: dict | None) -> str:
    return (ip or {}).get("address") or ""


def pull(nb: Netbox, site_id: int, templates: dict[str, dict], defaults) -> dict:
    """Devices of a site -> projects. templates: vendor -> project to start from; defaults(vendor) -> blank one."""
    site = nb.call("GET", f"/api/dcim/sites/{int(site_id)}/") or {}
    devices = nb.list("/api/dcim/devices/", site_id=site_id)[:MAX_DEVICES]
    try:
        vlans = nb.list("/api/ipam/vlans/", available_at_site=site_id)
    except NetboxError:
        vlans = nb.list("/api/ipam/vlans/", site_id=site_id)
    site_vlans = sorted({int(v["vid"]): v.get("name") or f"VLAN{v['vid']}" for v in vlans if v.get("vid")}.items())
    out = []
    for d in devices:
        name = d.get("name") or ""
        dtype = d.get("device_type") or {}
        manu = (dtype.get("manufacturer") or {})
        vendor = vendor_for(manu.get("name") or manu.get("slug") or "", dtype.get("model") or "")
        item = {"netbox_id": d.get("id"), "name": name, "manufacturer": manu.get("name") or "",
                "netbox_model": dtype.get("model") or "", "vendor": vendor, "notes": []}
        if not name:
            item["notes"].append("The device has no name in NetBox, so it was skipped.")
            out.append(item)
            continue
        if vendor is None:
            item["notes"].append(f"{item['manufacturer'] or 'Unknown maker'} is not a switch brand the builder knows.")
            out.append(item)
            continue
        tpl = templates.get(vendor)
        p = copy.deepcopy(tpl) if tpl else defaults(vendor)
        item["template"] = bool(tpl)
        p["vendor"] = vendor
        p["name"] = name
        sysd = p.setdefault("system", {})
        sysd["hostname"] = re.sub(r"[^A-Za-z0-9-]", "-", name.split(".")[0])[:63].strip("-")
        if sysd["hostname"] != name:
            item["notes"].append(f"Host name written as {sysd['hostname']}.")
        mgmt = _addr(d.get("primary_ip4"))
        if mgmt:
            sysd["mgmt_address"] = mgmt
        model = match_model(vendor, dtype.get("model") or "", dtype.get("part_number") or "")
        members = p.setdefault("switch", {}).setdefault("members", [{}]) or [{}]
        p["switch"]["members"] = members
        if model:
            members[0]["model"] = model
        else:
            item["notes"].append(f"Model {dtype.get('model') or '?'} is not in the {vendors.get(vendor).name} catalog; "
                                 f"kept {members[0].get('model') or 'the template model'}.")
        if d.get("serial"):
            members[0]["serial"] = d["serial"]
        if site.get("name"):
            p.setdefault("snmp", {})["location"] = site["name"]
        # VLANs: keep the template's, add the site's missing ones, fill VLAN interface addresses from NetBox.
        have = {str(v.get("id")): v for v in p.get("vlans") or [] if isinstance(v, dict)}
        p["vlans"] = list(have.values())
        for vid, vname in site_vlans:
            if str(vid) not in have:
                row = {"name": re.sub(r"[^A-Za-z0-9_.-]", "_", vname)[:63] or f"VLAN{vid}", "id": str(vid)}
                if not re.match(r"^[A-Za-z]", row["name"]):
                    row["name"] = f"V{row['name']}"
                p["vlans"].append(row)
                have[str(vid)] = row
        ips = nb.list("/api/ipam/ip-addresses/", device_id=d["id"]) if d.get("id") else []
        for ip in ips:
            iface = ((ip.get("assigned_object") or {}).get("name") or "")
            m = VLAN_IF.match(iface)
            if m and m.group(1) in have and ip.get("family", {}).get("value", 4) == 4:
                have[m.group(1)]["irb"] = ip["address"]
        item["project"] = p
        item["mgmt_address"] = mgmt
        item["model"] = members[0].get("model") or ""
        out.append(item)
    return {"site": {"id": site.get("id"), "name": site.get("name")}, "devices": out,
            "vlans": [{"vid": v, "name": n} for v, n in site_vlans]}


# --------------------------------------------------------------------- push
def _project_ips(p: dict) -> list[tuple[str, str]]:
    """(address with prefix, interface hint) a project owns."""
    out = []
    mgmt = ((p.get("system") or {}).get("mgmt_address") or "").strip()
    if mgmt:
        out.append((mgmt, "mgmt"))
    for v in p.get("vlans") or []:
        for a in re.split(r"[,\s]+", str(v.get("irb") or "").strip()):
            if a:
                out.append((a, f"vlan{v.get('id')}"))
    lo = ((p.get("routing") or {}).get("loopback") or "").strip()
    if lo:
        out.append((lo if "/" in lo else f"{lo}/32", "loopback"))
    return out


def _valid(addr: str) -> bool:
    try:
        ipaddress.ip_interface(addr)
        return True
    except ValueError:
        return False


def _iface_match(names: dict[str, int], hint: str) -> int | None:
    if hint == "mgmt":
        for n in ("me0", "em0", "fxp0", "mgmt0", "mgmt", "management1", "management0", "management", "ma1",
                  "gigabitethernet0/0", "vlan1"):
            if n in names:
                return names[n]
        return None
    if hint == "loopback":
        for n in ("lo0", "loopback0", "lo0.0", "loopback1"):
            if n in names:
                return names[n]
        return None
    vid = hint[4:]
    for n in (f"vlan{vid}", f"irb.{vid}", f"vlan.{vid}", f"ve{vid}", f"ve {vid}", f"vl{vid}"):
        if n in names:
            return names[n]
    return None


def plan_push(nb: Netbox, site_id: int, projects: list[dict], role_id: int | None) -> dict:
    """What a push would do. projects: [{name, data}]. Nothing is changed."""
    site_vlans = {int(v["vid"]): v for v in nb.list("/api/ipam/vlans/", site_id=site_id) if v.get("vid")}
    types = nb.list("/api/dcim/device-types/")
    by_model = {}
    for t in types:
        for k in (t.get("model"), t.get("part_number"), t.get("slug")):
            if k:
                by_model.setdefault(_norm(k), t)
    steps, notes, seen_vlans = [], [], set()
    for item in projects:
        p = item.get("data") or {}
        host = ((p.get("system") or {}).get("hostname") or "").strip()
        if not host:
            notes.append(f"{item.get('name')}: no host name, skipped.")
            continue
        existing = nb.list("/api/dcim/devices/", name=host)
        dev = existing[0] if existing else None
        member = (((p.get("switch") or {}).get("members") or [{}])[0]) or {}
        model, serial = str(member.get("model") or ""), str(member.get("serial") or "").strip()
        if dev is None:
            dtype = by_model.get(_norm(model))
            if dtype is None:
                hits = [t for k, t in by_model.items() if len(k) >= 5 and (k in _norm(model) or _norm(model) in k)]
                dtype = hits[0] if len(hits) == 1 else None
            if dtype is None:
                notes.append(f"{host}: not in NetBox and no NetBox device type matches {model or 'its model'}; "
                             "add the device type in NetBox first. Its VLANs and IPs are still added.")
            elif not role_id:
                notes.append(f"{host}: not in NetBox. Pick a device role to create it.")
            else:
                data = {"name": host, "device_type": dtype["id"], "role": role_id, "site": site_id, "status": "planned"}
                if serial:
                    data["serial"] = serial
                steps.append({"action": "create", "kind": "device", "what": f"{host} ({dtype.get('model')}, planned)",
                              "call": ["POST", "/api/dcim/devices/", data], "host": host})
        else:
            if (dev.get("site") or {}).get("id") not in (None, site_id):
                notes.append(f"{host}: is in NetBox at site {(dev.get('site') or {}).get('name')}, not this one.")
            if serial and dev.get("serial") != serial:
                steps.append({"action": "update", "kind": "device", "what": f"{host} serial {dev.get('serial') or '(empty)'} → {serial}",
                              "call": ["PATCH", f"/api/dcim/devices/{dev['id']}/", {"serial": serial}], "host": host})
        for v in p.get("vlans") or []:
            try:
                vid = int(str(v.get("id")))
            except ValueError:
                continue
            if vid in site_vlans or vid in seen_vlans or not 1 <= vid <= 4094:
                continue
            seen_vlans.add(vid)
            name = str(v.get("name") or f"VLAN{vid}")[:64]
            steps.append({"action": "create", "kind": "vlan", "what": f"VLAN {vid} {name}",
                          "call": ["POST", "/api/ipam/vlans/", {"site": site_id, "vid": vid, "name": name,
                                                                 "status": "active"}], "host": host})
        names = {}
        if dev is not None:
            names = {str(i.get("name", "")).lower(): i["id"] for i in nb.list("/api/dcim/interfaces/", device_id=dev["id"])}
        for addr, hint in _project_ips(p):
            if not _valid(addr):
                continue
            ip = str(ipaddress.ip_interface(addr).ip)
            found = nb.list("/api/ipam/ip-addresses/", address=ip)
            iface = _iface_match(names, hint)
            data = {"address": addr, "status": "active", "dns_name": "",
                    "description": f"{host} {hint}"}
            if iface:
                data.update(assigned_object_type="dcim.interface", assigned_object_id=iface)
            if not found:
                steps.append({"action": "create", "kind": "ip", "what": f"{addr} ({host} {hint}"
                              f"{', on its interface' if iface else ', not assigned: no matching interface in NetBox'})",
                              "call": ["POST", "/api/ipam/ip-addresses/", data], "host": host})
            else:
                cur = found[0]
                owner = ((cur.get("assigned_object") or {}).get("device") or {}).get("name")
                if owner and owner != host:
                    notes.append(f"{host}: {ip} is already in NetBox on {owner}.")
                elif iface and not cur.get("assigned_object_id"):
                    steps.append({"action": "update", "kind": "ip", "what": f"{cur['address']} assign to {host} {hint}",
                                  "call": ["PATCH", f"/api/ipam/ip-addresses/{cur['id']}/",
                                           {"assigned_object_type": "dcim.interface", "assigned_object_id": iface}],
                                  "host": host})
    return {"steps": steps, "notes": notes}


def apply(nb: Netbox, steps: list[dict]) -> list[dict]:
    """Run planned steps in order. Returns [{what, ok, error}]."""
    out = []
    for s in steps:
        method, path, data = s["call"]
        try:
            nb.call(method, path, data)
            out.append({"what": s["what"], "ok": True})
        except NetboxError as exc:
            out.append({"what": s["what"], "ok": False, "error": str(exc)})
    return out
