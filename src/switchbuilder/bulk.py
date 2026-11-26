"""Bulk builds: one template project plus a spreadsheet (CSV) gives one config per row.

Each CSV row is one switch. Columns fill the template three ways:

* Well-known columns set the usual per-switch fields: ``hostname`` (required), ``mgmt_address``,
  ``mgmt_gateway``, ``model``, ``serial``, ``location``, ``contact`` and ``domain``.
* A column named like a path into the project sets that field, for example ``system.banner``,
  ``vlans.MGMT.irb`` (the VLAN named MGMT, or with id MGMT) or ``ports.0.description`` (the first port
  group). A list item is found by its position, ``name`` or ``id``.
* Any other column fills ``{{column}}`` placeholders written anywhere in the template's text, for example
  an IRB address of ``10.{{site}}.20.1/24``.

Problems are reported per row: missing or repeated hostnames, management IPs used twice, placeholders
left unfilled and the vendor builder's own errors.
"""

from __future__ import annotations

import copy
import csv
import io
import ipaddress
import json
import re
import zipfile

from . import vendors
from .generator import build

MAX_ROWS = 500
MAX_CSV = 2_000_000

# column name (lower case, spaces and dashes as _) -> project path
WELL_KNOWN: dict[str, tuple] = {
    "hostname": ("system", "hostname"),
    "mgmt_address": ("system", "mgmt_address"),
    "mgmt_gateway": ("system", "mgmt_gateway"),
    "model": ("switch", "members", 0, "model"),
    "serial": ("switch", "members", 0, "serial"),
    "location": ("snmp", "location"),
    "contact": ("snmp", "contact"),
    "domain": ("system", "domain"),
}
ALIASES = {
    "host": "hostname", "name": "hostname", "switch": "hostname", "device": "hostname",
    "ip": "mgmt_address", "mgmt_ip": "mgmt_address", "management_ip": "mgmt_address", "address": "mgmt_address",
    "gateway": "mgmt_gateway", "gw": "mgmt_gateway", "mgmt_gw": "mgmt_gateway",
    "serial_number": "serial", "sn": "serial", "snmp_location": "location", "site_location": "location",
    "snmp_contact": "contact", "domain_name": "domain",
}
LINE = "\0line"  # where a row was in the file (not a column)
PLACEHOLDER = re.compile(r"\{\{\s*([A-Za-z0-9_.-]+)\s*\}\}")
TOP_LEVEL = ("switch", "system", "access", "snmp", "syslog", "vlans", "ports", "lags", "routing", "policy",
             "evpn", "qos", "security", "services")


class BulkError(ValueError):
    pass


def _key(name: str) -> str:
    return re.sub(r"[\s-]+", "_", (name or "").strip()).lower()


def read_csv(text: str) -> tuple[list[str], list[dict]]:
    """CSV text -> (header as written, rows keyed by header). Commas, semicolons or tabs."""
    text = (text or "").lstrip("\ufeff")
    if len(text) > MAX_CSV:
        raise BulkError("That spreadsheet is too large (2 MB at most).")
    lines = [(n, ln) for n, ln in enumerate(text.splitlines(), start=1)
             if ln.strip() and not ln.lstrip().startswith("#")]
    if len(lines) < 2:
        raise BulkError("Add a header line and at least one switch line.")
    delim = max((",", ";", "\t"), key=lines[0][1].count)

    def cells(line: str) -> list[str]:
        return next(csv.reader([line], delimiter=delim), [])

    header = [h.strip() for h in cells(lines[0][1])]
    named = [h for h in header if h]
    if not named or len({h.lower() for h in named}) != len(named):
        raise BulkError("Every column needs a different name in the header line.")
    out = []
    for n, line in lines[1:]:
        r = cells(line)
        if not any(c.strip() for c in r):
            continue
        row = {h: (r[i].strip() if i < len(r) else "") for i, h in enumerate(header) if h}
        row[LINE] = n
        out.append(row)
    if len(out) > MAX_ROWS:
        raise BulkError(f"At most {MAX_ROWS} switches at a time.")
    return named, out


def placeholders(template) -> list[str]:
    """The {{names}} used in a template, in first-seen order."""
    seen: list[str] = []

    def walk(v):
        if isinstance(v, str):
            for m in PLACEHOLDER.finditer(v):
                if m.group(1) not in seen:
                    seen.append(m.group(1))
        elif isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)

    walk(template)
    return seen


def csv_template(template: dict) -> str:
    """A header line (and one example line) to start the spreadsheet from."""
    sysd = template.get("system") or {}
    member = ((template.get("switch") or {}).get("members") or [{}])[0] or {}
    cols = ["hostname", "mgmt_address", "mgmt_gateway", "model", "serial", "location"]
    extra = [p for p in placeholders(template) if _key(p) not in cols]
    example = [sysd.get("hostname") or "sw-01", sysd.get("mgmt_address") or "10.0.0.11/24",
               sysd.get("mgmt_gateway") or "10.0.0.1", member.get("model") or "", "",
               (template.get("snmp") or {}).get("location") or ""] + ["" for _ in extra]
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(cols + extra)
    w.writerow(example)
    return buf.getvalue()


def _fill(value, row: dict, used: set):
    if isinstance(value, str):
        def sub(m):
            name = m.group(1)
            for k in (name, name.lower(), _key(name)):
                if row.get(k):
                    used.add(k)
                    return row[k]
            return m.group(0)
        return PLACEHOLDER.sub(sub, value)
    if isinstance(value, dict):
        return {k: _fill(v, row, used) for k, v in value.items()}
    if isinstance(value, list):
        return [_fill(v, row, used) for v in value]
    return value


def _find(lst: list, seg: str):
    if seg.isdigit() and int(seg) < len(lst):
        return int(seg)
    for i, item in enumerate(lst):
        if isinstance(item, dict) and seg.lower() in (str(item.get("name", "")).lower(), str(item.get("id", "")).lower()):
            return i
    return None


def set_path(project: dict, path, value: str) -> str | None:
    """Set a dotted path in the project. Returns why not, or None."""
    parts = path.split(".") if isinstance(path, str) else list(path)
    if not parts or (isinstance(path, str) and parts[0] not in TOP_LEVEL):
        return f"{path} is not a project field"
    node = project
    for i, seg in enumerate(parts):
        last = i == len(parts) - 1
        if isinstance(node, list):
            idx = seg if isinstance(seg, int) else _find(node, str(seg))
            if idx is None or idx >= len(node):
                return f"{path}: the template has no {seg!s} there"
            if last:
                node[idx] = value
                return None
            node = node[idx]
        elif isinstance(node, dict):
            if last:
                if isinstance(node.get(seg), (dict, list)):
                    return f"{path} is a whole section, not one field"
                if isinstance(node.get(seg), bool):
                    node[seg] = value.strip().lower() in ("1", "true", "yes", "y", "on")
                else:
                    node[seg] = value
                return None
            if seg not in node or not isinstance(node[seg], (dict, list)):
                node[seg] = {}
            node = node[seg]
        else:
            return f"{path}: the template has no {seg!s} there"
    return None


def _ip(text: str):
    try:
        return ipaddress.ip_interface(text.strip()).ip
    except ValueError:
        return None


def _ext(vendor: str) -> str:
    return {"mikrotik": "rsc", "unifi": "txt"}.get(vendor, "cfg")


def safe_name(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "-" for c in name)[:60].strip(".") or "switch"


def run(template: dict, csv_text: str) -> dict:
    """Build one config per CSV row. Returns {switches: [...], columns: {...}, summary}."""
    if not isinstance(template, dict):
        raise BulkError("Pick a template project first.")
    header, rows = read_csv(csv_text)
    vendor = vendors.get(template.get("vendor")).key
    keys = {h: ALIASES.get(_key(h), _key(h)) for h in header}
    if "hostname" not in keys.values():
        raise BulkError("The spreadsheet needs a hostname column.")
    holders = {_key(p) for p in placeholders(template)}
    kinds = {}
    for h, k in keys.items():
        if k in WELL_KNOWN:
            kinds[h] = "field"
        elif "." in h and h.split(".")[0] in TOP_LEVEL:
            kinds[h] = "path"
        elif _key(h) in holders or h in placeholders(template):
            kinds[h] = "placeholder"
        else:
            kinds[h] = "unused"

    out, names, ips = [], {}, {}
    for raw in rows:
        n = raw.pop(LINE)
        row = {**raw, **{h.lower(): v for h, v in raw.items()}, **{_key(h): v for h, v in raw.items()}}
        errors, warnings = [], []
        used: set = set()
        p = _fill(copy.deepcopy(template), row, used)
        for h, v in raw.items():
            k = keys[h]
            if kinds[h] == "field":
                if v or k == "hostname":
                    why = set_path(p, WELL_KNOWN[k], v)
                    if why:
                        errors.append(why)
            elif kinds[h] == "path" and v != "":
                why = set_path(p, h, v)
                if why:
                    errors.append(why)
        host = str((p.get("system") or {}).get("hostname") or "").strip()
        if not host:
            errors.append("No hostname on this line.")
        elif host.lower() in names:
            errors.append(f"Hostname {host} is also on line {names[host.lower()]}.")
        else:
            names[host.lower()] = n
        ip = _ip(str((p.get("system") or {}).get("mgmt_address") or ""))
        if ip is not None:
            if ip in ips:
                errors.append(f"Management IP {ip} is also on line {ips[ip]}.")
            else:
                ips[ip] = n
        left = placeholders(p)
        if left:
            errors.append("Not filled in: " + ", ".join("{{" + x + "}}" for x in left)
                          + ". Fill in that column (add it if it is missing).")
        p["name"] = host or p.get("name") or ""
        res = build(p)
        errors += [f"{e.get('section', '')}: {e.get('message', '')}".strip(": ") for e in res.errors]
        warnings += [f"{w.get('section', '')}: {w.get('message', '')}".strip(": ") for w in res.warnings]
        out.append({"line": n, "hostname": host, "mgmt_address": str((p.get("system") or {}).get("mgmt_address") or ""),
                    "ok": not errors, "errors": errors, "warnings": warnings, "project": p,
                    "config": "" if errors else res.set_text, "hierarchy": "" if errors else res.hier_text})
    ok = sum(1 for s in out if s["ok"])
    return {"vendor": vendor, "switches": out, "columns": kinds,
            "summary": {"total": len(out), "ok": ok, "failed": len(out) - ok}}


def to_zip(result: dict) -> bytes:
    """Every config that built, the projects, and a summary sheet."""
    buf = io.BytesIO()
    vendor = result.get("vendor") or "juniper"
    summary = io.StringIO()
    w = csv.writer(summary, lineterminator="\n")
    w.writerow(["line", "hostname", "mgmt_address", "status", "problems"])
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for s in result["switches"]:
            name = safe_name(s["hostname"] or f"line-{s['line']}")
            w.writerow([s["line"], s["hostname"], s["mgmt_address"], "ok" if s["ok"] else "failed",
                        " | ".join(s["errors"] or s["warnings"])])
            zf.writestr(f"projects/{name}.json", json.dumps(s["project"], indent=2))
            if not s["ok"]:
                continue
            if vendor == "juniper":
                zf.writestr(f"configs/{name}.set", s["config"])
                zf.writestr(f"configs/{name}.conf", s["hierarchy"])
            else:
                zf.writestr(f"configs/{name}.{_ext(vendor)}", s["config"])
        zf.writestr("summary.csv", summary.getvalue())
    return buf.getvalue()
