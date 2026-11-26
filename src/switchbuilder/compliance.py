"""Compliance checks: score each switch against your own standard.

A standard is a list of rules, each switched on or off, with a weight and sometimes a value (for example the NTP
servers every switch must use). Each switch gets a score out of 100: the weight of the rules it passes over the
weight of the rules that apply to it.

Switches can be checked from:

* builder projects (every brand): the project's settings are read directly;
* running configs (backups, pasted text): read into a project with the Converter's readers where the brand has
  one (Juniper, Cisco, Arista, Nexus, Dell), plus text rules for what a project cannot hold (telnet, plain HTTP).
  For the other brands the rules look at the config text, and a rule that cannot tell says so ("can't tell").
"""

from __future__ import annotations

import copy
import re

RULES = [
    # key, title, weight, what the value means ("" = no value)
    ("ntp", "NTP servers set", 10, "NTP servers every switch must use (comma separated, optional)"),
    ("syslog", "Remote syslog", 10, "Syslog server every switch must send to (optional)"),
    ("dns", "DNS servers set", 5, ""),
    ("snmpv3", "SNMPv3 only (no v1/v2c communities)", 15, ""),
    ("no_default_community", "No 'public' or 'private' SNMP community", 15, ""),
    ("banner", "Login banner", 5, "Text the banner must contain (optional)"),
    ("no_telnet", "Telnet off", 15, ""),
    ("no_http", "Plain HTTP management off", 10, ""),
    ("ssh_root", "SSH root login denied", 5, ""),
    ("timezone", "Time zone", 5, "Time zone every switch must use, like America/Edmonton (optional)"),
    ("bpdu_guard", "BPDU guard on edge ports", 10, ""),
    ("unused_off", "Unused ports disabled", 5, ""),
    ("local_users", "Named admin accounts (not only the default)", 5, ""),
]
RULE_KEYS = [r[0] for r in RULES]


def default_standard() -> dict:
    return {"rules": {k: {"on": True, "weight": w, "value": ""} for k, _t, w, _v in RULES}}


def clean_standard(data) -> dict:
    """User input -> a standard with only known rules and sane values."""
    std = default_standard()
    rules = (data or {}).get("rules") if isinstance(data, dict) else None
    if isinstance(rules, dict):
        for k, r in rules.items():
            if k not in std["rules"] or not isinstance(r, dict):
                continue
            try:
                weight = max(0, min(100, int(r.get("weight", std["rules"][k]["weight"]))))
            except (TypeError, ValueError):
                weight = std["rules"][k]["weight"]
            value = re.sub(r"[\x00-\x1f]", " ", str(r.get("value") or ""))[:300].strip()
            std["rules"][k] = {"on": bool(r.get("on")), "weight": weight, "value": value}
    return std


# ------------------------------------------------------------------ helpers
def _s(v) -> str:
    return "" if v is None else str(v).strip()


def _items(v) -> list[str]:
    if isinstance(v, list):
        out = []
        for x in v:
            out.append(_s(x.get("address") or x.get("host") or x.get("name")) if isinstance(x, dict) else _s(x))
        return [x for x in out if x]
    return [x for x in re.split(r"[,\s]+", _s(v)) if x]


def _need(value: str) -> list[str]:
    return [x for x in re.split(r"[,\s]+", value or "") if x]


def _lines(text: str, pattern: str) -> list[str]:
    return [ln for ln in (text or "").splitlines() if re.search(pattern, ln, re.I)]


PASS, FAIL, NA = "pass", "fail", "n/a"


class Target:
    def __init__(self, name: str, vendor: str, project: dict | None = None, text: str | None = None):
        if isinstance(project, dict) and text is None:
            from .generator import normalize
            project = normalize(project)   # missing settings mean the builder's defaults
        self.name, self.vendor, self.project, self.text = name, vendor, project, text

    def p(self, *path, default=None):
        node = self.project or {}
        for key in path:
            node = node.get(key) if isinstance(node, dict) else None
        return default if node is None else node


# Text patterns, for configs of any brand. "on" = the feature is turned on by that line.
NTP_LINE = (r"^\s*(?:ntp server\b|set system ntp server\b|ntp-server\b|sntp server\b|sntp unicast server\b|"
            r"configure sntp-client (?:primary|secondary)\b|/system ntp client set\b.*servers=|set ntpserver\d?\b)")
SYSLOG_LINE = (r"^\s*(?:logging (?:host |server )?\d|logging \S+\.\S+|set system syslog host\b|logging host\b|"
               r"configure syslog add\b|/system logging action .*remote=|syslog-server\b|logging server\b)")
DNS_LINE = (r"^\s*(?:ip name-server\b|set system name-server\b|ip dns server-address\b|name-server\b|"
            r"configure dns-client add\b|ip domain[- ]name-server\b|/ip dns set .*servers=|set primary \d)")
COMMUNITY_LINE = (r"^\s*(?:snmp-server community|set snmp community|snmp community|configure snmp add community|"
                  r"snmp-server host \S+ (?:version (?:1|2c) )?\S+|/snmp community add)\b")
V3_LINE = (r"^\s*(?:snmp-server user \S+ \S+ v3|snmp-server user \S+ .*\bauth\b|set snmp v3 usm|snmpv3 user|"
           r"configure snmpv3 add user|snmp-server user \S+ network-\w+ auth|/snmp community .*security=)")
BANNER_LINE = r"^\s*(?:banner (?:motd|login|exec)\b|set system login message\b|banner\b|configure banner\b|set pre-login-banner\b)"
BPDU_LINE = (r"(?:bpduguard|bpdu-block-on-edge|bpdu-protection|bpdu-guard|bpdu guard|bpdu-filter|edge-port.*bpdu|"
             r"stp-protection|spanning-tree portfast bpduguard default|admin-edge-port.*bpdu-protection)")


def _telnet(t: Target):
    """(status, why) for the telnet rule from config text."""
    text, v = t.text or "", t.vendor
    if v == "juniper":
        return (FAIL, "set system services telnet") if _lines(text, r"^\s*(?:set )?system services telnet\b|^\s*telnet;") else (PASS, "")
    if v == "cisco":
        bad = _lines(text, r"^\s*transport input (?:.*telnet|all)\b")
        vty = _lines(text, r"^line vty")
        ssh_only = _lines(text, r"^\s*transport input ssh\s*$")
        if bad:
            return FAIL, bad[0].strip()
        if vty and len(ssh_only) < len(vty):
            return FAIL, "a 'line vty' without 'transport input ssh' (older IOS allows telnet by default)"
        return PASS, ""
    if v == "nexus":
        return (FAIL, "feature telnet") if _lines(text, r"^feature telnet\b") else (PASS, "")
    if v == "arista":
        m = re.search(r"^management telnet\s*\n((?:[ \t]+.*\n?)*)", text, re.M)
        return (FAIL, "management telnet is not shut down") if m and "no shutdown" in m.group(1) else (PASS, "")
    if v == "dell":
        return (FAIL, "ip telnet server enable") if _lines(text, r"^ip telnet server enable") else (PASS, "")
    if v == "procurve":
        return (PASS, "") if _lines(text, r"^no telnet-server") else (FAIL, "no 'no telnet-server' (AOS-S has telnet on by default)")
    if v == "extreme":
        return (PASS, "") if _lines(text, r"^disable telnet") else (FAIL, "no 'disable telnet' (EXOS has telnet on by default)")
    if v == "mikrotik":
        return (PASS, "") if _lines(text, r"set telnet .*disabled=yes|set \[ find name=telnet \] disabled=yes") else (
            FAIL, "telnet service is not disabled (/ip service)")
    if v == "fortiswitch":
        bad = _lines(text, r"set allowaccess .*\btelnet\b")
        return (FAIL, bad[0].strip()) if bad else (PASS, "")
    if v == "ruckus":
        return (FAIL, "telnet server") if _lines(text, r"^telnet server") else (PASS, "")
    if v == "aruba":
        return PASS, "AOS-CX has no telnet server"
    return NA, "can't tell for this brand"


def _http(t: Target):
    text, v = t.text or "", t.vendor
    pats = {"juniper": r"system services web-management http\b|web-management \{[^}]*\bhttp\b",
            "cisco": r"^ip http server\b", "dell": r"^ip http server\b",
            "arista": r"^\s+protocol http\s*$", "nexus": r"^\s*nxapi http\b",
            "procurve": r"^web-management plaintext|^web-management\s*$",
            "aruba": r"^https-server .*http\b", "fortiswitch": r"set allowaccess .*\bhttp\b",
            "ruckus": r"^web-management http\b", "extreme": r"^enable web http\b",
            "mikrotik": r"set www .*disabled=no"}
    if v not in pats:
        return NA, "can't tell for this brand"
    bad = _lines(text, pats[v]) if v != "juniper" else re.findall(pats[v], text, re.M)
    if v == "procurve" and not _lines(text, r"^no web-management"):
        return FAIL, "no 'no web-management' (AOS-S serves HTTP by default)"
    if v == "mikrotik" and not _lines(text, r"set www .*disabled=yes|set \[ find name=www \] disabled=yes"):
        return FAIL, "the www service is not disabled (/ip service)"
    return (FAIL, (bad[0] if isinstance(bad[0], str) else "web-management http").strip()) if bad else (PASS, "")


# ------------------------------------------------------------------ rules
def check(t: Target, std: dict) -> dict:
    """One switch against the standard -> {name, vendor, score, results: [{rule, title, status, detail}]}."""
    rules = std["rules"]
    results = []
    proj = t.project is not None
    text = t.text
    pure = text is None          # a builder project: its settings are what goes on the switch

    def res(key, status, detail=""):
        title = next(r[1] for r in RULES if r[0] == key)
        results.append({"rule": key, "title": title, "status": status, "detail": detail,
                        "weight": rules[key]["weight"]})

    for key in RULE_KEYS:
        r = rules[key]
        if not r["on"]:
            continue
        need = _need(r["value"])
        if key == "ntp":
            have = _items(t.p("system", "ntp_servers")) if proj else []
            lines = _lines(text, NTP_LINE) if text is not None else []
            if not proj and not lines:
                res(key, FAIL, "no NTP server")
            elif proj and not have and not lines:
                res(key, FAIL, "no NTP server")
            else:
                pool = " ".join(have + lines)
                miss = [s for s in need if s not in pool]
                res(key, FAIL if miss else PASS, f"missing {', '.join(miss)}" if miss else ", ".join(have) or f"{len(lines)} server line(s)")
        elif key == "syslog":
            have = _items(t.p("syslog", "hosts")) if proj else []
            lines = _lines(text, SYSLOG_LINE) if text is not None else []
            if not have and not lines:
                res(key, FAIL, "no remote syslog server")
            else:
                pool = " ".join(have + lines)
                miss = [s for s in need if s not in pool]
                res(key, FAIL if miss else PASS, f"missing {', '.join(miss)}" if miss else ", ".join(have) or "set")
        elif key == "dns":
            have = _items(t.p("system", "name_servers")) if proj else []
            lines = _lines(text, DNS_LINE) if text is not None else []
            res(key, PASS if have or lines else FAIL, ", ".join(have) if have else ("set" if lines else "none"))
        elif key in ("snmpv3", "no_default_community"):
            comms = [c.get("name", "") if isinstance(c, dict) else str(c) for c in t.p("snmp", "communities", default=[]) or []]
            comm_lines = _lines(text, COMMUNITY_LINE) if text is not None else []
            if key == "snmpv3":
                v3 = bool(t.p("snmp", "v3_users")) or bool(_lines(text, V3_LINE) if text is not None else [])
                if comms or comm_lines:
                    res(key, FAIL, f"v1/v2c communities in use ({len(comms) or len(comm_lines)})")
                elif not v3:
                    res(key, FAIL, "no SNMPv3 user (SNMP off, or not set up)")
                else:
                    res(key, PASS, "SNMPv3 users only")
            else:
                names = [c.lower() for c in comms] + [ln.lower() for ln in comm_lines]
                bad = [n for n in ("public", "private") if any(re.search(rf"(?<![\w-]){n}(?![\w-])", x) for x in names)]
                res(key, FAIL if bad else PASS, f"uses {', '.join(bad)}" if bad else "")
        elif key == "banner":
            banner = _s(t.p("system", "banner")) if proj else ""
            lines = _lines(text, BANNER_LINE) if text is not None else []
            if not banner and not lines:
                res(key, FAIL, "no banner")
            else:
                hay = banner + "\n" + (text or "")
                miss = r["value"] and r["value"].lower() not in hay.lower()
                res(key, FAIL if miss else PASS, f"does not say “{r['value']}”" if miss else "")
        elif key == "no_telnet":
            if text is not None:
                res(key, *_telnet(t))
            else:
                res(key, PASS, "the builder never turns telnet on")
        elif key == "no_http":
            if text is not None:
                res(key, *_http(t))
            else:
                res(key, FAIL if t.p("access", "web") else PASS, "web management is on" if t.p("access", "web") else "")
        elif key == "ssh_root":
            if pure:
                v = _s(t.p("access", "ssh_root_login")) or "deny"
                res(key, PASS if v.startswith("deny") else FAIL, f"root login: {v}")
            elif t.vendor == "juniper":
                bad = _lines(text, r"root-login allow")
                res(key, FAIL if bad else PASS, "root-login allow" if bad else "")
            else:
                res(key, NA, "only Junos has an SSH root login")
        elif key == "timezone":
            tz = _s(t.p("system", "timezone")) if pure else ""
            if need:
                ok = tz == need[0] if pure else need[0].lower() in (text or "").lower()
                res(key, PASS if ok else FAIL, tz or ("" if ok else f"not {need[0]}"))
            elif pure:
                res(key, PASS if tz else FAIL, tz or "not set")
            else:
                res(key, NA, "put the time zone in the standard to check configs")
        elif key == "bpdu_guard":
            if pure:
                on = bool(t.p("services", "bpdu_block_on_edge"))
                res(key, PASS if on else FAIL, "" if on else "off")
            else:
                res(key, PASS if _lines(text, BPDU_LINE) else FAIL, "" if _lines(text, BPDU_LINE) else "not found")
        elif key == "unused_off":
            if pure:
                on = bool(t.p("services", "disable_unused"))
                res(key, PASS if on else FAIL, "" if on else "unused ports stay enabled")
            else:
                res(key, NA, "can't tell from the config alone")
        elif key == "local_users":
            if pure:
                users = [u for u in t.p("access", "users", default=[]) or [] if isinstance(u, dict) and _s(u.get("name"))]
                named = [u["name"] for u in users if _s(u["name"]).lower() not in ("admin", "root", "manager", "operator")]
                res(key, PASS if named else FAIL, ", ".join(named) if named else "only default accounts")
            else:
                names = re.findall(r"^\s*(?:username|set system login user|user|create account \w+|user-name)\s+\"?([\w.-]+)",
                                   text or "", re.M | re.I)
                named = sorted({n for n in names if n.lower() not in ("admin", "root", "manager", "operator", "name")})
                res(key, PASS if named else FAIL, ", ".join(named[:5]) if named else "only default accounts")
    applicable = [x for x in results if x["status"] != NA]
    total = sum(x["weight"] for x in applicable)
    got = sum(x["weight"] for x in applicable if x["status"] == PASS)
    score = round(100 * got / total) if total else None
    return {"name": t.name, "vendor": t.vendor, "score": score, "results": results,
            "failed": sum(1 for x in results if x["status"] == FAIL)}


def from_config(name: str, text: str, vendor: str = "") -> Target:
    """A running config -> a target, read into a project when the brand has a reader."""
    from . import convert
    vendor = vendor or convert.detect(text) or ""
    project = None
    if vendor in convert.READERS:
        try:
            project = convert.read(text, vendor)["project"]
        except Exception:  # noqa: BLE001 - a reader that trips still leaves the text rules
            project = None
    return Target(name, vendor or "unknown", project, text)


def run(targets: list[Target], std: dict) -> dict:
    rows = [check(t, std) for t in targets]
    scores = [r["score"] for r in rows if r["score"] is not None]
    worst = {}
    for r in rows:
        for x in r["results"]:
            if x["status"] == FAIL:
                worst[x["title"]] = worst.get(x["title"], 0) + 1
    return {"switches": sorted(rows, key=lambda r: (r["score"] if r["score"] is not None else 101, r["name"])),
            "average": round(sum(scores) / len(scores)) if scores else None,
            "most_failed": sorted(worst.items(), key=lambda kv: -kv[1])[:5],
            "standard": copy.deepcopy(std)}
