"""Firmware tracker: which software each switch runs, against the versions you want.

Versions are read from the latest config backup of each switch (configs and ``show version`` output of every brand
carry it), or from what you paste. A client admin keeps a policy per brand (and optionally per model family):

* minimum version: anything older is flagged;
* recommended version: older ones are told to update;
* known-bad versions: exact versions or ranges (``< 21.4R3``, ``22.2R1 - 22.2R3``) with a note such as an advisory
  number, so a switch on an affected release stands out.

Nothing is looked up on the internet; the policy is yours to keep current from the vendors' advisories.
"""

from __future__ import annotations

import re

STATUSES = ("vulnerable", "below minimum", "update", "ok", "unknown")

# brand -> patterns whose first group is the version
PATTERNS = [
    ("juniper", r"^\s*(?:set )?version\s+\"?([0-9][\w.\-]+?)\"?;?\s*$"),
    ("juniper", r"^Junos:\s*([0-9][\w.\-]+)"),
    ("juniper", r"JUNOS (?:Software Release|EX\s+Software Suite|Base OS boot) \[([0-9][\w.\-]+)\]"),
    ("arista", r"\bEOS-([0-9][\w.\-]*[0-9A-Za-z])"),
    ("arista", r"^Software image version:\s*([0-9][\w.\-]+)"),
    ("nexus", r"^\s*NXOS: version\s+([0-9][\w.()\-]+)"),
    ("nexus", r"^!Command: show running-config.*\n!Running configuration last done.*\n!Time.*\n\s*version\s+([0-9][\w.()\-]+)"),
    ("cisco", r"Cisco IOS[ -]XE Software, Version\s+([0-9][\w.()\-]+)"),
    ("cisco", r"Cisco IOS Software.*Version\s+([0-9][\w.()\-]+)"),
    ("aruba", r"ArubaOS-CX\s+([A-Z]{2}\.[0-9][\w.\-]+)"),
    ("aruba", r"^!Version ArubaOS-CX\s+([A-Z]{2}\.[0-9][\w.\-]+)"),
    ("procurve", r"Configuration Editor; Created on release #([A-Z]{2}\.[0-9][\w.\-]+)"),
    ("procurve", r"Software revision\s*:\s*([A-Z]{2}\.[0-9][\w.\-]+)"),
    ("dell", r"^! Version\s+(10\.[\w.\-]+)"),
    ("dell", r"OS Version:\s*(10\.[\w.\-]+)"),
    ("extreme", r"^# Software Version\s+([0-9][\w.\-]+)"),
    ("extreme", r"ExtremeXOS version\s+([0-9][\w.\-]+)"),
    ("ruckus", r"^ver\s+([0-9][\w.\-]+)"),
    ("ruckus", r"SW: Version\s+([0-9][\w.\-]+)"),
    ("fortiswitch", r"#config-version=\w+-([0-9][\d.]+)-FW-build(\d+)"),
    ("fortiswitch", r"^Version:\s*FortiSwitch-\S+\s+v([0-9][\w.,\- ]+?)\s*$"),
    ("mikrotik", r"^#.* by RouterOS\s+([0-9][\w.\-]+)"),
    ("mikrotik", r"^\s*version:\s*([0-9][\w.\-]+)"),
    ("cisco", r"^version\s+(1[25]\.\d+|16\.\d+|17\.\d+)\s*$"),     # the first line of an IOS config: train only
    ("nexus", r"^version\s+([0-9]+\.[0-9]+\([\w.]+\)\S*)"),
]
MODEL_PATTERNS = [
    r"^Model:\s*(\S+)", r"^\s*set chassis .*model (\S+)", r"^cisco ((?:WS-|C)\S+) .*processor", r"^Model [Nn]umber\s*:\s*(\S+)",
    r"^Arista (DCS-\S+)", r"^! device: \S+ \((\S+),", r"cisco Nexus\S* (\S+) [Cc]hassis", r"^; (J\w+) Configuration Editor",
    r"^#config-version=(\w+?)-", r"^# (?:software id|model) = (\S+)", r"^Hardware:\s*(\S+)", r"Product\s*:\s*(\S+)",
]


def detect(text: str, vendor_hint: str = "") -> tuple[str, str]:
    """(vendor, version) found in config or show-version text, or ('', '')."""
    text = text or ""
    order = sorted(PATTERNS, key=lambda p: p[0] != vendor_hint) if vendor_hint else PATTERNS
    for vendor, pat in order:
        m = re.search(pat, text, re.M | re.I)
        if m:
            ver = m.group(1)
            if vendor == "fortiswitch" and m.lastindex and m.lastindex > 1:
                ver = f"{ver} build{m.group(2)}"
            return vendor, ver.strip().rstrip(";,")
    return "", ""


def model_of(text: str) -> str:
    for pat in MODEL_PATTERNS:
        m = re.search(pat, text or "", re.M)
        if m:
            return m.group(1).strip(",")
    return ""


def _parts(version: str) -> list:
    """'22.4R3-S2.11' -> [22, 4, 'r', 3, 's', 2, 11]; numbers compare as numbers, letters as text."""
    out = []
    for tok in re.findall(r"\d+|[A-Za-z]+", version or ""):
        out.append(int(tok) if tok.isdigit() else tok.lower())
    return out


def compare(a: str, b: str) -> int:
    """-1, 0 or 1, like a <=> b."""
    pa, pb = _parts(a), _parts(b)
    for x, y in zip(pa, pb):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, int) != isinstance(y, int):
            # 4.31.1F vs 4.31.1 : the one with a letter suffix is a build of the same release; numbers win order
            return 1 if isinstance(x, int) else -1
        return -1 if x < y else 1
    if len(pa) == len(pb):
        return 0
    # 22.4R3 < 22.4R3-S2 (a service release comes after)
    return -1 if len(pa) < len(pb) else 1


def matches(version: str, rule: str) -> bool:
    """A known-bad rule: '22.2R1', '< 21.4R3', '<= 17.9.3', '22.2R1 - 22.2R3' (both ends included)."""
    rule = (rule or "").strip()
    if not rule or not version:
        return False
    if (m := re.match(r"^(<=|<|>=|>)\s*(\S+)$", rule)):
        c = compare(version, m.group(2))
        return {"<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0}[m.group(1)]
    if (m := re.match(r"^(\S+)\s+-\s+(\S+)$", rule)):
        return compare(version, m.group(1)) >= 0 and compare(version, m.group(2)) <= 0
    if rule.endswith("*"):
        return version.lower().startswith(rule[:-1].lower())
    return compare(version, rule) == 0


def clean_policy(data) -> dict:
    """User input -> {rows: [{vendor, family, minimum, recommended, bad: [{rule, note}]}]}."""
    rows = []
    for r in (data or {}).get("rows", []) if isinstance(data, dict) else []:
        if not isinstance(r, dict):
            continue
        clean = {k: re.sub(r"[\x00-\x1f<>]", "", str(r.get(k) or ""))[:60].strip()
                 for k in ("vendor", "family", "minimum", "recommended")}
        if not clean["vendor"]:
            continue
        bad = []
        for b in r.get("bad") or []:
            if isinstance(b, dict) and str(b.get("rule") or "").strip():
                bad.append({"rule": re.sub(r"[\x00-\x1f<>]", "", str(b["rule"]))[:60].strip(),
                            "note": re.sub(r"[\x00-\x1f<>]", "", str(b.get("note") or ""))[:200].strip()})
        clean["bad"] = bad[:50]
        rows.append(clean)
    return {"rows": rows[:100]}


def _policy_for(policy: dict, vendor: str, model: str) -> dict | None:
    best = None
    for r in policy.get("rows", []):
        if r["vendor"] != vendor:
            continue
        fam = r.get("family") or ""
        if fam and fam.lower() not in (model or "").lower():
            continue
        if best is None or len(fam) > len(best.get("family") or ""):
            best = r
    return best


def assess(name: str, vendor: str, version: str, model: str, policy: dict) -> dict:
    out = {"name": name, "vendor": vendor, "version": version, "model": model, "status": "unknown", "why": ""}
    if not version:
        out["why"] = "no version found in the backup"
        return out
    rule = _policy_for(policy, vendor, model)
    if rule is None:
        out["why"] = "no policy for this brand yet"
        return out
    hits = [b for b in rule.get("bad", []) if matches(version, b["rule"])]
    if hits:
        out.update(status="vulnerable", why="; ".join(f"{b['rule']}" + (f": {b['note']}" if b["note"] else "") for b in hits))
    elif rule.get("minimum") and compare(version, rule["minimum"]) < 0:
        out.update(status="below minimum", why=f"minimum is {rule['minimum']}")
    elif rule.get("recommended") and compare(version, rule["recommended"]) < 0:
        out.update(status="update", why=f"recommended is {rule['recommended']}")
    else:
        out.update(status="ok", why=f"recommended {rule['recommended']}" if rule.get("recommended") else "")
    if rule.get("recommended"):
        out["target"] = rule["recommended"]
    return out


def report(items: list[dict], policy: dict) -> dict:
    """items: [{name, text, vendor?}] -> {switches, counts, versions}."""
    rows = []
    for it in items:
        vendor, version = detect(str(it.get("text") or ""), str(it.get("vendor") or ""))
        vendor = str(it.get("vendor") or "") or vendor
        rows.append({**assess(str(it.get("name") or "?"), vendor, str(it.get("version") or "") or version,
                              str(it.get("model") or "") or model_of(str(it.get("text") or "")), policy),
                     "when": it.get("when", "")})
    rows.sort(key=lambda r: (STATUSES.index(r["status"]), r["vendor"], r["name"]))
    counts = {s: sum(1 for r in rows if r["status"] == s) for s in STATUSES}
    versions: dict = {}
    for r in rows:
        if r["version"]:
            versions.setdefault(r["vendor"] or "?", {}).setdefault(r["version"], 0)
            versions[r["vendor"] or "?"][r["version"]] += 1
    return {"switches": rows, "counts": counts, "versions": versions}
