"""Compare two switch configs line by line.

Junos configs:

Both configs are turned into ``set`` lines first (curly-brace configs too), so
the order of statements and the way they are written does not matter. The
result groups the differences by section (an interface, a VLAN, a protocol)
and also gives the commands that make one config look like the other.

Encrypted secrets ($9$, $6$ ...) are different every time Junos saves them, so
by default they are compared as "<secret>" and only a missing or added secret
shows up.

Other vendors (Cisco-style indented configs, FortiSwitch, MikroTik, ...): see
``text_compare``. Lines that change on every fetch without a config change (the
"Last configuration change" stamp, ntp clock-period, the RouterOS export date)
are left out first: ``stable_text``.
"""

from __future__ import annotations

import difflib
import re

from .importer import to_set_lines

SECRET = re.compile(r'"\$(?:9|1|5|6|8|sha1|sha256|sha512)\$[^"]*"|(?<=\s)\$(?:9|1|5|6|8)\$\S+')
# Statements that hold several values, where "set x members B" adds B next to A.
MULTI = {"members", "vlan-id-list", "community", "prefix-list", "address", "neighbor", "server", "servers",
         "name-server", "interface", "vlans", "import", "export", "from", "then", "clients", "allow"}
DEEP = {"policy-options": 3, "firewall": 4, "security": 3}
MAX_LINES = 60_000


def _natural(line: str):
    return [int(t) if t.isdigit() else t for t in re.split(r"(\d+)", line)]


def normalize(text: str, ignore_secrets: bool = True) -> list[str]:
    """Config text -> unique set lines (without 'set '), in their original order."""
    out, seen = [], set()
    for ln in to_set_lines(text)[:MAX_LINES]:
        if ln.startswith("version "):
            continue   # differs between releases and says nothing about the switch
        if ignore_secrets:
            ln = SECRET.sub('"<secret>"', ln)
        if ln not in seen:
            seen.add(ln)
            out.append(ln)
    return out


def _words(line: str) -> list[str]:
    return re.findall(r'"[^"]*"|\S+', line)


def section_of(line: str) -> str:
    words = _words(line)
    depth = DEEP.get(words[0], 2) if words else 1
    if words and words[0] == "interfaces" and len(words) > 3 and words[1] == "interface-range":
        depth = 3   # each range on its own
    elif words and words[0] == "interfaces" and len(words) > 3 and words[2] == "unit":
        depth = 4   # each unit on its own
    return " ".join(words[:depth])


def commands(have: list[str], want: list[str]) -> list[str]:
    """Junos commands that turn the config ``have`` into ``want``."""
    have_set, want_set = set(have), set(want)
    gone = [ln for ln in have if ln not in want_set]
    new = [ln for ln in want if ln not in have_set]
    replaced = {_path(ln) for ln in new}
    want_prefixes = set()
    for ln in want:
        w = _words(ln)
        want_prefixes.update(" ".join(w[:k]) for k in range(1, min(len(w), 4) + 1))
    out, done = [], set()
    for ln in gone:
        w = _words(ln)
        top = next((" ".join(w[:k]) for k in range(2, min(len(w) - 1, len(_words(section_of(ln)))) + 1)
                    if " ".join(w[:k]) not in want_prefixes), None)
        if top:                               # the whole interface / VLAN / unit ... goes
            if top not in done:
                done.add(top)
                out.append(f"delete {top}")
        elif _path(ln) not in replaced:       # a changed value is simply set again below
            out.append(f"delete {ln}")
    out.sort(key=_natural)
    out += [f"set {ln}" for ln in sorted(new, key=_natural)]
    return out


def _path(line: str) -> str:
    """The statement without its value, for single-value statements."""
    words = _words(line)
    if len(words) < 2 or words[-2] in MULTI:
        return line
    return " ".join(words[:-1])


# Lines that differ between two fetches of the same, unchanged config.
VOLATILE = re.compile(
    r"^(?:! Last configuration change at|! NVRAM config last updated|ntp clock-period|Building configuration|"
    r"Current configuration\s*:|!Time:|!Running configuration last done at|! Startup-config last modified|"
    r"# .* by RouterOS|#\s*(?:\w{3}/\d\d/\d{4}|\d{4}-\d\d-\d\d) \d\d:\d\d:\d\d)")
TEXT_SECRET = re.compile(
    r"(\b(?:secret|password|key-string|auth-key|authentication-key|community|passphrase|passwd|"
    r"pre-shared-key|key)\s+(?:\d\s+)?|\bENC\s+|\b(?:password|passphrase|secret|authentication-password|"
    r"encryption-password|wpa2?-pre-shared-key)=)(\"[^\"]*\"|\S+)", re.I)


def stable_text(text: str) -> str:
    """The config without the lines that change on every fetch."""
    return "\n".join(ln.rstrip() for ln in (text or "").replace("\r\n", "\n").split("\n")
                     if not VOLATILE.match(ln.strip()))


def _flatten(text: str, ignore_secrets: bool) -> list[tuple[str, str]]:
    """Config text -> [(section, line)]: a section is the unindented line above (or the line itself)."""
    out, seen, section = [], set(), ""
    for raw in stable_text(text).split("\n")[:MAX_LINES]:
        line = raw.rstrip()
        bare = line.strip()
        if not bare or bare in ("!", "#", "exit", "end", "next", "quit"):
            continue
        if ignore_secrets:
            line = TEXT_SECRET.sub(lambda m: m.group(1) + "<secret>", line)
        if not raw[:1].isspace():
            words = line.split()
            # MikroTik: "/interface vlan add ..." -> section "/interface vlan"
            section = " ".join(words[:2]) if bare.startswith("/") else line.strip()
        key = (section, line)
        if key not in seen:
            seen.add(key)
            out.append(key)
    return out


def text_compare(a_text: str, b_text: str, ignore_secrets: bool = True, context: int = 3) -> dict:
    """Differences between two configs of any vendor, grouped by top-level block, in config order."""
    a, b = _flatten(a_text, ignore_secrets), _flatten(b_text, ignore_secrets)
    if not a and not b:
        return {"error": "Neither side has any config lines."}
    order, by_a, by_b = [], {}, {}
    for sec, ln in a:
        if sec not in by_a and sec not in by_b:
            order.append(sec)
        by_a.setdefault(sec, []).append(ln)
    for sec, ln in b:
        if sec not in by_a and sec not in by_b:
            order.append(sec)
        by_b.setdefault(sec, []).append(ln)
    sections, only_a, only_b = [], 0, 0
    for sec in order:
        la, lb = by_a.get(sec, []), by_b.get(sec, [])
        if la == lb:
            continue
        lines = []
        for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, la, lb, autojunk=False).get_opcodes():
            if op == "equal":
                lines += [{"op": " ", "text": x} for x in la[i1:i2]]
            else:
                lines += [{"op": "-", "text": x} for x in la[i1:i2]] + [{"op": "+", "text": x} for x in lb[j1:j2]]
        removed, added = sum(x["op"] == "-" for x in lines), sum(x["op"] == "+" for x in lines)
        only_a, only_b = only_a + removed, only_b + added
        sections.append({"name": sec, "removed": removed, "added": added, "lines": _trim(lines, context)})
    return {"a_lines": len(a), "b_lines": len(b), "same": len(set(a) & set(b)), "only_a": only_a, "only_b": only_b,
            "identical": not sections, "sections": sections, "a_to_b": [], "b_to_a": [],
            "secrets_ignored": ignore_secrets, "plain": True}


def _trim(lines: list[dict], context: int) -> list[dict]:
    keep = [False] * len(lines)
    for i, x in enumerate(lines):
        if x["op"] != " ":
            for j in range(max(0, i - context), min(len(lines), i + context + 1)):
                keep[j] = True
    shown, skipped = [], 0
    for x, k in zip(lines, keep):
        if k:
            if skipped:
                shown.append({"op": "…", "text": f"{skipped} unchanged line{'s' if skipped > 1 else ''}"})
                skipped = 0
            shown.append(x)
        else:
            skipped += 1
    if skipped:
        shown.append({"op": "…", "text": f"{skipped} unchanged line{'s' if skipped > 1 else ''}"})
    return shown


def compare(a_text: str, b_text: str, ignore_secrets: bool = True, context: int = 3) -> dict:
    """Differences between config A and config B.

    sections: [{name, added, removed, lines: [{op: " " | "-" | "+", text}]}]
    where "-" is only in A and "+" only in B. Unchanged lines of a changed
    section are kept around the changes (``context`` lines).
    """
    a, b = normalize(a_text, ignore_secrets), normalize(b_text, ignore_secrets)
    if (not a or not b) and (a_text or "").strip() and (b_text or "").strip():
        return text_compare(a_text, b_text, ignore_secrets, context)   # not Junos: compare as text
    if not a and not b:
        return {"error": "Neither side has any config lines."}
    a_set, b_set = set(a), set(b)
    only_a = [ln for ln in a if ln not in b_set]
    only_b = [ln for ln in b if ln not in a_set]
    changed = {section_of(ln) for ln in only_a + only_b}
    by_sec: dict[str, list] = {}
    for ln in sorted(a_set | b_set, key=_natural):
        sec = section_of(ln)
        if sec in changed:
            op = " " if ln in a_set and ln in b_set else "-" if ln in a_set else "+"
            by_sec.setdefault(sec, []).append({"op": op, "text": ln})
    sections = []
    for sec in sorted(by_sec, key=_natural):
        lines = by_sec[sec]
        keep = [False] * len(lines)
        for i, x in enumerate(lines):
            if x["op"] != " ":
                for j in range(max(0, i - context), min(len(lines), i + context + 1)):
                    keep[j] = True
        shown, skipped = [], 0
        for x, k in zip(lines, keep):
            if k:
                if skipped:
                    shown.append({"op": "…", "text": f"{skipped} unchanged line{'s' if skipped > 1 else ''}"})
                    skipped = 0
                shown.append(x)
            else:
                skipped += 1
        if skipped:
            shown.append({"op": "…", "text": f"{skipped} unchanged line{'s' if skipped > 1 else ''}"})
        sections.append({"name": sec, "removed": sum(x["op"] == "-" for x in lines),
                         "added": sum(x["op"] == "+" for x in lines), "lines": shown})
    return {"a_lines": len(a), "b_lines": len(b), "same": len(a_set & b_set), "only_a": len(only_a),
            "only_b": len(only_b), "identical": not only_a and not only_b, "sections": sections,
            "a_to_b": commands(a, b), "b_to_a": commands(b, a), "secrets_ignored": ignore_secrets}
