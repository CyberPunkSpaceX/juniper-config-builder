"""Port names and port lists such as ``ge-0/0/0-23, xe-0/1/0``."""

from __future__ import annotations

import re

PHYS_TYPES = ("ge", "xe", "mge", "et")
_ONE = re.compile(r"^(ge|xe|mge|et)-(\d{1,2})/(\d)/(\d{1,2})$")
_RANGE = re.compile(r"^(ge|xe|mge|et)-(\d{1,2})/(\d)/(\d{1,2})\s*(?:-|to)\s*(?:(?:ge|xe|mge|et)-\d{1,2}/\d/)?(\d{1,2})$")
_AE = re.compile(r"^ae(\d{1,3})$")


def split(name: str) -> tuple[str, int, int, int]:
    m = _ONE.match(name)
    if not m:
        raise ValueError(f"not a port name: {name}")
    return m.group(1), int(m.group(2)), int(m.group(3)), int(m.group(4))


def sort_key(name: str):
    try:
        kind, fpc, pic, port = split(name)
        return (fpc, pic, PHYS_TYPES.index(kind), port)
    except ValueError:
        return (999, 0, 0, 0)


def expand(spec: str) -> list[str]:
    """``ge-0/0/0-3, xe-0/1/0`` -> the individual port names. Raises ValueError."""
    ports: list[str] = []
    text = re.sub(r"\s+to\s+", "~", (spec or "").strip())
    for part in re.split(r"[,;\s]+", text):
        part = part.replace("~", " to ")
        if not part:
            continue
        m = _ONE.match(part)
        if m:
            ports.append(part)
            continue
        m = _RANGE.match(part)
        if not m:
            raise ValueError(f"'{part}' is not a port or port range (example: ge-0/0/0-23)")
        kind, fpc, pic, start, end = m.group(1), m.group(2), m.group(3), int(m.group(4)), int(m.group(5))
        if end < start:
            raise ValueError(f"'{part}': the range runs backwards")
        ports.extend(f"{kind}-{fpc}/{pic}/{n}" for n in range(start, end + 1))
    return ports


def runs(ports: list[str]) -> list[tuple[str, str]]:
    """Group sorted ports into (first, last) runs on the same FPC/PIC and type."""
    out: list[list] = []
    for name in sorted(set(ports), key=sort_key):
        kind, fpc, pic, num = split(name)
        if out:
            last = out[-1]
            lk, lf, lp, ln = split(last[1])
            if (lk, lf, lp) == (kind, fpc, pic) and num == ln + 1:
                last[1] = name
                continue
        out.append([name, name])
    return [(a, b) for a, b in out]


def compact(ports: list[str]) -> str:
    """The reverse of expand(): ``ge-0/0/0-3, xe-0/1/0``."""
    parts = []
    for first, last in runs(ports):
        parts.append(first if first == last else f"{first}-{split(last)[3]}")
    return ", ".join(parts)


def is_ae(name: str) -> bool:
    return bool(_AE.match(name or ""))
