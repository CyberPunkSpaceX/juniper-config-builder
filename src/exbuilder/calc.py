"""Calculators for network engineers: subnets, a VLAN address plan, and a PoE power budget."""

from __future__ import annotations

import ipaddress
import math
import re

MAX_SPLIT = 256
MAX_VLANS = 200

# Power a switch port must reserve per PoE class (watts at the switch, IEEE 802.3af/at/bt).
POE_CLASSES = {"0": 15.4, "1": 4.0, "2": 7.0, "3": 15.4, "4": 30.0, "5": 45.0, "6": 60.0, "7": 75.0, "8": 90.0}
# Typical devices, as a starting point the user can change.
POE_DEVICES = [
    {"device": "IP phone", "class": "2", "watts": 6.5},
    {"device": "IP phone with colour screen / sidecar", "class": "3", "watts": 12.0},
    {"device": "Wi-Fi 6 access point", "class": "4", "watts": 25.5},
    {"device": "Wi-Fi 7 access point", "class": "6", "watts": 45.0},
    {"device": "Fixed IP camera", "class": "3", "watts": 12.95},
    {"device": "PTZ camera", "class": "6", "watts": 51.0},
    {"device": "Door controller / badge reader", "class": "3", "watts": 12.95},
]


class CalcError(ValueError):
    pass


def _net(text: str, strict: bool = False):
    text = (text or "").strip()
    try:
        if "/" not in text and " " in text:          # "10.0.0.1 255.255.255.0"
            addr, mask = text.split()[:2]
            text = f"{addr}/{mask}"
        return ipaddress.ip_interface(text) if not strict else ipaddress.ip_network(text, strict=True)
    except ValueError:
        raise CalcError(f"'{text}' is not an address with a prefix, like 10.20.30.40/24 or 10.20.30.40 255.255.255.0.") from None


def subnet(text: str) -> dict:
    """An address with prefix -> everything about its subnet."""
    iface = _net(text)
    net = iface.network
    v4 = net.version == 4
    size = net.num_addresses
    if v4 and net.prefixlen <= 30:
        first, last, usable = net.network_address + 1, net.broadcast_address - 1, size - 2
    elif v4:   # /31 point-to-point and /32 host routes use every address
        first, last, usable = net.network_address, net.broadcast_address, size
    else:
        first, last, usable = net.network_address, net.broadcast_address, size
    out = {"address": str(iface.ip), "network": str(net), "prefix": net.prefixlen, "version": net.version,
           "first": str(first), "last": str(last), "usable": usable, "total": size}
    if v4:
        out.update(mask=str(net.netmask), wildcard=str(net.hostmask), broadcast=str(net.broadcast_address),
                   private=net.is_private, binary_mask=".".join(f"{int(o):08b}" for o in str(net.netmask).split(".")))
    return out


def split(text: str, prefix: int | None = None, count: int | None = None, hosts: int | None = None) -> dict:
    """Split a network into equal parts by new prefix, number of parts, or hosts per part."""
    net = _net(text).network
    width = 32 if net.version == 4 else 128
    if hosts:
        need = hosts + (2 if net.version == 4 else 0)
        prefix = width - max(0, math.ceil(math.log2(max(need, 1))))
    elif count:
        prefix = net.prefixlen + max(0, math.ceil(math.log2(max(count, 1))))
    if prefix is None:
        raise CalcError("Give a new prefix, a number of subnets, or hosts per subnet.")
    if not net.prefixlen <= prefix <= width:
        raise CalcError(f"The new prefix must be between /{net.prefixlen} and /{width}.")
    n = 2 ** (prefix - net.prefixlen)
    subs = []
    for i, s in enumerate(net.subnets(new_prefix=prefix)):
        if i >= MAX_SPLIT:
            break
        info = subnet(str(s))
        subs.append({k: info[k] for k in ("network", "first", "last", "usable")})
    return {"network": str(net), "prefix": prefix, "count": n, "shown": len(subs), "subnets": subs}


def vlan_plan(supernet: str, rows: list[dict], gateway: str = "first", spare: int = 0) -> dict:
    """Give each VLAN a subnet from the supernet, biggest first (VLSM). rows: [{name, id, hosts}]."""
    try:
        block = ipaddress.ip_network((supernet or "").strip(), strict=False)
    except ValueError:
        raise CalcError(f"'{supernet}' is not a network, like 10.20.0.0/16.") from None
    if block.version != 4:
        raise CalcError("The VLAN plan works with IPv4 blocks.")
    errors, want = [], []
    seen_ids, seen_names = set(), set()
    for i, r in enumerate(rows[:MAX_VLANS], start=1):
        name = str(r.get("name") or "").strip()
        vid = str(r.get("id") or "").strip()
        try:
            hosts = int(str(r.get("hosts") or "0").strip())
        except ValueError:
            hosts = -1
        if not name and not vid:
            continue
        if not re.match(r"^[A-Za-z][A-Za-z0-9_.-]{0,62}$", name):
            errors.append(f"Line {i}: VLAN name '{name}' must start with a letter (letters, digits, _ . -).")
            continue
        if not vid.isdigit() or not 1 <= int(vid) <= 4094:
            errors.append(f"Line {i}: VLAN ID must be 1-4094.")
            continue
        if vid in seen_ids or name.lower() in seen_names:
            errors.append(f"Line {i}: VLAN {vid} {name} is listed twice.")
            continue
        if hosts < 1:
            errors.append(f"Line {i}: how many hosts does {name} need?")
            continue
        seen_ids.add(vid)
        seen_names.add(name.lower())
        grow = math.ceil(hosts * (1 + max(0, min(spare, 400)) / 100))
        prefix = 32 - math.ceil(math.log2(grow + 3))   # network, broadcast, gateway
        prefix = min(prefix, 30)
        want.append({"name": name, "id": vid, "hosts": hosts, "prefix": prefix, "order": i})
    free = [block]
    out = []
    for w in sorted(want, key=lambda x: (x["prefix"], x["order"])):
        free.sort(key=lambda n: (n.network_address, n.prefixlen))
        spot = next((n for n in free if n.prefixlen <= w["prefix"]), None)
        if spot is None:
            errors.append(f"{w['name']} ({w['hosts']} hosts, /{w['prefix']}) does not fit in {block}.")
            continue
        free.remove(spot)
        sub = next(spot.subnets(new_prefix=w["prefix"]))
        free += [x for x in spot.address_exclude(sub)] if spot != sub else []
        gw = sub.network_address + 1 if gateway != "last" else sub.broadcast_address - 1
        out.append({**{k: w[k] for k in ("name", "id", "hosts")}, "subnet": str(sub), "gateway": str(gw),
                    "irb": f"{gw}/{sub.prefixlen}", "usable": sub.num_addresses - 2,
                    "range": f"{sub.network_address + (2 if gateway != 'last' else 1)} - "
                             f"{sub.broadcast_address - (1 if gateway != 'last' else 2)}", "order": w["order"]})
    out.sort(key=lambda x: x["order"])
    for x in out:
        x.pop("order")
    used = sum(ipaddress.ip_network(x["subnet"]).num_addresses for x in out)
    return {"supernet": str(block), "vlans": out, "errors": errors,
            "used": used, "total": block.num_addresses, "free": [str(n) for n in sorted(free)][:50]}


def poe_budget(budget, rows: list[dict], reserve: str = "class") -> dict:
    """PoE power: what the devices draw and what the switch reserves (by class or by actual draw)."""
    try:
        budget = float(str(budget).strip()) if str(budget).strip() else 0.0
    except ValueError:
        raise CalcError("The PoE budget is a number of watts, like 740.") from None
    lines, draw, reserved, ports = [], 0.0, 0.0, 0
    for r in rows[:100]:
        try:
            count = int(str(r.get("count") or "0"))
            watts = float(str(r.get("watts") or "0"))
        except ValueError:
            raise CalcError(f"{r.get('device') or 'A line'}: count and watts must be numbers.") from None
        if count <= 0:
            continue
        cls = str(r.get("class") or "").strip()
        per_port = POE_CLASSES.get(cls, watts) if reserve == "class" else watts
        per_port = max(per_port, watts)
        lines.append({"device": str(r.get("device") or "Device")[:80], "count": count, "watts": watts, "class": cls,
                      "draw": round(count * watts, 1), "reserved": round(count * per_port, 1)})
        draw += count * watts
        reserved += count * per_port
        ports += count
    need = reserved if reserve == "class" else draw
    left = budget - need
    return {"lines": lines, "ports": ports, "draw": round(draw, 1), "reserved": round(reserved, 1),
            "budget": budget, "left": round(left, 1), "ok": budget > 0 and left >= 0,
            "use": round(100 * need / budget) if budget else None,
            "note": ("Over budget: some devices will not get power. Lower the count, use a bigger power supply, or "
                     "move devices to another switch.") if budget and left < 0 else
                    ("Under 20% left: a few more devices or a failed power supply will run out." if budget and left < budget * 0.2
                     else "")}
