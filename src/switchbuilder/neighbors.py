"""Auto network map from LLDP and CDP neighbours, for every switch brand.

Neighbour tables are read from the usual commands' output:

* ``show lldp neighbors detail`` (Cisco IOS/IOS-XE, Nexus, Arista, Dell OS10, Ruckus), ``show cdp neighbors detail``
  (Cisco), ``show lldp neighbors`` and ``... detail`` (Juniper), ``show lldp neighbor-info detail`` (Aruba CX),
  ``show lldp info remote-device detail`` (ProCurve), ``show lldp neighbors detailed`` (Extreme),
  ``get switch lldp neighbors-detail`` (FortiSwitch) and ``/ip neighbor print detail`` (MikroTik).

The output can be pasted (one block per switch) or fetched over SSH: ``discover`` starts from a few switches and
follows the neighbours' management addresses, inside the client's allowed networks, until it has seen everyone
or reaches the limit. Only fixed, read-only commands are sent.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor

from . import sshfetch

MAX_SWITCHES = 80
COMMANDS = (
    "show lldp neighbors detail",
    "show cdp neighbors detail",
    "show lldp neighbor-info detail",
    "show lldp neighbors detailed",
    "show lldp info remote-device detail",
    "get switch lldp neighbors-detail",
    "/ip neighbor print detail without-paging",
    "show lldp neighbors | no-more",
)

KEYS = {
    "local": {"localintf", "localinterface", "localport", "localportid", "lldpport", "interface", "port",
              "neighborlearnedonport", "localportname"},
    "port": {"portid", "neighborportid", "remoteportid", "portinfo", "portidinterfacename", "portidoutgoingport",
             "interfacename", "remoteport", "portidlocallyassigned", "portidmacaddress"},
    "port_desc": {"portdescription", "neighborportdescription", "neighborportdesc", "remoteportdescription", "portdescr"},
    "name": {"systemname", "sysname", "neighborchassisname", "remotesystemname", "deviceid", "identity",
             "neighborsystemname"},
    "mgmt": {"managementaddress", "managementaddresses", "ipaddress", "ip", "address", "neighbormanagementaddress",
             "remotemanagementaddressipv4", "managementaddressipv4", "mgmtaddress", "ipv4address", "managementip",
             "entryaddresses"},
    "platform": {"platform", "systemdescription", "neighborsystemdescription", "remotesystemdesc", "sysdescr",
                 "board"},
    "chassis": {"chassisid", "neighborchassisid", "remotechassisid", "macaddress"},
    "caps": {"systemcapabilities", "capabilities", "enabledcapabilities", "systemcapabilitiessupported"},
}
_KEY_OF = {k: field for field, keys in KEYS.items() for k in keys}
STARTS = [
    re.compile(r"^Interface\s+(\S+)\s+detected\s+\d+\s+LLDP neighbors?", re.I),          # Arista
    re.compile(r"^LLDP Port\s+(\S+)\s+detected\s+\d+\s+neighbors?", re.I),               # Extreme
    re.compile(r"^Neighbor learned on port\s+(\S+)", re.I),                               # FortiSwitch
]
CDP_IF = re.compile(r"^Interface:\s*([^,]+),\s*Port ID \(outgoing port\):\s*(.+)$", re.I)
JUNIPER_HEAD = re.compile(r"^Local Interface\s+Parent Interface\s+Chassis Id\s+Port info\s+System Name", re.I)
MIKROTIK = re.compile(r'([\w-]+)=("[^"]*"|\S+)')


def _clean(v: str) -> str:
    v = v.strip().rstrip(",").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v.strip()


def _ip(v: str) -> str:
    v = _clean(v).split()[0] if _clean(v) else ""
    try:
        return str(ipaddress.ip_address(v.split("/")[0]))
    except ValueError:
        return ""


def short(name: str) -> str:
    """sw2.example.com -> sw2 (lower case), for matching."""
    name = _clean(name or "")
    try:
        ipaddress.ip_address(name)
        return name
    except ValueError:
        return name.split(".")[0].lower()


def parse(text: str) -> list[dict]:
    """Neighbour output of any brand -> [{local, port, name, mgmt, platform, chassis, port_desc}]."""
    out: list[dict] = []
    cur: dict = {}

    def flush():
        nonlocal cur
        if cur.get("local") and (cur.get("name") or cur.get("chassis") or cur.get("mgmt")):
            out.append({k: cur.get(k, "") for k in ("local", "port", "name", "mgmt", "platform", "chassis", "port_desc")})
        cur = {}

    def take(body: str) -> None:
        if ":" not in body:
            return
        key, _, val = body.partition(":")
        k = re.sub(r"[^a-z0-9]", "", key.lower())
        if k.endswith(("type", "subtype")):
            return
        field = _KEY_OF.get(k)
        if field is None and k.startswith(("managementaddress", "remotemanagementaddress", "mgmtaddress")):
            field = "mgmt"
        if field is None:
            return
        val = _clean(val)
        if field in ("port", "chassis", "name") and val and cur.get(field) and cur.get("local"):
            flush()   # the next neighbour starts (Nexus prints the local port after the remote ones)
        if field == "local":
            if cur.get("local") and (cur.get("name") or cur.get("port") or cur.get("chassis")):
                flush()
            if val:
                cur["local"] = val
        elif field == "mgmt":
            ip = _ip(val)
            if ip and not cur.get("mgmt"):
                cur["mgmt"] = ip
        elif val and not cur.get(field):
            cur[field] = re.split(r",\s+Capabilities", val)[0] if field == "platform" else val

    juniper_table = False
    for raw in (text or "").replace("\r", "").split("\n"):
        line = raw.strip()
        if not line:
            continue
        if JUNIPER_HEAD.match(line):
            juniper_table = True
            continue
        if juniper_table:
            t = line.split()
            if len(t) >= 5 and re.match(r"^[a-z]{2,4}-\d", t[0]):
                out.append({"local": t[0], "port": t[3], "name": " ".join(t[4:]), "mgmt": "", "platform": "",
                            "chassis": t[2], "port_desc": ""})
                continue
            juniper_table = False
        if (m := MIKROTIK.findall(line)) and len(m) >= 3 and "interface" in {k for k, _ in m}:
            d = {k: _clean(v) for k, v in m}
            flush()
            cur = {"local": d.get("interface", ""), "port": d.get("interface-name", ""), "name": d.get("identity", ""),
                   "mgmt": _ip(d.get("address", "") or d.get("address4", "")),
                   "platform": " ".join(x for x in (d.get("platform", ""), d.get("board", "")) if x),
                   "chassis": d.get("mac-address", "")}
            flush()
            continue
        started = next((m for rx in STARTS if (m := rx.match(line))), None)
        if started:
            flush()
            cur["local"] = _clean(started.group(1)).rstrip(":")
            continue
        if (m := CDP_IF.match(line)):
            cur["local"], cur["port"] = _clean(m.group(1)), _clean(m.group(2))
            continue
        if line.startswith(("---", "===")):
            continue
        for part in line.lstrip("-+* ").strip().split("; "):
            take(part.strip())
    flush()
    # Some outputs print a neighbour twice.
    seen, uniq = set(), []
    for e in out:
        key = (e["local"].lower(), short(e["name"]) or e["chassis"], e["port"].lower())
        if key not in seen:
            seen.add(key)
            uniq.append(e)
    return uniq


def _ifkey(name: str) -> str:
    """Interface names compared loosely: GigabitEthernet1/0/1 == Gi1/0/1, Ethernet1 == Et1."""
    n = (name or "").lower().replace(" ", "")
    m = re.match(r"^([a-z-]+?)(\d.*)$", n)
    if not m:
        return n
    prefix, rest = m.groups()
    for full, ab in (("tengigabitethernet", "te"), ("twentyfivegige", "twe"), ("fortygigabitethernet", "fo"),
                     ("hundredgige", "hu"), ("gigabitethernet", "gi"), ("fastethernet", "fa"), ("ethernet", "et"),
                     ("port-channel", "po"), ("mgmt", "mgmt"), ("management", "ma")):
        if prefix == full or (len(prefix) >= 2 and full.startswith(prefix) and ab.startswith(prefix[:2])):
            return ab + rest
    return prefix + rest


def build_map(items: list[dict]) -> dict:
    """items: [{name, address, text}] (one per switch) -> {nodes, links, checks}."""
    switches = []
    for i, it in enumerate(items[:MAX_SWITCHES]):
        entries = parse(str(it.get("text") or ""))
        switches.append({"name": _clean(str(it.get("name") or "")), "address": _clean(str(it.get("address") or "")),
                         "entries": entries})
    # Each switch's own name: given, else what a neighbour calls the address we used.
    by_ip = {}
    for sw in switches:
        for e in sw["entries"]:
            if e["mgmt"] and e["name"]:
                by_ip.setdefault(e["mgmt"], e["name"])
    for i, sw in enumerate(switches):
        if not sw["name"]:
            sw["name"] = by_ip.get(_ip(sw["address"]) or "", "") or sw["address"] or f"switch-{i + 1}"

    nodes: dict[str, dict] = {}

    def node(name: str, **info) -> str:
        key = short(name)
        n = nodes.setdefault(key, {"id": key, "name": _clean(name), "mgmt": "", "platform": "", "read": False})
        for k, v in info.items():
            if v and (not n.get(k) or k == "read"):
                n[k] = v
        return key

    for sw in switches:
        node(sw["name"], read=True, mgmt=_ip(sw["address"]))
    ip_to_node = {n["mgmt"]: k for k, n in nodes.items() if n["mgmt"]}
    links: dict[tuple, dict] = {}
    checks: list[dict] = []
    for sw in switches:
        me = short(sw["name"])
        if not sw["entries"]:
            checks.append({"level": "warn", "message": f"{sw['name']}: no LLDP or CDP neighbours found in its output."})
        for e in sw["entries"]:
            far = ip_to_node.get(e["mgmt"]) if e["mgmt"] else None
            far = far or (node(e["name"] or e["chassis"], mgmt=e["mgmt"], platform=e["platform"].split("\n")[0][:80]))
            if e["mgmt"]:
                nodes[far]["mgmt"] = nodes[far]["mgmt"] or e["mgmt"]
                ip_to_node.setdefault(e["mgmt"], far)
            if far == me:
                continue
            a, ai, b, bi = me, e["local"], far, e["port"]
            k = (a, _ifkey(ai), b) if a < b else (b, _ifkey(bi) if bi else "?" + _ifkey(ai), a)
            # The same cable seen from the other end has the ports the other way round.
            rev = next((x for x in links.values() if x["a"] == b and x["b"] == a and _ifkey(x["a_if"]) == _ifkey(bi or "")
                        and (not x["b_if"] or _ifkey(x["b_if"]) == _ifkey(ai))), None)
            if rev:
                rev["seen"] = "both ends"
                rev["b_if"] = rev["b_if"] or ai
                continue
            key = (a, _ifkey(ai), b, _ifkey(bi or ""))
            if key in links:
                continue
            links[key] = {"a": a, "a_if": ai, "b": b, "b_if": bi, "seen": f"from {nodes[a]['name']}"}
    read = {k for k, n in nodes.items() if n["read"]}
    for x in links.values():
        if x["a"] in read and x["b"] in read and x["seen"] != "both ends":
            checks.append({"level": "info", "message": f"{nodes[x['a']]['name']} {x['a_if']} ↔ {nodes[x['b']]['name']} "
                                                       f"{x['b_if'] or '?'} is only seen from one end. Is LLDP on at the other end?"})
    # Two different neighbours on one port: an unmanaged switch or hub in between.
    per_port = defaultdict(set)
    for x in links.values():
        per_port[(x["a"], _ifkey(x["a_if"]))].add(x["b"])
    for (n, port), fars in per_port.items():
        if len(fars) > 1:
            checks.append({"level": "warn", "message": f"{nodes[n]['name']} {port}: {len(fars)} neighbours on one port "
                                                       f"({', '.join(nodes[f]['name'] for f in sorted(fars))}). An "
                                                       "unmanaged switch may be in between."})
    others = sorted(n["name"] for n in nodes.values() if not n["read"])
    if others:
        checks.append({"level": "info", "message": f"Seen but not read: {', '.join(others[:30])}"
                                                   f"{'…' if len(others) > 30 else ''}."})
    degree, core = defaultdict(int), defaultdict(int)
    for x in links.values():
        degree[x["a"]] += 1
        degree[x["b"]] += 1
        if x["a"] in read and x["b"] in read:
            core[x["a"]] += 1
            core[x["b"]] += 1
    return {"nodes": sorted(nodes.values(), key=lambda n: (-core[n["id"]], -degree[n["id"]], n["name"])),
            "links": list(links.values()), "checks": checks}


# ------------------------------------------------------------ SSH discovery
def _run(host: str, username: str, password: str, data_dir, port: int, nets: list, pkey) -> dict:
    """Connect like sshfetch does (same host-key rules) and run the neighbour commands."""
    import paramiko

    out = {"host": host, "ok": False}
    try:
        ip = sshfetch.resolve(host, nets, port)
        out["address"] = ip
        sock = socket.create_connection((ip, port), timeout=sshfetch.timeout())
        transport = None
        try:
            transport = paramiko.Transport(sock)
            transport.banner_timeout = sshfetch.timeout()
            transport.start_client(timeout=sshfetch.timeout())
            key = transport.get_remote_server_key()
            entry = f"[{ip}]:{port}" if port != 22 else ip
            with sshfetch._kh_lock:
                known = sshfetch._load_known(data_dir)
                if entry in known and known[entry] != (key.get_name(), key.get_base64()):
                    raise sshfetch.FetchError(f"{host}: the switch's SSH host key has CHANGED. Clear it under "
                                              "'Known switches' if you expected it.")
                if entry not in known:
                    known[entry] = (key.get_name(), key.get_base64())
                    sshfetch._save_known(data_dir, known)
            if pkey is not None:
                transport.auth_publickey(username, pkey)
            else:
                try:
                    transport.auth_password(username, password)
                except paramiko.BadAuthenticationType:
                    transport.auth_interactive(username, lambda title, instr, prompts: [password] * len(prompts))
            texts = []
            for cmd in COMMANDS:
                chan = transport.open_session(timeout=sshfetch.timeout())
                chan.settimeout(sshfetch.timeout() * 2)
                try:
                    chan.exec_command(cmd)
                    buf = bytearray()
                    while len(buf) < sshfetch.MAX_OUTPUT:
                        data = chan.recv(65536)
                        if not data:
                            break
                        buf += data
                    text = buf.decode("utf-8", "replace")
                finally:
                    chan.close()
                if parse(text):
                    texts.append(text)
                    break   # the first command that gives neighbours is enough
            out.update(ok=True, text="\n".join(texts))
        finally:
            if transport is not None:
                transport.close()
            sock.close()
    except sshfetch.FetchError as exc:
        out["error"] = str(exc)
    except paramiko.AuthenticationException:
        out["error"] = f"{host}: sign-in failed (wrong username, password or key)."
    except (OSError, paramiko.SSHException, EOFError) as exc:
        out["error"] = f"{host}: could not connect ({exc.__class__.__name__}: {exc})."[:300]
    return out


def discover(seeds: list[str], username: str, password: str, data_dir, nets: list, port: int = 22, pkey=None,
             limit: int = 30, follow: bool = True, run=_run) -> dict:
    """Read the seeds, then (if follow) every neighbour with a management address in the allowed networks."""
    limit = max(1, min(limit, sshfetch.MAX_HOSTS))
    queue = list(dict.fromkeys(s.strip() for s in seeds if s and s.strip()))
    done, results = set(), []
    while queue and len(done) < limit:
        batch = []
        while queue and len(done) + len(batch) < limit:
            h = queue.pop(0)
            if h not in done and h not in batch:
                batch.append(h)
        done.update(batch)
        with ThreadPoolExecutor(max_workers=min(8, len(batch) or 1)) as pool:
            got = list(pool.map(lambda h: run(h, username, password, data_dir, port, nets, pkey), batch))
        results += got
        if not follow:
            break
        for r in got:
            if not r.get("ok"):
                continue
            for e in parse(r["text"]):
                ip = e["mgmt"]
                if not ip or ip in done or ip in queue:
                    continue
                addr = ipaddress.ip_address(ip)
                if any(addr in n for n in nets):
                    queue.append(ip)
    skipped = [q for q in queue if q not in done]
    items = [{"name": "", "address": r.get("address") or r["host"], "text": r.get("text", "")} for r in results if r.get("ok")]
    out = build_map(items)
    out["fetched"] = [{"host": r["host"], "ok": r["ok"], "error": r.get("error", "")} for r in results]
    if skipped:
        out["checks"].append({"level": "info", "message": f"Stopped at {limit} switches; not read yet: "
                                                          f"{', '.join(skipped[:20])}."})
    return out
