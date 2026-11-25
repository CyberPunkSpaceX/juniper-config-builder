"""Test switch configs in an EVE-NG lab.

Push: the switches on the network map become an EVE-NG lab. Each switch is a
vJunos-switch node; every link between two switches on the map becomes a
point-to-point network between the matching lab ports. The real port names
(ge-0/0/47, xe-0/1/0, ...) are mapped onto the lab's ports (ge-0/0/0 to
ge-0/0/9) and the configs are rewritten to match. Then the lab starts and each
config is typed into the node's console and committed.

Pull: each lab node's config is read back over its console
(``show configuration | display set``), so you can bring tested changes back
into the builder.

Safety: the app only talks to the EVE-NG address a client admin set, and only
when it resolves inside the networks the server allows (the same limit as SSH
fetch). Console connections go to that same host. The EVE-NG password and the
lab login are stored encrypted (see web/clients.py).

EVE-NG REST API (Community 5.x and Pro): /api/auth/login, /api/list/templates,
/api/folders, /api/labs, .../nodes, .../networks, .../nodes/<id>/interfaces,
.../nodes/start|stop.
"""

from __future__ import annotations

import http.cookiejar
import ipaddress
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from . import sshfetch, topology
from .importer import to_set_lines

# Lab node types the builder can build. ``first`` is the EVE interface index of
# the first data port (index 0 is the management port fxp0).
TEMPLATES = {
    "vjunosswitch": {"label": "vJunos-switch", "first": 1, "ports": 10, "prefix": "ge-0/0/", "cpu": 4, "ram": 5120,
                     "icon": "Switch L3.png"},
    "vjunosrouter": {"label": "vJunos-router", "first": 1, "ports": 10, "prefix": "ge-0/0/", "cpu": 4, "ram": 5120,
                     "icon": "Router.png"},
}
JUNIPER = re.compile(r"junos|vqfx|vmx|vsrx|vptx|vjunos|juniper", re.I)
LAB_USER = "exb-lab"
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$")
PHYS = topology.PHYS
DROP_TOP = ("chassis", "virtual-chassis", "poe", "version")       # hardware-only parts a lab node can't take
MGMT = re.compile(r"^interfaces (?:em0|me0|vme)\b")


class EveError(Exception):
    pass


# --------------------------------------------------------------- address
def check_url(url: str) -> tuple[str, str]:
    """An EVE-NG URL -> (base URL, host), or EveError. The host must be inside the allowed networks."""
    u = urllib.parse.urlparse((url or "").strip())
    if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password:
        raise EveError("Enter the EVE-NG address like https://eve.example.lan or http://10.40.45.50.")
    try:
        infos = socket.getaddrinfo(u.hostname, u.port or (443 if u.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise EveError(f"{u.hostname}: name not found.") from None
    top = sshfetch.ceiling()
    addrs = {ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos}
    bad = [a for a in addrs if not any(a in n for n in top)]
    if not addrs or bad:
        raise EveError(f"{u.hostname} ({', '.join(map(str, bad or addrs))}) is outside the networks this server "
                       f"may reach ({', '.join(map(str, top))}).")
    base = f"{u.scheme}://{u.netloc}{u.path.rstrip('/')}"
    return base, u.hostname


# ------------------------------------------------------------ the REST API
class Eve:
    """A small EVE-NG REST client (one session per instance)."""

    def __init__(self, url: str, username: str, password: str, verify_tls: bool = True, timeout: float = 30):
        self.base, self.host = check_url(url)
        self.username, self.password, self.timeout = username, password, timeout
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),
                                                  urllib.request.HTTPCookieProcessor(self.jar),
                                                  _NoRedirect())

    def call(self, method: str, path: str, data=None, ok404: bool = False):
        body = json.dumps(data).encode() if data is not None else None
        req = urllib.request.Request(self.base + path, data=body, method=method,
                                     headers={"Content-Type": "application/json", "Accept": "application/json"})
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                raw = resp.read(20_000_000)
        except urllib.error.HTTPError as exc:
            if exc.code == 404 and ok404:
                return None
            try:
                msg = json.loads(exc.read(100_000) or b"{}").get("message", "")
            except ValueError:
                msg = ""
            raise EveError(f"EVE-NG {method} {path}: {exc.code} {msg or exc.reason}".strip()) from None
        except (urllib.error.URLError, OSError) as exc:
            raise EveError(f"Could not reach EVE-NG at {self.base}: {getattr(exc, 'reason', exc)}") from None
        try:
            out = json.loads(raw or b"{}")
        except ValueError:
            raise EveError(f"EVE-NG {path} did not answer with JSON. Is the address right?") from None
        if isinstance(out, dict) and out.get("status") not in (None, "success"):
            raise EveError(f"EVE-NG: {out.get('message') or out.get('status')}")
        return out.get("data") if isinstance(out, dict) else out

    def login(self) -> None:
        try:
            self.call("POST", "/api/auth/login", {"username": self.username, "password": self.password, "html5": "-1"})
        except EveError as exc:
            if " 400 " in str(exc) or " 401 " in str(exc) or " 403 " in str(exc):
                raise EveError("EVE-NG sign-in failed (wrong username or password).") from None
            raise

    def logout(self) -> None:
        try:
            self.call("GET", "/api/auth/logout")
        except EveError:
            pass

    def status(self) -> dict:
        return self.call("GET", "/api/status") or {}

    def juniper_images(self) -> list[dict]:
        """Juniper node types installed on the EVE-NG server, with their images."""
        return self.images(JUNIPER)

    def images(self, pattern) -> list[dict]:
        """Node types whose template name or label matches ``pattern``, with their installed images."""
        rx = re.compile(pattern, re.I) if isinstance(pattern, str) else pattern
        out = []
        for tpl, label in sorted((self.call("GET", "/api/list/templates/") or {}).items()):
            if not rx.search(f"{tpl} {label}") or "missing" in str(label).lower():
                continue
            info = self.call("GET", f"/api/list/templates/{urllib.parse.quote(tpl)}") or {}
            images = sorted(((info.get("options") or {}).get("image") or {}).get("list") or {})
            if images:
                out.append({"template": tpl, "label": str(label), "images": images,
                            "supported": tpl in TEMPLATES})
        return out

    # labs ------------------------------------------------------------
    @staticmethod
    def _q(path: str) -> str:
        return "/".join(urllib.parse.quote(p) for p in path.split("/"))

    def ensure_folder(self, folder: str) -> None:
        path = ""
        for part in [p for p in folder.split("/") if p]:
            parent, path = path or "/", f"{path}/{part}"
            if self.call("GET", "/api/folders" + self._q(path), ok404=True) is None:
                self.call("POST", "/api/folders", {"path": parent, "name": part})

    def lab_exists(self, lab: str) -> bool:
        return self.call("GET", "/api/labs" + self._q(lab), ok404=True) is not None

    def create_lab(self, folder: str, name: str, description: str) -> str:
        self.call("POST", "/api/labs", {"path": folder or "/", "name": name, "version": "1",
                                        "author": "Multi-Vendor Switch Config Builder", "description": description[:500]})
        return f"{folder.rstrip('/')}/{name}.unl"

    def delete_lab(self, lab: str) -> None:
        self.call("DELETE", "/api/labs" + self._q(lab))

    def add_node(self, lab: str, node: dict) -> int:
        data = self.call("POST", f"/api/labs{self._q(lab)}/nodes", node) or {}
        return int(data.get("id"))

    def add_network(self, lab: str, name: str, left: int, top: int) -> int:
        data = self.call("POST", f"/api/labs{self._q(lab)}/networks",
                         {"type": "bridge", "name": name, "left": left, "top": top, "visibility": "0"}) or {}
        return int(data.get("id"))

    def connect(self, lab: str, node_id: int, links: dict[int, int]) -> None:
        self.call("PUT", f"/api/labs{self._q(lab)}/nodes/{node_id}/interfaces",
                  {str(k): str(v) for k, v in links.items()})

    def start(self, lab: str) -> None:
        self.call("GET", f"/api/labs{self._q(lab)}/nodes/start")

    def stop(self, lab: str) -> None:
        self.call("GET", f"/api/labs{self._q(lab)}/nodes/stop")

    def nodes(self, lab: str) -> dict:
        return self.call("GET", f"/api/labs{self._q(lab)}/nodes") or {}

    def console(self, lab: str, node_id: int) -> tuple[str, int]:
        """(host, port) of a node's telnet console. Always the EVE-NG host itself."""
        node = (self.nodes(lab) or {}).get(str(node_id)) or {}
        m = re.match(r"^telnet://[^:/]+:(\d+)$", str(node.get("url") or ""))
        if not m:
            raise EveError(f"EVE-NG gave no telnet console for node {node_id} (is it started, and set to telnet?).")
        return self.host, int(m.group(1))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):  # never follow EVE-NG somewhere else
        return None


# -------------------------------------------------------------- lab plan
def plan(items: list[dict], positions: dict | None = None, template: str = "vjunosswitch") -> dict:
    """Map switches -> lab nodes, links -> lab networks, real ports -> lab ports.

    Returns {nodes: [{name, hostname, text, ports: {real: lab}, left, top}],
             links: [{a, a_port, b, b_port, name}], notes: [...]}.
    """
    spec = TEMPLATES[template]
    data = topology.analyze(items)
    sws = data["switches"]
    notes: list[str] = []
    used: dict[int, list[str]] = {s["id"]: [] for s in sws}
    pairs = []
    for link in data["links"]:
        if link.get("b_if") is None or link.get("a_if") is None:
            continue
        members = link.get("members") or []
        ends = members if members else [[link["a_if"], link["b_if"]]]
        for ai, bi in ends:
            if not (ai and bi and PHYS.match(ai) and PHYS.match(bi)):
                notes.append(f"{sws[link['a']]['hostname']} {link['a_if']} to {sws[link['b']]['hostname']} "
                             f"{link['b_if']}: the member ports are not known, so this link is left out.")
                continue
            pairs.append((link["a"], ai, link["b"], bi))
            used[link["a"]].append(ai)
            used[link["b"]].append(bi)

    def port_key(name: str):
        return tuple(int(x) for x in re.findall(r"\d+", name))

    maps: dict[int, dict[str, str]] = {}
    for sid, ports in used.items():
        ports = sorted(set(ports), key=port_key)
        if len(ports) > spec["ports"]:
            notes.append(f"{sws[sid]['hostname']} has {len(ports)} links to other switches; a {spec['label']} "
                         f"node has {spec['ports']} ports, so {', '.join(ports[spec['ports']:])} are left out.")
            ports = ports[:spec["ports"]]
        maps[sid] = {p: f"{spec['prefix']}{i}" for i, p in enumerate(ports)}
    links = []
    for a, ai, b, bi in pairs:
        if ai in maps[a] and bi in maps[b]:
            links.append({"a": a, "a_port": ai, "b": b, "b_port": bi,
                          "name": f"{sws[a]['hostname']}:{maps[a][ai]}-{sws[b]['hostname']}:{maps[b][bi]}"[:60]})
    positions = positions or {}
    nodes = []
    for i, s in enumerate(sws):
        pos = positions.get(s["hostname"]) or {}
        name = re.sub(r"[^A-Za-z0-9_-]", "-", s["hostname"] or f"switch{i + 1}")[:30]
        nodes.append({"name": name, "hostname": s["hostname"], "text": items[i].get("text", ""),
                      "ports": maps.get(s["id"], {}),
                      "left": int(pos.get("x", 80 + 220 * (i % 5))) + 60,
                      "top": int(pos.get("y", 60 + 200 * (i // 5))) + 60})
    if not links and len(nodes) > 1:
        notes.append("No links between these switches were found, so the lab nodes are not connected. "
                     "Add 'show lldp neighbors' output or port descriptions to the map.")
    return {"nodes": nodes, "links": links, "notes": notes}


PORT = re.compile(r"(?<![\w/-])((?:ge|xe|mge|et)-\d{1,2}/\d{1,2}/\d{1,3})(?=$|[\s.:\"\]])")


def rename_ports(text: str, mapping: dict[str, str]) -> str:
    """Rename ports outside quoted text (descriptions keep what they say)."""
    def line(ln: str) -> str:
        parts = re.split(r'("[^"]*")', ln)
        return "".join(p if i % 2 else PORT.sub(lambda m: mapping.get(m.group(1), m.group(1)), p)
                       for i, p in enumerate(parts))
    return "\n".join(line(ln) for ln in text.split("\n"))


def lab_config(text: str, ports: dict[str, str], lab_hash: str) -> tuple[list[str], list[str]]:
    """Rewrite a switch config for a lab node. Returns (set lines, notes).

    Real ports become lab ports; lines for ports, ranges and hardware the lab node
    doesn't have are left out; a lab login (exb-lab) is added so the builder can
    read the config back.
    """
    lines = to_set_lines(text)
    out, notes = [], []
    dropped_hw = dropped_ports = 0
    # Interface ranges: keep only mapped members.
    ranges: dict[str, list[str]] = {}
    for ln in lines:
        m = re.match(r"^interfaces interface-range (\S+) member (\S+)$", ln)
        if m:
            ranges.setdefault(m.group(1), []).append(m.group(2))
    empty_ranges = {r for r, mem in ranges.items() if not any(p in ports for p in mem)}
    pattern = PORT
    for ln in lines:
        words = ln.split()
        if (words and words[0] in DROP_TOP and not ln.startswith("chassis aggregated-devices")) or MGMT.match(ln):
            dropped_hw += 1
            continue
        if ln.startswith("system root-authentication"):
            out.append(ln)
            continue
        if any(re.search(rf"(?<![\w-]){re.escape(r)}(?![\w-])", ln) for r in empty_ranges):
            dropped_ports += 1
            continue
        if re.match(r"^interfaces interface-range \S+ member-range ", ln):
            dropped_ports += 1     # member-range can't be mapped one to one
            continue
        # Port names inside quotes (descriptions) are text, not ports: leave them.
        parts = re.split(r'("[^"]*")', ln)
        names = [n for i, part in enumerate(parts) if i % 2 == 0 for n in pattern.findall(part)]
        if any(n not in ports for n in names):
            dropped_ports += 1
            continue
        out.append(rename_ports(ln, ports))
    if not any(ln.startswith("system root-authentication") for ln in out):
        out.append(f'system root-authentication encrypted-password "{lab_hash}"')
    out = [ln for ln in out if not ln.startswith(f"system login user {LAB_USER} ")]
    out.append(f'system login user {LAB_USER} class super-user authentication encrypted-password "{lab_hash}"')
    if dropped_hw:
        notes.append(f"{dropped_hw} version, chassis, Virtual Chassis, PoE or management-port lines left out.")
    if dropped_ports:
        notes.append(f"{dropped_ports} lines for ports not linked to another switch on the map left out.")
    return ["set " + ln for ln in out], notes


# ------------------------------------------------------------ the console
class Console:
    """A minimal telnet client for a Junos serial console (no telnet options accepted)."""

    IAC, DONT, DO, WONT, WILL, SB, SE = 255, 254, 253, 252, 251, 250, 240

    def __init__(self, host: str, port: int, timeout: float = 20):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(1.0)
        self.buf = ""
        self.transcript: list[str] = []

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass

    def _recv(self) -> str:
        try:
            data = self.sock.recv(65536)
        except socket.timeout:
            return ""
        if not data:
            raise EveError("The console connection closed.")
        out, i = bytearray(), 0
        while i < len(data):
            b = data[i]
            if b == self.IAC and i + 1 < len(data):
                cmd = data[i + 1]
                if cmd in (self.DO, self.DONT, self.WILL, self.WONT) and i + 2 < len(data):
                    reply = self.WONT if cmd in (self.DO, self.DONT) else self.DONT
                    self.sock.sendall(bytes([self.IAC, reply, data[i + 2]]))
                    i += 3
                    continue
                if cmd == self.SB:
                    end = data.find(bytes([self.IAC, self.SE]), i)
                    i = len(data) if end < 0 else end + 2
                    continue
                if cmd == self.IAC:
                    out.append(self.IAC)
                i += 2
                continue
            out.append(b)
            i += 1
        text = out.decode("utf-8", "replace").replace("\r", "")
        self.transcript.append(text)
        return text

    def drain(self, wait: float = 1.0) -> None:
        end = time.monotonic() + wait
        while time.monotonic() < end:
            self._recv()
        self.buf = ""

    def send(self, line: str) -> None:
        self.sock.sendall(line.encode() + b"\r")

    def expect(self, patterns: list[str], timeout: float, poke: float = 0) -> tuple[int, str]:
        """Wait for one of the regexes. ``poke`` sends Enter every so many seconds."""
        regs = [re.compile(p, re.M) for p in patterns]
        end, last = time.monotonic() + timeout, time.monotonic()
        while time.monotonic() < end:
            for i, r in enumerate(regs):
                m = r.search(self.buf)
                if m:
                    before = self.buf[:m.end()]
                    self.buf = self.buf[m.end():]
                    return i, before
            self.buf = (self.buf + self._recv())[-200_000:]
            if poke and time.monotonic() - last > poke:
                self.send("")
                last = time.monotonic()
        raise EveError(f"Timed out waiting for {patterns[0]!r} on the console.")

    def login(self, users: list[tuple[str, str]], boot_timeout: float = 1200) -> None:
        """Get to the Junos CLI '>' prompt. ``users`` are tried in order at 'login:'."""
        tries = list(users)
        first = True
        while True:
            i, _ = self.expect([r"login: ?$", r"Password: ?$", r"^\S*% ?$|^\S*:~ ?# ?$", r"^\S+> ?$", r"^\S+# ?$",
                                r"Login incorrect"], boot_timeout, poke=3 if first else 30)
            first = False
            if i == 0:
                if not tries:
                    raise EveError("Could not sign in on the console (no account worked).")
                self.drain()   # extra Enters print extra login prompts: drop them
                user, self._pw = tries.pop(0)
                self.send(user)
            elif i == 1:
                self.send(self._pw)
            elif i == 2:
                self.send("cli")
            elif i == 3:
                self.send("set cli screen-length 0")
                self.expect([r"^\S+> ?$"], 30)
                return
            elif i == 4:
                self.send("exit configuration-mode")
            elif i == 5:
                continue

    def push(self, lines: list[str], tops: list[str]) -> str:
        """Replace the parts of the config the switch config sets, then commit."""
        self.send("configure")
        self.expect([r"^\S+# ?$"], 60)
        for cmd in ["delete chassis auto-image-upgrade", *(f"delete {t}" for t in tops)]:
            self.send(cmd)
            self.expect([r"^\S+# ?$"], 60)
        self.send("load set terminal")
        self.expect([r"\^D"], 30)
        for i in range(0, len(lines), 20):
            self.sock.sendall(("\r".join(lines[i:i + 20]) + "\r").encode())
            time.sleep(0.2)
        self.sock.sendall(b"\x04")
        _, out = self.expect([r"load complete.*$"], 300)
        if "error" in out:
            self.send("rollback 0")
            raise EveError("The lab node refused some lines: " + _tail(out))
        self.expect([r"^\S+# ?$"], 60)
        self.send("commit and-quit")
        i, out = self.expect([r"commit complete", r"error:|commit failed|missing mandatory"], 600)
        if i != 0:
            more = ""
            try:
                more = self.expect([r"^\S+# ?$"], 10)[1]
            except EveError:
                pass
            self.send("rollback 0")
            self.send("exit configuration-mode")
            raise EveError("Commit failed: " + _tail(out + more))
        return "committed"

    def pull(self) -> str:
        self.send("show configuration | display set | no-more")
        _, out = self.expect([r"^\S+> ?$"], 300)
        lines = out.split("\n")[1:-1]
        return "\n".join(ln for ln in lines if ln.startswith("set ")) + "\n"


def _tail(text: str, n: int = 6) -> str:
    rows = [r for r in text.strip().split("\n") if r.strip()]
    return " | ".join(rows[-n:])[:600]


def top_levels(lines: list[str]) -> list[str]:
    """The top-level sections the config sets ('set vlans ...' -> 'vlans'), minus system."""
    tops = []
    for ln in lines:
        w = ln.split()
        if len(w) > 1 and w[1] not in tops and w[1] != "system":
            tops.append(w[1])
    return tops
