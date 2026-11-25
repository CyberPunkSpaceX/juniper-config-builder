"""Fetch the running config (and LLDP neighbours) from switches over SSH.

Each client (see ``web/clients.py``) has its own settings, kept in the
database and set by that client's admins on the client page:

* the networks its switches are in. A host must resolve to addresses inside
  them, and every address it resolves to is checked, so a DNS name cannot point
  the app somewhere else;
* an optional SSH key the server made for it (encrypted at rest), so nobody
  types a password;
* its own list of known switch host keys.

Server-wide rules, all on by default:

* Client networks must lie inside ``EXB_SSH_ALLOW`` when it is set, otherwise
  inside the private ranges (10/8, 172.16/12, 192.168/16, 100.64/10, fc00::/7).
  ``EXB_SSH_DISABLE=true`` turns SSH fetch off for everyone.
* Only client admins can use it (checked by the web route).
* Only fixed, read-only commands run (``COMMANDS``); nothing typed by a user is
  sent to the switch.
* A typed password is used for that one connection and then dropped. It is
  never written to disk or a log. The switch's host key is never trusted
  blindly: the first key seen is remembered and a changed key stops the fetch
  until an admin clears it.
* ``EXB_SSH_KEY_FILE`` (for example a Docker secret) is a server-wide key that
  clients without their own key can use.
* Each attempt is logged (who, which client and switch, the result), and each
  user gets at most ``EXB_SSH_RATE`` fetches a minute (default 10).
"""

from __future__ import annotations

import ipaddress
import logging
import os
import socket
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

log = logging.getLogger("exbuilder.ssh")

COMMANDS = (
    "show configuration | display set | no-more",
    "show lldp neighbors | no-more",
    "show version | no-more",            # the model of each member
    "show virtual-chassis | no-more",    # members, serial numbers and roles
)
MAX_HOSTS = 30
MAX_OUTPUT = 5_000_000

# Read-only commands per vendor for a config backup. The first command's output
# is the config; the others are extra information kept below it.
# mode "exec" runs each command on its own channel; "shell" opens a prompt and
# types them (for switches that do not run SSH exec commands, or need the pager
# turned off first). Keys are the builder's vendor keys (vendors.VENDORS).
VENDOR_CMDS = {
    "juniper": {"commands": COMMANDS, "mode": "exec"},
    "cisco": {"commands": ("show running-config",), "mode": "exec"},
    "arista": {"commands": ("show running-config",), "mode": "exec"},
    "nexus": {"commands": ("show running-config",), "mode": "exec"},
    "dell": {"commands": ("show running-configuration",), "mode": "exec"},
    "aruba": {"commands": ("show running-config",), "mode": "exec"},
    "extreme": {"commands": ("disable clipaging", "show configuration"), "mode": "shell"},
    "fortiswitch": {"commands": ("show",), "mode": "exec"},
    "mikrotik": {"commands": ("/export terse",), "mode": "exec"},
    "ruckus": {"commands": ("skip-page-display", "show running-config"), "mode": "shell"},
    "procurve": {"commands": ("no page", "show running-config"), "mode": "shell", "wake": True},
}
# A config from each vendor has at least one of these lines.
_LOOKS = {
    "juniper": r"^\s*set\s|\{",
    "mikrotik": r"^/(?:interface|ip|system)\b",
    "fortiswitch": r"^config (?:system|switch)",
    "extreme": r"^(?:configure|create|enable|disable) ",
}
_LOOKS_DEFAULT = r"^(?:interface|hostname|vlan|ip |snmp-server|username)\b"


class FetchError(Exception):
    pass


# ------------------------------------------------------------- settings
PRIVATE = tuple(ipaddress.ip_network(n) for n in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"))


def _parse(text: str) -> tuple[list, list[str]]:
    nets, bad = [], []
    for part in (text or "").replace(";", ",").replace("\n", ",").split(","):
        part = part.strip()
        if part:
            try:
                nets.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                bad.append(part)
    return nets, bad


def disabled() -> bool:
    return os.environ.get("EXB_SSH_DISABLE", "").lower() in ("1", "true", "yes")


def ceiling() -> list:
    """The networks any client may use: EXB_SSH_ALLOW, or the private ranges."""
    nets, bad = _parse(os.environ.get("EXB_SSH_ALLOW", ""))
    for b in bad:
        log.warning("EXB_SSH_ALLOW: ignored %r (not a network)", b)
    return nets or list(PRIVATE)


def check_networks(text: str) -> tuple[list, list[str]]:
    """A client's network list -> (networks, problems)."""
    nets, bad = _parse(text)
    problems = [f"'{b}' is not a network (use for example 10.40.10.0/24)." for b in bad]
    top = ceiling()
    for n in nets:
        if n.prefixlen < (8 if n.version == 4 else 32):
            problems.append(f"{n} is too large.")
        elif not any(n.version == c.version and n.subnet_of(c) for c in top):
            problems.append(f"{n} is outside what this server allows ({', '.join(map(str, top))}).")
    return nets, problems


def key_file() -> Path | None:
    path = os.environ.get("EXB_SSH_KEY_FILE", "").strip()
    return Path(path) if path and Path(path).is_file() else None


def key_user() -> str:
    return os.environ.get("EXB_SSH_KEY_USER", "").strip()


def server_key():
    """The server-wide key from EXB_SSH_KEY_FILE as a paramiko key, or None."""
    kf = key_file()
    if not kf:
        return None
    import paramiko
    return paramiko.PKey.from_path(str(kf))


def generate_key(comment: str = "exbuilder") -> tuple[str, str]:
    """A new ed25519 key pair -> (private key in OpenSSH format, public key line)."""
    from cryptography.hazmat.primitives import serialization as ser
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    k = Ed25519PrivateKey.generate()
    private = k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.OpenSSH, ser.NoEncryption()).decode()
    public = k.public_key().public_bytes(ser.Encoding.OpenSSH, ser.PublicFormat.OpenSSH).decode()
    return private, f"{public} {comment}"


def load_key(private: str):
    import io
    import paramiko
    return paramiko.Ed25519Key.from_private_key(io.StringIO(private))


def timeout() -> float:
    try:
        return max(3.0, float(os.environ.get("EXB_SSH_TIMEOUT", "20")))
    except ValueError:
        return 20.0


# --------------------------------------------------------- rate limiting
_rate_lock = threading.Lock()
_recent: dict[str, deque] = {}


def check_rate(user: str) -> None:
    try:
        limit = int(os.environ.get("EXB_SSH_RATE", "10"))
    except ValueError:
        limit = 10
    now = time.monotonic()
    with _rate_lock:
        q = _recent.setdefault(user, deque())
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= limit:
            raise FetchError(f"Too many fetches; wait a minute (at most {limit} a minute).")
        q.append(now)


# ------------------------------------------------------------ addresses
def resolve(host: str, nets: list, port: int = 22) -> str:
    """Host -> one allowed IP address, or FetchError. Every resolved address must be allowed."""
    host = host.strip()
    top = ceiling()
    if disabled() or not nets:
        raise FetchError("SSH fetch is turned off for this client (no switch networks are set).")
    if not host or len(host) > 253 or any(c.isspace() for c in host) or host.startswith("-"):
        raise FetchError(f"'{host}' is not a host name or address.")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise FetchError(f"{host}: name not found.") from None
    addrs = sorted({ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos}, key=str)
    bad = [a for a in addrs if not (any(a in n for n in nets) and any(a in n for n in top))]
    if not addrs or bad:
        raise FetchError(f"{host} ({', '.join(map(str, bad or addrs))}) is outside the allowed networks "
                         f"({', '.join(map(str, nets))}).")
    return str(addrs[0])


# ------------------------------------------------------------- host keys
_kh_lock = threading.Lock()


def _known_hosts(folder: Path) -> Path:
    """Each client keeps its own list in its own folder."""
    return folder / "ssh_known_hosts"


def _load_known(data_dir: Path) -> dict[str, tuple[str, str]]:
    out = {}
    path = _known_hosts(data_dir)
    if path.exists():
        for line in path.read_text().splitlines():
            parts = line.split()
            if len(parts) == 3:
                out[parts[0]] = (parts[1], parts[2])
    return out


def _save_known(data_dir: Path, known: dict[str, tuple[str, str]]) -> None:
    path = _known_hosts(data_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text("".join(f"{h} {t} {k}\n" for h, (t, k) in sorted(known.items())))
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def known_hosts(data_dir: Path) -> list[dict]:
    import base64
    import hashlib
    rows = []
    for host, (ktype, key) in _load_known(data_dir).items():
        fp = base64.b64encode(hashlib.sha256(base64.b64decode(key)).digest()).decode().rstrip("=")
        rows.append({"host": host, "type": ktype, "fingerprint": "SHA256:" + fp})
    return rows


def forget_host(data_dir: Path, host: str) -> bool:
    with _kh_lock:
        known = _load_known(data_dir)
        if host in known:
            del known[host]
            _save_known(data_dir, known)
            return True
    return False


def _fingerprint(key) -> str:
    import base64
    import hashlib
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


# ----------------------------------------------------------------- fetch
def looks_like_config(text: str, vendor: str = "juniper") -> bool:
    import re
    return bool(re.search(_LOOKS.get(vendor, _LOOKS_DEFAULT), text or "", re.M))


def _run_exec(transport, cmd: str, host: str) -> str:
    chan = transport.open_session(timeout=timeout())
    chan.settimeout(timeout() * 3)
    chan.exec_command(cmd)
    buf = bytearray()
    while True:
        data = chan.recv(65536)
        if not data:
            break
        buf += data
        if len(buf) > MAX_OUTPUT:
            raise FetchError(f"{host}: output too large.")
    chan.close()
    return buf.decode("utf-8", "replace")


def _run_shell(transport, commands, host: str, wake: bool = False, quiet: float = 3.0) -> list[str]:
    """Type the commands at the switch prompt; return each command's output (prompt and echo removed)."""
    import re
    chan = transport.open_session(timeout=timeout())
    chan.get_pty(width=511, height=1000)
    chan.invoke_shell()
    chan.settimeout(0.3)

    def read_until_quiet(limit: float) -> str:
        buf, last, start = bytearray(), time.monotonic(), time.monotonic()
        while time.monotonic() - last < quiet and time.monotonic() - start < limit:
            try:
                data = chan.recv(65536)
            except socket.timeout:
                continue
            if not data:
                break
            buf += data
            last = time.monotonic()
            if len(buf) > MAX_OUTPUT:
                raise FetchError(f"{host}: output too large.")
        return buf.decode("utf-8", "replace")

    try:
        read_until_quiet(timeout())                # banner and first prompt
        if wake:                                   # "Press any key to continue"
            chan.sendall(b"\n")
            read_until_quiet(timeout())
        outs = []
        for cmd in commands:
            chan.sendall(cmd.encode() + b"\n")
            text = read_until_quiet(timeout() * 3).replace("\r", "")
            text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)   # terminal escape codes
            lines = text.split("\n")
            if lines and cmd in lines[0]:
                lines = lines[1:]                  # the echoed command
            if lines and re.match(r"^\S*[#>]\s*$", lines[-1].strip() or "#"):
                lines = lines[:-1]                 # the next prompt
            outs.append("\n".join(lines))
        return outs
    finally:
        chan.close()


def fetch_one(host: str, username: str, password: str, data_dir: Path, port: int = 22, nets: list | None = None,
              pkey=None, vendor: str = "juniper") -> dict:
    """Connect, run the vendor's read-only commands, return {host, ok, text | error, fingerprint, new_key}."""
    import paramiko

    out = {"host": host, "ok": False, "vendor": vendor}
    if vendor not in VENDOR_CMDS:
        out["error"] = f"{host}: config backups over SSH are not available for {vendor or 'this vendor'}."
        return out
    try:
        ip = resolve(host, nets or [], port)
        transport = None
        sock = socket.create_connection((ip, port), timeout=timeout())
        try:
            transport = paramiko.Transport(sock)
            transport.banner_timeout = timeout()
            transport.start_client(timeout=timeout())
            key = transport.get_remote_server_key()
            fp = _fingerprint(key)
            out["fingerprint"] = fp
            entry = f"[{ip}]:{port}" if port != 22 else ip
            with _kh_lock:
                known = _load_known(data_dir)
                if entry in known:
                    if known[entry] != (key.get_name(), key.get_base64()):
                        raise FetchError(f"{host}: the switch's SSH host key has CHANGED (now {fp}). This can mean "
                                         "someone is in the middle, or the switch was replaced or reset. If you "
                                         "expected it, clear the old key under 'Known switches' and try again.")
                else:
                    known[entry] = (key.get_name(), key.get_base64())
                    _save_known(data_dir, known)
                    out["new_key"] = True
            if pkey is not None:
                transport.auth_publickey(username, pkey)
            else:
                try:
                    transport.auth_password(username, password)
                except paramiko.BadAuthenticationType:
                    # Junos often offers keyboard-interactive for passwords.
                    transport.auth_interactive(username, lambda title, instr, prompts: [password] * len(prompts))
            spec = VENDOR_CMDS[vendor]
            if spec["mode"] == "shell":
                texts = _run_shell(transport, spec["commands"], host, wake=bool(spec.get("wake")))
                texts = [t for c, t in zip(spec["commands"], texts) if c.startswith("show")]
            else:
                texts = [_run_exec(transport, cmd, host) for cmd in spec["commands"]]
            config = texts[0]
            if vendor == "juniper" and "set " not in config and "{" not in config:
                raise FetchError(f"{host}: the switch did not return a config. Is the account allowed to "
                                 "'show configuration'? (root lands in a Unix shell: use a normal Junos user.)")
            if not looks_like_config(config, vendor):
                raise FetchError(f"{host}: the switch did not return a config. Is the account allowed to "
                                 f"run '{[c for c in spec['commands'] if c.startswith(('show', '/'))][0]}'?")
            extra = [t.strip() for t in texts[1:] if t.strip() and not t.lstrip().startswith(("error:", "% "))]
            out.update(ok=True, text=config.rstrip() + "\n\n" + "\n\n".join(extra) + "\n")
        finally:
            if transport is not None:
                transport.close()
            sock.close()
    except FetchError as exc:
        out["error"] = str(exc)
    except paramiko.AuthenticationException:
        out["error"] = f"{host}: sign-in failed (wrong username, password or key)."
    except (OSError, paramiko.SSHException, EOFError) as exc:
        out["error"] = f"{host}: could not connect ({exc.__class__.__name__}: {exc})."[:300]
    return out


def fetch(hosts: list[str], username: str, password: str, data_dir: Path, who: str, port: int = 22,
          nets: list | None = None, pkey=None, client: str = "", vendors: dict | None = None,
          ports: dict | None = None, max_hosts: int = MAX_HOSTS) -> list[dict]:
    """Fetch from many switches. ``vendors`` / ``ports`` map a host to its vendor key / SSH port."""
    hosts = [h.strip() for h in hosts if h and h.strip()]
    hosts = list(dict.fromkeys(hosts))[:max_hosts]
    vendors, ports = vendors or {}, ports or {}
    with ThreadPoolExecutor(max_workers=min(8, len(hosts) or 1)) as pool:
        results = list(pool.map(lambda h: fetch_one(h, username, password, data_dir, ports.get(h, port), nets, pkey,
                                                     vendors.get(h, "juniper")), hosts))
    for r in results:
        # Audit log: who, where, result. Never the password.
        log.warning("audit: ssh fetch by %r for client %r: %s as %r (%s) -> %s", who, client, r["host"], username,
                    "key" if pkey is not None else "password", "ok" if r["ok"] else r.get("error", "failed"))
    return results
