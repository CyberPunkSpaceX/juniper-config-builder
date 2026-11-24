"""Fetch the running config (and LLDP neighbours) from switches over SSH.

Off unless ``EXB_SSH_ALLOW`` lists the networks the app may connect to, for
example ``10.40.0.0/16, 192.168.1.0/24``. Every safety rule is on by default:

* Only admins can use it (checked by the web route).
* A host must resolve to addresses inside ``EXB_SSH_ALLOW``; every address it
  resolves to is checked, so a DNS name cannot point the app somewhere else.
* Only fixed, read-only commands run (``COMMANDS``); nothing typed by a user is
  sent to the switch.
* The password is used for that one connection and then dropped. It is never
  written to disk or a log, and the switch's host key is never trusted blindly:
  the first key seen is remembered in ``<data dir>/ssh_known_hosts`` and a
  changed key stops the fetch until an admin clears it.
* ``EXB_SSH_KEY_FILE`` (for example a Docker secret) lets the app sign in with a
  key for a read-only account, so nobody types a password at all.
* Each attempt is logged (who, which switch, the result), and each user gets at
  most ``EXB_SSH_RATE`` fetches a minute (default 10).
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
)
MAX_HOSTS = 30
MAX_OUTPUT = 5_000_000


class FetchError(Exception):
    pass


# ------------------------------------------------------------- settings
def allowed_networks() -> list:
    out = []
    for part in os.environ.get("EXB_SSH_ALLOW", "").replace(";", ",").split(","):
        part = part.strip()
        if part:
            try:
                out.append(ipaddress.ip_network(part, strict=False))
            except ValueError:
                log.warning("EXB_SSH_ALLOW: ignored %r (not a network)", part)
    return out


def enabled() -> bool:
    return bool(allowed_networks())


def key_file() -> Path | None:
    path = os.environ.get("EXB_SSH_KEY_FILE", "").strip()
    return Path(path) if path and Path(path).is_file() else None


def key_user() -> str:
    return os.environ.get("EXB_SSH_KEY_USER", "").strip()


def timeout() -> float:
    try:
        return max(3.0, float(os.environ.get("EXB_SSH_TIMEOUT", "20")))
    except ValueError:
        return 20.0


def settings() -> dict:
    """What the page needs to know (never secrets)."""
    return {"enabled": enabled(), "allow": [str(n) for n in allowed_networks()],
            "key": bool(key_file()), "key_user": key_user()}


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
def resolve(host: str, port: int = 22) -> str:
    """Host -> one allowed IP address, or FetchError. Every resolved address must be allowed."""
    host = host.strip()
    nets = allowed_networks()
    if not nets:
        raise FetchError("SSH fetch is turned off (EXB_SSH_ALLOW is not set).")
    if not host or len(host) > 253 or any(c.isspace() for c in host) or host.startswith("-"):
        raise FetchError(f"'{host}' is not a host name or address.")
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise FetchError(f"{host}: name not found.") from None
    addrs = sorted({ipaddress.ip_address(i[4][0].split("%")[0]) for i in infos}, key=str)
    bad = [a for a in addrs if not any(a in n for n in nets)]
    if not addrs or bad:
        raise FetchError(f"{host} ({', '.join(map(str, bad or addrs))}) is outside the allowed networks "
                         f"({', '.join(map(str, nets))}).")
    return str(addrs[0])


# ------------------------------------------------------------- host keys
_kh_lock = threading.Lock()


def _known_hosts(data_dir: Path) -> Path:
    return data_dir / "ssh_known_hosts"


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
def fetch_one(host: str, username: str, password: str, data_dir: Path, port: int = 22, use_key: bool = False) -> dict:
    """Connect, run COMMANDS, return {host, ok, text | error, fingerprint, new_key}."""
    import paramiko

    out = {"host": host, "ok": False}
    try:
        ip = resolve(host, port)
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
            if use_key:
                kf = key_file()
                if not kf:
                    raise FetchError("No SSH key is configured (EXB_SSH_KEY_FILE).")
                pkey = paramiko.PKey.from_path(str(kf))
                transport.auth_publickey(username or key_user(), pkey)
            else:
                try:
                    transport.auth_password(username, password)
                except paramiko.BadAuthenticationType:
                    # Junos often offers keyboard-interactive for passwords.
                    transport.auth_interactive(username, lambda title, instr, prompts: [password] * len(prompts))
            texts = []
            for cmd in COMMANDS:
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
                texts.append(buf.decode("utf-8", "replace"))
            config = texts[0]
            if "set " not in config and "{" not in config:
                raise FetchError(f"{host}: the switch did not return a config. Is the account allowed to "
                                 "'show configuration'? (root lands in a Unix shell: use a normal Junos user.)")
            out.update(ok=True, text=config.rstrip() + "\n\n" + texts[1].strip() + "\n")
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
          use_key: bool = False) -> list[dict]:
    hosts = [h.strip() for h in hosts if h and h.strip()]
    hosts = list(dict.fromkeys(hosts))[:MAX_HOSTS]
    with ThreadPoolExecutor(max_workers=min(8, len(hosts) or 1)) as pool:
        results = list(pool.map(lambda h: fetch_one(h, username, password, data_dir, port, use_key), hosts))
    for r in results:
        # Audit log: who, where, result. Never the password.
        log.warning("audit: ssh fetch by %r: %s as %r -> %s", who, r["host"], username or key_user(),
                 "ok" if r["ok"] else r.get("error", "failed"))
    return results
