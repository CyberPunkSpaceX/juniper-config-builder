"""Push a generated config to a switch, with a backup first and an automatic rollback.

The flow, for every vendor that can do it:

1. **Preview.** Sign in, read the running config (it is kept as a backup),
   load the new config into a private candidate, ask the switch itself what
   would change, check it, then throw the candidate away. Nothing changes.
2. **Push.** Sign in again, check the running config is still the one from
   the preview, load the config and commit it with the switch's own
   safe-revert timer (Junos ``commit confirmed N``). If the switch does not
   hear a confirmation before the timer runs out, it puts the old config back
   by itself, even when this server has lost access to it.
3. **Check.** A new SSH session shows the switch is still reachable after the
   change and that the timer is running.
4. **Confirm** (keep the change) or **roll back now**. Doing nothing is the
   same as rolling back: the switch reverts when the timer runs out.

Only fixed commands and the config the builder generated from an approved
Production project are sent. Nothing typed on the page goes to the switch.

``SUPPORT`` says, per vendor, which native safe-revert method is used (or
will be) and whether pushing is available yet.
"""

from __future__ import annotations

import hashlib
import logging
import re
import socket
import time
from dataclasses import dataclass
from pathlib import Path

from . import sshfetch

log = logging.getLogger("exbuilder.push")

MIN_MINUTES, MAX_MINUTES, DEFAULT_MINUTES = 1, 60, 10
MAX_CONFIG = 2_000_000


class PushError(Exception):
    pass


@dataclass(frozen=True)
class Support:
    ready: bool        # pushing works today
    method: str        # the switch's own safe-revert feature
    auto_revert: bool  # the switch reverts by itself when access is lost
    note: str


# Every vendor of the builder, and how a push is made safe on it. Only "ready" ones can be pushed today;
# the others are shown on the page so people know what is coming and what to expect.
SUPPORT: dict[str, Support] = {
    "juniper": Support(True, "commit confirmed (default 10 minutes)", True,
                       "Loaded into a private candidate; the switch's own 'show | compare' is the preview."),
    "arista": Support(False, "configure session + commit timer", True,
                      "The session is committed with a timer and confirmed with 'configure session … commit'."),
    "cisco": Support(False, "configure terminal revert timer + configure confirm", True,
                     "Needs the config archive (the push sets 'archive path flash:'). IOS-XE only; classic IOS "
                     "2960-X has no revert timer."),
    "nexus": Support(False, "configure replace … commit-timeout", True,
                     "A checkpoint is taken first; NX-OS 9.3(1) or later."),
    "aruba": Support(False, "checkpoint auto N + checkpoint auto confirm", True, "AOS-CX 10.x."),
    "mikrotik": Support(False, "Safe Mode", True,
                        "RouterOS undoes Safe Mode changes when the session drops; the server holds the session "
                        "until you confirm or the timer runs out."),
    "fortiswitch": Support(False, "to be checked", False,
                           "FortiSwitchOS revert-timer support differs by release; until checked, pushes would "
                           "be backup + manual restore only."),
    "dell": Support(False, "none", False, "OS10 has no commit timer: backup + manual restore only."),
    "extreme": Support(False, "none", False, "EXOS has no commit timer: backup + manual restore only."),
    "ruckus": Support(False, "none", False, "FastIron has no commit timer: backup + manual restore only."),
    "procurve": Support(False, "none", False, "AOS-S has no commit timer: backup + manual restore only."),
    "unifi": Support(False, "not pushable", False, "UniFi switches are set up in the UniFi Network app."),
}


def support(vendor: str) -> Support:
    return SUPPORT.get(vendor or "juniper", SUPPORT["juniper"])


def sha(text: str) -> str:
    return hashlib.sha256((text or "").encode()).hexdigest()


def minutes(value) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        raise PushError(f"The rollback timer must be {MIN_MINUTES} to {MAX_MINUTES} minutes.") from None
    if not MIN_MINUTES <= n <= MAX_MINUTES:
        raise PushError(f"The rollback timer must be {MIN_MINUTES} to {MAX_MINUTES} minutes.")
    return n


# ------------------------------------------------------------ SSH session
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\r")
PROMPT = re.compile(r"(?:^|\n)[^\n]*[>#%] ?$")


class Shell:
    """An interactive SSH shell (the CLI) with the same safety checks as SSH fetch."""

    def __init__(self, host: str, username: str, password: str, folder: Path, port: int = 22, nets=None, pkey=None):
        import paramiko
        self.host = host
        ip = sshfetch.resolve(host, nets or [], port)
        self.sock = socket.create_connection((ip, port), timeout=sshfetch.timeout())
        self.transport = None
        try:
            self.transport = paramiko.Transport(self.sock)
            self.transport.banner_timeout = sshfetch.timeout()
            self.transport.start_client(timeout=sshfetch.timeout())
            self._check_host_key(ip, port, folder)
            if pkey is not None:
                self.transport.auth_publickey(username, pkey)
            else:
                try:
                    self.transport.auth_password(username, password)
                except paramiko.BadAuthenticationType:
                    self.transport.auth_interactive(username, lambda t, i, prompts: [password] * len(prompts))
            self.chan = self.transport.open_session(timeout=sshfetch.timeout())
            self.chan.get_pty(width=511, height=1000)
            self.chan.invoke_shell()
            self.chan.settimeout(0.2)
            self.read_until_prompt()
        except Exception:
            self.close()
            raise

    def _check_host_key(self, ip: str, port: int, folder: Path) -> None:
        """Pushing needs a switch whose key is already known (from an SSH fetch); a changed key stops it."""
        key = self.transport.get_remote_server_key()
        entry = f"[{ip}]:{port}" if port != 22 else ip
        with sshfetch._kh_lock:
            known = sshfetch._load_known(folder)
        if entry not in known:
            raise PushError(f"{self.host}: this switch's SSH key is not known yet. Fetch its config once over SSH "
                            "(Network map tab) so its key is remembered, then push.")
        if known[entry] != (key.get_name(), key.get_base64()):
            raise PushError(f"{self.host}: the switch's SSH host key has CHANGED (now {sshfetch._fingerprint(key)}). "
                            "Nothing was sent. If you expected it, clear the old key under 'Known switches'.")

    def read_until_prompt(self, wait: float | None = None, until: str | None = None) -> str:
        """Read until the CLI shows a prompt again and stays quiet a moment (and ``until`` was seen, if given)."""
        deadline = time.monotonic() + (wait or sshfetch.timeout() * 3)
        buf = ""

        def done() -> bool:
            clean = ANSI.sub("", buf)
            return bool(PROMPT.search(clean)) and (until is None or re.search(until, clean, re.I) is not None)
        while time.monotonic() < deadline:
            try:
                data = self.chan.recv(65536)
            except socket.timeout:
                if done():
                    return ANSI.sub("", buf)
                continue
            if not data:
                break
            buf += data.decode("utf-8", "replace")
            if len(buf) > sshfetch.MAX_OUTPUT:
                raise PushError(f"{self.host}: output too large.")
        if done():
            return ANSI.sub("", buf)
        raise PushError(f"{self.host}: the switch stopped answering.")

    def run(self, command: str, wait: float | None = None, until: str | None = None) -> str:
        """Send one command; return its output without the echoed command and the prompt."""
        self.chan.sendall((command + "\n").encode())
        out = self.read_until_prompt(wait, until)
        lines = out.split("\n")
        if lines and command.strip() and command.strip()[:40] in lines[0]:
            lines = lines[1:]
        if lines and PROMPT.search(lines[-1]):
            lines = lines[:-1]
        return "\n".join(lines).strip("\n")

    def send_text(self, text: str, end: str, wait: float | None = None, until: str | None = None) -> str:
        for i in range(0, len(text), 4096):
            self.chan.sendall(text[i:i + 4096].encode())
        self.chan.sendall(end.encode())
        return self.read_until_prompt(wait, until)

    def close(self) -> None:
        try:
            if self.transport is not None:
                self.transport.close()
        finally:
            self.sock.close()


# ---------------------------------------------------------------- Junos
LOAD_ERR = re.compile(r"^.*(syntax error|load complete \(\d+ errors?\)).*$", re.I | re.M)
COMMITTED = r"(?m)commit complete|^\s*error|commit failed|^\s*failed"
ERR = re.compile(r"^\s*(error|syntax error|unknown command|missing)\b.*$", re.I | re.M)


class Junos:
    """Junos: private candidate, show | compare, commit check, commit confirmed N."""

    def __init__(self, shell: Shell):
        self.sh = shell
        self.in_config = False
        for cmd in ("set cli screen-length 0", "set cli screen-width 0", "set cli complete-on-space off"):
            self.sh.run(cmd)

    def running(self) -> str:
        text = self.sh.run("show configuration | display set | no-more")
        if "set " not in text:
            raise PushError(f"{self.sh.host}: could not read the running config (is the account allowed to?).")
        return text.strip() + "\n"

    def pending_confirm(self) -> str:
        """The commit-confirmed line from 'show system commit', or ''."""
        out = self.sh.run("show system commit | no-more")
        m = re.search(r"^.*(rollback in|commit confirmed).*$", out, re.M | re.I)
        return m.group(0).strip() if m else ""

    def _enter(self) -> None:
        out = self.sh.run("configure private")
        if ERR.search(out):
            raise PushError(f"{self.sh.host}: could not start a private configuration "
                            f"({_first_error(out) or 'no config prompt'}). Someone may have uncommitted changes "
                            "on the switch.")
        self.in_config = True

    def _leave(self, discard: bool) -> None:
        if not self.in_config:
            return
        if discard:
            self.sh.run("rollback 0")
        self.sh.run("exit configuration-mode")
        self.in_config = False

    def _load(self, set_text: str, hier_text: str, mode: str) -> None:
        cmd, text = ("load override terminal", hier_text) if mode == "replace" else ("load set terminal", set_text)
        # Comments and blank lines are left out: only statements go to the switch.
        text = "\n".join(ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#"))
        self.sh.chan.sendall((cmd + "\n").encode())
        time.sleep(0.5)  # let the switch print "[Type ^D at a new line to end input]"
        out = self.sh.send_text(text.rstrip("\n") + "\n", "\x04", wait=max(120, sshfetch.timeout() * 6),
                                until=r"(?m)load complete|^\s*(syntax )?error")
        if ERR.search(out) or LOAD_ERR.search(out) or "load complete" not in out.lower():
            self._leave(discard=True)
            raise PushError(f"{self.sh.host}: the switch did not accept the config: "
                            f"{_first_error(out) or 'load did not complete'}. Nothing was committed.")

    def preview(self, set_text: str, hier_text: str, mode: str) -> dict:
        """Load into a private candidate, return the switch's diff and commit check, then discard it."""
        self._enter()
        try:
            self._load(set_text, hier_text, mode)
            diff = self.sh.run("show | compare | no-more")
            check = self.sh.run("commit check", wait=max(120, sshfetch.timeout() * 6),
                                until=r"(?m)succeeds|^\s*error|failed")
        finally:
            self._leave(discard=True)
        ok = "succeeds" in check and not ERR.search(check)
        return {"diff": diff.strip(), "check_ok": ok, "check": check.strip()[-2000:]}

    def apply(self, set_text: str, hier_text: str, mode: str, mins: int, comment: str) -> str:
        self._enter()
        self._load(set_text, hier_text, mode)
        out = self.sh.run(f'commit confirmed {mins} comment "{comment}"', wait=max(120, sshfetch.timeout() * 6),
                         until=COMMITTED)
        if "commit complete" not in out.lower():
            self._leave(discard=True)
            raise PushError(f"{self.sh.host}: commit failed: {_first_error(out) or out.strip()[-300:]}. "
                            "Nothing was changed.")
        self._leave(discard=False)
        return out.strip()

    def confirm(self, comment: str) -> str:
        if not self.pending_confirm():
            raise PushError(f"{self.sh.host}: there is no commit waiting for confirmation (the timer may have run "
                            "out and the switch rolled back).")
        self._enter()
        out = self.sh.run(f'commit comment "{comment}"', wait=max(120, sshfetch.timeout() * 6),
                         until=COMMITTED)
        self._leave(discard="commit complete" not in out.lower())
        if "commit complete" not in out.lower():
            raise PushError(f"{self.sh.host}: confirm failed: {_first_error(out) or out.strip()[-300:]}.")
        return out.strip()

    def rollback(self, comment: str) -> str:
        if not self.pending_confirm():
            raise PushError(f"{self.sh.host}: there is no commit waiting for confirmation, so there is nothing to "
                            "roll back here (it may already have rolled back by itself).")
        self._enter()
        out = self.sh.run("rollback 1")
        if ERR.search(out):
            self._leave(discard=True)
            raise PushError(f"{self.sh.host}: rollback failed: {_first_error(out)}")
        out = self.sh.run(f'commit comment "{comment}"', wait=max(120, sshfetch.timeout() * 6),
                         until=COMMITTED)
        self._leave(discard="commit complete" not in out.lower())
        if "commit complete" not in out.lower():
            raise PushError(f"{self.sh.host}: rollback commit failed: {_first_error(out) or out.strip()[-300:]}. "
                            "The switch still rolls back by itself when the timer runs out.")
        return out.strip()


def _first_error(out: str) -> str:
    m = ERR.search(out or "") or LOAD_ERR.search(out or "")
    return m.group(0).strip()[:300] if m else ""


DRIVERS = {"juniper": Junos}


def connect(vendor: str, host: str, username: str, password: str, folder: Path, port: int = 22, nets=None,
            pkey=None):
    """(shell, driver) for a vendor that can be pushed to."""
    if not support(vendor).ready or vendor not in DRIVERS:
        raise PushError(f"Pushing to {vendor} switches is not available yet.")
    shell = Shell(host, username, password, folder, port, nets, pkey)
    try:
        return shell, DRIVERS[vendor](shell)
    except Exception:
        shell.close()
        raise


def comment(text: str) -> str:
    """A commit comment: printable, no quotes or backslashes, short."""
    return re.sub(r"[^\w .:#@/()-]+", "", text)[:120]
