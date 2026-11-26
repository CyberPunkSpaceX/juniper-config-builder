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

log = logging.getLogger("switchbuilder.push")

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
    "arista": Support(True, "configure session + commit timer", True,
                      "The switch shows the diff of a config session; the session is committed with a timer and "
                      "confirmed with 'configure session … commit'. Not yet tried on a real switch."),
    "cisco": Support(True, "configure terminal revert timer + configure confirm", True,
                     "Needs the config archive: the push turns it on (archive path flash:) if it is off. The diff is "
                     "worked out by the builder. Not yet tried on a real switch."),
    "nexus": Support(True, "checkpoint + one-time scheduler rollback job", True,
                     "A checkpoint is taken, a scheduler job rolls back to it when the timer ends, and confirming "
                     "removes the job. 'verify' of a config session is the check. Not yet tried on a real switch."),
    "aruba": Support(True, "checkpoint auto N + checkpoint auto confirm", True,
                     "A checkpoint is also taken first, for Roll back now. AOS-CX 10.x. Not yet tried on a real "
                     "switch."),
    "mikrotik": Support(True, "Safe Mode", True,
                        "RouterOS undoes Safe Mode changes when the session drops. The server holds the session "
                        "open until you confirm, roll back or the timer runs out (a server restart also undoes it). "
                        "Not yet tried on a real switch."),
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


def config_sha(text: str) -> str:
    """A fingerprint of the config itself, without comment and timestamp lines that change on every read."""
    keep = [ln.rstrip() for ln in (text or "").splitlines() if ln.strip() and not ln.lstrip().startswith(("!", "#"))
            and not re.match(r"\s*(ntp clock-period|Current configuration|Building configuration)", ln)]
    return sha("\n".join(keep))


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
            self.chan.get_pty(term="vt100", width=511, height=1000)
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

    def read_until_prompt(self, wait: float | None = None, until: str | None = None, fast: bool = False) -> str:
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
            if fast and done():
                return ANSI.sub("", buf)
        if done():
            return ANSI.sub("", buf)
        raise PushError(f"{self.host}: the switch stopped answering.")

    def run(self, command: str, wait: float | None = None, until: str | None = None, fast: bool = False) -> str:
        """Send one command; return its output without the echoed command and the prompt."""
        self.chan.sendall((command + "\n").encode())
        out = self.read_until_prompt(wait, until, fast)
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

    modes = ("merge", "replace")
    held = False

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

    @staticmethod
    def hostname(text: str) -> str:
        found = re.findall(r"host-name\s+\"?([\w.-]+)", text or "")
        return found[-1] if found else ""

    def pending_confirm(self, tag: str = "") -> str:
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

    def preview(self, res, mode: str) -> dict:
        """Load into a private candidate, return the switch's diff and commit check, then discard it."""
        set_text, hier_text = res.set_text, res.hier_text
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

    def apply(self, res, mode: str, mins: int, tag: str, comment: str) -> str:
        self._enter()
        self._load(res.set_text, res.hier_text, mode)
        out = self.sh.run(f'commit confirmed {mins} comment "{comment}"', wait=max(120, sshfetch.timeout() * 6),
                         until=COMMITTED)
        if "commit complete" not in out.lower():
            self._leave(discard=True)
            raise PushError(f"{self.sh.host}: commit failed: {_first_error(out) or out.strip()[-300:]}. "
                            "Nothing was changed.")
        self._leave(discard=False)
        return out.strip()

    def confirm(self, tag: str, comment: str) -> str:
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

    def rollback(self, tag: str, comment: str) -> str:
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


# ------------------------------------------------- industry-style CLIs (EOS, IOS-XE, NX-OS, AOS-CX)
CLI_ERR = re.compile(r"^\s*(% ?(Invalid|Incomplete|Ambiguous|Error|Unrecognized|Cannot|Failed|Bad|Not)[^\n]*|"
                     r"Invalid input[^\n]*|ERROR:[^\n]*|Error:[^\n]*|syntax error[^\n]*)$", re.I | re.M)
EXEC_PROMPT = r"(?m)^[^\s(]+#\s*$"


def statements(text: str, comment: str = "!") -> list[str]:
    """The lines that go to the switch: no comments, no blank lines, indentation kept."""
    return [ln.rstrip() for ln in (text or "").splitlines()
            if ln.strip() and not ln.lstrip().startswith(comment) and ln.strip() not in ("end", "exit")]


def blocks(text: str, comment: str = "!") -> list[tuple[str, str]]:
    """Config lines as (top-level line, line) pairs, so 'description X' under two interfaces differ."""
    out, top = [], ""
    for ln in statements(text, comment):
        if ln[:1].isspace():
            out.append((top, " ".join(ln.split())))
        else:
            top = " ".join(ln.split())
            out.append(("", top))
    return out


def block_diff(running: str, new: str, comment: str = "!") -> str:
    """What the new config adds or changes compared with the running config (computed here, not by the switch)."""
    have = set(blocks(running, comment))
    lines, last = [], None
    for top, ln in blocks(new, comment):
        if (top, ln) in have:
            continue
        if top and top != last:
            lines.append(top if ("", top) in have else "+ " + top)
            last = top
        if not top:
            last = ln
        lines.append(("    + " if top else "+ ") + ln)
    return "\n".join(lines)


class _Cli:
    """Shared parts of the industry-style CLIs: paging off, line-by-line entry with error checks."""

    modes = ("merge",)
    held = False
    page_off = ("terminal length 0", "terminal width 511")
    show_running = "show running-config"
    save_cmd = "write memory"
    diff_note = ("Worked out by the builder from the running config (this switch has no dry run). Lines already "
                 "on the switch are left out; nothing is removed.")

    def __init__(self, shell: Shell):
        self.sh = shell
        for cmd in self.page_off:
            self.sh.run(cmd)

    def running(self) -> str:
        text = self.sh.run(self.show_running, wait=max(60, sshfetch.timeout() * 3))
        if "hostname" not in text and "interface" not in text:
            raise PushError(f"{self.sh.host}: could not read the running config (is the account allowed to?).")
        return text.strip() + "\n"

    @staticmethod
    def hostname(text: str) -> str:
        found = re.findall(r"^hostname\s+\"?([\w.-]+)", text or "", re.M)
        return found[-1] if found else ""

    def enter_lines(self, lines: list[str]) -> list[str]:
        """Type the config one line at a time; return the error lines the switch printed."""
        errors = []
        for ln in lines:
            out = self.sh.run(ln, wait=max(30, sshfetch.timeout()), fast=True)
            for m in CLI_ERR.finditer(out):
                errors.append(f"{ln.strip()}: {m.group(0).strip()}")
        return errors

    def check(self, res) -> dict:
        return {"check_ok": True, "check": "This switch has no dry run: any line it refuses during the push stops "
                                           "the push and the change is rolled back at once."}

    def preview(self, res, mode: str) -> dict:
        running = self.running()
        return {"diff": block_diff(running, res.set_text), "note": self.diff_note, **self.check(res)}

    def save(self) -> None:
        out = self.sh.run(self.save_cmd, wait=120)
        if CLI_ERR.search(out):
            raise PushError(f"{self.sh.host}: the change is kept, but saving it to the startup config failed: "
                            f"{CLI_ERR.search(out).group(0).strip()}. Save it by hand.")


class Eos(_Cli):
    """Arista EOS: configure session, show session-config diffs, commit timer, then commit to confirm."""

    modes = ("merge", "replace")
    diff_note = "From the switch itself (show session-config diffs)."

    @staticmethod
    def session(tag: str) -> str:
        return "switchbuilder-" + re.sub(r"[^\w-]", "", tag)[:40]

    def _load(self, res, mode: str, name: str) -> None:
        out = self.sh.run(f"configure session {name}")
        if CLI_ERR.search(out):
            raise PushError(f"{self.sh.host}: could not start a config session: {CLI_ERR.search(out).group(0)}")
        if mode == "replace":
            self.sh.run("rollback clean-config")
        errors = self.enter_lines(statements(res.set_text))
        self.sh.run("end", fast=True)  # leaves the session uncommitted; it stays pending
        if errors:
            self.sh.run(f"configure session {name} abort")
            raise PushError(f"{self.sh.host}: the switch refused {len(errors)} line(s), first: {errors[0]}. "
                            "Nothing was committed.")

    def preview(self, res, mode: str) -> dict:
        name = self.session("preview-" + str(int(time.time())))
        self._load(res, mode, name)
        try:
            self.sh.run(f"configure session {name}")
            diff = self.sh.run("show session-config diffs", wait=60)
            self.sh.run("end", fast=True)
        finally:
            self.sh.run(f"configure session {name} abort")
        return {"diff": diff.strip(), "check_ok": True, "note": self.diff_note,
                "check": "Every line was accepted by the switch in a config session."}

    def apply(self, res, mode: str, mins: int, tag: str, comment: str) -> str:
        name = self.session(tag)
        self._load(res, mode, name)
        self.sh.run(f"configure session {name}")
        out = self.sh.run(f"commit timer {mins // 60:02d}:{mins % 60:02d}:00", wait=120)
        if CLI_ERR.search(out):
            self.sh.run("end", fast=True)
            self.sh.run(f"configure session {name} abort")
            raise PushError(f"{self.sh.host}: commit failed: {CLI_ERR.search(out).group(0).strip()}. Nothing was "
                            "changed.")
        return out.strip() or "committed with a timer"

    def pending_confirm(self, tag: str = "") -> str:
        out = self.sh.run("show configuration sessions detail", wait=60)
        name = self.session(tag) if tag else "switchbuilder-"
        for ln in out.splitlines():
            if name in ln and "pending" in ln.lower():
                return " ".join(ln.split())
        return ""

    def confirm(self, tag: str, comment: str) -> str:
        if not self.pending_confirm(tag):
            raise PushError(f"{self.sh.host}: there is no session waiting for confirmation (the timer may have run "
                            "out and the switch rolled back).")
        out = self.sh.run(f"configure session {self.session(tag)} commit", wait=120)
        if CLI_ERR.search(out):
            raise PushError(f"{self.sh.host}: confirm failed: {CLI_ERR.search(out).group(0).strip()}.")
        self.save()
        return out.strip()

    def rollback(self, tag: str, comment: str) -> str:
        if not self.pending_confirm(tag):
            raise PushError(f"{self.sh.host}: there is no session waiting for confirmation, so nothing to roll back "
                            "(it may already have rolled back by itself).")
        out = self.sh.run(f"configure session {self.session(tag)} abort", wait=120)
        if CLI_ERR.search(out):
            raise PushError(f"{self.sh.host}: rollback failed: {CLI_ERR.search(out).group(0).strip()}. The switch "
                            "still rolls back by itself when the timer runs out.")
        return out.strip()


class IosXe(_Cli):
    """Cisco IOS-XE: configure terminal revert timer N, then configure confirm (needs the config archive)."""

    archive_path = "flash:switchbuilder-archive"

    def _has_archive(self) -> bool:
        return bool(re.search(r"next archive file|archive #", self.sh.run("show archive", wait=60), re.I))

    def _archive(self) -> None:
        if self._has_archive():
            return
        errs = self.enter_lines(["configure terminal", "archive", f" path {self.archive_path}", " maximum 14", "end"])
        if errs:
            raise PushError(f"{self.sh.host}: could not turn on the config archive the revert timer needs: "
                            f"{errs[0]}. Nothing was changed.")

    def preview(self, res, mode: str) -> dict:
        out = super().preview(res, mode)
        if not self._has_archive():
            out["diff"] = (f"+ archive\n    + path {self.archive_path}\n    + maximum 14\n"
                           "(the revert timer needs the config archive; it is turned on first)\n" + out["diff"])
        return out

    def apply(self, res, mode: str, mins: int, tag: str, comment: str) -> str:
        self._archive()
        out = self.sh.run(f"configure terminal revert timer {mins}", wait=60)
        if CLI_ERR.search(out):
            self.sh.run("end", fast=True)
            raise PushError(f"{self.sh.host}: could not start the revert timer: {CLI_ERR.search(out).group(0).strip()}. "
                            "Nothing was changed.")
        errors = self.enter_lines(statements(res.set_text))
        self.sh.run("end", fast=True)
        if errors:
            self.sh.run("configure revert now", wait=120)
            raise PushError(f"{self.sh.host}: the switch refused {len(errors)} line(s), first: {errors[0]}. The "
                            "change was rolled back at once.")
        return "Config entered with a revert timer."

    def pending_confirm(self, tag: str = "") -> str:
        out = self.sh.run("show archive config rollback timer", wait=60)
        m = re.search(r"^.*(timer value|time remaining|remaining).*$", out, re.I | re.M)
        return " ".join(m.group(0).split()) if m and not re.search(r"no .*pending|not armed", out, re.I) else ""

    def confirm(self, tag: str, comment: str) -> str:
        if not self.pending_confirm():
            raise PushError(f"{self.sh.host}: there is no revert timer running (it may have run out and the switch "
                            "rolled back).")
        out = self.sh.run("configure confirm", wait=60)
        if CLI_ERR.search(out):
            raise PushError(f"{self.sh.host}: confirm failed: {CLI_ERR.search(out).group(0).strip()}.")
        self.save()
        return out.strip()

    def rollback(self, tag: str, comment: str) -> str:
        if not self.pending_confirm():
            raise PushError(f"{self.sh.host}: there is no revert timer running, so nothing to roll back.")
        out = self.sh.run("configure revert now", wait=180)
        if CLI_ERR.search(out):
            raise PushError(f"{self.sh.host}: rollback failed: {CLI_ERR.search(out).group(0).strip()}. The switch "
                            "still rolls back by itself when the timer runs out.")
        return out.strip()


class Nxos(_Cli):
    """NX-OS: checkpoint, a one-time scheduler job that rolls back to it, config session commit; confirm removes the job."""

    save_cmd = "copy running-config startup-config"

    @staticmethod
    def names(tag: str) -> tuple[str, str]:
        t = re.sub(r"[^\w-]", "", tag)[:30]
        return f"switchbuilder-{t}", f"sb-rollback-{t}"

    def check(self, res) -> dict:
        name = "switchbuilder-preview"
        self.sh.run(f"configure session {name}")
        errors = self.enter_lines(statements(res.set_text))
        out = self.sh.run("verify", wait=120)
        self.sh.run("abort", fast=True)
        self.sh.run("end", fast=True)
        ok = not errors and "success" in out.lower()
        return {"check_ok": ok, "check": (f"Refused: {errors[0]}" if errors else out.strip()[-1000:])}

    def apply(self, res, mode: str, mins: int, tag: str, comment: str) -> str:
        cp, job = self.names(tag)
        out = self.sh.run(f"checkpoint {cp} description switchbuilder push", wait=120)
        if CLI_ERR.search(out):
            raise PushError(f"{self.sh.host}: could not take a checkpoint: {CLI_ERR.search(out).group(0).strip()}. "
                            "Nothing was changed.")
        errs = self.enter_lines(["configure terminal", "feature scheduler", f"scheduler job name {job}",
                                 f"rollback running-config checkpoint {cp}", "exit", f"scheduler schedule name {job}",
                                 f"job name {job}", f"time start +0:0:{mins}", "end"])
        if errs:
            self._unschedule(job)
            raise PushError(f"{self.sh.host}: could not set up the rollback timer (scheduler): {errs[0]}. Nothing "
                            "else was changed.")
        self.sh.run(f"configure session {cp}")
        errors = self.enter_lines(statements(res.set_text))
        out = self.sh.run("commit", wait=300)
        self.sh.run("end", fast=True)
        if errors or "success" not in out.lower():
            self.sh.run(f"rollback running-config checkpoint {cp}", wait=300)
            self._unschedule(job)
            first = errors[0] if errors else out.strip()[-300:]
            raise PushError(f"{self.sh.host}: the switch refused the config ({first}). It was rolled back to the "
                            "checkpoint at once.")
        return out.strip()

    def _unschedule(self, job: str) -> None:
        self.enter_lines(["configure terminal", f"no scheduler schedule name {job}", f"no scheduler job name {job}",
                          "end"])

    def pending_confirm(self, tag: str = "") -> str:
        cp, job = self.names(tag)
        out = self.sh.run(f"show scheduler schedule name {job}", wait=60)
        return f"rollback job {job} is scheduled" if job in out and not CLI_ERR.search(out) else ""

    def confirm(self, tag: str, comment: str) -> str:
        cp, job = self.names(tag)
        if not self.pending_confirm(tag):
            raise PushError(f"{self.sh.host}: the rollback job is not scheduled any more (the timer may have run "
                            "out and the switch rolled back).")
        self._unschedule(job)
        if self.pending_confirm(tag):
            raise PushError(f"{self.sh.host}: could not remove the rollback job; it still runs when the timer ends.")
        self.save()
        return "rollback job removed"

    def rollback(self, tag: str, comment: str) -> str:
        cp, job = self.names(tag)
        out = self.sh.run(f"rollback running-config checkpoint {cp}", wait=300)
        if CLI_ERR.search(out):
            raise PushError(f"{self.sh.host}: rollback failed: {CLI_ERR.search(out).group(0).strip()}. The "
                            "scheduled rollback still runs when the timer ends.")
        self._unschedule(job)
        return out.strip()


class AosCx(_Cli):
    """Aruba AOS-CX: checkpoint auto N, then checkpoint auto confirm."""

    page_off = ("no page",)

    @staticmethod
    def name(tag: str) -> str:
        return "sb-before-" + re.sub(r"[^\w-]", "", tag)[:30]

    def apply(self, res, mode: str, mins: int, tag: str, comment: str) -> str:
        out = self.sh.run(f"copy running-config checkpoint {self.name(tag)}", wait=120)
        if CLI_ERR.search(out):
            raise PushError(f"{self.sh.host}: could not take a checkpoint: {CLI_ERR.search(out).group(0).strip()}. "
                            "Nothing was changed.")
        out = self.sh.run(f"checkpoint auto {mins}", wait=60)
        if CLI_ERR.search(out):
            raise PushError(f"{self.sh.host}: could not start the auto checkpoint timer: "
                            f"{CLI_ERR.search(out).group(0).strip()}. Nothing was changed.")
        errors = self.enter_lines(["configure terminal", *statements(res.set_text)])
        self.sh.run("end", fast=True)
        if errors:
            self.sh.run(f"copy checkpoint {self.name(tag)} running-config", wait=300)
            raise PushError(f"{self.sh.host}: the switch refused {len(errors)} line(s), first: {errors[0]}. The "
                            "checkpoint from before the push was put back.")
        return "Config entered under checkpoint auto."

    def pending_confirm(self, tag: str = "") -> str:
        out = self.sh.run("show checkpoint", wait=60)
        m = re.search(r"^.*\bauto\b.*$", out, re.I | re.M)
        return " ".join(m.group(0).split()) if m else ""

    def confirm(self, tag: str, comment: str) -> str:
        out = self.sh.run("checkpoint auto confirm", wait=60)
        if CLI_ERR.search(out):
            raise PushError(f"{self.sh.host}: confirm failed: {CLI_ERR.search(out).group(0).strip()} (the timer may "
                            "have run out and the switch rolled back).")
        self.save()
        return out.strip() or "confirmed"

    def rollback(self, tag: str, comment: str) -> str:
        out = self.sh.run(f"copy checkpoint {self.name(tag)} running-config", wait=300)
        if CLI_ERR.search(out):
            raise PushError(f"{self.sh.host}: rollback failed: {CLI_ERR.search(out).group(0).strip()}. The switch "
                            "still rolls back by itself when the timer runs out.")
        return out.strip()


# ---------------------------------------------------------------- MikroTik
ROS_ERR = re.compile(r"^.*(syntax error|failure:|bad command name|expected end of command|input does not match|"
                     r"no such item|invalid value|ambiguous value|not enough permissions).*$", re.I | re.M)


class RouterOs:
    """MikroTik RouterOS: Safe Mode in a session the server holds open; closing it without Ctrl+X undoes the change."""

    modes = ("merge",)
    held = True
    diff_note = "RouterOS has no dry run: this is the script the server runs in Safe Mode."

    def __init__(self, shell: Shell):
        self.sh = shell
        self.safe = False

    def running(self) -> str:
        text = self.sh.run("/export terse", wait=max(60, sshfetch.timeout() * 3))
        if "/" not in text:
            raise PushError(f"{self.sh.host}: could not read the running config (is the account allowed to?).")
        return text.strip() + "\n"

    @staticmethod
    def hostname(text: str) -> str:
        found = re.findall(r"/system identity\s+set\s+name=\"?([\w.-]+)", text or "")
        return found[-1] if found else ""

    def preview(self, res, mode: str) -> dict:
        return {"diff": "\n".join(statements(res.set_text, "#")), "check_ok": True, "note": self.diff_note,
                "check": "Any line RouterOS refuses stops the push, and Safe Mode undoes what was done."}

    def apply(self, res, mode: str, mins: int, tag: str, comment: str) -> str:
        self.sh.chan.sendall(b"\x18")  # Ctrl+X: Safe Mode on
        out = self.sh.read_until_prompt(wait=30)
        if "SAFE" not in out:
            raise PushError(f"{self.sh.host}: could not turn on Safe Mode (someone else may hold it). Nothing was "
                            "changed.")
        self.safe = True
        for ln in statements(res.set_text, "#"):
            out = self.sh.run(ln.strip(), wait=max(30, sshfetch.timeout()), fast=True)
            m = ROS_ERR.search(out)
            if m:
                self.drop()
                raise PushError(f"{self.sh.host}: RouterOS refused '{ln.strip()[:80]}': {m.group(0).strip()}. "
                                "Safe Mode undid everything.")
        return "Script run in Safe Mode; the server holds the session until you confirm."

    def pending_confirm(self, tag: str = "") -> str:
        return "Safe Mode is on in the session the server holds" if self.safe else ""

    def confirm(self, tag: str = "", comment: str = "") -> str:
        self.sh.chan.sendall(b"\x18")  # Ctrl+X again: leave Safe Mode and keep the changes
        out = self.sh.read_until_prompt(wait=30)
        if "SAFE" in out.splitlines()[-1]:
            raise PushError(f"{self.sh.host}: Safe Mode did not end.")
        self.safe = False
        return "kept"

    def drop(self) -> None:
        """Close the session while in Safe Mode: RouterOS undoes every change made in it."""
        self.safe = False
        self.sh.close()

    def rollback(self, tag: str = "", comment: str = "") -> str:
        self.drop()
        return "Session closed in Safe Mode: RouterOS undid the change."


DRIVERS = {"juniper": Junos, "arista": Eos, "cisco": IosXe, "nexus": Nxos, "aruba": AosCx, "mikrotik": RouterOs}


def connect(vendor: str, host: str, username: str, password: str, folder: Path, port: int = 22, nets=None,
            pkey=None):
    """(shell, driver) for a vendor that can be pushed to."""
    if not support(vendor).ready or vendor not in DRIVERS:
        raise PushError(f"Pushing to {vendor} switches is not available yet.")
    if vendor == "mikrotik" and "+" not in username:
        username += "+ct"  # RouterOS login options: no colours, no terminal detection
    shell = Shell(host, username, password, folder, port, nets, pkey)
    try:
        return shell, DRIVERS[vendor](shell)
    except Exception:
        shell.close()
        raise


def comment(text: str) -> str:
    """A commit comment: printable, no quotes or backslashes, short."""
    return re.sub(r"[^\w .:#@/()-]+", "", text)[:120]
