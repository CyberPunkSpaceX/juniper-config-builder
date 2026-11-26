"""One-switch EVE-NG labs for every vendor that has a virtual switch image.

The map-based lab in eveng.py links several Juniper switches together. This
module does the simpler thing for any vendor: take the project open in the
builder, move it onto the vendor's virtual lab switch (vEOS, Cat9kv, Nexus
9000v, OS10 VM, EXOS VM, AOS-CX simulator, MikroTik CHR or vJunos-switch),
and type the config into the lab node's console.

``lab_project`` rewrites the project for the lab model: the ports the project
uses are moved, in order, onto the lab model's ports (every port group and LAG
gets at least one), stacking members, the management address and the banner
are dropped, and a lab login ``exb-lab`` is added so the builder can read the
config back. ``LabConsole`` knows each network OS's first-boot questions,
config mode and save command.

FortiSwitch, Ruckus/Brocade ICX, ProCurve/AOS-S and UniFi have no virtual
switch image that runs in EVE-NG, so ``NO_LAB`` explains that instead.
"""

from __future__ import annotations

import copy
import re
import time
from dataclasses import dataclass

from . import eveng
from . import ports as P
from .eveng import EveError, LAB_USER


@dataclass(frozen=True)
class Lab:
    vendor: str
    label: str            # what EVE-NG calls the node type, for people
    match: str            # regex over EVE-NG template name + label
    default: str          # EVE-NG template name we try first
    model: str            # lab model in the vendor's catalog
    dialect: str          # how to talk to its console
    ports: int            # data ports we use on the lab node
    cpu: int
    ram: int              # MB
    boot: str             # roughly how long it takes to boot, for the progress text
    icon: str = "Switch L3.png"

    def to_dict(self) -> dict:
        return {"vendor": self.vendor, "label": self.label, "model": self.model, "ports": self.ports,
                "cpu": self.cpu, "ram": self.ram, "boot": self.boot, "default": self.default}


LABS: dict[str, Lab] = {l.vendor: l for l in (
    Lab("juniper", "vJunos-switch", r"vjunos-?switch", "vjunosswitch", "EX2300-24T", "junos", 10, 4, 5120,
        "5 to 10 minutes"),
    Lab("arista", "Arista vEOS-lab", r"\bveos|arista", "veos", "vEOS-lab", "eos", 12, 2, 4096, "3 to 5 minutes"),
    Lab("cisco", "Cisco Catalyst 9000v (Cat9kv)", r"c9kv|cat9k|catalyst ?9000v", "cat9kv", "Cat9kv", "ios", 8, 4,
        18432, "10 to 15 minutes"),
    Lab("nexus", "Cisco Nexus 9000v", r"nxosv?9k|nexus ?9000v|n9kv", "nxosv9k", "N9K-C9300v (Nexus 9000v lab)",
        "nxos", 16, 2, 10240, "5 to 10 minutes"),
    Lab("dell", "Dell OS10 virtual", r"dellos10|os10", "dellos10", "OS10 virtual (lab)", "os10", 16, 2, 4096,
        "5 to 8 minutes"),
    Lab("extreme", "Extreme EXOS VM", r"\bexos|extreme", "exos", "EXOS VM (lab)", "exos", 8, 1, 1024,
        "2 to 4 minutes"),
    Lab("aruba", "HPE Aruba AOS-CX simulator", r"aoscx|aruba ?cx|aos-cx", "aoscx", "AOS-CX simulator", "aoscx", 8,
        2, 4096, "3 to 5 minutes"),
    Lab("mikrotik", "MikroTik Cloud Hosted Router (CHR)", r"mikrotik|\bchr\b|routeros", "mikrotik", "CHR (lab)",
        "routeros", 8, 1, 512, "1 to 2 minutes", "Router.png"),
)}

NO_LAB = {
    "fortiswitch": "FortiSwitch has no virtual switch image (Fortinet only ships FortiGate and FortiManager VMs), "
                   "so it can't run in EVE-NG. Test the config on a spare switch instead.",
    "ruckus": "Brocade / Ruckus ICX has no virtual switch image, so it can't run in EVE-NG. Test the config on a "
              "spare switch instead.",
    "procurve": "HPE ProCurve / AOS-S has no virtual switch image, so it can't run in EVE-NG. The AOS-CX simulator "
                "is a different OS. Test the config on a spare switch instead.",
    "unifi": "UniFi switches are set up from the UniFi Network app and have no virtual switch image, so there is "
             "nothing to run in EVE-NG. You can run the UniFi Network app in a VM to try the settings.",
}


def lab_for(vendor: str) -> Lab | None:
    return LABS.get(vendor)


# --------------------------------------------------------------- the project
def _model_ports(vendor: str, model: str) -> list[str]:
    if vendor == "juniper":
        return [f"ge-0/0/{i}" for i in range(LABS["juniper"].ports)]
    from .web import _VENDOR_MODELS   # the same catalog the page uses
    m = _VENDOR_MODELS[vendor].get(model)
    return [p["name"] for p in m.to_dict()["ports"]]


def _expander(vendor: str):
    if vendor == "juniper":
        return P.expand
    from .web import _VENDOR_MODELS
    mod = _VENDOR_MODELS[vendor]
    if hasattr(mod, "expand"):
        return mod.expand
    return lambda spec: P.expand_named(spec, mod.ALIASES)


def lab_project(project: dict, lab_password: str) -> tuple[dict, dict, list[str]]:
    """The project rewritten for the vendor's lab model.

    Returns (lab project, {real port: lab port}, notes). Raises EveError when the
    vendor has no lab image.
    """
    vendor = str(project.get("vendor") or "juniper")
    lab = LABS.get(vendor)
    if lab is None:
        raise EveError(NO_LAB.get(vendor, "This vendor has no EVE-NG lab image."))
    p = copy.deepcopy(project)
    notes: list[str] = []
    expand = _expander(vendor)
    free = _model_ports(vendor, lab.model)[:lab.ports]

    # Every port group and LAG, with the ports it lists.
    rows: list[tuple[str, int, list[str]]] = []
    for kind, key in (("lags", "members"), ("ports", "ports")):
        for i, row in enumerate(p.get(kind) or []):
            if not isinstance(row, dict) or row.get("mode") == "disabled":
                continue
            try:
                names = expand(str(row.get(key) or ""))
            except ValueError:
                names = []
            if names:
                rows.append((kind, i, names))
    # Round robin: each group gets its first port, then each its second, ...
    mapping: dict[str, str] = {}
    depth = 0
    while free and any(depth < len(r[2]) for r in rows):
        for _, _, names in rows:
            if depth < len(names) and free and names[depth] not in mapping:
                mapping[names[depth]] = free.pop(0)
        depth += 1
    left_out = sum(1 for _, _, names in rows for n in names if n not in mapping)
    if left_out:
        notes.append(f"The lab switch has {lab.ports} ports, so {left_out} of the project's ports are left out. "
                     "Every port group and LAG still gets at least one port.")
    keep: dict[str, list[int]] = {"ports": [], "lags": []}
    for kind, i, names in rows:
        lab_names = [mapping[n] for n in names if n in mapping]
        if lab_names:
            p[kind][i]["members" if kind == "lags" else "ports"] = ", ".join(lab_names)
            keep[kind].append(i)
    for kind in ("ports", "lags"):
        dropped = [r.get("name") or "(no name)" for i, r in enumerate(p.get(kind) or []) if i not in keep[kind]]
        p[kind] = [r for i, r in enumerate(p.get(kind) or []) if i in keep[kind]]
        if dropped and kind == "ports":
            notes.append(f"Port groups left out (disabled or no ports): {', '.join(map(str, dropped))}.")

    sw = p.setdefault("switch", {})
    members = sw.get("members") or [{"fpc": 0}]
    first = dict(members[0])
    first["model"] = lab.model
    first["serial"] = ""
    if vendor == "cisco":
        first["fpc"] = 1
    elif vendor == "juniper":
        first["fpc"] = 0
    if len(members) > 1:
        notes.append(f"The lab runs one switch, so the other {len(members) - 1} stack member(s) are left out.")
    sw["members"] = [first]
    sw["custom_ports"] = ""
    system = p.setdefault("system", {})
    if system.get("banner"):
        notes.append("The login banner is left out in the lab.")
    for k in ("mgmt_address", "mgmt_gateway", "mgmt_interface", "banner"):
        system[k] = ""
    system["mgmt_vrf"] = False
    access = p.setdefault("access", {})
    access["users"] = [u for u in access.get("users") or [] if str(u.get("name")) != LAB_USER]
    access["users"].append({"name": LAB_USER, "class": "super-user", "password": lab_password, "ssh_key": ""})
    if vendor == "juniper":
        access["root_password"] = access.get("root_password") or lab_password
        p.setdefault("services", {})["use_ranges"] = False   # one member line per port
    return p, mapping, notes


def lab_text(project: dict, lab_password: str, lab_hash: str) -> tuple[list[str], dict, list[str]]:
    """The config lines to type into the lab node. Returns (lines, port map, notes)."""
    from .generator import build
    p, mapping, notes = lab_project(project, lab_password)
    res = build(p)
    if res.errors:
        first = res.errors[0]
        raise EveError(f"The lab version of this project has errors ({len(res.errors)}), first: "
                       f"{first.get('section')}: {first.get('message')}")
    if p.get("vendor", "juniper") == "juniper":
        lines, more = eveng.lab_config(res.set_text, {v: v for v in mapping.values()}, lab_hash)
        return lines, mapping, notes + [n for n in more if "linked to another switch" not in n]
    return [ln for ln in res.set_text.split("\n")], mapping, notes


# ---------------------------------------------------------------- consoles
ANSI = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b[()][A-Za-z0-9]|\x1b[=>]")
ERRORS = re.compile(r"^\s*(% ?(Invalid|Incomplete|Ambiguous|Error|Unrecognized|Bad)\b.*|%Error.*|Error: .*|"
                    r"failure: .*|bad command name.*|syntax error.*|expected end of command.*|"
                    r"Invalid input.*|ERROR: .*)$", re.M | re.I)


@dataclass(frozen=True)
class Dialect:
    users: tuple            # usernames to try, in order, with "{lab}" for the lab password
    boot: tuple             # (regex, reply) answers to first-boot questions
    prompt: str             # the CLI prompt (any mode)
    enter: tuple            # commands before the config
    leave: tuple            # commands after the config (save it)
    pager: str              # command that turns paging off
    show: str               # command that prints the config
    comment: str            # comment character in the config text
    skip: tuple = ("end",)  # config lines not to type
    ztp: str = ""           # EOS: if the boot shows this, cancel zero-touch provisioning (the switch reloads)


LOGIN = r"(?i)(?:^|\n)\S*\s*(?:login|username): ?$"
PASSWORD = r"(?i)password: ?$"
DIALECTS: dict[str, Dialect] = {
    "eos": Dialect(
        users=(("admin", ""), (LAB_USER, "{lab}")),
        boot=(),
        prompt=r"(?m)^[\w.-]+(\([\w.-]+[^)]*\))?[>#] ?$",
        enter=("enable", "configure terminal"), leave=("end", "write memory"),
        pager="terminal length 0", show="show running-config", comment="!", ztp=r"(?i)zerotouch"),
    "ios": Dialect(
        users=((LAB_USER, "{lab}"),),
        boot=((r"(?i)initial configuration dialog\? \[yes/no\]: ?$", "no"),
              (r"(?i)terminate autoinstall\? \[yes\]: ?$", "yes"),
              (r"(?i)press return to get started", "")),
        prompt=r"(?m)^[\w.-]+(\([\w.-]+[^)]*\))?[>#] ?$",
        enter=("enable", "configure terminal"), leave=("end", "write memory"),
        pager="terminal length 0", show="show running-config", comment="!"),
    "nxos": Dialect(
        users=(("admin", "{lab}"), (LAB_USER, "{lab}")),
        boot=((r"(?i)abort power on auto provisioning.*: ?$", "yes"),
              (r"(?i)enforce secure password standard.*: ?$", "no"),
              (r"(?i)(enter|confirm) the password for .admin.: ?$", "{lab}"),
              (r"(?i)basic configuration dialog.*: ?$", "no")),
        prompt=r"(?m)^[\w.-]+(\([\w.-]+[^)]*\))?# ?$",
        enter=("configure terminal",), leave=("end", "copy running-config startup-config"),
        pager="terminal length 0", show="show running-config", comment="!"),
    "os10": Dialect(
        users=(("admin", "admin"), (LAB_USER, "{lab}")),
        boot=((r"(?i)(new|retype|confirm) password: ?$", "{lab}"),),
        prompt=r"(?m)^[\w.-]+(\([\w.-]+[^)]*\))?# ?$",
        enter=("configure terminal",), leave=("end", "write memory"),
        pager="terminal length 0", show="show running-configuration", comment="!"),
    "exos": Dialect(
        users=(("admin", ""), (LAB_USER, "{lab}")),
        boot=((r"\[y/N\]:? ?$", "n"), (r"\(y/N\)\?? ?$", "y"), (r"\[Y/n\]:? ?$", "y")),
        prompt=r"(?m)^\*? ?[\w.-]+(\.\d+)? ?# ?$",
        enter=(), leave=("save configuration",),
        pager="disable clipaging", show="show configuration", comment="#", skip=()),
    "aoscx": Dialect(
        users=(("admin", ""), (LAB_USER, "{lab}")),
        boot=((r"(?i)(enter new|confirm new) password: ?$", "{lab}"),),
        prompt=r"(?m)^[\w.-]+(\([\w.-]+[^)]*\))?# ?$",
        enter=("configure terminal",), leave=("end", "write memory"),
        pager="no page", show="show running-config", comment="!"),
    "routeros": Dialect(
        users=(("admin+ct", ""), (LAB_USER + "+ct", "{lab}")),
        boot=((r"(?i)see the software license\? \[Y/n\]:? ?$", "n"),
              (r"(?i)(repeat )?new password> ?$", "{lab}")),
        prompt=r"(?m)^\[[^\]\n]+\] [^>\n]*> ?$",
        enter=(), leave=(), pager="", show="/export", comment="#", skip=()),
}


class LabConsole(eveng.Console):
    """A console that knows one network OS's first boot, config mode and save command."""

    def __init__(self, host: str, port: int, dialect: str, lab_password: str, timeout: float = 20):
        super().__init__(host, port, timeout)
        self.d = DIALECTS[dialect]
        self.name = dialect
        self.lab = lab_password

    def _recv(self) -> str:
        return ANSI.sub("", super()._recv())

    def _fill(self, text: str) -> str:
        return text.replace("{lab}", self.lab)

    def login(self, boot_timeout: float = 1800) -> None:  # type: ignore[override]
        """Answer the first-boot questions and sign in, until the CLI prompt shows."""
        users = list(self.d.users)
        # First-boot questions first: some of them end in "password:" too.
        rules = [*self.d.boot, (LOGIN, "login"), (PASSWORD, "password"), (self.d.prompt, "prompt"),
                 (r"(?i)login incorrect|authentication failed|% bad passwords|access denied", "bad")]
        pw = ""
        first = True
        ztp_done = False
        while True:
            i, seen = self.expect([r for r, _ in rules], boot_timeout, poke=5 if first else 60)
            first = False
            reply = rules[i][1]
            if reply == "login":
                if not users:
                    raise EveError("Could not sign in on the console (no account worked).")
                self.drain(0.5)
                user, pw = users.pop(0)
                self.send(user)
            elif reply == "password":
                self.send(self._fill(pw))
            elif reply == "bad":
                continue
            elif reply == "prompt":
                if self.d.ztp and not ztp_done and re.search(self.d.ztp, "".join(self.transcript)):
                    # Zero-touch provisioning would keep replacing the config: cancel it. The switch
                    # reloads, so sign in again once it is back.
                    ztp_done = True
                    self.command("enable", timeout=20)
                    self.send("zerotouch cancel")
                    self.drain(3)
                    self.transcript.clear()
                    users = list(self.d.users)
                    first = True
                    continue
                return
            else:
                self.send(self._fill(reply))

    def command(self, cmd: str, timeout: float = 60) -> str:
        """Send one line and wait for the prompt, answering yes/no questions with yes."""
        self.send(cmd)
        out = ""
        end = time.monotonic() + timeout
        while True:
            try:
                i, seen = self.expect([self.d.prompt, r"\((y/n|y/N|Y/n|yes/no)\)\?? ?$|\[(y/n|y/N|Y/n|yes/no|confirm)\]:? ?$"],
                                      max(1.0, end - time.monotonic()))
            except EveError:
                return out + "\n(no prompt)"
            out += seen
            if i == 0:
                return out
            self.send("y")

    def push(self, lines: list[str]) -> list[str]:  # type: ignore[override]
        """Type the config. Returns the lines the switch refused, with its message."""
        if self.d.pager:
            self.command(self.d.pager)
        for cmd in self.d.enter:
            self.command(cmd)
        refused = []
        for ln in lines:
            s = ln.strip()
            if not s or s.startswith(self.d.comment) or s in self.d.skip:
                continue
            out = self.command(s, timeout=60)
            m = ERRORS.search(out)
            if m:
                refused.append(f"{s}  ->  {m.group(0).strip()}")
        for cmd in self.d.leave:
            self.command(cmd, timeout=180)
        return refused

    def pull(self) -> str:  # type: ignore[override]
        if self.d.pager:
            self.command(self.d.pager)
        out = self.command(self.d.show, timeout=300)
        rows = out.split("\n")[1:]
        if rows and re.search(self.d.prompt, rows[-1] + "\n"):
            rows = rows[:-1]
        return "\n".join(r.rstrip() for r in rows).strip() + "\n"


def strip_lab_user(text: str) -> str:
    """Leave the lab login out of a config read back from the lab."""
    return "\n".join(ln for ln in text.split("\n") if not re.search(rf"(?<![\w-]){re.escape(LAB_USER)}(?![\w-])", ln)) \
        .strip() + "\n"


def rename_back(text: str, mapping: dict[str, str]) -> str:
    """Lab port names back to the project's, for names that can't be mistaken for numbers."""
    back = {lab: real for real, lab in mapping.items() if not lab.isdigit()}
    if not back:
        return text
    rx = re.compile(r"(?<![\w/.-])(" + "|".join(re.escape(k) for k in sorted(back, key=len, reverse=True))
                    + r")(?![\w/.-])")
    return rx.sub(lambda m: back[m.group(1)], text)


def catalog() -> dict:
    """For the page: what each vendor's lab runs on, or why there is none."""
    out = {k: dict(lab.to_dict(), possible=True) for k, lab in LABS.items()}
    out.update({k: {"vendor": k, "possible": False, "why": why} for k, why in NO_LAB.items()})
    return out

