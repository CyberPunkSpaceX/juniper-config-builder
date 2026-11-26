"""Hide secrets from people with the Read-only role.

Read-only users may open saved projects, network maps and config backups, but
must not see passwords, password hashes, SNMP communities, RADIUS/TACACS keys
or routing protocol keys. Two helpers do that:

* ``config(text)`` masks secrets in a switch config of any supported vendor.
  It errs on the side of hiding too much: a hidden value reads ``<hidden>``.
* ``project(data)`` blanks the secret fields of a builder project (JSON), so
  a rebuilt config simply has no passwords instead of wrong ones.
"""

from __future__ import annotations

import copy
import re

HIDDEN = "<hidden>"

# Words after which the next value is a secret.
_KEYWORDS = (r"password|passwd|secret|key-string|authentication-key|auth-key|md5-key|pre-shared-key|psk|"
             r"encrypted-password|plain-text-password|community|key|auth-password|priv-password|"
             r"authentication-password|privacy-password|shared-secret|radius-key|tacacs-key|message-digest-key|ospf-key")
# Words that may sit between the keyword and the value (encryption type and friends).
_TYPES = r"\d{1,3}|md5|sha\d*|sha-\d+|cipher|encrypted|hash|unencrypted|plaintext|clear|ENC|plain|text|ascii-text"
# Values after "key" that are not secrets (commands, not keys).
_NOT_SECRET = {"generate", "zeroize", "chain", "config-key", "exchange", "{", ";", "rsa", "ecdsa", "ed25519",
               "pubkey-chain", "import", "export", "storage", "label",
               # ProCurve "password manager user-name x plaintext ...", EXOS "community readonly ...":
               # the secret comes later on the line (see _LATER)
               "manager", "operator", "all", "readonly", "readwrite", "read-only", "read-write"}

_GENERIC = re.compile(rf"(?i)(?<![\w-])({_KEYWORDS})((?:\s+(?:{_TYPES}))*)(\s*=\s*|\s+)(\"[^\"]*\"|'[^']*'|[^\s;]+)")
_SNMPV3 = re.compile(r"(?i)(?<![\w-])(auth|priv|authentication|privacy)(\s+(?:md5|sha\w*|des\w*|aes\w*|3des)(?:\s+\d{3})?)"
                     r"(\s+)(\"[^\"]*\"|[^\s;]+)")
# Secrets that come later on the line than the generic pattern looks.
_LATER = (
    # AOS-S: password manager user-name "x" plaintext "secret" (or sha1/sha256 hash)
    re.compile(r'(?i)(\bpassword\s+(?:manager|operator)\b.*?\b(?:plaintext|sha1|sha256)\s+)("[^"]*"|\S+)'),
    # EXOS: create account admin netadmin "secret" ; configure snmpv2c add community readonly "x"
    re.compile(r'(?i)(\bcreate\s+account\s+(?:admin|user)\s+\S+\s+(?:encrypted\s+)?)("[^"]*"|\S+)'),
    re.compile(r'(?i)(\bcommunity\s+(?:readonly|readwrite)\s+(?:encrypted\s+)?)("[^"]*"|\S+)'),
)
# FortiSwitch "config system snmp community ... set name x" and MikroTik "/snmp community add name=x":
# the community is a plain "name".
_FORTI_NAME = re.compile(r'(?i)^(\s*set\s+name\s+)("[^"]*"|\S+)')
_ROS_NAME = re.compile(r'(?i)(\bname=)("[^"]*"|[^\s\]]+)')


def _hide(m: re.Match) -> str:
    value = m.group(2)
    if value.strip("\"'") == HIDDEN:
        return m.group(0)
    quote = '"' if value.startswith('"') else ""
    return f"{m.group(1)}{quote}{HIDDEN}{quote}"


# Password hashes wherever they appear: $1$ $5$ $6$ $8$ $9$ (Junos, Cisco, Linux crypt).
_HASH = re.compile(r'"\$(?:9|1|5|6|8|sha1|sha256|sha512)\$[^"]*"|(?<![\w$])\$(?:9|1|5|6|8)\$\S+')


def _sub(m: re.Match) -> str:
    value = m.group(4)
    if value.strip("\"'").lower() in _NOT_SECRET or value.startswith(HIDDEN) or value.strip("\"'") == HIDDEN:
        return m.group(0)
    quote = '"' if value.startswith('"') else ""
    return f"{m.group(1)}{m.group(2)}{m.group(3)}{quote}{HIDDEN}{quote}"


def config(text: str) -> str:
    """The config with every secret replaced by <hidden>."""
    out = []
    communities: set[str] = set()   # SNMP communities found, masked again wherever else they show up

    def hide_comm(m: re.Match) -> str:
        value = m.group(2).strip("\"'")
        if value != HIDDEN and len(value) >= 4:
            communities.add(value)
        return _hide(m)

    def sub_comm(m: re.Match) -> str:
        value = m.group(4).strip("\"'")
        if (m.group(1).lower() == "community" and value != HIDDEN and len(value) >= 4
                and value.lower() not in _NOT_SECRET):
            communities.add(value)
        return _sub(m)
    forti_depth = 0          # inside "config system snmp community" (FortiSwitch)
    ros_section = ""         # current MikroTik section, like "/snmp community"
    for line in str(text).splitlines(keepends=True):
        bare = line.strip()
        if forti_depth:
            if bare.startswith("config "):
                forti_depth += 1
            elif bare == "end":
                forti_depth -= 1
            else:
                line = _FORTI_NAME.sub(hide_comm, line)
        elif bare.lower() == "config system snmp community":
            forti_depth = 1
        if bare.startswith("/"):
            ros_section = " ".join(w for w in bare.split()[:3] if w not in ("add", "set") and "=" not in w).lower()
        if ros_section.startswith("/snmp community"):
            line = _ROS_NAME.sub(hide_comm, line)
        for rx in _LATER:
            line = rx.sub(hide_comm if rx is _LATER[2] else _hide, line)
        line = _HASH.sub(lambda m: f'"{HIDDEN}"' if m.group(0).startswith('"') else HIDDEN, line)
        line = _SNMPV3.sub(_sub, line)
        line = _GENERIC.sub(sub_comm, line)
        out.append(line)
    text = "".join(out)
    # A community can also sit in a name, like the SNMP-S3CRET-RO access list older builder versions wrote.
    for value in sorted(communities - {"public", "private"}, key=len, reverse=True):   # defaults are no secret
        text = re.sub(re.escape(value), HIDDEN, text, flags=re.I)
    return text


# Builder project fields that hold secrets (anywhere in the project).
SECRET_FIELDS = {"password", "root_password", "auth_password", "priv_password", "secret", "md5_key", "auth_key",
                 "key", "psk", "community_string"}


def project(data):
    """A copy of a builder project with secret fields blanked and SNMP community names hidden."""
    data = copy.deepcopy(data)

    def walk(o, path=()):
        if isinstance(o, dict):
            for k, v in o.items():
                if k in SECRET_FIELDS and isinstance(v, str) and v:
                    o[k] = ""
                elif isinstance(v, str) and k == "name" and path[-1:] == ("communities",) and v:
                    o[k] = HIDDEN
                else:
                    walk(v, path + (k,))
        elif isinstance(o, list):
            for x in o:
                walk(x, path)
    walk(data)
    return data


def map_data(data):
    """A copy of a saved network map with the configs in it masked."""
    data = copy.deepcopy(data)
    for item in (data.get("items") or []) if isinstance(data, dict) else []:
        if isinstance(item, dict) and isinstance(item.get("text"), str):
            item["text"] = config(item["text"])
    return data
