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
               "pubkey-chain", "import", "export", "storage", "label"}

_GENERIC = re.compile(rf"(?i)(?<![\w-])({_KEYWORDS})((?:\s+(?:{_TYPES}))*)(\s*=\s*|\s+)(\"[^\"]*\"|'[^']*'|[^\s;]+)")
_SNMPV3 = re.compile(r"(?i)(?<![\w-])(auth|priv|authentication|privacy)(\s+(?:md5|sha\w*|des\w*|aes\w*|3des)(?:\s+\d{3})?)"
                     r"(\s+)(\"[^\"]*\"|[^\s;]+)")
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
    for line in str(text).splitlines(keepends=True):
        line = _HASH.sub(lambda m: f'"{HIDDEN}"' if m.group(0).startswith('"') else HIDDEN, line)
        line = _SNMPV3.sub(_sub, line)
        line = _GENERIC.sub(_sub, line)
        out.append(line)
    return "".join(out)


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
