"""SHA-512 crypt (``$6$``) password hashes, the format Junos stores in
``encrypted-password``, and SHA-256 crypt (``$5$``) for NX-OS. Python 3.13
removed the ``crypt`` module, so this is the published algorithm (Ulrich Drepper, "Unix crypt using SHA-256 and
SHA-512") in plain Python.
"""

from __future__ import annotations

import hashlib
import re
import secrets

_ITOA = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
HASHED = re.compile(r"^\$(1|5|6|sha1)\$[^\s]+$")
_ORDER = [(0, 21, 42), (22, 43, 1), (44, 2, 23), (3, 24, 45), (25, 46, 4), (47, 5, 26), (6, 27, 48),
          (28, 49, 7), (50, 8, 29), (9, 30, 51), (31, 52, 10), (53, 11, 32), (12, 33, 54), (34, 55, 13),
          (56, 14, 35), (15, 36, 57), (37, 58, 16), (59, 17, 38), (18, 39, 60), (40, 61, 19), (62, 20, 41)]


def is_hashed(value: str) -> bool:
    return bool(HASHED.match(value or ""))


def _b64(b2: int, b1: int, b0: int, n: int) -> str:
    w = (b2 << 16) | (b1 << 8) | b0
    out = []
    for _ in range(n):
        out.append(_ITOA[w & 0x3F])
        w >>= 6
    return "".join(out)


_ORDER256 = [(0, 10, 20), (21, 1, 11), (12, 22, 2), (3, 13, 23), (24, 4, 14), (15, 25, 5), (6, 16, 26),
             (27, 7, 17), (18, 28, 8), (9, 19, 29)]


def _sha_crypt(hasher, size: int, password: str, salt: str | None, rounds: int) -> bytes:
    pw = password.encode("utf-8")
    s = salt.encode("ascii")[:16]

    b = hasher(pw + s + pw).digest()
    a = hasher(pw + s)
    n = len(pw)
    while n > size:
        a.update(b)
        n -= size
    a.update(b[:n])
    n = len(pw)
    while n:
        a.update(b if n & 1 else pw)
        n >>= 1
    a_dig = a.digest()

    dp = hasher(pw * len(pw)).digest()
    p = (dp * (len(pw) // size + 1))[:len(pw)]
    ds = hasher(s * (16 + a_dig[0])).digest()
    s_bytes = (ds * (len(s) // size + 1))[:len(s)]

    c = a_dig
    for i in range(rounds):
        h = hasher()
        h.update(p if i & 1 else c)
        if i % 3:
            h.update(s_bytes)
        if i % 7:
            h.update(p)
        h.update(c if i & 1 else p)
        c = h.digest()
    return c


def _salt(salt: str | None) -> str:
    return (salt if salt is not None else "".join(secrets.choice(_ITOA) for _ in range(16)))[:16]


def sha512_crypt(password: str, salt: str | None = None, rounds: int = 5000) -> str:
    salt = _salt(salt)
    c = _sha_crypt(hashlib.sha512, 64, password, salt, rounds)
    out = "".join(_b64(c[x], c[y], c[z], 4) for x, y, z in _ORDER) + _b64(0, 0, c[63], 2)
    prefix = "$6$" if rounds == 5000 else f"$6$rounds={rounds}$"
    return f"{prefix}{salt}${out}"


def sha256_crypt(password: str, salt: str | None = None, rounds: int = 5000) -> str:
    """SHA-256 crypt (``$5$``), the format Cisco NX-OS stores as ``password 5``."""
    salt = _salt(salt)
    c = _sha_crypt(hashlib.sha256, 32, password, salt, rounds)
    out = "".join(_b64(c[x], c[y], c[z], 4) for x, y, z in _ORDER256) + _b64(0, c[31], c[30], 3)
    prefix = "$5$" if rounds == 5000 else f"$5$rounds={rounds}$"
    return f"{prefix}{salt}${out}"


# ---------------------------------------------------------------- Cisco type 8
# IOS / IOS-XE "secret 8": PBKDF2-HMAC-SHA256, 20000 rounds, a 14-character
# salt, the 32-byte result in base64 with Cisco's ./0-9A-Za-z alphabet.
_STD64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
TYPE8 = re.compile(r"^\$8\$[./0-9A-Za-z]{14}\$[./0-9A-Za-z]{43}$")


def cisco_type8(password: str, salt: str | None = None) -> str:
    import base64
    import hashlib
    if salt is None:
        salt = "".join(secrets.choice(_ITOA) for _ in range(14))
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("ascii"), 20000)
    enc = base64.b64encode(dk).decode().rstrip("=").translate(str.maketrans(_STD64, _ITOA))
    return f"$8${salt}${enc}"


def is_type8(value: str) -> bool:
    return bool(TYPE8.match(value or ""))


# ---------------------------------------------------------------- MD5 crypt
# "$1$" hashes, what Brocade/Ruckus FastIron shows as 'password 8 $1$...'.
def md5_crypt(password: str, salt: str | None = None) -> str:
    if salt is None:
        salt = "".join(secrets.choice(_ITOA) for _ in range(8))
    salt = salt[:8]
    pw, sb, magic = password.encode("utf-8"), salt.encode("ascii"), b"$1$"
    alt = hashlib.md5(pw + sb + pw).digest()
    ctx = pw + magic + sb
    n = len(pw)
    while n > 0:
        ctx += alt[:min(16, n)]
        n -= 16
    i = len(pw)
    while i:
        ctx += b"\0" if i & 1 else pw[:1]
        i >>= 1
    final = hashlib.md5(ctx).digest()
    for r in range(1000):
        c = (pw if r & 1 else final) + (sb if r % 3 else b"") + (pw if r % 7 else b"") + (final if r & 1 else pw)
        final = hashlib.md5(c).digest()
    out = ""
    for a, b, c in ((0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)):
        out += _b64(final[a], final[b], final[c], 4)
    out += _b64(0, 0, final[11], 2)
    return f"$1${salt}${out}"


MD5 = re.compile(r"^\$1\$[./0-9A-Za-z]{1,8}\$[./0-9A-Za-z]{22}$")


def is_md5(value: str) -> bool:
    return bool(MD5.match(value or ""))
