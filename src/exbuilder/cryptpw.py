"""SHA-512 crypt (``$6$``) password hashes, the format Junos stores in
``encrypted-password``. Python 3.13 removed the ``crypt`` module, so this is
the published algorithm (Ulrich Drepper, "Unix crypt using SHA-256 and
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


def sha512_crypt(password: str, salt: str | None = None, rounds: int = 5000) -> str:
    pw = password.encode("utf-8")
    if salt is None:
        salt = "".join(secrets.choice(_ITOA) for _ in range(16))
    s = salt.encode("ascii")[:16]

    b = hashlib.sha512(pw + s + pw).digest()
    a = hashlib.sha512(pw + s)
    n = len(pw)
    while n > 64:
        a.update(b)
        n -= 64
    a.update(b[:n])
    n = len(pw)
    while n:
        a.update(b if n & 1 else pw)
        n >>= 1
    a_dig = a.digest()

    dp = hashlib.sha512(pw * len(pw)).digest()
    p = (dp * (len(pw) // 64 + 1))[:len(pw)]
    ds = hashlib.sha512(s * (16 + a_dig[0])).digest()
    s_bytes = (ds * (len(s) // 64 + 1))[:len(s)]

    c = a_dig
    for i in range(rounds):
        h = hashlib.sha512()
        h.update(p if i & 1 else c)
        if i % 3:
            h.update(s_bytes)
        if i % 7:
            h.update(p)
        h.update(c if i & 1 else p)
        c = h.digest()

    out = "".join(_b64(c[x], c[y], c[z], 4) for x, y, z in _ORDER) + _b64(0, 0, c[63], 2)
    prefix = "$6$" if rounds == 5000 else f"$6$rounds={rounds}$"
    return f"{prefix}{s.decode()}${out}"
