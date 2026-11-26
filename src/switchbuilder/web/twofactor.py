"""Two-factor sign-in codes (TOTP, RFC 6238) and recovery codes.

TOTP is the 6-digit code that changes every 30 seconds. One setup works with
Google Authenticator, Microsoft Authenticator, Duo Mobile, Authy, 1Password,
Bitwarden and any other authenticator app.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from urllib.parse import quote

STEP = 30
DIGITS = 6
WINDOW = 1  # accept one step before and after, for clock drift
RECOVERY_CODES = 10


def new_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def code_at(secret: str, step: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** DIGITS).zfill(DIGITS)


def check(secret: str, code: str, last_step: int | None = None, now: float | None = None) -> int | None:
    """Return the time step the code belongs to, or None.

    A code is accepted once only: steps at or before ``last_step`` are refused.
    """
    code = "".join(ch for ch in code or "" if ch.isdigit())
    if len(code) != DIGITS or not secret:
        return None
    current = int((time.time() if now is None else now) // STEP)
    for step in range(current - WINDOW, current + WINDOW + 1):
        if last_step is not None and step <= last_step:
            continue
        if hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def provisioning_uri(secret: str, username: str, issuer: str) -> str:
    label = quote(f"{issuer}:{username}")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={DIGITS}&period={STEP}")


def qr_svg(uri: str) -> str:
    """The setup QR code as inline SVG (empty if segno isn't installed)."""
    try:
        import segno
    except ImportError:
        return ""
    return segno.make(uri, error="m").svg_inline(scale=5, dark="#000000", light="#ffffff", border=3)


# ------------------------------------------------------------ recovery codes
def _digest(code: str) -> str:
    return hashlib.sha256(_normalize(code).encode()).hexdigest()


def _normalize(code: str) -> str:
    return "".join(ch for ch in (code or "").lower() if ch.isalnum())


def new_recovery_codes() -> tuple[list[str], str]:
    """Return (codes to show once, JSON of their hashes to store)."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    codes = []
    for _ in range(RECOVERY_CODES):
        raw = "".join(secrets.choice(alphabet) for _ in range(10))
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes, json.dumps([_digest(c) for c in codes])


def use_recovery_code(stored: str | None, code: str) -> str | None:
    """If ``code`` is one of the stored codes, return the stored JSON without it."""
    if not stored or len(_normalize(code)) != 10:
        return None
    hashes = json.loads(stored)
    digest = _digest(code)
    for h in hashes:
        if hmac.compare_digest(h, digest):
            hashes.remove(h)
            return json.dumps(hashes)
    return None


def recovery_left(stored: str | None) -> int:
    return len(json.loads(stored)) if stored else 0
