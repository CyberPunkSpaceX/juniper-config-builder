"""Alerts: email (SMTP) and chat webhooks (Microsoft Teams, Slack, Discord, or any JSON webhook).

Email uses the server's SMTP settings (environment):

* ``EXB_SMTP_HOST`` (no host = no email), ``EXB_SMTP_PORT`` (587),
  ``EXB_SMTP_TLS`` (``starttls`` default, ``ssl`` or ``none``),
  ``EXB_SMTP_USER`` and ``EXB_SMTP_PASSWORD_FILE`` (a Docker secret is best),
  ``EXB_SMTP_FROM`` (the sender address).

Webhooks are per client. Only ``https://`` addresses are used, redirects are not
followed, and the answer is not read beyond the status, so a webhook cannot be
used to read pages from inside the network.
"""

from __future__ import annotations

import json
import logging
import os
import re
import smtplib
import ssl
import urllib.error
import urllib.request
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlsplit

log = logging.getLogger("switchbuilder.notify")

EMAIL_RE = re.compile(r"^[^@\s<>\"',;]+@[^@\s<>\"',;]+\.[^@\s<>\"',;]+$")
MAX_TEXT = 12_000          # chat messages are cut here


class NotifyError(Exception):
    pass


# ----------------------------------------------------------------- email
def smtp_ready() -> bool:
    return bool(os.environ.get("EXB_SMTP_HOST", "").strip())


def parse_emails(text: str) -> tuple[list[str], list[str]]:
    good, bad = [], []
    for part in re.split(r"[\s,;]+", text or ""):
        if part:
            (good if EMAIL_RE.match(part) and len(part) <= 200 else bad).append(part)
    return list(dict.fromkeys(good))[:20], bad


def send_email(to: list[str], subject: str, body: str) -> None:
    host = os.environ.get("EXB_SMTP_HOST", "").strip()
    if not host:
        raise NotifyError("email is not set up on this server (EXB_SMTP_HOST)")
    port = int(os.environ.get("EXB_SMTP_PORT", "587") or 587)
    mode = os.environ.get("EXB_SMTP_TLS", "starttls").strip().lower()
    user = os.environ.get("EXB_SMTP_USER", "").strip()
    pw_file = os.environ.get("EXB_SMTP_PASSWORD_FILE", "").strip()
    password = Path(pw_file).read_text().strip() if pw_file and Path(pw_file).is_file() else ""
    msg = EmailMessage()
    msg["From"] = os.environ.get("EXB_SMTP_FROM", "").strip() or (user if "@" in user else f"switchbuilder@{host}")
    msg["To"] = ", ".join(to)
    msg["Subject"] = subject.replace("\n", " ")[:200]
    msg.set_content(body)
    ctx = ssl.create_default_context()
    try:
        if mode == "ssl":
            smtp = smtplib.SMTP_SSL(host, port, timeout=20, context=ctx)
        else:
            smtp = smtplib.SMTP(host, port, timeout=20)
        with smtp:
            if mode == "starttls":
                smtp.starttls(context=ctx)
            if user and password:
                smtp.login(user, password)
            smtp.send_message(msg)
    except (OSError, smtplib.SMTPException) as exc:
        raise NotifyError(f"email failed: {exc.__class__.__name__}: {exc}"[:300]) from None


# -------------------------------------------------------------- webhooks
def hook_kind(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower()
    if host == "hooks.slack.com":
        return "slack"
    if host.endswith((".webhook.office.com", ".logic.azure.com", ".powerplatform.com", ".powerautomate.com")):
        return "teams"
    if host in ("discord.com", "discordapp.com"):
        return "discord"
    return "json"


def check_hook(url: str) -> str | None:
    """A problem with a webhook address, or None."""
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        return f"{short(url)}: use an https:// webhook address."
    if parts.username or parts.password or len(url) > 1000 or any(c.isspace() for c in url):
        return f"{short(url)}: not a webhook address."
    return None


def parse_hooks(text: str) -> tuple[list[str], list[str]]:
    hooks, problems = [], []
    for part in re.split(r"\s+", text or ""):
        if part:
            p = check_hook(part)
            (problems.append(p) if p else hooks.append(part))
    return list(dict.fromkeys(hooks))[:10], problems


def short(url: str) -> str:
    """A webhook address without its secret part, for showing on the page and in logs."""
    p = urlsplit(url)
    return f"{p.scheme}://{p.hostname or '?'}/…" if p.hostname else url[:20] + "…"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _payload(kind: str, title: str, text: str, facts: dict | None) -> dict:
    text = text[:MAX_TEXT]
    if kind == "slack":
        return {"text": f"*{title}*\n{text}"}
    if kind == "discord":
        return {"content": f"**{title}**\n{text}"[:1990]}
    if kind == "teams":
        body = [{"type": "TextBlock", "text": title, "weight": "Bolder", "size": "Medium", "wrap": True},
                {"type": "TextBlock", "text": text, "wrap": True, "fontType": "Monospace"}]
        return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive", "content": {
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard", "version": "1.4",
            "body": body}}]}
    return {"title": title, "text": text, **(facts or {})}


def send_hook(url: str, title: str, text: str, facts: dict | None = None) -> None:
    problem = check_hook(url)
    if problem:
        raise NotifyError(problem)
    data = json.dumps(_payload(hook_kind(url), title, text, facts)).encode()
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "Content-Type": "application/json", "User-Agent": "switch-config-builder"})
    opener = urllib.request.build_opener(_NoRedirect)
    try:
        with opener.open(req, timeout=15) as resp:
            if resp.status >= 300:
                raise NotifyError(f"{short(url)}: answered {resp.status}")
    except urllib.error.HTTPError as exc:
        raise NotifyError(f"{short(url)}: answered {exc.code}") from None
    except (OSError, ValueError) as exc:
        raise NotifyError(f"{short(url)}: {exc.__class__.__name__}: {exc}"[:300]) from None


def send_all(emails: list[str], hooks: list[str], title: str, text: str, facts: dict | None = None) -> list[str]:
    """Send to every address and webhook. Returns the problems (empty when all went out)."""
    problems = []
    if emails:
        try:
            send_email(emails, title, text)
        except NotifyError as exc:
            problems.append(str(exc))
    for url in hooks:
        try:
            send_hook(url, title, text, facts)
        except NotifyError as exc:
            problems.append(str(exc))
    for p in problems:
        log.warning("alert not sent: %s", p)
    return problems
