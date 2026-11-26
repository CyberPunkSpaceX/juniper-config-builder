"""Users, login sessions and user management for the EX config builder web UI.

Users live in a small SQLite database in ``EXB_DATA_DIR`` (default
``/data``). Passwords are stored as salted scrypt hashes, never in clear text.

On first start with an empty database, an admin is created from
``EXB_USERNAME`` and ``EXB_PASSWORD`` / ``EXB_PASSWORD_FILE``. If
those aren't set, the first admin is ``admin`` with password ``admin``, and it
must choose a new password at its first sign-in.

Access levels (shown on the Users page):

* **Super Admin** (``role = 'admin'``): manages users, sign-in settings and
  every client, including new ones.
* **Admin**, **Configurator**, **Read-only** (``role = 'user'``): their level
  in a client is the client role ``admin``, ``editor`` or ``viewer`` (see
  clients.py). A user gets that level either in chosen clients
  (``client_members``) or in all clients, also ones made later
  (``users.all_clients``). Where both apply, the higher one wins.

Two-factor sign-in: each user can turn on authenticator-app codes (TOTP) on
"My account". Server admins must use it (``EXB_REQUIRE_2FA_ADMINS``, default
true); ``EXB_REQUIRE_2FA=true`` makes it compulsory for everyone. Admins can
reset a user's 2FA when a phone is lost.

Failed sign-ins are counted per address (see ``client_ip``). After
``EXB_LOCKOUT_ATTEMPTS`` (default 5) failures for one username from one
address, or ``EXB_LOCKOUT_IP_ATTEMPTS`` (default 20) failures for any
usernames from one address, in ``EXB_LOCKOUT_MINUTES`` (default 15) minutes,
that address can't sign in for the rest of the window. Someone else's wrong
guesses therefore never lock you out. Failures are logged.

Scripts call ``/api/*`` with HTTP basic auth: the username plus either the
password or an API token from "My account". Accounts with 2FA need the token.
"""

from __future__ import annotations

import fcntl
import logging
import functools
import hmac
import ipaddress
import os
import re
import secrets
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

from flask import (
    Blueprint,
    Flask,
    Response,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash

from . import twofactor

bp = Blueprint("auth", __name__, template_folder="templates")

ROLES = ("user", "admin")  # first one is the default for new users
# Access levels on the Users page: a client role, or "super" (server admin).
LEVELS = {"viewer": "Read-only", "editor": "Configurator", "admin": "Admin", "super": "Super Admin"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{2,64}$")
MIN_PASSWORD = 10
DEFAULT_ADMIN = "admin"  # first-start username and password when none is configured
PUBLIC_ENDPOINTS = {"auth.login", "auth.login_2fa", "auth.setup", "healthz", "static"}
log = logging.getLogger("switchbuilder.auth")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    active INTEGER NOT NULL DEFAULT 1,
    must_change INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    last_login TEXT
);
CREATE TABLE IF NOT EXISTS login_failures (
    username TEXT NOT NULL COLLATE NOCASE,
    at REAL NOT NULL,
    ip TEXT NOT NULL DEFAULT ''
);
"""
# Projects, maps and clients: see clients.py.
# Columns added after the first release, added to existing databases on start.
NEW_COLUMNS = {
    "totp_secret": "TEXT",       # base32 TOTP secret; NULL = 2FA off
    "totp_last": "INTEGER",      # last accepted time step, so a code works once
    "recovery": "TEXT",          # JSON list of sha256 hashes of unused recovery codes
    "api_token": "TEXT",         # scrypt hash of the user's API token
    "all_clients": "TEXT",       # client role in every client (also new ones); NULL = only chosen clients
}


def _flag(name: str, default: str = "") -> bool:
    return os.environ.get(name, default).lower() in ("1", "true", "yes")


def require_2fa() -> bool:
    """2FA is compulsory for everyone."""
    return _flag("EXB_REQUIRE_2FA")


def needs_2fa(user) -> bool:
    """This user must have 2FA: everyone when EXB_REQUIRE_2FA is on, server admins unless turned off."""
    if user and _source(user) in ("oidc", "saml"):
        return False  # the identity provider does the second factor
    return require_2fa() or (bool(user) and user["role"] == "admin" and _flag("EXB_REQUIRE_2FA_ADMINS", "true"))


def _source(user) -> str:
    """Where the account signs in: local, ldap, oidc or saml (see sso.py)."""
    return user["source"] if "source" in user.keys() and user["source"] else "local"


def _lockout() -> tuple[int, int, int]:
    """(failures per username and address, failures per address, window in seconds)."""
    return (int(os.environ.get("EXB_LOCKOUT_ATTEMPTS", "5")), int(os.environ.get("EXB_LOCKOUT_IP_ATTEMPTS", "20")),
            int(os.environ.get("EXB_LOCKOUT_MINUTES", "15")) * 60)


# ----------------------------------------------------------------- storage
def data_dir() -> Path:
    return Path(os.environ.get("EXB_DATA_DIR", "/data"))


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


def db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(data_dir() / "users.db", timeout=10)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


def _close_db(_exc=None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def _hash(password: str) -> str:
    return generate_password_hash(password, method="scrypt")


def password_problem(password: str) -> str | None:
    if len(password) < MIN_PASSWORD:
        return f"Passwords need at least {MIN_PASSWORD} characters."
    return None


def count_admins(exclude_id: int | None = None) -> int:
    row = db().execute(
        "SELECT COUNT(*) FROM users WHERE role='admin' AND active=1 AND id IS NOT ?", (exclude_id,)
    ).fetchone()
    return row[0]


def create_user(username: str, password: str, role: str = "user", must_change: bool = False) -> None:
    db().execute(
        "INSERT INTO users (username, password_hash, role, must_change, created_at) VALUES (?, ?, ?, ?, ?)",
        (username, _hash(password), role, int(must_change), _now()),
    )
    db().commit()


def verify(username: str, password: str) -> sqlite3.Row | None:
    row = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is None:
        # Spend the same time as a real check so usernames can't be probed.
        check_password_hash(_DUMMY_HASH, password)
        return None
    if not check_password_hash(row["password_hash"], password) or not row["active"] or _source(row) != "local":
        return None
    return row


_DUMMY_HASH = generate_password_hash("not-a-real-password", method="scrypt")


def verify_api(username: str, secret: str) -> sqlite3.Row | None:
    """Basic auth for /api/*: password (only without 2FA) or the user's API token."""
    row = verify(username, secret)
    if row is not None and not row["totp_secret"]:
        return row
    row = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if row is not None and row["active"] and row["api_token"] and check_password_hash(row["api_token"], secret):
        return row
    return None


# ----------------------------------------------------------------- lockout
def client_ip() -> str:
    """The address the request came from.

    X-Forwarded-For is only believed from a proxy on a private network (Nginx
    Proxy Manager, the swarm ingress), and only its last ``EXB_TRUSTED_PROXIES``
    (default 1) entries, which those proxies added. Entries further left were
    sent by the browser and can say anything.
    """
    remote = request.remote_addr or "?"
    try:
        hops = max(0, int(os.environ.get("EXB_TRUSTED_PROXIES", "1")))
    except ValueError:
        hops = 1
    forwarded = [f.strip() for f in request.headers.get("X-Forwarded-For", "").split(",") if f.strip()]
    if not hops or not forwarded or not _private(remote):
        return remote
    return forwarded[-min(hops, len(forwarded))]


def _private(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback


_client = client_ip


def _minutes_left(rows: list, attempts: int, window: int) -> int:
    if attempts <= 0 or len(rows) < attempts:
        return 0
    return max(1, int((rows[-attempts]["at"] + window - time.time()) // 60) + 1)


def locked_minutes(username: str) -> int:
    """Minutes left before this address may try this username again, or 0."""
    per_user, per_ip, window = _lockout()
    ip, since = client_ip(), time.time() - window
    mine = db().execute("SELECT at FROM login_failures WHERE username = ? AND ip = ? AND at > ? ORDER BY at",
                        (username, ip, since)).fetchall()
    every = db().execute("SELECT at FROM login_failures WHERE ip = ? AND at > ? ORDER BY at", (ip, since)).fetchall()
    return max(_minutes_left(mine, per_user, window), _minutes_left(every, per_ip, window))


def record_failure(username: str, what: str) -> None:
    window = _lockout()[2]
    db().execute("INSERT INTO login_failures (username, at, ip) VALUES (?, ?, ?)",
                 (username[:64], time.time(), client_ip()[:64]))
    db().execute("DELETE FROM login_failures WHERE at < ?", (time.time() - 2 * window,))
    db().commit()
    log.warning("failed %s for user %r from %s", what, username[:64], client_ip())


def clear_failures(username: str) -> None:
    """A good sign-in clears that username's failures from this address."""
    db().execute("DELETE FROM login_failures WHERE username = ? AND ip = ?", (username, client_ip()))
    db().commit()


def _init_storage(app: Flask) -> None:
    folder = data_dir()
    folder.mkdir(parents=True, exist_ok=True)
    # Several gunicorn workers can start at once on an empty volume. A file
    # lock makes the first-start setup run one at a time.
    with open(folder / ".init.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            _init_db(folder)
            app.secret_key = _secret_key(folder)
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)


def _init_db(folder: Path) -> None:
    conn = sqlite3.connect(folder / "users.db", timeout=10)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(SCHEMA)
        have = {row[1] for row in conn.execute("PRAGMA table_info(users)")}
        for column, kind in NEW_COLUMNS.items():
            if column not in have:
                conn.execute(f"ALTER TABLE users ADD COLUMN {column} {kind}")
        if "ip" not in {row[1] for row in conn.execute("PRAGMA table_info(login_failures)")}:
            conn.execute("ALTER TABLE login_failures ADD COLUMN ip TEXT NOT NULL DEFAULT ''")
        conn.execute("CREATE INDEX IF NOT EXISTS login_failures_ip ON login_failures (ip, at)")
        empty = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
        username = os.environ.get("EXB_USERNAME")
        password = _env_password()
        if empty and username and password:
            conn.execute(
                "INSERT OR IGNORE INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', ?)",
                (username, _hash(password), _now()),
            )
        elif empty:
            # Default first login, admin / admin, which has to be changed at once.
            conn.execute(
                "INSERT OR IGNORE INTO users (username, password_hash, role, must_change, created_at) "
                "VALUES (?, ?, 'admin', 1, ?)",
                (DEFAULT_ADMIN, _hash(DEFAULT_ADMIN), _now()),
            )
            log.warning("No users yet: created '%s' with password '%s'. Sign in and change it now.",
                        DEFAULT_ADMIN, DEFAULT_ADMIN)
        from . import clients, sso
        sso.migrate(conn)
        clients.migrate(conn, folder)
        conn.commit()
    finally:
        conn.close()


def _env_password() -> str | None:
    path = os.environ.get("EXB_PASSWORD_FILE")
    if path and Path(path).exists():
        return Path(path).read_text(encoding="utf-8").strip()
    return os.environ.get("EXB_PASSWORD")


def _secret_key(folder: Path) -> bytes:
    """Session signing key, created once and shared by all workers."""
    path = Path(os.environ.get("EXB_SECRET_KEY_FILE", folder / "secret_key"))
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        for _ in range(50):  # another worker may be writing it right now
            key = path.read_bytes()
            if key:
                return key
            time.sleep(0.05)
        raise RuntimeError(f"{path} is empty")
    key = secrets.token_bytes(32)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key)
    return key


# ------------------------------------------------------------ request hooks
def current_user() -> sqlite3.Row | None:
    return g.get("user")


def _session_user() -> sqlite3.Row | None:
    """The signed-in user for this browser session, or None if it's missing or stale."""
    uid = session.get("uid")
    user = db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone() if uid else None
    if user is None or not user["active"] or session.get("pwv") != user["password_hash"][-16:]:
        return None
    return user


def _load_user() -> Response | None:
    g.user = None
    if request.endpoint in PUBLIC_ENDPOINTS:
        return None

    if request.path.startswith("/api/"):
        auth = request.authorization
        username = (auth.username or "") if auth else ""
        if username and locked_minutes(username):
            return Response("Too many failed sign-ins; try again later", 429)
        user = verify_api(username, auth.password or "") if auth else None
        if user is None:
            if username:
                record_failure(username, "API sign-in")
            return Response("Login required", 401, {"WWW-Authenticate": 'Basic realm="Switch Config Builder"'})
        if user["must_change"]:
            return Response("Sign in to the web UI and change your password first", 403)
        if needs_2fa(user) and not user["totp_secret"]:
            return Response("Sign in to the web UI and set up two-factor sign-in first", 403)
        g.user = user
        return None

    if db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        return redirect(url_for("auth.setup"))
    user = _session_user()
    if user is None:
        if session.get("uid"):
            session.clear()  # keep a half-finished 2FA sign-in, drop a stale session
        return redirect(url_for("auth.login", next=request.full_path if request.method == "GET" else None))
    g.user = user
    if user["must_change"] and request.endpoint not in ("auth.account", "auth.logout"):
        flash("Please choose a new password before continuing.", "info")
        return redirect(url_for("auth.account"))
    if needs_2fa(user) and not user["totp_secret"] and request.endpoint not in (
            "auth.account", "auth.twofa_setup", "auth.logout"):
        flash("Two-factor sign-in is required for your account. Set it up to continue." if user["role"] == "admin"
              and not require_2fa() else "Two-factor sign-in is required here. Set it up to continue.", "info")
        return redirect(url_for("auth.twofa_setup"))
    if request.method == "POST":
        token = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
        if not hmac.compare_digest(token, session.get("csrf", "")):
            abort(400, "Form expired. Reload the page and try again.")
    return None


def _start_session(user: sqlite3.Row) -> None:
    session.clear()
    session.permanent = True
    session["uid"] = user["id"]
    # Logging out everywhere on a password change: sessions carry a piece
    # of the hash, so a new password invalidates old sessions.
    session["pwv"] = user["password_hash"][-16:]
    session["csrf"] = secrets.token_urlsafe(32)


def admin_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None or user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapper


def _safe_next(target: str | None) -> str:
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return url_for("index")


# ------------------------------------------------------------------ routes
@bp.route("/setup", methods=["GET", "POST"])
def setup():
    """First-run page that creates the first admin when there are no users."""
    if db().execute("SELECT COUNT(*) FROM users").fetchone()[0] > 0:
        return redirect(url_for("auth.login"))
    error = None
    if request.method == "POST" and _cross_site_post():
        abort(400, "Use this site's own setup page.")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not USERNAME_RE.match(username):
            error = "Usernames are 2 to 64 letters, digits, dots, dashes, underscores or @."
        elif password != request.form.get("confirm", ""):
            error = "The passwords don't match."
        else:
            error = password_problem(password)
        if error is None:
            create_user(username, password, "admin")
            _start_session(verify(username, password))
            return redirect(url_for("index"))
    return render_template("auth/setup.html", error=error)


def _finish_login(user: sqlite3.Row, next_url: str | None) -> Response:
    clear_failures(user["username"])
    db().execute("UPDATE users SET last_login = ? WHERE id = ?", (_now(), user["id"]))
    db().commit()
    _start_session(user)
    log.info("audit: %r signed in from %s", user["username"], client_ip())
    return redirect(_safe_next(next_url))


def _locked_message(minutes: int) -> str:
    return f"Too many failed attempts. Try again in {minutes} minute{'s' if minutes != 1 else ''}."


def _cross_site_post() -> bool:
    """A sign-in form sent from another web site (login CSRF: signing someone in to an attacker's account).

    The sign-in forms have no session yet to hold a CSRF token, so the browser's Origin header is checked
    instead: browsers send it with every cross-site POST. Scripts and tests that send none are allowed.
    """
    origin = request.headers.get("Origin")
    if origin is None:
        return False
    from urllib.parse import urlparse
    allowed = {request.host.lower()}
    public = os.environ.get("EXB_PUBLIC_URL", "").strip()
    if public:
        allowed.add(urlparse(public).netloc.lower())
    return urlparse(origin).netloc.lower() not in allowed


@bp.route("/login", methods=["GET", "POST"])
def login():
    # Already signed in (for example the browser's Back button landed here):
    # go back into the app instead of showing the sign-in form again.
    if request.method == "GET" and _session_user() is not None:
        return redirect(_safe_next(request.args.get("next")))
    error = None
    if request.method == "POST" and _cross_site_post():
        abort(400, "Sign in from this site's own sign-in page.")
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if minutes := locked_minutes(username):
            return render_template("auth/login.html", error=_locked_message(minutes)), 429
        password = request.form.get("password", "")
        user = verify(username, password)
        if user is None and not db().execute("SELECT 1 FROM users WHERE username = ? AND source = 'local'",
                                             (username,)).fetchone():
            from . import sso
            user = sso.ldap_login(username, password)  # company directory, when set up
            if isinstance(user, str):
                return render_template("auth/login.html", error=user, providers=sso.login_providers()), 403
        if user is None:
            record_failure(username, "sign-in")
            time.sleep(0.5)
            error = "Wrong username or password, or the account is disabled."
        elif user["totp_secret"] and needs_code(user):
            # Password is right; the code is asked on the next page.
            session.clear()
            session["pending"] = {"uid": user["id"], "pwv": user["password_hash"][-16:],
                                  "until": time.time() + 300, "next": request.args.get("next")}
            return redirect(url_for("auth.login_2fa"))
        else:
            return _finish_login(user, request.args.get("next"))
    from . import sso
    return render_template("auth/login.html", error=error, providers=sso.login_providers())


def needs_code(user) -> bool:
    """Ask the authenticator code at sign-in (not for OIDC/SAML: the identity provider did MFA)."""
    return _source(user) not in ("oidc", "saml")


@bp.route("/login/code", methods=["GET", "POST"])
def login_2fa():
    if request.method == "GET" and _session_user() is not None:
        return redirect(url_for("index"))
    pending = session.get("pending") or {}
    user = db().execute("SELECT * FROM users WHERE id = ?", (pending.get("uid"),)).fetchone() if pending else None
    if (user is None or not user["active"] or not user["totp_secret"] or time.time() > pending.get("until", 0)
            or pending.get("pwv") != user["password_hash"][-16:]):
        session.clear()
        flash("Sign in again.", "info")
        return redirect(url_for("auth.login"))
    error = None
    if request.method == "POST":
        if minutes := locked_minutes(user["username"]):
            session.clear()
            return render_template("auth/login.html", error=_locked_message(minutes)), 429
        code = request.form.get("code", "")
        step = twofactor.check(user["totp_secret"], code, user["totp_last"])
        if step is not None:
            db().execute("UPDATE users SET totp_last = ? WHERE id = ?", (step, user["id"]))
            return _finish_login(user, pending.get("next"))
        remaining = twofactor.use_recovery_code(user["recovery"], code)
        if remaining is not None:
            db().execute("UPDATE users SET recovery = ? WHERE id = ?", (remaining, user["id"]))
            flash(f"Recovery code used. {twofactor.recovery_left(remaining)} left; make new ones on My account "
                  "if you're running low.", "info")
            return _finish_login(user, pending.get("next"))
        record_failure(user["username"], "2FA code")
        time.sleep(0.5)
        error = "That code didn't work. Use the current code from your app, or a recovery code."
    return render_template("auth/login_2fa.html", error=error)


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/account", methods=["GET", "POST"])
def account():
    user = current_user()
    if request.method == "POST" and _source(user) != "local":
        flash("Your password is managed by your company directory, so change it there.", "error")
        return redirect(url_for("auth.account"))
    if request.method == "POST":
        current = request.form.get("current", "")
        new = request.form.get("password", "")
        if not check_password_hash(user["password_hash"], current):
            flash("Your current password is wrong.", "error")
        elif new != request.form.get("confirm", ""):
            flash("The new passwords don't match.", "error")
        elif problem := password_problem(new):
            flash(problem, "error")
        elif new == current:
            flash("Choose a password different from the current one.", "error")
        else:
            db().execute("UPDATE users SET password_hash = ?, must_change = 0 WHERE id = ?", (_hash(new), user["id"]))
            db().commit()
            _start_session(db().execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone())
            flash("Password changed.", "ok")
            return redirect(url_for("auth.account"))
    return render_template("auth/account.html", recovery_left=twofactor.recovery_left(user["recovery"]),
                           require_2fa=needs_2fa(user))


def _issuer() -> str:
    return os.environ.get("EXB_2FA_ISSUER", "Multi-Vendor Switch Config Builder")


@bp.route("/account/2fa", methods=["GET", "POST"])
def twofa_setup():
    """Turn on two-factor sign-in: scan the QR code, confirm with one code."""
    user = current_user()
    if user["totp_secret"]:
        return redirect(url_for("auth.account"))
    secret = session.get("totp_setup") or twofactor.new_secret()
    session["totp_setup"] = secret
    error = None
    if request.method == "POST":
        step = twofactor.check(secret, request.form.get("code", ""))
        if step is None:
            error = "That code didn't match. Check the time on your phone and try the newest code."
        else:
            codes, stored = twofactor.new_recovery_codes()
            db().execute("UPDATE users SET totp_secret = ?, totp_last = ?, recovery = ? WHERE id = ?",
                         (secret, step, stored, user["id"]))
            db().commit()
            session.pop("totp_setup", None)
            log.info("2FA turned on for %r", user["username"])
            return render_template("auth/recovery.html", codes=codes, first=True)
    uri = twofactor.provisioning_uri(secret, user["username"], _issuer())
    return render_template("auth/twofa_setup.html", secret=secret, qr=twofactor.qr_svg(uri), uri=uri, error=error)


def _check_code(user: sqlite3.Row) -> bool:
    step = twofactor.check(user["totp_secret"], request.form.get("code", ""), user["totp_last"])
    if step is None:
        record_failure(user["username"], "2FA code")
        return False
    db().execute("UPDATE users SET totp_last = ? WHERE id = ?", (step, user["id"]))
    return True


@bp.post("/account/2fa/off")
def twofa_off():
    user = current_user()
    if needs_2fa(user):
        flash("Two-factor sign-in is required for your account, so it can't be turned off.", "error")
    elif not check_password_hash(user["password_hash"], request.form.get("current", "")):
        flash("Your current password is wrong.", "error")
    elif not _check_code(user):
        flash("That code didn't work.", "error")
    else:
        db().execute("UPDATE users SET totp_secret = NULL, totp_last = NULL, recovery = NULL WHERE id = ?",
                     (user["id"],))
        log.info("2FA turned off by %r", user["username"])
        flash("Two-factor sign-in is off.", "ok")
    db().commit()
    return redirect(url_for("auth.account"))


@bp.post("/account/2fa/recovery")
def twofa_recovery():
    user = current_user()
    if not user["totp_secret"] or not _check_code(user):
        db().commit()
        flash("That code didn't work.", "error")
        return redirect(url_for("auth.account"))
    codes, stored = twofactor.new_recovery_codes()
    db().execute("UPDATE users SET recovery = ? WHERE id = ?", (stored, user["id"]))
    db().commit()
    return render_template("auth/recovery.html", codes=codes, first=False)


@bp.post("/account/token")
def api_token():
    user = current_user()
    if request.form.get("action") == "delete":
        db().execute("UPDATE users SET api_token = NULL WHERE id = ?", (user["id"],))
        db().commit()
        flash("API token deleted.", "ok")
        return redirect(url_for("auth.account"))
    token = "exb_" + secrets.token_urlsafe(30)
    db().execute("UPDATE users SET api_token = ? WHERE id = ?", (_hash(token), user["id"]))
    db().commit()
    return render_template("auth/token.html", token=token)


def access_of(user_id: int) -> dict:
    """A user's access: level and clients, for the Users page."""
    u = db().execute("SELECT role, all_clients FROM users WHERE id = ?", (user_id,)).fetchone()
    rows = db().execute("SELECT c.id, c.name, m.role FROM client_members m JOIN clients c ON c.id = m.client_id "
                        "WHERE m.user_id = ? ORDER BY c.name COLLATE NOCASE", (user_id,)).fetchall()
    if u["role"] == "admin":
        return {"level": "super", "scope": "all", "clients": [], "text": "Super Admin, all clients"}
    if u["all_clients"] in LEVELS:
        extra = [f"{r['name']}: {LEVELS[r['role']]}" for r in rows
                 if _rank(r["role"]) > _rank(u["all_clients"])]
        text = f"{LEVELS[u['all_clients']]}, all clients" + (f" ({', '.join(extra)})" if extra else "")
        return {"level": u["all_clients"], "scope": "all", "clients": [r["id"] for r in rows], "text": text}
    levels = {r["role"] for r in rows}
    level = max(levels, key=_rank) if levels else "viewer"
    text = ", ".join(f"{r['name']}: {LEVELS[r['role']]}" for r in rows) or "No clients yet"
    return {"level": level, "scope": "some", "clients": [r["id"] for r in rows], "text": text}


def _rank(role: str | None) -> int:
    return ("viewer", "editor", "admin").index(role) if role in ("viewer", "editor", "admin") else -1


def _read_access(form) -> tuple[str, str, list[int]] | str:
    """(level, scope, client ids) from the Users page form, or an error message."""
    level = form.get("level", "viewer")
    scope = form.get("scope", "some")
    if level not in LEVELS:
        return "Unknown access level."
    if scope not in ("all", "some"):
        return "Pick all clients or the chosen clients."
    try:
        ids = sorted({int(x) for x in form.getlist("clients")})
    except ValueError:
        return "Unknown client."
    known = {r[0] for r in db().execute("SELECT id FROM clients")}
    if any(i not in known for i in ids):
        return "Unknown client."
    return level, scope, ids


def set_access(uid: int, level: str, scope: str, ids: list[int]) -> None:
    """Give a user a level in all clients (also future ones) or in the chosen clients only."""
    if level == "super":
        db().execute("UPDATE users SET role = 'admin', all_clients = NULL WHERE id = ?", (uid,))
        return
    db().execute("UPDATE users SET role = 'user', all_clients = ? WHERE id = ?",
                 (level if scope == "all" else None, uid))
    db().execute("DELETE FROM client_members WHERE user_id = ?", (uid,))
    if scope == "some":
        db().executemany("INSERT INTO client_members (client_id, user_id, role) VALUES (?, ?, ?)",
                         [(cid, uid, level) for cid in ids])


@bp.get("/users")
@admin_required
def users():
    from . import sso
    rows = db().execute("SELECT * FROM users ORDER BY username COLLATE NOCASE").fetchall()
    all_clients = db().execute("SELECT id, name FROM clients ORDER BY name COLLATE NOCASE").fetchall()
    return render_template("auth/users.html", users=rows, levels=LEVELS, min_password=MIN_PASSWORD, sources=sso.SOURCES,
                           clients=all_clients, access={u["id"]: access_of(u["id"]) for u in rows})


@bp.post("/users")
@admin_required
def users_create():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    access = _read_access(request.form)
    if not USERNAME_RE.match(username):
        flash("Usernames are 2 to 64 letters, digits, dots, dashes, underscores or @.", "error")
    elif isinstance(access, str):
        flash(access, "error")
    elif problem := password_problem(password):
        flash(problem, "error")
    elif db().execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        flash(f"User {username} already exists.", "error")
    else:
        create_user(username, password, "user", must_change=bool(request.form.get("must_change")))
        uid = db().execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]
        set_access(uid, *access)
        db().commit()
        log.warning("audit: %r created user %r (%s)", current_user()["username"], username, access_of(uid)["text"])
        flash(f"User {username} created: {access_of(uid)['text']}.", "ok")
    return redirect(url_for("auth.users"))


@bp.post("/users/<int:uid>")
@admin_required
def users_update(uid: int):
    me = current_user()
    target = db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    if target is None:
        abort(404)
    action = request.form.get("action")
    name = target["username"]

    if action == "delete":
        if uid == me["id"]:
            flash("You can't delete your own account.", "error")
        elif target["role"] == "admin" and count_admins(exclude_id=uid) == 0:
            flash("You can't delete the last active Super Admin.", "error")
        else:
            db().execute("DELETE FROM client_members WHERE user_id = ?", (uid,))
            db().execute("DELETE FROM users WHERE id = ?", (uid,))
            flash(f"User {name} deleted.", "ok")
    elif action == "access":
        access = _read_access(request.form)
        if isinstance(access, str):
            flash(access, "error")
        elif access[0] != "super" and target["role"] == "admin" and count_admins(exclude_id=uid) == 0:
            flash("You can't remove the last active Super Admin.", "error")
        else:
            set_access(uid, *access)
            text = access_of(uid)["text"]
            log.warning("audit: %r set the access of %r to %s", me["username"], name, text)
            flash(f"{name}: {text}.", "ok")
    elif action == "toggle":
        if uid == me["id"]:
            flash("You can't disable your own account.", "error")
        elif target["active"] and target["role"] == "admin" and count_admins(exclude_id=uid) == 0:
            flash("You can't disable the last active Super Admin.", "error")
        else:
            db().execute("UPDATE users SET active = ? WHERE id = ?", (0 if target["active"] else 1, uid))
            flash(f"{name} {'disabled' if target['active'] else 'enabled'}.", "ok")
    elif action == "reset2fa":
        db().execute("UPDATE users SET totp_secret = NULL, totp_last = NULL, recovery = NULL WHERE id = ?", (uid,))
        log.info("2FA of %r reset by %r", name, me["username"])
        flash(f"Two-factor sign-in for {name} was reset. They can set it up again on My account.", "ok")
    elif action == "reset":
        password = request.form.get("password", "")
        if _source(target) != "local":
            flash(f"{name} signs in with the company directory; reset the password there.", "error")
        elif problem := password_problem(password):
            flash(problem, "error")
        else:
            db().execute("UPDATE users SET password_hash = ?, must_change = 1 WHERE id = ?", (_hash(password), uid))
            flash(f"Password for {name} reset. They must change it at their next login.", "ok")
    else:
        abort(400)
    db().commit()
    return redirect(url_for("auth.users"))


# -------------------------------------------------------------------- setup
def init_app(app: Flask) -> None:
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=_flag("EXB_SECURE_COOKIES"),
        SESSION_COOKIE_NAME="exbuilder_session",  # old name kept on purpose: renaming it would sign everyone out
        PERMANENT_SESSION_LIFETIME=int(os.environ.get("EXB_SESSION_HOURS", "12")) * 3600,
    )
    _init_storage(app)
    app.register_blueprint(bp)
    app.before_request(_load_user)
    app.teardown_appcontext(_close_db)

    @app.context_processor
    def inject_user():
        return {"current_user": current_user(), "csrf_token": session.get("csrf", "")}
