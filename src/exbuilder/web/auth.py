"""Users, login sessions and user management for the EX config builder web UI.

Users live in a small SQLite database in ``EXB_DATA_DIR`` (default
``/data``). Passwords are stored as salted scrypt hashes, never in clear text.

On first start with an empty database, an admin is created from
``EXB_USERNAME`` and ``EXB_PASSWORD`` / ``EXB_PASSWORD_FILE``. If
those aren't set, the first admin is ``admin`` with password ``admin``, and it
must choose a new password at its first sign-in.

Roles:

* ``admin``: build configs, and create, edit, disable and delete users.
* ``user``: build configs and change their own password.

Two-factor sign-in: each user can turn on authenticator-app codes (TOTP) on
"My account". ``EXB_REQUIRE_2FA=true`` makes it compulsory. Admins can
reset a user's 2FA when a phone is lost.

Failed sign-ins are counted per username: after ``EXB_LOCKOUT_ATTEMPTS``
(default 5) failures in ``EXB_LOCKOUT_MINUTES`` (default 15) minutes, that
username is locked for the rest of the window. Failures are logged.

Scripts call ``/api/*`` with HTTP basic auth: the username plus either the
password or an API token from "My account". Accounts with 2FA need the token.
"""

from __future__ import annotations

import fcntl
import logging
import functools
import hmac
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
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.@-]{2,64}$")
MIN_PASSWORD = 10
DEFAULT_ADMIN = "admin"  # first-start username and password when none is configured
PUBLIC_ENDPOINTS = {"auth.login", "auth.login_2fa", "auth.setup", "healthz", "static"}
log = logging.getLogger("exbuilder.auth")

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
    at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS login_failures_user ON login_failures (username, at);
CREATE TABLE IF NOT EXISTS projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    data TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (owner_id, name)
);
"""
# Columns added after the first release, added to existing databases on start.
NEW_COLUMNS = {
    "totp_secret": "TEXT",       # base32 TOTP secret; NULL = 2FA off
    "totp_last": "INTEGER",      # last accepted time step, so a code works once
    "recovery": "TEXT",          # JSON list of sha256 hashes of unused recovery codes
    "api_token": "TEXT",         # scrypt hash of the user's API token
}


def _flag(name: str, default: str = "") -> bool:
    return os.environ.get(name, default).lower() in ("1", "true", "yes")


def require_2fa() -> bool:
    return _flag("EXB_REQUIRE_2FA")


def _lockout() -> tuple[int, int]:
    return (int(os.environ.get("EXB_LOCKOUT_ATTEMPTS", "5")),
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
    if not check_password_hash(row["password_hash"], password) or not row["active"]:
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
def _client() -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() or request.remote_addr or "?"


def locked_minutes(username: str) -> int:
    """Minutes left on a lockout for this username, or 0."""
    attempts, window = _lockout()
    if attempts <= 0:
        return 0
    rows = db().execute("SELECT at FROM login_failures WHERE username = ? AND at > ? ORDER BY at",
                        (username, time.time() - window)).fetchall()
    if len(rows) < attempts:
        return 0
    return max(1, int((rows[-attempts]["at"] + window - time.time()) // 60) + 1)


def record_failure(username: str, what: str) -> None:
    _attempts, window = _lockout()
    db().execute("INSERT INTO login_failures (username, at) VALUES (?, ?)", (username[:64], time.time()))
    db().execute("DELETE FROM login_failures WHERE at < ?", (time.time() - 2 * window,))
    db().commit()
    log.warning("failed %s for user %r from %s", what, username[:64], _client())


def clear_failures(username: str) -> None:
    db().execute("DELETE FROM login_failures WHERE username = ?", (username,))
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
            return Response("Login required", 401, {"WWW-Authenticate": 'Basic realm="exbuilder"'})
        if user["must_change"]:
            return Response("Sign in to the web UI and change your password first", 403)
        g.user = user
        return None

    if db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        return redirect(url_for("auth.setup"))
    uid = session.get("uid")
    user = db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone() if uid else None
    if user is None or not user["active"] or session.get("pwv") != user["password_hash"][-16:]:
        if uid:
            session.clear()  # keep a half-finished 2FA sign-in, drop a stale session
        return redirect(url_for("auth.login", next=request.full_path if request.method == "GET" else None))
    g.user = user
    if user["must_change"] and request.endpoint not in ("auth.account", "auth.logout"):
        flash("Please choose a new password before continuing.", "info")
        return redirect(url_for("auth.account"))
    if require_2fa() and not user["totp_secret"] and request.endpoint not in (
            "auth.account", "auth.twofa_setup", "auth.logout"):
        flash("Two-factor sign-in is required here. Set it up to continue.", "info")
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
    return redirect(_safe_next(next_url))


def _locked_message(minutes: int) -> str:
    return f"Too many failed attempts. Try again in {minutes} minute{'s' if minutes != 1 else ''}."


@bp.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        if minutes := locked_minutes(username):
            return render_template("auth/login.html", error=_locked_message(minutes)), 429
        user = verify(username, request.form.get("password", ""))
        if user is None:
            record_failure(username, "sign-in")
            time.sleep(0.5)
            error = "Wrong username or password, or the account is disabled."
        elif user["totp_secret"]:
            # Password is right; the code is asked on the next page.
            session.clear()
            session["pending"] = {"uid": user["id"], "pwv": user["password_hash"][-16:],
                                  "until": time.time() + 300, "next": request.args.get("next")}
            return redirect(url_for("auth.login_2fa"))
        else:
            return _finish_login(user, request.args.get("next"))
    return render_template("auth/login.html", error=error)


@bp.route("/login/code", methods=["GET", "POST"])
def login_2fa():
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
                           require_2fa=require_2fa())


def _issuer() -> str:
    return os.environ.get("EXB_2FA_ISSUER", "EX Config Builder")


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
    if require_2fa():
        flash("Two-factor sign-in is required on this server, so it can't be turned off.", "error")
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


@bp.get("/users")
@admin_required
def users():
    rows = db().execute("SELECT * FROM users ORDER BY username COLLATE NOCASE").fetchall()
    return render_template("auth/users.html", users=rows, roles=ROLES, min_password=MIN_PASSWORD)


@bp.post("/users")
@admin_required
def users_create():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "user")
    if not USERNAME_RE.match(username):
        flash("Usernames are 2 to 64 letters, digits, dots, dashes, underscores or @.", "error")
    elif role not in ROLES:
        flash("Unknown role.", "error")
    elif problem := password_problem(password):
        flash(problem, "error")
    elif db().execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
        flash(f"User {username} already exists.", "error")
    else:
        create_user(username, password, role, must_change=bool(request.form.get("must_change")))
        flash(f"User {username} created.", "ok")
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
            flash("You can't delete the last active admin.", "error")
        else:
            db().execute("DELETE FROM projects WHERE owner_id = ?", (uid,))
            db().execute("DELETE FROM users WHERE id = ?", (uid,))
            flash(f"User {name} deleted.", "ok")
    elif action == "role":
        role = request.form.get("role")
        if role not in ROLES:
            flash("Unknown role.", "error")
        elif role != "admin" and target["role"] == "admin" and count_admins(exclude_id=uid) == 0:
            flash("You can't remove the last active admin.", "error")
        else:
            db().execute("UPDATE users SET role = ? WHERE id = ?", (role, uid))
            flash(f"{name} is now {role}.", "ok")
    elif action == "toggle":
        if uid == me["id"]:
            flash("You can't disable your own account.", "error")
        elif target["active"] and target["role"] == "admin" and count_admins(exclude_id=uid) == 0:
            flash("You can't disable the last active admin.", "error")
        else:
            db().execute("UPDATE users SET active = ? WHERE id = ?", (0 if target["active"] else 1, uid))
            flash(f"{name} {'disabled' if target['active'] else 'enabled'}.", "ok")
    elif action == "reset2fa":
        db().execute("UPDATE users SET totp_secret = NULL, totp_last = NULL, recovery = NULL WHERE id = ?", (uid,))
        log.info("2FA of %r reset by %r", name, me["username"])
        flash(f"Two-factor sign-in for {name} was reset. They can set it up again on My account.", "ok")
    elif action == "reset":
        password = request.form.get("password", "")
        if problem := password_problem(password):
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
        SESSION_COOKIE_NAME="exbuilder_session",
        PERMANENT_SESSION_LIFETIME=int(os.environ.get("EXB_SESSION_HOURS", "12")) * 3600,
    )
    _init_storage(app)
    app.register_blueprint(bp)
    app.before_request(_load_user)
    app.teardown_appcontext(_close_db)

    @app.context_processor
    def inject_user():
        return {"current_user": current_user(), "csrf_token": session.get("csrf", "")}
