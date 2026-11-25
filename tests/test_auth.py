import base64
import re
import time

import pytest

flask = pytest.importorskip("flask")

ADMIN = ("admin", "admin-password-1")


@pytest.fixture
def app(monkeypatch, tmp_path):
    monkeypatch.setenv("EXB_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("EXB_USERNAME", ADMIN[0])
    monkeypatch.setenv("EXB_PASSWORD", ADMIN[1])
    monkeypatch.delenv("EXB_PASSWORD_FILE", raising=False)
    from exbuilder.web import auth, create_app

    monkeypatch.setattr(auth.time, "sleep", lambda _s: None)
    app = create_app()
    app.testing = True
    return app


def login(client, username, password):
    resp = client.post("/login", data={"username": username, "password": password})
    return resp


def csrf(client, path="/"):
    page = client.get(path, follow_redirects=True).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)


@pytest.fixture
def admin(app):
    client = app.test_client()
    assert login(client, *ADMIN).status_code == 302
    return client


def basic(username, password):
    return {"Authorization": "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()}


# ------------------------------------------------------------------ basics
def test_healthz_is_open(app):
    assert app.test_client().get("/healthz").json["status"] == "ok"


def test_pages_redirect_to_login(app):
    resp = app.test_client().get("/")
    assert resp.status_code == 302 and "/login" in resp.location


def test_login_page_skipped_when_signed_in(admin):
    # The browser's Back button lands on /login after signing in; it must not
    # show the form again (or look like a sign-out) while the session is valid.
    resp = admin.get("/login")
    assert resp.status_code == 302 and resp.location.endswith("/")
    resp = admin.get("/login?next=/clients")
    assert resp.status_code == 302 and resp.location.endswith("/clients")
    assert admin.get("/login/code").status_code == 302
    assert admin.get("/help").status_code == 200


def test_login_page_shown_after_sign_out(admin):
    admin.post("/logout", data={"csrf_token": csrf(admin)})
    assert admin.get("/login").status_code == 200


def test_wrong_password_rejected(app):
    resp = login(app.test_client(), "admin", "nope")
    assert resp.status_code == 200 and b"Wrong username or password" in resp.data


def test_default_admin_must_change_password(monkeypatch, tmp_path):
    monkeypatch.setenv("EXB_DATA_DIR", str(tmp_path))
    monkeypatch.delenv("EXB_USERNAME", raising=False)
    monkeypatch.delenv("EXB_PASSWORD", raising=False)
    monkeypatch.delenv("EXB_PASSWORD_FILE", raising=False)
    from exbuilder.web import auth, create_app

    monkeypatch.setattr(auth.time, "sleep", lambda _s: None)
    client = create_app().test_client()
    assert "/login" in client.get("/").location
    assert login(client, "admin", "admin").status_code == 302
    assert "/account" in client.get("/").location  # has to choose a new password first
    assert client.get("/api/models", headers=basic("admin", "admin")).status_code == 403
    token = csrf(client, "/account")
    resp = client.post("/account", data={"current": "admin", "password": "short", "confirm": "short",
                                         "csrf_token": token}, follow_redirects=True)
    assert b"at least 10 characters" in resp.data
    client.post("/account", data={"current": "admin", "password": "new-admin-password", "csrf_token": token,
                                  "confirm": "new-admin-password"})
    assert client.get("/help").status_code == 200
    assert login(create_app().test_client(), "admin", "admin").status_code == 200  # old password refused


def test_password_is_hashed(app, tmp_path):
    raw = (tmp_path / "users.db").read_bytes()
    assert ADMIN[1].encode() not in raw and b"scrypt" in raw


# ------------------------------------------------------------------ users

# ----------------------------------------------------------- user management
def add_user(admin, username="bob", password="bob-password-1", role="user", must_change=False):
    data = {"username": username, "password": password, "level": "super" if role == "admin" else "viewer",
            "csrf_token": csrf(admin, "/users")}
    if must_change:
        data["must_change"] = "1"
    return admin.post("/users", data=data, follow_redirects=True)


def user_id(app, username):
    from exbuilder.web import auth

    with app.app_context():
        return auth.db().execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]


def test_admin_creates_user_who_can_sign_in(app, admin):
    assert b"User bob created" in add_user(admin).data
    bob = app.test_client()
    assert login(bob, "bob", "bob-password-1").status_code == 302
    assert bob.get("/help").status_code == 200
    assert bob.get("/users").status_code == 403  # not an admin


def test_short_password_rejected(admin):
    assert b"at least 10 characters" in add_user(admin, password="short").data


def test_duplicate_user_rejected(admin):
    add_user(admin)
    assert b"already exists" in add_user(admin, username="BOB").data


def test_must_change_password_on_first_login(app, admin):
    add_user(admin, must_change=True)
    bob = app.test_client()
    login(bob, "bob", "bob-password-1")
    assert "/account" in bob.get("/").location
    token = csrf(bob, "/account")
    bob.post("/account", data={"current": "bob-password-1", "password": "bob-new-password",
                               "confirm": "bob-new-password", "csrf_token": token})
    assert bob.get("/help").status_code == 200


def test_disable_role_reset_and_delete(app, admin):
    add_user(admin)
    uid = user_id(app, "bob")

    def act(**data):
        data["csrf_token"] = csrf(admin, "/users")
        return admin.post(f"/users/{uid}", data=data, follow_redirects=True)

    assert b"bob disabled" in act(action="toggle").data
    assert login(app.test_client(), "bob", "bob-password-1").status_code == 200  # refused
    act(action="toggle")
    assert b"bob: Super Admin, all clients" in act(action="access", level="super").data
    assert b"Password for bob reset" in act(action="reset", password="reset-password-1").data
    assert login(app.test_client(), "bob", "reset-password-1").status_code == 302
    assert b"User bob deleted" in act(action="delete").data


def test_password_reset_signs_out_existing_sessions(app, admin):
    add_user(admin)
    bob = app.test_client()
    login(bob, "bob", "bob-password-1")
    assert bob.get("/help").status_code == 200
    uid = user_id(app, "bob")
    admin.post(f"/users/{uid}", data={"action": "reset", "password": "reset-password-1",
                                      "csrf_token": csrf(admin, "/users")})
    assert "/login" in bob.get("/").location


def test_last_admin_is_protected(app, admin):
    uid = user_id(app, "admin")
    token = csrf(admin, "/users")
    resp = admin.post(f"/users/{uid}", data={"action": "access", "level": "admin", "scope": "all", "csrf_token": token},
                      follow_redirects=True)
    assert b"last active Super Admin" in resp.data
    resp = admin.post(f"/users/{uid}", data={"action": "delete", "csrf_token": token}, follow_redirects=True)
    assert b"can&#39;t delete your own account" in resp.data


def test_logout(admin):
    admin.post("/logout", data={"csrf_token": csrf(admin)})
    assert "/login" in admin.get("/").location


def test_concurrent_first_start(monkeypatch, tmp_path):
    """Several workers starting on an empty volume must not fail."""
    import multiprocessing as mp

    monkeypatch.setenv("EXB_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("EXB_USERNAME", ADMIN[0])
    monkeypatch.setenv("EXB_PASSWORD", ADMIN[1])
    ctx = mp.get_context("fork")
    procs = [ctx.Process(target=_start_app) for _ in range(6)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
    assert [p.exitcode for p in procs] == [0] * 6
    import sqlite3

    assert sqlite3.connect(tmp_path / "users.db").execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1


def _start_app():
    from exbuilder.web import create_app

    create_app()


# ------------------------------------------------------- two-factor sign-in
def _setup_2fa(client):
    from exbuilder.web import twofactor

    page = client.get("/account/2fa").get_data(as_text=True)
    secret = re.search(r'<code class="secret">([A-Z2-7]+)</code>', page).group(1)
    assert "<svg" in page
    token = csrf(client, "/account/2fa")
    resp = client.post("/account/2fa", data={"code": twofactor.code_at(secret, int(time.time() // 30)),
                                             "csrf_token": token})
    codes = re.search(r"<pre class=\"codes\">(.*?)</pre>", resp.get_data(as_text=True), re.S).group(1).split()
    assert resp.status_code == 200 and len(codes) == 10
    return secret, codes


def test_2fa_setup_and_login(app, admin):
    from exbuilder.web import twofactor

    add_user(admin)
    bob = app.test_client()
    login(bob, "bob", "bob-password-1")
    secret, codes = _setup_2fa(bob)

    fresh = app.test_client()
    resp = login(fresh, "bob", "bob-password-1")
    assert "/login/code" in resp.location
    assert "/login" in fresh.get("/").location  # not signed in yet
    assert b"didn&#39;t work" in fresh.post("/login/code", data={"code": "000000"}).data
    now = int(time.time() // 30)
    code = twofactor.code_at(secret, now + 1)  # the next step, so it wasn't used during setup
    assert fresh.post("/login/code", data={"code": code}).status_code == 302
    assert fresh.get("/help").status_code == 200

    # The same code can't be used twice.
    again = app.test_client()
    login(again, "bob", "bob-password-1")
    assert again.post("/login/code", data={"code": code}).status_code == 200

    # A recovery code works once.
    rec = app.test_client()
    login(rec, "bob", "bob-password-1")
    assert rec.post("/login/code", data={"code": codes[0].upper()}).status_code == 302
    rec2 = app.test_client()
    login(rec2, "bob", "bob-password-1")
    assert rec2.post("/login/code", data={"code": codes[0]}).status_code == 200

    # Admin resets it; bob signs in with the password alone again.
    uid = user_id(app, "bob")
    resp = admin.post(f"/users/{uid}", data={"action": "reset2fa", "csrf_token": csrf(admin, "/users")},
                      follow_redirects=True)
    assert b"was reset" in resp.data
    assert login(app.test_client(), "bob", "bob-password-1").location.endswith("/")


def test_require_2fa(monkeypatch, app, admin):
    monkeypatch.setenv("EXB_REQUIRE_2FA", "true")
    assert "/account/2fa" in admin.get("/").location
    _setup_2fa(admin)
    assert admin.get("/help").status_code == 200


def test_lockout_after_failed_logins(app, admin):
    add_user(admin)
    for _ in range(5):
        assert login(app.test_client(), "bob", "wrong-password").status_code == 200
    resp = login(app.test_client(), "bob", "bob-password-1")
    assert resp.status_code == 429 and b"Too many failed attempts" in resp.data
    assert app.test_client().get("/api/models", headers=basic("bob", "bob-password-1")).status_code == 429
    # Other users are not affected.
    assert login(app.test_client(), *ADMIN).status_code == 302


def test_admins_must_use_2fa(monkeypatch, app, admin):
    add_user(admin)
    monkeypatch.setenv("EXB_REQUIRE_2FA_ADMINS", "true")
    # A plain user is not asked.
    bob = app.test_client()
    login(bob, "bob", "bob-password-1")
    assert bob.get("/help").status_code == 200
    # The server admin is sent to set it up, and the API refuses them until then.
    assert "/account/2fa" in admin.get("/").location
    assert app.test_client().get("/api/models", headers=basic(*ADMIN)).status_code == 403
    _setup_2fa(admin)
    assert admin.get("/help").status_code == 200
    # And it can't be turned off again.
    page = admin.post("/account/2fa/off", data={"csrf_token": csrf(admin, "/account"), "current": ADMIN[1]},
                      follow_redirects=True).get_data(as_text=True)
    assert "can&#39;t be turned off" in page or "can't be turned off" in page


def test_lockout_is_per_address(app, admin):
    add_user(admin)
    attacker = {"REMOTE_ADDR": "203.0.113.9"}
    for _ in range(5):
        c = app.test_client()
        assert c.post("/login", data={"username": "bob", "password": "nope"}, environ_base=attacker).status_code == 200
    c = app.test_client()
    assert c.post("/login", data={"username": "bob", "password": "bob-password-1"},
                  environ_base=attacker).status_code == 429
    # Bob, from his own address, still gets in.
    assert app.test_client().post("/login", data={"username": "bob", "password": "bob-password-1"},
                                  environ_base={"REMOTE_ADDR": "10.1.1.5"}).status_code == 302


def test_lockout_across_usernames(monkeypatch, app, admin):
    monkeypatch.setenv("EXB_LOCKOUT_IP_ATTEMPTS", "6")
    add_user(admin)
    sprayer = {"REMOTE_ADDR": "198.51.100.7"}
    for i in range(6):
        app.test_client().post("/login", data={"username": f"guess{i}", "password": "Winter2026!"}, environ_base=sprayer)
    resp = app.test_client().post("/login", data={"username": "bob", "password": "bob-password-1"},
                                  environ_base=sprayer)
    assert resp.status_code == 429


def test_forwarded_for_only_from_a_proxy(app):
    from exbuilder.web import auth

    with app.test_request_context(environ_base={"REMOTE_ADDR": "10.40.45.202"},
                                  headers={"X-Forwarded-For": "1.2.3.4, 203.0.113.9"}):
        assert auth.client_ip() == "203.0.113.9"  # the entry the proxy added, not the browser's
    with app.test_request_context(environ_base={"REMOTE_ADDR": "8.8.8.8"},
                                  headers={"X-Forwarded-For": "10.0.0.1"}):
        assert auth.client_ip() == "8.8.8.8"  # a public client can't claim another address


def test_api_token_and_2fa(app, admin):
    add_user(admin)
    bob = app.test_client()
    login(bob, "bob", "bob-password-1")
    _setup_2fa(bob)
    resp = bob.post("/account/token", data={"action": "new", "csrf_token": csrf(bob, "/account")})
    token = re.search(r"exb_[A-Za-z0-9_-]+", resp.get_data(as_text=True)).group(0)
    client = app.test_client()
    # With 2FA on, the password alone doesn't open the API, the token does.
    assert client.post("/api/generate", headers=basic("bob", "bob-password-1"), json={}).status_code == 401
    resp = client.post("/api/generate", headers=basic("bob", token), json={"system": {"hostname": "sw1"}})
    assert resp.status_code == 200 and "host-name sw1" in resp.json["set"]


def test_totp_matches_rfc6238():
    from exbuilder.web import twofactor

    secret = base64.b32encode(b"12345678901234567890").decode()
    # RFC 6238 appendix B, SHA-1, last 6 digits.
    assert twofactor.code_at(secret, 59 // 30) == "287082"
    assert twofactor.code_at(secret, 1111111109 // 30) == "081804"
    assert twofactor.check(secret, "287 082", now=59) == 1
    assert twofactor.check(secret, "287082", last_step=1, now=59) is None


# ----------------------------------------------------------- upgrade mode