"""Sign-in with a company directory: LDAP / Active Directory and OpenID Connect.

OpenID Connect (OIDC) covers Microsoft Entra ID (Azure AD), Google Workspace,
Okta, Authentik, Keycloak, JumpCloud and most other identity providers. SAML
lives in saml.py. Local accounts always keep working, so a Super Admin can
sign in when the directory is down.

A Super Admin sets everything up on **Sign-in settings** (``/signin-settings``).
Settings are kept in the ``sso_settings`` table; the LDAP bind password and the
OIDC client secret are encrypted with the master key (see clients.py).

Who gets what: each provider has group rules, one per line::

    <group> = <level> @ <clients>

``level`` is readonly, configurator, admin or superadmin; ``clients`` is
``all`` or a comma separated list of client names. At every sign-in the
person's access is set from the rules their groups match (the highest level
wins, client lists add up). When no rule matches, the sign-in is refused, or
(if "Let people in without a matching group" is on) a new person is created
with no clients and an existing person keeps the access a Super Admin gave.

Two-factor: people from OIDC and SAML sign in with the identity provider's own
MFA, so the app's authenticator codes are not asked. LDAP only checks a
password, so LDAP users follow the same 2FA rules as local users.
"""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import secrets
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from flask import Blueprint, abort, flash, redirect, render_template, request, session, url_for

from . import auth, clients

bp = Blueprint("sso", __name__, template_folder="templates")
log = logging.getLogger("exbuilder.sso")

SCHEMA = """
CREATE TABLE IF NOT EXISTS sso_settings (
    name TEXT PRIMARY KEY,
    data TEXT NOT NULL
);
"""
USER_COLUMNS = {
    "source": "TEXT NOT NULL DEFAULT 'local'",   # local, ldap, oidc or saml
    "external_id": "TEXT",                       # the provider's id for the person (OIDC sub, LDAP DN, SAML NameID)
}
SOURCES = {"local": "Local", "ldap": "LDAP / AD", "oidc": "OIDC", "saml": "SAML"}
LEVEL_WORDS = {"readonly": "viewer", "read-only": "viewer", "viewer": "viewer", "configurator": "editor",
               "editor": "editor", "admin": "admin", "superadmin": "super", "super-admin": "super", "super": "super"}
LEVEL_RANK = {"viewer": 0, "editor": 1, "admin": 2, "super": 3}
SECRET_FIELDS = {"ldap": "bind_password", "oidc": "client_secret", "saml": None}

DEFAULTS = {
    "general": {"base_url": ""},
    "ldap": {"enabled": False, "label": "Company directory", "url": "", "starttls": False, "verify_tls": True,
             "ca_pem": "", "bind_dn": "", "bind_password": "", "base_dn": "",
             "user_filter": "(&(objectClass=user)(sAMAccountName={username}))", "group_attr": "memberOf",
             "nested_ad": True, "rules": "", "allow_unmapped": False},
    "oidc": {"enabled": False, "label": "Microsoft", "issuer": "", "client_id": "", "client_secret": "",
             "scopes": "openid email profile", "username_claim": "preferred_username", "groups_claim": "groups",
             "email_domains": "", "rules": "", "allow_unmapped": False},
}


# ----------------------------------------------------------------- storage
def migrate(conn) -> None:
    conn.executescript(SCHEMA)
    have = {r[1] for r in conn.execute("PRAGMA table_info(users)")}
    for column, kind in USER_COLUMNS.items():
        if column not in have:
            conn.execute(f"ALTER TABLE users ADD COLUMN {column} {kind}")


def settings(name: str) -> dict:
    """A provider's settings with secrets decrypted (server side only)."""
    row = auth.db().execute("SELECT data FROM sso_settings WHERE name = ?", (name,)).fetchone()
    out = dict(DEFAULTS.get(name, {}))
    if row:
        out.update(json.loads(row["data"]))
    field = SECRET_FIELDS.get(name)
    if field and out.get(field):
        try:
            out[field] = clients._fernet().decrypt(out[field].encode()).decode()
        except Exception:  # master key changed: the secret has to be typed again
            out[field] = ""
    return out


def save_settings(name: str, data: dict) -> None:
    data = dict(data)
    field = SECRET_FIELDS.get(name)
    if field and data.get(field):
        data[field] = clients._fernet().encrypt(data[field].encode()).decode()
    auth.db().execute("INSERT INTO sso_settings (name, data) VALUES (?, ?) ON CONFLICT (name) DO UPDATE SET "
                      "data = excluded.data", (name, json.dumps(data)))
    auth.db().commit()


def enabled(name: str) -> bool:
    try:
        return bool(settings(name).get("enabled"))
    except Exception:
        return False


def base_url() -> str:
    """The address people use to open the app, for redirect URLs (Nginx Proxy Manager sits in front)."""
    url = settings("general").get("base_url", "").strip().rstrip("/")
    return url or request.url_root.rstrip("/")


# ------------------------------------------------------------- group rules
def parse_rules(text: str) -> tuple[list[dict], list[str]]:
    """Group rules from the settings box. Returns (rules, problems)."""
    names = {r["name"].lower(): r["id"] for r in auth.db().execute("SELECT id, name FROM clients")}
    rules, problems = [], []
    for n, raw in enumerate(str(text or "").splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^(.+?)\s*=\s*([A-Za-z-]+)\s*(?:@\s*(.+))?$", line)
        if not m:
            problems.append(f"Line {n}: write it as  group = level @ clients")
            continue
        group, word, where = m.group(1).strip(), m.group(2).lower(), (m.group(3) or "all").strip()
        level = LEVEL_WORDS.get(word)
        if level is None:
            problems.append(f"Line {n}: unknown level {word!r} (use readonly, configurator, admin or superadmin)")
            continue
        if level == "super" or where.lower() == "all":
            rules.append({"group": group, "level": level, "all": True, "clients": []})
            continue
        ids, missing = [], []
        for name in (x.strip() for x in where.split(",")):
            if name:
                (ids.append(names[name.lower()]) if name.lower() in names else missing.append(name))
        if missing:
            problems.append(f"Line {n}: no client called {', '.join(missing)}")
        rules.append({"group": group, "level": level, "all": False, "clients": ids})
    return rules, problems


def _group_matches(rule_group: str, groups: list[str]) -> bool:
    """A rule names a group by its full DN, its CN, its name or (Entra ID) its object id; case does not matter."""
    want = rule_group.strip().lower()
    for g in groups:
        g = str(g).strip().lower()
        if g == want:
            return True
        cn = re.match(r"^cn=([^,]+)", g)
        if cn and cn.group(1) == want:
            return True
    return False


def access_from_groups(provider: str, groups: list[str]) -> tuple[str, str, list[int]] | None:
    """(level, scope, client ids) from the provider's rules, or None when no rule matches."""
    rules, _ = parse_rules(settings(provider).get("rules", ""))
    hits = [r for r in rules if _group_matches(r["group"], groups)]
    if not hits:
        return None
    if any(r["level"] == "super" for r in hits):
        return "super", "all", []
    top = max(hits, key=lambda r: LEVEL_RANK[r["level"]])
    if top["all"]:
        return top["level"], "all", []
    # Chosen clients: the highest level, in every client any matching rule names.
    ids = sorted({cid for r in hits for cid in r["clients"]})
    return top["level"], "some", ids


def sign_in_external(provider: str, username: str, external_id: str, groups: list[str]):
    """Find or create the user for a directory sign-in and set their access. Returns the user row or an error string."""
    username = re.sub(r"[^A-Za-z0-9_.@-]", "_", username.strip())[:64]
    if not auth.USERNAME_RE.match(username):
        return "The identity provider did not send a usable username."
    db = auth.db()
    user = db.execute("SELECT * FROM users WHERE source = ? AND external_id = ?", (provider, external_id)).fetchone()
    if user is None:
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if user is not None and user["source"] != provider:
            log.warning("%s sign-in for %r refused: a %s account with that name exists", provider, username,
                        user["source"])
            return (f"There is already a {SOURCES.get(user['source'], user['source'])} account called {username}. "
                    "Ask a Super Admin to remove it, or to rename it, first.")
    access = access_from_groups(provider, groups)
    if access is None and not settings(provider).get("allow_unmapped"):
        log.warning("%s sign-in for %r refused: no group rule matches (groups: %s)", provider, username,
                    ", ".join(map(str, groups))[:500])
        return "You are not in any group that has access to this app. Ask your administrator."
    if user is None:
        db.execute("INSERT INTO users (username, password_hash, role, created_at, source, external_id) "
                   "VALUES (?, ?, 'user', ?, ?, ?)",
                   (username, auth._hash(secrets.token_urlsafe(32)), auth._now(), provider, external_id))
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        log.warning("audit: %s sign-in created user %r", provider, username)
    elif user["external_id"] != external_id:
        db.execute("UPDATE users SET external_id = ? WHERE id = ?", (external_id, user["id"]))
    if not user["active"]:
        return "Your account is disabled here. Ask a Super Admin."
    if access is not None:
        if user["role"] == "admin" and access[0] != "super" and auth.count_admins(exclude_id=user["id"]) == 0:
            log.warning("%s sign-in: kept %r as Super Admin, the last one", provider, username)
        else:
            auth.set_access(user["id"], *access)
    db.commit()
    return db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)).fetchone()


# -------------------------------------------------------------------- LDAP
def _ldap_server(cfg: dict):
    import ldap3
    tls = None
    if cfg["url"].lower().startswith("ldaps://") or cfg.get("starttls"):
        kwargs = {"validate": ssl.CERT_REQUIRED if cfg.get("verify_tls", True) else ssl.CERT_NONE}
        if cfg.get("ca_pem", "").strip():
            kwargs["ca_certs_data"] = cfg["ca_pem"]
        tls = ldap3.Tls(**kwargs)
    servers = [ldap3.Server(u.strip(), tls=tls, connect_timeout=5, get_info=ldap3.NONE)
               for u in re.split(r"[\s,]+", cfg["url"]) if u.strip()]
    return ldap3.ServerPool(servers, ldap3.FIRST, active=1, exhaust=True) if len(servers) > 1 else servers[0]


def _ldap_connect(cfg: dict, user: str | None, password: str | None):
    """A bound connection, or raises. Tests replace this with a mock directory."""
    import ldap3
    conn = ldap3.Connection(_ldap_server(cfg), user=user, password=password, receive_timeout=10,
                            raise_exceptions=True, auto_bind=ldap3.AUTO_BIND_NONE)
    conn.open()
    if cfg.get("starttls") and not cfg["url"].lower().startswith("ldaps://"):
        conn.start_tls()
    conn.bind()
    return conn


def _ldap_find(cfg: dict, conn, username: str):
    """(dn, groups) of a user, or None."""
    from ldap3.utils.conv import escape_filter_chars
    attr = cfg.get("group_attr") or "memberOf"
    flt = cfg["user_filter"].replace("{username}", escape_filter_chars(username))
    conn.search(cfg["base_dn"], flt, attributes=[attr], size_limit=2)
    entries = [e for e in conn.response or [] if e.get("type") == "searchResEntry"]
    if len(entries) != 1:
        return None
    dn = entries[0]["dn"]
    groups = [str(g) for g in (entries[0].get("attributes", {}).get(attr) or [])]
    if cfg.get("nested_ad"):
        # Active Directory: groups inside groups, via the "in chain" matching rule.
        try:
            conn.search(cfg["base_dn"], f"(member:1.2.840.113556.1.4.1941:={escape_filter_chars(dn)})",
                        attributes=["cn"], size_limit=500)
            groups += [e["dn"] for e in conn.response or [] if e.get("type") == "searchResEntry"]
        except Exception:  # not AD, or not allowed: direct groups only
            pass
    return dn, sorted(set(groups), key=str.lower)


def ldap_login(username: str, password: str):
    """Check a username and password against the directory. Returns the user row, an error string, or None (wrong)."""
    cfg = settings("ldap")
    if not cfg.get("enabled") or not cfg.get("url") or not password:
        return None  # never bind with an empty password: that is an anonymous bind and always "succeeds"
    try:
        svc = _ldap_connect(cfg, cfg.get("bind_dn") or None, cfg.get("bind_password") or None)
        found = _ldap_find(cfg, svc, username)
        svc.unbind()
    except Exception as exc:
        log.error("LDAP lookup failed: %s", exc)
        return "The company directory can't be reached right now. Try again, or use a local account."
    if found is None:
        return None
    dn, groups = found
    try:
        _ldap_connect(cfg, dn, password).unbind()
    except Exception:
        return None
    return sign_in_external("ldap", username, dn, groups)


def ldap_test(cfg: dict, username: str = "") -> str:
    svc = _ldap_connect(cfg, cfg.get("bind_dn") or None, cfg.get("bind_password") or None)
    msg = "Connected and signed in with the service account."
    if username:
        found = _ldap_find(cfg, svc, username)
        if found is None:
            msg += f" No single user matched {username}."
        else:
            access = None
            rules, _ = parse_rules(cfg.get("rules", ""))
            hits = [r["group"] for r in rules if _group_matches(r["group"], found[1])]
            msg += f" Found {found[0]} in {len(found[1])} group(s)."
            msg += f" Matching rules: {', '.join(hits)}." if hits else " No group rule matches this user."
            del access
    svc.unbind()
    return msg


# -------------------------------------------------------------------- OIDC
_DISCOVERY: dict[str, tuple[float, dict]] = {}


def _https_ok(url: str) -> bool:
    p = urllib.parse.urlparse(url)
    return p.scheme == "https" or (p.scheme == "http" and p.hostname in ("localhost", "127.0.0.1"))


def _http_json(url: str, data: dict | None = None, headers: dict | None = None) -> dict:
    """GET (or form POST) a JSON document. Tests replace this."""
    if not _https_ok(url):
        raise ValueError(f"{url} is not https")
    body = urllib.parse.urlencode(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"Accept": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310 (https checked above)
        return json.loads(resp.read(2_000_000).decode())


def discovery(issuer: str) -> dict:
    issuer = issuer.rstrip("/")
    hit = _DISCOVERY.get(issuer)
    if hit and time.time() - hit[0] < 3600:
        return hit[1]
    doc = _http_json(issuer + "/.well-known/openid-configuration")
    for key in ("authorization_endpoint", "token_endpoint", "issuer"):
        if not isinstance(doc.get(key), str):
            raise ValueError(f"The provider's discovery document has no {key}.")
    _DISCOVERY[issuer] = (time.time(), doc)
    return doc


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _jwt_claims(token: str) -> dict:
    part = token.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))


def oidc_redirect_uri() -> str:
    return base_url() + url_for("sso.oidc_callback")


@bp.get("/sso/oidc")
def oidc_start():
    cfg = settings("oidc")
    if not cfg.get("enabled"):
        abort(404)
    try:
        doc = discovery(cfg["issuer"])
    except Exception as exc:
        log.error("OIDC discovery failed: %s", exc)
        flash(f"{cfg['label']} sign-in is not reachable right now. Use your username and password.", "error")
        return redirect(url_for("auth.login"))
    verifier = secrets.token_urlsafe(48)
    state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
    session["oidc"] = {"state": state, "nonce": nonce, "verifier": verifier, "until": time.time() + 600,
                       "next": request.args.get("next")}
    params = {"response_type": "code", "client_id": cfg["client_id"], "redirect_uri": oidc_redirect_uri(),
              "scope": cfg.get("scopes") or "openid email profile", "state": state, "nonce": nonce,
              "code_challenge": _b64(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"}
    sep = "&" if "?" in doc["authorization_endpoint"] else "?"
    return redirect(doc["authorization_endpoint"] + sep + urllib.parse.urlencode(params))


def _oidc_fail(message: str, detail: str = ""):
    log.warning("OIDC sign-in failed: %s %s", message, detail)
    session.pop("oidc", None)
    return render_template("auth/login.html", error=message, providers=login_providers()), 403


@bp.get("/sso/oidc/callback")
def oidc_callback():
    cfg = settings("oidc")
    pending = session.get("oidc") or {}
    if not cfg.get("enabled"):
        abort(404)
    if request.args.get("error"):
        return _oidc_fail("The identity provider did not sign you in.", request.args.get("error_description", "")[:300])
    if (not pending or time.time() > pending.get("until", 0)
            or not secrets.compare_digest(str(request.args.get("state", "")), str(pending.get("state", "")))):
        return _oidc_fail("That sign-in link expired. Try again.")
    try:
        doc = discovery(cfg["issuer"])
        token = _http_json(doc["token_endpoint"], {
            "grant_type": "authorization_code", "code": request.args.get("code", ""),
            "redirect_uri": oidc_redirect_uri(), "client_id": cfg["client_id"],
            "client_secret": cfg.get("client_secret", ""), "code_verifier": pending["verifier"]})
        # The id_token came straight from the token endpoint over verified TLS, so (OpenID Connect
        # Core 3.1.3.7) the TLS check stands in for the signature check. Every claim is still checked.
        claims = _jwt_claims(token["id_token"])
    except Exception as exc:
        return _oidc_fail("Sign-in with the identity provider failed. Try again.", str(exc)[:300])
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    if (claims.get("iss") != doc["issuer"] or cfg["client_id"] not in auds or float(claims.get("exp", 0)) < time.time() - 60
            or not secrets.compare_digest(str(claims.get("nonce", "")), str(pending["nonce"]))):
        return _oidc_fail("The identity provider's answer did not check out.", json.dumps(
            {k: claims.get(k) for k in ("iss", "aud", "exp")}))
    if doc.get("userinfo_endpoint") and token.get("access_token"):
        try:
            info = _http_json(doc["userinfo_endpoint"], headers={"Authorization": f"Bearer {token['access_token']}"})
            if info.get("sub") == claims.get("sub"):
                claims = {**info, **claims}
        except Exception as exc:
            log.info("OIDC userinfo not used: %s", exc)
    email = str(claims.get("email") or "")
    domains = [d.strip().lower().lstrip("@") for d in re.split(r"[\s,]+", cfg.get("email_domains", "")) if d.strip()]
    if domains and (email.rsplit("@", 1)[-1].lower() not in domains or claims.get("email_verified") is False):
        return _oidc_fail("Your account's email domain is not allowed here.", email)
    username = str(claims.get(cfg.get("username_claim") or "preferred_username") or email or claims.get("sub", ""))
    groups = claims.get(cfg.get("groups_claim") or "groups") or []
    groups = [groups] if isinstance(groups, str) else [str(g) for g in groups]
    user = sign_in_external("oidc", username, str(claims.get("sub", "")), groups)
    session.pop("oidc", None)
    if isinstance(user, str):
        return _oidc_fail(user)
    log.info("OIDC sign-in of %r", user["username"])
    return auth._finish_login(user, pending.get("next"))


# ---------------------------------------------------------- settings page
def login_providers() -> list[dict]:
    """Buttons on the sign-in page."""
    out = []
    try:
        if enabled("oidc"):
            out.append({"label": settings("oidc")["label"] or "single sign-on", "url": url_for("sso.oidc_start")})
        from . import saml
        if saml.enabled():
            out.append({"label": settings("saml")["label"] or "SAML", "url": url_for("saml.start")})
    except Exception as exc:  # never block the local sign-in page
        log.error("sign-in providers: %s", exc)
    return out


def _form_bool(name: str) -> bool:
    return request.form.get(name) == "1"


@bp.route("/signin-settings", methods=["GET", "POST"])
@auth.admin_required
def settings_page():
    me = auth.current_user()["username"]
    if request.method == "POST":
        which = request.form.get("provider")
        if which == "general":
            url = request.form.get("base_url", "").strip().rstrip("/")
            if url and not re.match(r"^https?://[A-Za-z0-9.-]+(:\d+)?$", url):
                flash("The app address looks like https://switchbuilder.example.com (no path).", "error")
            else:
                save_settings("general", {"base_url": url})
                flash("Saved.", "ok")
        elif which in ("ldap", "oidc"):
            cfg = settings(which)
            for key, default in DEFAULTS[which].items():
                if isinstance(default, bool):
                    cfg[key] = _form_bool(key)
                elif key == SECRET_FIELDS[which]:
                    if request.form.get(key):        # empty box = keep the saved secret
                        cfg[key] = request.form[key]
                    if request.form.get(key + "_clear"):
                        cfg[key] = ""
                elif key in request.form:
                    cfg[key] = request.form.get(key, "").strip() if key not in ("ca_pem", "rules") else request.form[key]
            _, problems = parse_rules(cfg.get("rules", ""))
            if which == "oidc" and cfg["issuer"] and not _https_ok(cfg["issuer"]):
                problems.append("The issuer must be an https:// address.")
            if which == "ldap" and cfg["url"] and not all(
                    re.match(r"^ldaps?://[^\s/]+$", u) for u in re.split(r"[\s,]+", cfg["url"].strip()) if u):
                problems.append("The server looks like ldaps://dc1.example.com:636 (several separated by spaces).")
            if which == "ldap" and cfg["url"].lower().startswith("ldap://") and not cfg["starttls"]:
                problems.append("Plain ldap:// sends passwords unencrypted. Use ldaps:// or tick StartTLS.")
            if cfg["enabled"] and not (cfg.get("url") if which == "ldap" else cfg.get("issuer") and cfg.get("client_id")):
                problems.append("Fill in the server details before turning this on.")
            for p in problems:
                flash(p, "error")
            if not problems:
                save_settings(which, cfg)
                log.warning("audit: %r changed %s sign-in settings (enabled=%s)", me, which, cfg["enabled"])
                flash(f"{'LDAP' if which == 'ldap' else 'OpenID Connect'} settings saved.", "ok")
        elif which == "ldap_test":
            try:
                if not str(settings("ldap").get("url") or "").strip():
                    raise ValueError("save the LDAP server address first")
                flash(ldap_test(settings("ldap"), request.form.get("test_user", "").strip()), "ok")
            except Exception as exc:
                flash(f"LDAP test failed: {exc}", "error")
        elif which == "oidc_test":
            try:
                if not str(settings("oidc").get("issuer") or "").strip():
                    raise ValueError("save the issuer URL first")
                doc = discovery(settings("oidc")["issuer"])
                flash(f"Found the provider: {doc['issuer']}.", "ok")
            except Exception as exc:
                flash(f"OpenID Connect test failed: {exc}", "error")
        else:
            from . import saml
            if not saml.handle_settings_form(which, me):
                abort(400)
        return redirect(url_for("sso.settings_page") + "#" + (which or "").split("_")[0])
    from . import saml
    ldap, oidc = settings("ldap"), settings("oidc")
    return render_template("auth/signin_settings.html", general=settings("general"), ldap=ldap, oidc=oidc,
                           ldap_secret=bool(ldap.get("bind_password")), oidc_secret=bool(oidc.get("client_secret")),
                           redirect_uri=oidc_redirect_uri(), base=base_url(), saml=saml.page_context(),
                           client_names=[r["name"] for r in auth.db().execute(
                               "SELECT name FROM clients ORDER BY name COLLATE NOCASE")])


def init_app(app) -> None:
    app.register_blueprint(bp)
    auth.PUBLIC_ENDPOINTS.update({"sso.oidc_start", "sso.oidc_callback"})
