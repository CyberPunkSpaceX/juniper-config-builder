"""Sign-in with LDAP / Active Directory, OpenID Connect and SAML."""

import base64
import json
import re
import time
import urllib.parse

import pytest

flask = pytest.importorskip("flask")
ldap3 = pytest.importorskip("ldap3")
pytest.importorskip("signxml")

from test_auth import app, admin, csrf, login  # noqa: F401,E402

from exbuilder.web import saml, sso  # noqa: E402


def _settings(admin, **data):
    return admin.post("/signin-settings", data={"csrf_token": csrf(admin, "/users"), **data}, follow_redirects=True)


def _db_user(app, username):
    from exbuilder.web import auth
    with app.app_context():
        return dict(auth.db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone() or {})


def _access(app, username):
    from exbuilder.web import auth
    with app.app_context():
        return auth.access_of(_db_user(app, username)["id"])["text"]


def test_settings_page_is_for_super_admins(app, admin):
    page = admin.get("/signin-settings").get_data(as_text=True)
    assert "LDAP / Active Directory" in page and "/sso/oidc/callback" in page and "/sso/saml/acs" in page
    assert "Sign-in</a>" in admin.get("/users").get_data(as_text=True)
    from test_auth import add_user
    add_user(admin)
    bob = app.test_client()
    login(bob, "bob", "bob-password-1")
    assert bob.get("/signin-settings").status_code == 403


def test_settings_are_checked(app, admin):
    r = _settings(admin, provider="ldap", url="ldap://dc1.example.com", base_dn="DC=x")
    assert b"sends passwords unencrypted" in r.data
    r = _settings(admin, provider="ldap", url="ldaps://dc1.example.com", rules="Admins = boss")
    assert b"unknown level" in r.data
    r = _settings(admin, provider="ldap", url="ldaps://dc1.example.com", base_dn="DC=x", bind_dn="CN=svc",
                  bind_password="svc-pass", rules="Admins = superadmin\nEng = configurator @ Default, Nope")
    assert b"no client called Nope" in r.data
    r = _settings(admin, provider="ldap", enabled="1", url="ldaps://dc1.example.com", base_dn="DC=x", bind_dn="CN=svc",
                  bind_password="svc-pass", rules="Admins = superadmin")
    assert b"LDAP settings saved" in r.data
    with app.app_context():
        from exbuilder.web import auth
        raw = auth.db().execute("SELECT data FROM sso_settings WHERE name = 'ldap'").fetchone()[0]
        assert "svc-pass" not in raw                          # stored encrypted
        assert sso.settings("ldap")["bind_password"] == "svc-pass"
    # An empty password box keeps the saved one.
    _settings(admin, provider="ldap", enabled="1", url="ldaps://dc2.example.com", base_dn="DC=x", rules="")
    with app.app_context():
        assert sso.settings("ldap")["bind_password"] == "svc-pass"
    assert b"must be an https" in _settings(admin, provider="oidc", issuer="http://idp.example.com").data


def test_group_rules(app, admin):
    admin.post("/clients", data={"csrf_token": csrf(admin, "/clients"), "name": "Acme"})
    with app.test_request_context():
        from exbuilder.web import auth
        auth.db()  # noqa
        sso.save_settings("ldap", {**sso.DEFAULTS["ldap"], "rules": "# comment\nCN=NetAdmins,OU=G,DC=x = superadmin\n"
                                   "Eng = configurator @ all\nHelp = readonly @ Acme\nAcmeAdm = admin @ Acme"})
        assert sso.access_from_groups("ldap", ["CN=Other,DC=x"]) is None
        assert sso.access_from_groups("ldap", ["CN=Help,OU=G,DC=x"]) == ("viewer", "some", [2])
        assert sso.access_from_groups("ldap", ["cn=help,ou=g,dc=x", "CN=Eng,DC=x"]) == ("editor", "all", [])
        assert sso.access_from_groups("ldap", ["CN=AcmeAdm,DC=x", "CN=Help,DC=x"]) == ("admin", "some", [2])
        assert sso.access_from_groups("ldap", ["CN=NetAdmins,OU=G,DC=x"]) == ("super", "all", [])


# ------------------------------------------------------------------- LDAP
DIR = {"cn=svc,dc=corp": "svc-pass", "cn=Jane Smith,ou=people,dc=corp": "jane-pass-1",
       "cn=Joe Nobody,ou=people,dc=corp": "joe-pass-1"}


@pytest.fixture
def directory(monkeypatch):
    server = ldap3.Server("fake")

    def connect(cfg, user, password):
        conn = ldap3.Connection(server, user=user, password=password, client_strategy=ldap3.MOCK_SYNC,
                                raise_exceptions=True)
        conn.strategy.add_entry("cn=svc,dc=corp", {"userPassword": "svc-pass", "objectClass": "person"})
        conn.strategy.add_entry("cn=Jane Smith,ou=people,dc=corp", {
            "userPassword": "jane-pass-1", "sAMAccountName": "jsmith", "objectClass": "user",
            "memberOf": ["CN=Network Engineers,OU=Groups,DC=corp"]})
        conn.strategy.add_entry("cn=Joe Nobody,ou=people,dc=corp", {
            "userPassword": "joe-pass-1", "sAMAccountName": "joe", "objectClass": "user", "memberOf": []})
        if not password:
            raise ldap3.core.exceptions.LDAPBindError("empty password")
        conn.bind()
        if not conn.bound:
            raise ldap3.core.exceptions.LDAPBindError("invalid credentials")
        return conn
    monkeypatch.setattr(sso, "_ldap_connect", connect)


def _ldap_on(admin, **extra):
    r = _settings(admin, provider="ldap", enabled="1", url="ldaps://dc1.corp", base_dn="dc=corp",
                  bind_dn="cn=svc,dc=corp", bind_password="svc-pass", user_filter="(sAMAccountName={username})",
                  rules="Network Engineers = configurator @ all", verify_tls="1", **extra)
    assert b"LDAP settings saved" in r.data


def test_ldap_sign_in(app, admin, directory):
    _ldap_on(admin)
    jane = app.test_client()
    assert login(jane, "jsmith", "wrong-password").status_code == 200
    r = login(jane, "jsmith", "jane-pass-1")
    assert r.status_code == 302
    u = _db_user(app, "jsmith")
    assert u["source"] == "ldap" and u["external_id"] == "cn=Jane Smith,ou=people,dc=corp"
    assert _access(app, "jsmith") == "Configurator, all clients"
    # Not in any mapped group: refused with a clear message.
    r = app.test_client().post("/login", data={"username": "joe", "password": "joe-pass-1"})
    assert r.status_code == 403 and b"not in any group" in r.data
    # Empty passwords never reach the directory (anonymous bind).
    assert login(app.test_client(), "jsmith", "").status_code == 200
    # The password page says the directory owns the password.
    assert "changed there" in jane.get("/account").get_data(as_text=True)
    # Test button.
    r = _settings(admin, provider="ldap_test", test_user="jsmith")
    assert b"Found cn=Jane Smith" in r.data and b"Matching rules: Network Engineers" in r.data


def test_ldap_does_not_take_over_local_accounts(app, admin, directory):
    _ldap_on(admin)
    # "admin" is a local account; a directory password for "admin" must not sign in.
    assert login(app.test_client(), "admin", "jane-pass-1").status_code == 200


def test_ldap_down_falls_back_to_local(app, admin, monkeypatch):
    _settings(admin, provider="ldap", enabled="1", url="ldaps://dc1.corp", base_dn="dc=corp")

    def down(*a):
        raise OSError("no route")
    monkeypatch.setattr(sso, "_ldap_connect", down)
    r = app.test_client().post("/login", data={"username": "someone", "password": "pw-123456789"})
    assert b"be reached right now" in r.data
    assert login(app.test_client(), "admin", "admin-password-1").status_code == 302


# ------------------------------------------------------------------- OIDC
ISSUER = "https://idp.example.com"


def _jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()  # noqa: E731
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.c2ln"


@pytest.fixture
def idp(monkeypatch):
    state = {"claims": {}, "calls": []}
    sso._DISCOVERY.clear()

    def http_json(url, data=None, headers=None):
        state["calls"].append((url, data))
        if url.endswith("/.well-known/openid-configuration"):
            return {"issuer": ISSUER, "authorization_endpoint": ISSUER + "/authorize",
                    "token_endpoint": ISSUER + "/token", "userinfo_endpoint": ISSUER + "/userinfo"}
        if url.endswith("/token"):
            return {"id_token": _jwt(state["claims"]), "access_token": "at"}
        if url.endswith("/userinfo"):
            return {"sub": state["claims"].get("sub"), "groups": state.get("userinfo_groups", [])}
        raise AssertionError(url)
    monkeypatch.setattr(sso, "_http_json", http_json)
    return state


def _oidc_round(client, idp, **claims):
    r = client.get("/sso/oidc")
    assert r.status_code == 302 and r.location.startswith(ISSUER + "/authorize?")
    q = urllib.parse.parse_qs(urllib.parse.urlparse(r.location).query)
    assert q["code_challenge_method"] == ["S256"] and q["redirect_uri"] == ["http://localhost/sso/oidc/callback"]
    idp["claims"] = {"iss": ISSUER, "aud": "client-1", "exp": time.time() + 300, "nonce": q["nonce"][0],
                     "sub": "u-123", "preferred_username": "kim@example.com", "email": "kim@example.com",
                     "groups": ["Network Admins"], **claims}
    return client.get(f"/sso/oidc/callback?code=abc&state={q['state'][0]}")


def test_oidc_sign_in(app, admin, idp, monkeypatch):
    r = _settings(admin, provider="oidc", enabled="1", label="Contoso", issuer=ISSUER, client_id="client-1",
                  client_secret="sec", scopes="openid email profile", username_claim="preferred_username",
                  groups_claim="groups", rules="Network Admins = superadmin\nEng = readonly @ Default")
    assert b"OpenID Connect settings saved" in r.data
    monkeypatch.setenv("EXB_REQUIRE_2FA_ADMINS", "true")
    login_page = app.test_client().get("/login").get_data(as_text=True)
    assert "Sign in with Contoso" in login_page
    kim = app.test_client()
    r = _oidc_round(kim, idp)
    assert r.status_code == 302, r.data
    assert _access(app, "kim@example.com") == "Super Admin, all clients"
    # The identity provider did MFA: no local 2FA setup is forced on this Super Admin.
    assert kim.get("/users").status_code == 200
    token_call = [c for c in idp["calls"] if c[0].endswith("/token")][0][1]
    assert token_call["code_verifier"] and token_call["client_secret"] == "sec"
    # Group change in the provider: access follows at the next sign-in.
    r = _oidc_round(app.test_client(), idp, groups=["Eng"])
    assert _access(app, "kim@example.com") == "Default: Read-only"


def test_oidc_checks_the_answer(app, admin, idp):
    _settings(admin, provider="oidc", enabled="1", issuer=ISSUER, client_id="client-1", rules="Network Admins = admin")
    assert _oidc_round(app.test_client(), idp, nonce="other").status_code == 403
    assert _oidc_round(app.test_client(), idp, aud="someone-else").status_code == 403
    assert _oidc_round(app.test_client(), idp, iss="https://evil.example.com").status_code == 403
    assert _oidc_round(app.test_client(), idp, exp=time.time() - 3600).status_code == 403
    assert _oidc_round(app.test_client(), idp, groups=["Nobody"]).status_code == 403
    # Wrong state.
    c = app.test_client()
    c.get("/sso/oidc")
    assert c.get("/sso/oidc/callback?code=abc&state=forged").status_code == 403
    # Email domain allow-list.
    _settings(admin, provider="oidc", enabled="1", issuer=ISSUER, client_id="client-1", rules="Network Admins = admin",
              email_domains="corp.example")
    assert b"email domain" in _oidc_round(app.test_client(), idp).data
    assert _db_user(app, "kim@example.com") == {}


def test_oidc_name_clash_with_local_account(app, admin, idp):
    _settings(admin, provider="oidc", enabled="1", issuer=ISSUER, client_id="client-1", rules="Network Admins = admin")
    r = _oidc_round(app.test_client(), idp, preferred_username="admin")
    assert r.status_code == 403 and b"already a Local account" in r.data


# ------------------------------------------------------------------- SAML
@pytest.fixture
def saml_idp():
    from datetime import datetime, timedelta, timezone
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "idp")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=30))
            .sign(key, hashes.SHA256()))
    return {"key": key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()),
            "cert": cert.public_bytes(serialization.Encoding.PEM).decode()}


def _saml_response(idp, request_id, groups=("Network Engineers",), name_id="pat@example.com", audience=None,
                   tamper=False):
    from lxml import etree
    from signxml import XMLSigner
    now = time.time()
    iso = saml._iso
    assertion = f"""<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_a1" Version="2.0" IssueInstant="{iso(now)}">
<saml:Issuer>https://idp.example.com/saml</saml:Issuer>
<saml:Subject><saml:NameID>{name_id}</saml:NameID>
<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData InResponseTo="{request_id}" NotOnOrAfter="{iso(now + 300)}" Recipient="http://localhost/sso/saml/acs"/></saml:SubjectConfirmation></saml:Subject>
<saml:Conditions NotBefore="{iso(now - 60)}" NotOnOrAfter="{iso(now + 300)}"><saml:AudienceRestriction><saml:Audience>{audience or 'http://localhost/sso/saml/metadata'}</saml:Audience></saml:AudienceRestriction></saml:Conditions>
<saml:AttributeStatement><saml:Attribute Name="groups">{''.join(f'<saml:AttributeValue>{g}</saml:AttributeValue>' for g in groups)}</saml:Attribute></saml:AttributeStatement>
</saml:Assertion>"""
    signed = XMLSigner(c14n_algorithm="http://www.w3.org/2001/10/xml-exc-c14n#").sign(
        etree.fromstring(assertion), key=idp["key"], cert=idp["cert"])
    text = etree.tostring(signed).decode()
    if tamper:
        text = text.replace("Network Engineers", "Network Admins")
    resp = (f'<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="_r1" Version="2.0" '
            f'IssueInstant="{iso(now)}" Destination="http://localhost/sso/saml/acs" InResponseTo="{request_id}">'
            f'<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
            f'{text}</samlp:Response>')
    return base64.b64encode(resp.encode()).decode()


def _saml_start(client):
    r = client.get("/sso/saml")
    assert r.status_code == 302 and r.location.startswith("https://idp.example.com/sso?SAMLRequest=")
    import zlib
    raw = urllib.parse.parse_qs(urllib.parse.urlparse(r.location).query)["SAMLRequest"][0]
    xml = zlib.decompress(base64.b64decode(raw), -15).decode()
    return re.search(r'ID="([^"]+)"', xml).group(1)


def test_saml_sign_in(app, admin, saml_idp):
    r = _settings(admin, provider="saml", enabled="1", label="Entra ID", idp_entity_id="https://idp.example.com/saml",
                  idp_sso_url="https://idp.example.com/sso", idp_cert=saml_idp["cert"], groups_attr="groups",
                  username_attr="", rules="Network Engineers = configurator @ Default\nNetwork Admins = superadmin")
    assert b"SAML settings saved" in r.data
    assert "Sign in with Entra ID" in app.test_client().get("/login").get_data(as_text=True)
    md = app.test_client().get("/sso/saml/metadata").get_data(as_text=True)
    assert 'Location="http://localhost/sso/saml/acs"' in md
    pat = app.test_client()
    rid = _saml_start(pat)
    resp = _saml_response(saml_idp, rid)
    r = pat.post("/sso/saml/acs", data={"SAMLResponse": resp})
    assert r.status_code == 302, r.data
    assert _access(app, "pat@example.com") == "Default: Configurator"
    # The same answer can't be used twice.
    assert app.test_client().post("/sso/saml/acs", data={"SAMLResponse": resp}).status_code == 403
    # A changed answer fails the signature check.
    rid = _saml_start(app.test_client())
    assert app.test_client().post("/sso/saml/acs", data={
        "SAMLResponse": _saml_response(saml_idp, rid, tamper=True)}).status_code == 403
    # Wrong audience.
    rid = _saml_start(app.test_client())
    assert app.test_client().post("/sso/saml/acs", data={
        "SAMLResponse": _saml_response(saml_idp, rid, audience="https://other")}).status_code == 403
    # An answer nobody asked for.
    assert app.test_client().post("/sso/saml/acs", data={
        "SAMLResponse": _saml_response(saml_idp, "_unknown")}).status_code == 403
    assert _access(app, "pat@example.com") == "Default: Configurator"


def test_saml_metadata_import(app, admin, saml_idp):
    body = "".join(saml_idp["cert"].splitlines()[1:-1])
    xml = f"""<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sts.example.com/t/">
<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
<KeyDescriptor use="signing"><KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>{body}</X509Certificate></X509Data></KeyInfo></KeyDescriptor>
<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://login.example.com/t/saml2"/>
</IDPSSODescriptor></EntityDescriptor>"""
    r = _settings(admin, provider="saml_metadata", metadata_xml=xml)
    assert b"Read the metadata: https://sts.example.com/t/, 1 signing" in r.data
    with app.app_context():
        cfg = sso.settings("saml")
    assert cfg["idp_sso_url"] == "https://login.example.com/t/saml2" and "BEGIN CERTIFICATE" in cfg["idp_cert"]
