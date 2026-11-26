"""Access levels: Read-only, Configurator, Admin, Super Admin; all clients or chosen ones; hidden secrets."""

import io
import re
import zipfile

import pytest

from switchbuilder import redact

flask = pytest.importorskip("flask")

from test_auth import add_user, app, admin, csrf, login, user_id  # noqa: F401,E402
from test_builder_web import token  # noqa: E402


def _client(admin, name):
    admin.post("/clients", data={"csrf_token": csrf(admin, "/clients"), "name": name})


def _create(admin, username, level, scope="some", clients=()):
    return admin.post("/users", data={"csrf_token": csrf(admin, "/users"), "username": username,
                                      "password": "long-password-1", "level": level, "scope": scope,
                                      "clients": [str(c) for c in clients]}, follow_redirects=True)


def _options(client):
    page = client.get("/build/juniper").get_data(as_text=True)
    return re.findall(r'<option value="\d+"[^>]*>([^<]*)</option>', page.split('id="client-pick"')[1].split("</select>")[0])


def _signin(app, username):
    c = app.test_client()
    assert login(c, username, "long-password-1").status_code == 302
    return c


def test_chosen_clients(app, admin):
    _client(admin, "Acme")
    _client(admin, "Beta")
    resp = _create(admin, "carol", "editor", clients=[2])
    assert b"carol created: Acme: Configurator" in resp.data
    carol = _signin(app, "carol")
    assert _options(carol) == ["Acme (Configurator)"]


def test_all_clients_includes_future_ones(app, admin):
    resp = _create(admin, "dave", "viewer", scope="all")
    assert b"dave created: Read-only, all clients" in resp.data
    _client(admin, "Later Inc")
    dave = _signin(app, "dave")
    assert _options(dave) == ["Default (Read-only)", "Later Inc (Read-only)"]
    # A client admin can still give a higher role in one client.
    admin.post("/clients/2", data={"csrf_token": csrf(admin, "/clients"), "action": "member_add",
                                   "username": "dave", "role": "admin"})
    dave = _signin(app, "dave")
    assert "Later Inc (Admin)" in dave.get("/build/juniper").get_data(as_text=True)
    # The client page lists people who have access through "all clients".
    assert "all clients, set on the Users page" in admin.get("/clients/1").get_data(as_text=True)


def test_change_access_and_super_admin(app, admin):
    _client(admin, "Acme")
    _create(admin, "erin", "viewer", clients=[1, 2])
    uid = user_id(app, "erin")

    def change(**data):
        return admin.post(f"/users/{uid}", data={"csrf_token": csrf(admin, "/users"), "action": "access", **data},
                          follow_redirects=True)
    assert b"erin: Admin, all clients" in change(level="admin", scope="all").data
    assert b"erin: Acme: Configurator" in change(level="editor", scope="some", clients=["2"]).data
    assert b"erin: Super Admin, all clients" in change(level="super").data
    erin = _signin(app, "erin")
    assert erin.get("/users").status_code == 200
    assert b"Unknown client" in change(level="viewer", scope="some", clients=["99"]).data
    page = admin.get("/users").get_data(as_text=True)
    assert "All clients, also ones added later" in page and "Configurator" in page


def test_admin_level_is_not_super_admin(app, admin):
    _create(admin, "fred", "admin", scope="all")
    fred = _signin(app, "fred")
    assert fred.get("/users").status_code == 403
    assert fred.get("/clients/1").status_code == 200          # manages the client
    assert fred.post("/clients", data={"csrf_token": csrf(fred, "/clients"), "name": "X"}).status_code == 403


SECRET_PROJECT = {"system": {"hostname": "sw1"},
                  "access": {"root_password": "$6$salt$hash", "users": [
                      {"name": "netadmin", "password": "$6$a$b", "ssh_keys": "ssh-ed25519 AAAA key"}]},
                  "snmp": {"communities": [{"name": "s3cret-comm", "access": "read-only"}],
                           "v3_users": [{"name": "nms", "auth_password": "authpw123", "priv_password": "privpw123"}]},
                  "security": {"radius_servers": [{"address": "10.0.0.30", "secret": "radkey"}]}}
CONFIG = """set system host-name sw1
set system root-authentication encrypted-password "$6$abc$def"
set system login user admin authentication encrypted-password "$9$abcdefg"
set snmp community s3cret-comm authorization read-only
set system radius-server 10.0.0.30 secret 0822455D0A16
set interfaces ge-0/0/1 description "to server"
"""


def test_read_only_never_sees_secrets(app, admin):
    h = {"X-CSRF-Token": token(admin)}
    pid = admin.post("/projects", json={"name": "P", "data": SECRET_PROJECT}, headers=h).json["id"]
    mid = admin.post("/maps", json={"name": "M", "data": {"items": [{"name": "sw1", "text": CONFIG}], "pos": {}}},
                     headers=h).json["id"]
    bid = admin.post("/backups", json={"items": [{"name": "sw1", "text": CONFIG}], "source": "upload"},
                     headers=h).json["saved"][0]["id"]
    # Configurators see everything.
    _create(admin, "conf", "editor", scope="all")
    conf = _signin(app, "conf")
    assert conf.get(f"/projects/{pid}").json["data"] == SECRET_PROJECT
    assert "s3cret-comm" in conf.get(f"/backups/{bid}").json["text"]
    # Read-only: secrets hidden everywhere.
    _create(admin, "ro", "viewer", scope="all")
    ro = _signin(app, "ro")
    p = ro.get(f"/projects/{pid}").json
    assert p["redacted"] is True and "s3cret" not in str(p) and "$6$" not in str(p) and "radkey" not in str(p)
    assert p["data"]["access"]["users"][0]["ssh_keys"] == "ssh-ed25519 AAAA key"  # public keys are not secrets
    for text in (ro.get(f"/backups/{bid}").json["text"], ro.get(f"/backups/{bid}?download=1").get_data(as_text=True),
                 ro.get(f"/maps/{mid}").json["data"]["items"][0]["text"]):
        assert "s3cret-comm" not in text and "$9$" not in text and "0822455D0A16" not in text
        assert 'description "to server"' in text and "<hidden>" in text
    z = zipfile.ZipFile(io.BytesIO(ro.get("/backups/export").data))
    assert "s3cret-comm" not in z.read(z.namelist()[0]).decode()


@pytest.mark.parametrize("line, hidden, kept", [
    ('set system root-authentication encrypted-password "$6$abc$def"', "$6$abc", "encrypted-password"),
    ("snmp-server community public RO", "public", "RO"),
    ("enable secret 5 $1$aa$bb", "$1$aa", "enable secret 5"),
    (" ip ospf message-digest-key 1 md5 7 ABCDEF", "ABCDEF", "message-digest-key 1 md5 7"),
    ("snmp-server user lib grp v3 auth sha AUTHPW priv aes 128 PRIVPW", "AUTHPW", "priv aes 128"),
    ("set password ENC SH2abc", "SH2abc", "set password ENC"),
    ("/user add name=bob password=hunter2 group=full", "hunter2", "group=full"),
    ("set snmp community public authorization read-only", "public", "authorization read-only"),
    ("crypto key generate rsa modulus 2048", None, "crypto key generate rsa modulus 2048"),
    ("tacacs-server key MyKey", "MyKey", "tacacs-server key"),
    # Secrets that sit later on the line, or are only called "name" (found in a full QA pass).
    ('password manager user-name "netadmin" plaintext "Pw-2026"', "Pw-2026", 'password manager user-name "netadmin"'),
    ('create account admin netadmin "Pw-2026"', "Pw-2026", "create account admin netadmin"),
    ('configure snmpv2c add community readonly "s3cret-ro"', "s3cret-ro", "community readonly"),
    ("config system snmp community\n    edit 1\n        set name \"s3cret-ro\"\n    next\nend\n"
     "config system interface\n    edit \"vlan10\"\n        set name keep-me\n    next\nend", "s3cret-ro", "set name keep-me"),
    ("snmp-server community s3cret-ro RO SNMP-S3CRET-RO\nip access-list standard SNMP-S3CRET-RO", "S3CRET",
     "ip access-list standard SNMP-<hidden>"),
    ("/snmp community\nadd name=s3cret-ro addresses=10.0.0.1/32\n/user\nadd name=bob group=full",
     "s3cret-ro", "add name=bob group=full"),
])
def test_redact_config(line, hidden, kept):
    out = redact.config(line)
    assert kept in out
    if hidden:
        assert hidden not in out and "<hidden>" in out

