import sqlite3
from datetime import datetime, timezone

import pytest

paramiko = pytest.importorskip("paramiko")
pytest.importorskip("flask")

import test_sshfetch  # noqa: E402
from test_sshfetch import FakeJunos, env, switch  # noqa: F401,E402
from test_auth import ADMIN, app, admin, csrf, login  # noqa: F401,E402

from exbuilder import compare, notify, sshfetch  # noqa: E402
from exbuilder.web import backups, nightly  # noqa: E402

IOS = """Building configuration...

Current configuration : 1234 bytes
!
! Last configuration change at 10:01:02 UTC Mon Nov 23 2026 by admin
!
version 15.2
hostname access-sw1
enable secret 5 $1$abcd$xyz
!
interface GigabitEthernet0/1
 description pc
 switchport access vlan 10
!
interface GigabitEthernet0/2
 shutdown
!
ntp clock-period 36028797
end
"""


def test_other_vendors_are_configs_with_stable_fingerprints():
    assert backups.is_config(IOS) and backups.host_of(IOS) == "access-sw1"
    assert backups.host_of("/system identity set name=mt-core\n/interface vlan add name=v10 vlan-id=10\n") == "mt-core"
    assert backups.host_of("config system global\n    set hostname \"fsw-1\"\nend\n") == "fsw-1"
    later = IOS.replace("10:01:02", "11:00:00").replace("36028797", "36028800")
    assert backups.sha_of(IOS) == backups.sha_of(later)          # time stamps only
    assert compare.compare(IOS, later)["identical"]
    changed = later.replace("vlan 10", "vlan 20")
    r = compare.compare(IOS, changed)
    assert r["plain"] and r["only_a"] == 1 and r["only_b"] == 1
    assert [s["name"] for s in r["sections"]] == ["interface GigabitEthernet0/1"]
    secret = compare.compare(IOS, IOS.replace("xyz", "new"))
    assert secret["identical"]                                   # secrets ignored by default
    assert not compare.compare(IOS, IOS.replace("xyz", "new"), ignore_secrets=False)["identical"]
    assert "$1$" not in str(compare.compare(IOS, changed.replace("xyz", "q"), ignore_secrets=True))


def test_parse_switches():
    sw, problems = nightly.parse_switches("10.0.0.1\n10.0.0.2 cisco\ncore.lan arista 2222 # core\n\n10.0.0.1 juniper")
    assert sw == [{"host": "10.0.0.1", "vendor": "juniper", "port": 22}, {"host": "10.0.0.2", "vendor": "cisco", "port": 22},
                  {"host": "core.lan", "vendor": "arista", "port": 2222}] and not problems
    _, problems = nightly.parse_switches("10.0.0.3 unifi\n10.0.0.4 cisco 70000")
    assert len(problems) == 2


def test_due():
    s = {"enabled": 1, "at_time": "02:00", "tz": "Asia/Tokyo", "last_day": ""}
    late = datetime(2026, 11, 25, 17, 30, tzinfo=timezone.utc)     # 02:30 on the 26th in Tokyo
    early = datetime(2026, 11, 25, 16, 30, tzinfo=timezone.utc)     # 01:30
    assert nightly.is_due(s, late) and not nightly.is_due(s, early)
    assert not nightly.is_due({**s, "last_day": "2026-11-26"}, late)
    assert not nightly.is_due({**s, "enabled": 0}, late)


def test_hooks_are_checked():
    hooks, problems = notify.parse_hooks("https://hooks.slack.com/services/T/B/x http://x.example/hook https://u:p@x.example/")
    assert hooks == ["https://hooks.slack.com/services/T/B/x"] and len(problems) == 2
    assert notify.hook_kind("https://prod-1.westus.logic.azure.com/workflows/x") == "teams"
    assert notify.short("https://hooks.slack.com/services/T/B/secret") == "https://hooks.slack.com/…"
    card = notify._payload("teams", "t", "body", None)
    assert card["attachments"][0]["content"]["type"] == "AdaptiveCard"


def test_nightly_run_end_to_end(switch, app, admin, monkeypatch, tmp_path):  # noqa: F811
    sent = []
    monkeypatch.setattr(notify, "send_hook", lambda url, title, text, facts=None: sent.append((url, title, text)))
    page = "/clients/1"
    tok = csrf(admin, page)
    admin.post(page, data={"csrf_token": tok, "action": "ssh", "networks": "127.0.0.0/24", "ssh_user": "exbuilder-ro"})
    admin.post(page, data={"csrf_token": tok, "action": "key_generate"})
    pub = admin.get(page).get_data(as_text=True).split("ssh-ed25519 ")[1].split()[0]
    FakeJunos.pubkey = pub
    form = {"csrf_token": tok, "action": "save", "enabled": "1", "at_time": "02:00", "tz": "UTC",
            "switches": f"127.0.0.1 juniper {switch['port']}\n127.0.0.2 unifi", "notify_on": "changes",
            "hooks": "https://hooks.slack.com/services/T/B/secret", "emails": ""}
    resp = admin.post("/clients/1/nightly", data=form, follow_redirects=True)
    assert "not a vendor with SSH backups" in resp.get_data(as_text=True)       # unifi refused, nothing saved
    form["switches"] = f"127.0.0.1 juniper {switch['port']}"
    resp = admin.post("/clients/1/nightly", data=form, follow_redirects=True)
    text = resp.get_data(as_text=True)
    assert "Saved." in text and "https://hooks.slack.com/…" in text and "secret" not in text.split("Last runs")[0].split("placeholder")[-1]
    db = sqlite3.connect(tmp_path / "users.db")
    db.row_factory = sqlite3.Row
    stored = db.execute("SELECT hooks FROM nightly_settings").fetchone()[0]
    assert stored and "slack" not in stored                                    # encrypted

    with app.app_context():
        first = nightly.run(db, 1, "test")
        assert first["changed"] == 1 and first["failed"] == 0, first
        assert sent and "1 switch config changed" in sent[-1][1]               # first backup counts as new
        again = nightly.run(db, 1, "test")
        assert again["unchanged"] == 1 and again["changed"] == 0
        n = len(sent)
        assert len(sent) == n                                                  # nothing changed: no alert
        monkeypatch.setattr(test_sshfetch, "CONFIG", test_sshfetch.CONFIG + "set vlans VOICE vlan-id 30\n")
        third = nightly.run(db, 1, "test")
        assert third["changed"] == 1
        assert "+ vlans VOICE vlan-id 30" in sent[-1][2]
    rows = db.execute("SELECT source FROM config_backups ORDER BY id").fetchall()
    assert [r[0] for r in rows] == ["nightly", "nightly"]
    newest = db.execute("SELECT MAX(id) FROM config_backups").fetchone()[0]
    ch = admin.get(f"/backups/{newest}/changes").json
    assert ch["previous"] and ch["result"]["only_b"] == 1
    page = admin.get("/clients/1/nightly").get_data(as_text=True)
    assert "1 changed" in page and "vlans VOICE" in page

    # Scheduling: claimed once per day.
    db.execute("UPDATE nightly_settings SET last_day = ''")
    db.commit()
    noon = datetime(2026, 11, 26, 12, 0, tzinfo=timezone.utc)
    with app.app_context():
        assert nightly.run_due(db, noon) == [1]
        assert nightly.run_due(db, noon) == []


def test_viewers_cannot_open_the_settings(app, admin):  # noqa: F811
    from test_clients import _bob
    bob = _bob(app, admin, role="admin")
    assert bob.get("/clients/1/nightly").status_code == 200
    viewer = _bob(app, admin, role="viewer")
    assert viewer.get("/clients/1/nightly").status_code in (403, 404)
