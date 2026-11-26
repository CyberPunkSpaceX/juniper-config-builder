import socket
import sqlite3
import threading
import time

import pytest

pytest.importorskip("flask")

from test_auth import ADMIN, app, admin, csrf, login  # noqa: F401,E402

from switchbuilder import notify, syslogd  # noqa: E402
from switchbuilder.web import logs  # noqa: E402


def test_parse_formats():
    p = syslogd.parse(b"<187>Nov 25 23:10:01 access-sw1 %LINK-3-UPDOWN: Interface Gi0/1, changed state to down")
    assert (p["facility"], p["severity"], p["host"], p["tag"]) == (23, 3, "access-sw1", "%LINK-3-UPDOWN")
    assert p["message"].startswith("Interface Gi0/1")
    p = syslogd.parse(b"<28>1 2026-11-25T23:10:01.123Z ex4300 mib2d 1234 SNMP_TRAP_LINK_DOWN - ifIndex 512 down")
    assert (p["severity"], p["host"], p["tag"], p["message"]) == (4, "ex4300", "mib2d", "ifIndex 512 down")
    p = syslogd.parse(b"<13>Nov 25 23:10:01 sshd[123]: Accepted publickey")      # no host name
    assert p["host"] == "" and p["tag"] == "sshd" and p["message"] == "Accepted publickey"
    p = syslogd.parse(b"<189>123: *Nov 25 23:10:01.111: %SYS-5-CONFIG_I: Configured from console by admin")
    assert p["tag"] == "%SYS-5-CONFIG_I" and p["severity"] == 5
    assert syslogd.parse(b"no pri at all")["message"] == "no pri at all"
    assert len(syslogd.parse(b"<13>" + b"x" * 20000)["message"]) <= syslogd.MAX_MSG


def test_router_most_specific_network_wins():
    r = syslogd.Router(lambda: [(1, "10.0.0.0/8"), (2, "10.40.10.0/24, 192.168.5.0/24"), (3, "bad")])
    assert r.client_of("10.40.10.7") == 2 and r.client_of("10.9.9.9") == 1
    assert r.client_of("::ffff:192.168.5.1") == 2 and r.client_of("172.16.0.1") is None


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_server_end_to_end(app, admin, tmp_path, monkeypatch):  # noqa: F811
    monkeypatch.setenv("EXB_SSH_ALLOW", "127.0.0.0/8")
    sent = []
    monkeypatch.setattr(notify, "send_hook", lambda url, title, text, facts=None: sent.append((title, text)))
    # A second client the logs must never reach.
    tok = csrf(admin, "/clients")
    admin.post("/clients", data={"csrf_token": tok, "name": "Other"})
    resp = admin.post("/clients/1/logs", data={"csrf_token": csrf(admin, "/clients/1/logs"), "enabled": "1",
                                              "networks": "127.0.0.0/8", "keep_days": "30", "alert_severity": "3"},
                      follow_redirects=True)
    assert "Saved." in resp.get_data(as_text=True)
    admin.post("/clients/1/nightly", data={"csrf_token": csrf(admin, "/clients/1/nightly"), "action": "save",
                                          "at_time": "02:00", "tz": "UTC", "switches": "", "notify_on": "changes",
                                          "hooks": "https://hooks.slack.com/services/T/B/x", "emails": ""})
    users = sqlite3.connect(tmp_path / "users.db")
    assert logs.networks_for(users) == [(1, "127.0.0.0/8")]

    stop = threading.Event()
    port = _free_port()
    servers = syslogd.serve(tmp_path, lambda: logs.networks_for(sqlite3.connect(tmp_path / "users.db")), stop, port)
    try:
        lc = syslogd.connect(tmp_path)
        logs.send_alerts(users, lc)                     # first call only marks the start
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.sendto(b"<187>Nov 25 23:10:01 access-sw1 %LINK-3-UPDOWN: Interface Gi0/1, changed state to down",
                 ("127.0.0.1", port))
        t = socket.create_connection(("127.0.0.1", port))
        msg = b"<190>Nov 25 23:10:02 access-sw1 %SYS-6-LOGGINGHOST: hello over tcp"
        t.sendall(str(len(msg)).encode() + b" " + msg + b"<13>Nov 25 23:10:03 core-sw newline framed\n")
        t.close()
        for _ in range(50):
            if lc.execute("SELECT COUNT(*) FROM logs").fetchall()[0][0] >= 3:
                break
            threading.Event().wait(0.1)   # time.sleep is switched off by the app fixture
        rows = lc.execute("SELECT client_id, host, severity, message FROM logs ORDER BY id").fetchall()
        assert len(rows) == 3 and {r[0] for r in rows} == {1}
        page = admin.get("/logs").get_data(as_text=True)
        assert "changed state to down" in page and "hello over tcp" in page
        data = admin.get("/logs/data?sev=3").json
        assert [r["tag"] for r in data["rows"]] == ["%LINK-3-UPDOWN"]
        assert len(admin.get("/logs/data?q=tcp&range=1h").json["rows"]) == 1
        assert "hello over tcp" in admin.get("/logs/download").get_data(as_text=True)
        # The other client sees nothing.
        admin.post("/clients/select", data={"csrf_token": csrf(admin, "/logs"), "client_id": "2", "next": "/logs"})
        assert admin.get("/logs/data").json["rows"] == []
        # Alert: only the error, once.
        assert logs.send_alerts(users, lc) == [1]
        assert len(sent) == 1 and "UPDOWN" in sent[0][1] and "hello" not in sent[0][1]
        assert logs.send_alerts(users, lc) == []        # 5 minutes between alerts
        # Retention: turning logs off deletes them at the next prune.
        assert syslogd.prune(lc, {1: 30}) == 0
        assert syslogd.prune(lc, {}) == 3
    finally:
        stop.set()
        for s in servers:
            s.shutdown()
            s.server_close()


def test_settings_need_client_admin(app, admin):  # noqa: F811
    from test_clients import _bob
    viewer = _bob(app, admin, role="viewer")
    assert viewer.get("/clients/1/logs").status_code in (403, 404)
    assert viewer.get("/logs").status_code == 200
