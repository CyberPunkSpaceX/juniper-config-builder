import pytest


@pytest.fixture(autouse=True)
def _admins_without_2fa(monkeypatch):
    # Most tests sign in as an admin with a password only. The 2FA rule for
    # admins has its own tests in test_auth.py, which turn it back on.
    monkeypatch.setenv("EXB_REQUIRE_2FA_ADMINS", "false")


@pytest.fixture(autouse=True)
def _no_sample_clients(monkeypatch):
    # The built-in sample clients would change client counts and the picker in
    # most tests. test_samples.py turns them back on.
    monkeypatch.setenv("EXB_SAMPLES", "off")
