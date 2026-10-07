"""Independent authenticated restart boundaries; disposable evidence only."""

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from zacai.connectors.gmail_installed_load import AuthenticatedGmailInstallation, _record


def encrypted(plain=b'{"version":1}', *, key=b"K" * 32, context=b"invented-load-context"):
    nonce = b"N" * 12
    return nonce + AESGCM(key).encrypt(nonce, plain, context)


@pytest.mark.parametrize("change", ["ciphertext", "key", "context", "nonce"])
def test_actual_record_authentication_rejects_wrong_domain_or_changed_bytes(change):
    data = encrypted()
    key, context = b"K" * 32, b"invented-load-context"
    if change == "key":
        key = b"F" * 32
    elif change == "context":
        context = b"foreign-owner-context"
    else:
        offset = 0 if change == "nonce" else len(data) - 1
        data = data[:offset] + bytes([data[offset] ^ 1]) + data[offset + 1 :]
    with pytest.raises(InvalidTag):
        _record(AESGCM(key), data, context)


@pytest.mark.parametrize(
    "plain",
    [
        b'{"version":1,"version":1}',
        b'{"nested":{"subject":"one","subject":"two"}}',
        b'{ "version": 1 }',
        b'{"version":NaN}',
        b"[]",
    ],
)
def test_authenticated_bytes_still_require_canonical_unique_object(plain):
    with pytest.raises(ValueError):
        _record(AESGCM(b"K" * 32), encrypted(plain), b"invented-load-context")


def test_public_capability_constructor_cannot_turn_record_metadata_into_authority():
    assert _record(AESGCM(b"K" * 32), encrypted(), b"invented-load-context") == {"version": 1}
    with pytest.raises(TypeError, match="privately issued"):
        AuthenticatedGmailInstallation()


def reopen_form(browser):
    import re

    page = browser.get("/connections/gmail/reopen")
    assert page.status_code == 200
    return dict(re.findall(r'name="([^"]+)" value="([^"]*)"', page.text))


def paired_restart(browser):
    from tests.test_private_host import ORIGIN, sign_in

    sign_in(browser)
    reply = browser.post(
        "/connections/gmail/recover/pair",
        data=reopen_form(browser),
        headers={"origin": ORIGIN},
    )
    assert reply.status_code == 303


def run_restarted(f, plan, action, *, terminal=True):
    from zacai.interfaces.gmail_recovery_host import (
        GmailRecoveryHostError,
        GmailRecoveryHostFatal,
    )

    failures, done = [], []

    def browse(browser):
        try:
            action(browser)
            done.append(True)
        except BaseException as error:
            failures.append(error)
            raise

    f.browser_action = browse
    try:
        plan.run()
    except (GmailRecoveryHostError, GmailRecoveryHostFatal):
        assert terminal
    if failures:
        raise failures[0]
    assert done == [True]
    assert plan._runtime is plan._windows is plan._consumer is plan._loaded is None


def test_new_current_owner_cannot_clone_capability_or_replay_completed_approval(
    tmp_path, monkeypatch
):
    from tests.test_gmail_installed_load import fixture_restarted
    from tests.test_private_host import ORIGIN
    from zacai.connectors.gmail_recovery_authorization import GmailRecoveryAuthorizationError

    f, plan = fixture_restarted(tmp_path, monkeypatch)
    before = len(f.secret_reads), len(f.provider_calls), len(f.reader_bindings)

    def browse(browser):
        paired_restart(browser)
        f.both_leases()
        loader, cap = plan._loaded, plan._loaded._issued
        assert cap is not None and plan._consumer is None
        assert repr(cap) == "AuthenticatedGmailInstallation(live_access_proven=False)"
        assert "Gmail connected" not in browser.get("/connections/gmail/reopen").text
        clone = object.__new__(AuthenticatedGmailInstallation)
        for key, value in vars(cap).items():
            object.__setattr__(clone, key, value)
        with pytest.raises(GmailRecoveryAuthorizationError):
            clone.current()
        assert loader._old_attempts and all(
            b'"state":"completed"' in row for row in loader._old_attempts.values()
        )
        old = dict(loader._old_attempts)
        fields = reopen_form(browser)
        # Current CSRF is valid. The previous process's completed approval is not
        # a review of this newly issued attempt under the new owner session.
        denied = browser.post(
            "/connector-execute", data={"csrf": fields["csrf"]}, headers={"origin": ORIGIN}
        )
        assert denied.status_code == 403 and f.servers[-1].should_exit
        assert loader._old_attempts == old
        assert loader._preflight is not None
        f.both_leases()

    run_restarted(f, plan, browse)
    assert (len(f.secret_reads), len(f.provider_calls), len(f.reader_bindings)) == before


def test_installed_capability_rechecks_expiry_after_terminal_owner_clock(tmp_path, monkeypatch):
    import inspect
    from datetime import timedelta

    from tests.test_gmail_installed_load import fixture_restarted
    from tests.test_private_host import CONFIG
    from zacai.connectors.connector_authority import _json
    from zacai.connectors.gmail_installation import ACTIVE
    from zacai.connectors.gmail_installed_load import _cipher
    from zacai.connectors.gmail_recovery_authorization import GmailRecoveryAuthorizationError

    f, plan = fixture_restarted(tmp_path, monkeypatch)
    # A shorter, authenticated conservative installed lifetime leaves both new
    # owner sessions valid when the installed access reaches its own deadline.
    context = b"zac-fresh-gmail-installation-v1\x00" + f.authority._context
    cipher = _cipher(CONFIG.session_key, b"zac-fresh-gmail-installation-v1", context)
    path = f.authority._directory / ACTIVE
    record = _record(cipher, path.read_bytes(), context)
    record["expires"] = (f.now + timedelta(minutes=1)).isoformat()
    nonce = b"E" * 12
    path.write_bytes(nonce + cipher.encrypt(nonce, _json(record), context))
    before = len(f.secret_reads), len(f.provider_calls), len(f.reader_bindings)
    triggered = []

    def browse(browser):
        paired_restart(browser)
        cap = plan._loaded._issued
        assert cap is not None
        original = f.clock._read
        direct_observed = []

        def clock():
            frame = inspect.currentframe()
            direct = frame.f_back.f_back
            if (
                direct.f_code.co_name == "current"
                and direct.f_globals.get("__name__") == "zacai.connectors.gmail_installed_load"
                and direct.f_locals.get("cap") is cap
            ):
                direct_observed.append(True)
            elif direct_observed and not triggered:
                cursor = direct
                while cursor is not None:
                    if (
                        cursor.f_code.co_name == "current"
                        and cursor.f_globals.get("__name__")
                        == "zacai.connectors.gmail_installed_load"
                        and cursor.f_locals.get("cap") is cap
                    ):
                        f.now = cap._expires
                        triggered.append(True)
                        break
                    cursor = cursor.f_back
            return original()

        monkeypatch.setattr(f.clock, "_read", clock)
        with pytest.raises(GmailRecoveryAuthorizationError):
            cap.current()
        assert direct_observed and triggered == [True]
        assert browser.get("/connections/gmail/reopen").status_code == 403
        assert f.servers[-1].should_exit
        f.both_leases()

    run_restarted(f, plan, browse)
    assert triggered == [True]
    assert (len(f.secret_reads), len(f.provider_calls), len(f.reader_bindings)) == before


def test_reopened_gateway_rejects_changed_singleton_before_data_or_provider(tmp_path, monkeypatch):
    import json

    from tests.test_gmail_installed_load import fixture_restarted
    from tests.test_gmail_native_reader import Bindings
    from tests.test_private_host import ORIGIN
    from zacai.connectors.gmail_installation import QUARANTINED

    f, plan = fixture_restarted(tmp_path, monkeypatch)
    before = len(f.secret_reads), len(f.provider_calls), len(f.reader_bindings)
    persistent = Bindings.persistent_reference

    def substituted(self, item):
        persistent(self, item)
        return b"different-current-item-in-the-same-native-namespace"

    monkeypatch.setattr(Bindings, "persistent_reference", substituted)

    def browse(browser):
        paired_restart(browser)
        old = dict(plan._loaded._old_attempts)
        reviewed = browser.post(
            "/connector-review", data=reopen_form(browser), headers={"origin": ORIGIN}
        )
        assert reviewed.status_code == 303
        reply = browser.post(
            "/connector-execute", data=reopen_form(browser), headers={"origin": ORIGIN}
        )
        assert reply.status_code == 403 and f.servers[-1].should_exit
        authority = plan._loaded._connector
        with authority._locked():
            rows = authority._read()["rows"]
        for key, previous in old.items():
            assert rows[key] == json.loads(previous)
        new = set(rows) - set(old)
        assert len(new) == 1 and rows[new.pop()]["state"] == "held"
        assert (f.authority._directory / QUARANTINED).is_file()
        f.both_leases()

    run_restarted(f, plan, browse)
    assert (len(f.secret_reads), len(f.provider_calls)) == before[:2]
    assert len(f.reader_bindings) == before[2] + 1
    events = f.reader_bindings[-1].events
    assert not any(event[0] == "read_item" for event in events)
    released = {event[1] for event in events if event[0] == "release"}
    assert {101, 202, 303, 404, 505} <= released
