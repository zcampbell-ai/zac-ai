"""Invented held-stage integration with real transaction and native staging stores."""

from __future__ import annotations

import ctypes
import re
import subprocess
from dataclasses import replace
from datetime import timedelta

import pytest

from tests.test_gmail_native_staging import InventedBindings, candidate
from tests.test_oauth_transactions import Fixture as Transactions
from zacai.connectors.gmail_held_staging import GmailHeldStageError, HeldGmailNativeStage
from zacai.connectors.oauth_exchange import (
    CheckedOAuthExchange,
    OAuthExchangeCancellationHoldUnconfirmed,
    OAuthExchangeHoldUnconfirmed,
)
from zacai.interfaces.gmail_connection_web import GmailConnectionFatal

PRIVATE = "invented-private-stage-diagnostic"


class Guard:
    def __init__(self):
        self.halts = 0
        self.failure = None

    def ready(self):
        if self.failure:
            raise self.failure
        if self.halts:
            raise RuntimeError(PRIVATE)

    def halt_unconfirmed(self):
        self.halts += 1


class Bindings(InventedBindings):
    def __init__(self):
        super().__init__()
        self.action = None

    def record(self, name, *values):
        super().record(name, *values)
        if self.action:
            self.action(name)


class Fixture:
    def __init__(self, temporary, monkeypatch):
        self.transaction = Transactions(temporary)
        self.configuration = self.transaction.configuration
        self.operation = self.transaction.callback(self.transaction.state())
        self.operation.take_exchange()
        self.checked = CheckedOAuthExchange(
            replace(candidate(self.configuration), subject_pin_verified=False)
        )
        parent = temporary / "invented-keychain"
        parent.mkdir(mode=0o700)
        self.path = parent / "login.keychain-db"
        self.path.write_bytes(b"invented metadata only")
        self.path.chmod(0o644)
        self.guard, self.bindings = Guard(), Bindings()
        self.factories = self.stops = 0
        self.factory_action = None

        def forbidden(*args, **kwargs):
            raise AssertionError("Actual native calls forbidden in invented stage tests")

        monkeypatch.setattr(ctypes, "CDLL", forbidden)
        monkeypatch.setattr(subprocess, "run", forbidden)
        self.stage = HeldGmailNativeStage(
            configuration=self.configuration,
            authority=self.transaction.authority,
            keychain_path=self.path,
            keychain_file_policy="reviewed_login",
            host_guard=self.guard,
            stop_host=self.stop,
            bindings_factory=self.factory,
        )

    def factory(self):
        self.factories += 1
        if self.factory_action:
            self.factory_action()
        return self.bindings

    def stop(self):
        self.stops += 1

    def run(self):
        return self.stage(self.checked, self.operation)

    def revoke(self):
        self.transaction.sessions.sessions.revoke(self.transaction.sessions.cookie)

    def expire(self):
        self.transaction.sessions.now += timedelta(minutes=5)


def safe(error):
    assert error.__context__ is None and error.__cause__ is None
    assert PRIVATE not in str(error) and PRIVATE not in repr(error)


def test_real_store_guarded_native_stage_uses_original_deterministic_generation(
    tmp_path, monkeypatch
):
    f = Fixture(tmp_path, monkeypatch)
    assert not f.bindings.events and f.factories == 0
    generation = f.operation.staging_generation()
    assert re.fullmatch("[0-9a-f]{32}", generation)
    assert f.run() is None
    names = [event[0] for event in f.bindings.events]
    assert names == ["open", "access", "add", "readback", "release", "release"]
    add = next(event for event in f.bindings.events if event[0] == "add")
    assert add[3] == "zacai-brainstorm-gmail-stage-" + generation
    assert add[4] == "zac-owner-source-access"
    assert f.factories == 1 and f.stops == f.guard.halts == 0
    assert f.path.read_bytes() == b"invented metadata only"
    assert f.checked.installed is False and f.checked.processing_authorized is False
    assert f.checked.candidate.subject_pin_verified is False


@pytest.mark.parametrize("change", ["authority", "configuration", "revoked", "expired"])
def test_invalid_original_binding_denies_before_native_factory(tmp_path, monkeypatch, change):
    f = Fixture(tmp_path, monkeypatch)
    if change == "authority":
        other = tmp_path / "other"
        other.mkdir()
        transaction = Transactions(other)
        f.operation = transaction.callback(transaction.state())
        f.operation.take_exchange()
    elif change == "configuration":
        f.checked = CheckedOAuthExchange(
            replace(f.checked.candidate, configuration_digest="f" * 64)
        )
    elif change == "revoked":
        f.revoke()
    else:
        f.expire()
    with pytest.raises(GmailHeldStageError) as raised:
        f.run()
    safe(raised.value)
    assert f.factories == 0 and not f.bindings.events


@pytest.mark.parametrize("phase", ["open", "access", "add", "readback"])
@pytest.mark.parametrize("change", ["revoked", "expired"])
def test_post_native_current_check_denies_and_always_releases_references(
    tmp_path, monkeypatch, phase, change
):
    f = Fixture(tmp_path, monkeypatch)
    f.bindings.action = lambda name: (
        (f.revoke() if change == "revoked" else f.expire()) if name == phase else None
    )
    expected = OAuthExchangeHoldUnconfirmed if phase in {"add", "readback"} else GmailHeldStageError
    with pytest.raises(expected) as raised:
        f.run()
    safe(raised.value)
    names = [event[0] for event in f.bindings.events]
    assert names.count("add") == (1 if phase in {"add", "readback"} else 0)
    releases = [event[1] for event in f.bindings.events if event[0] == "release"]
    assert releases.count(101) == 1
    if phase != "open":
        assert releases.count(202) == 1
    assert f.factories == 1


def test_revocation_during_bindings_construction_denies_before_open(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    f.factory_action = f.revoke
    with pytest.raises(GmailHeldStageError):
        f.run()
    assert f.factories == 1 and not f.bindings.events


@pytest.mark.parametrize("cancel", [False, True])
def test_ambiguous_native_write_is_preserved_as_exchange_hold_uncertainty(
    tmp_path, monkeypatch, cancel
):
    f = Fixture(tmp_path, monkeypatch)
    f.bindings.failure, f.bindings.cancel = "add", cancel
    expected = OAuthExchangeCancellationHoldUnconfirmed if cancel else OAuthExchangeHoldUnconfirmed
    with pytest.raises(expected) as raised:
        f.run()
    safe(raised.value)
    assert [event[0] for event in f.bindings.events].count("add") == 1
    assert sorted(event[1] for event in f.bindings.events if event[0] == "release") == [101, 202]


@pytest.mark.parametrize("phase", ["open", "access", "add", "readback"])
def test_fatal_guard_after_native_step_survives_store_sanitizer_and_stops_host(
    tmp_path, monkeypatch, phase
):
    from zacai.connectors.oauth_host_guard import OAuthHostHaltUnconfirmed

    f = Fixture(tmp_path, monkeypatch)
    f.bindings.action = lambda name: (
        setattr(f.guard, "failure", OAuthHostHaltUnconfirmed(PRIVATE)) if name == phase else None
    )
    with pytest.raises(GmailConnectionFatal) as raised:
        f.run()
    safe(raised.value)
    assert f.stops == 1 and f.guard.halts >= 1
    releases = [event[1] for event in f.bindings.events if event[0] == "release"]
    assert releases.count(101) == 1
    if phase != "open":
        assert releases.count(202) == 1


def test_unconsumed_exchange_operation_denies_native_staging(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    other = tmp_path / "pending"
    other.mkdir()
    transaction = Transactions(other)
    operation = transaction.callback(transaction.state())
    stage = HeldGmailNativeStage(
        configuration=transaction.configuration,
        authority=transaction.authority,
        keychain_path=f.path,
        keychain_file_policy="reviewed_login",
        host_guard=f.guard,
        stop_host=f.stop,
        bindings_factory=f.factory,
    )
    with pytest.raises(GmailHeldStageError):
        stage(f.checked, operation)
    assert f.factories == 0 and not f.bindings.events


@pytest.mark.parametrize(
    "field,value",
    [
        ("generation", "f" * 32),
        ("held", 1),
        ("installed", True),
        ("readback_matched", 1),
        ("durable_hold_verified", True),
        ("type", None),
    ],
)
def test_exact_native_receipt_flags_cannot_be_promoted_or_forged(
    tmp_path, monkeypatch, field, value
):
    from zacai.connectors.gmail_native_staging import GmailNativeStagingStore

    f = Fixture(tmp_path, monkeypatch)
    original = GmailNativeStagingStore.stage

    def forged(store, **kwargs):
        receipt = original(store, **kwargs)
        if field == "type":
            return object()
        object.__setattr__(receipt, field, value)
        return receipt

    monkeypatch.setattr(GmailNativeStagingStore, "stage", forged)
    with pytest.raises(OAuthExchangeHoldUnconfirmed) as raised:
        f.run()
    safe(raised.value)
    assert [event[0] for event in f.bindings.events].count("add") == 1
    before = list(f.bindings.events)
    with pytest.raises(GmailHeldStageError):
        f.run()
    assert f.bindings.events == before


@pytest.mark.parametrize("phase", ["before_native", "after_acknowledgement"])
@pytest.mark.parametrize("cancel", [False, True])
def test_transaction_persistence_uncertainty_reaches_controller_halt_even_when_hold_succeeds(
    tmp_path, monkeypatch, phase, cancel
):
    from tests.test_gmail_connection_web import Fixture as WebFixture
    from zacai.connectors.oauth_transactions import (
        OAuthTransactionCancellationUnconfirmed,
        OAuthTransactionUnconfirmed,
    )

    f = WebFixture(tmp_path)
    parent = tmp_path / "invented-web-keychain"
    parent.mkdir(mode=0o700)
    path = parent / "login.keychain-db"
    path.write_bytes(b"invented metadata only")
    path.chmod(0o644)
    bindings = Bindings()
    hook = HeldGmailNativeStage(
        configuration=f.configuration,
        authority=f.authority,
        keychain_path=path,
        keychain_file_policy="reviewed_login",
        host_guard=f.guard,
        stop_host=f.stop,
        bindings_factory=lambda: bindings,
    )
    active = fired = False
    original = f.authority._persist
    kind = OAuthTransactionCancellationUnconfirmed if cancel else OAuthTransactionUnconfirmed

    def persist(value, state):
        nonlocal fired
        if active and not fired:
            fired = True
            raise kind(PRIVATE)
        return original(value, state)

    def checked_stage(checked, operation):
        nonlocal active
        if phase == "before_native":
            active = True
        return hook(checked, operation)

    def native_event(name):
        nonlocal active
        if phase == "after_acknowledgement" and name == "release":
            active = True

    bindings.action = native_event
    monkeypatch.setattr(f.authority, "_persist", persist)
    monkeypatch.setattr(f.controller, "_stage", checked_stage)
    with f.browser() as browser:
        from urllib.parse import urlencode, urlsplit

        from starlette.requests import Request

        from tests.test_private_host import ORIGIN, sign_in
        from zacai.interfaces.gmail_connection_web import (
            GmailConnectionCancelled,
            GmailConnectionError,
        )

        cookie = sign_in(browser)
        state = f.begin(browser)
        request = Request(
            {
                "type": "http",
                "method": "GET",
                "scheme": "https",
                "path": "/connections/gmail/callback",
                "query_string": urlencode(
                    {"state": state, "code": "invented-authorization-code"}
                ).encode(),
                "headers": [
                    (b"host", urlsplit(ORIGIN).netloc.encode()),
                    (b"cookie", ("__Host-zac-session=" + cookie).encode()),
                ],
                "server": (urlsplit(ORIGIN).hostname, 443),
                "client": ("127.0.0.1", 1),
            }
        )
        expected = GmailConnectionCancelled if cancel else GmailConnectionError
        with pytest.raises(expected):
            f.controller.callback(request)
        assert fired is True and f.guard.halts >= 1
        assert f.row()["state"] == "held"
        assert f.stop_calls == 0
        assert [event[0] for event in bindings.events].count("add") == (
            phase == "after_acknowledgement"
        )


@pytest.mark.parametrize("field", ["expires_at", "refresh_expires_at"])
def test_expired_checked_candidate_denies_before_native_factory(tmp_path, monkeypatch, field):
    f = Fixture(tmp_path, monkeypatch)
    f.checked = CheckedOAuthExchange(
        replace(f.checked.candidate, **{field: f.transaction.sessions.now})
    )
    with pytest.raises(GmailHeldStageError):
        f.run()
    assert f.factories == 0 and not f.bindings.events


def test_failing_fatal_halt_and_stop_callbacks_do_not_skip_native_cleanup(tmp_path, monkeypatch):
    from zacai.connectors.oauth_host_guard import OAuthHostHaltUnconfirmed

    f = Fixture(tmp_path, monkeypatch)

    def fail_halt():
        f.guard.halts += 1
        raise RuntimeError(PRIVATE)

    def fail_stop():
        f.stops += 1
        raise KeyboardInterrupt(PRIVATE)

    monkeypatch.setattr(f.guard, "halt_unconfirmed", fail_halt)
    monkeypatch.setattr(f.stage, "_stop", fail_stop)
    f.bindings.action = lambda name: (
        setattr(f.guard, "failure", OAuthHostHaltUnconfirmed(PRIVATE)) if name == "access" else None
    )
    with pytest.raises(GmailConnectionFatal) as raised:
        f.run()
    safe(raised.value)
    assert f.stops == f.guard.halts == 1
    assert sorted(event[1] for event in f.bindings.events if event[0] == "release") == [101, 202]
    before = list(f.bindings.events)
    with pytest.raises(GmailHeldStageError):
        f.run()
    assert f.bindings.events == before and f.stops == 1
