"""Fresh actual recovery admission and invented native reader controls only."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from tests.test_gmail_native_staging import ACCOUNT
from tests.test_gmail_recovery_host import Fixture, form
from tests.test_private_host import ORIGIN, sign_in
from zacai.connectors.gmail_held_reconciliation import HeldGmailReconciliation
from zacai.connectors.gmail_held_staging import HeldGmailNativeStage
from zacai.connectors.gmail_native_reader import (
    GmailNativeRead,
    GmailNativeReadCancelled,
    GmailNativeReader,
    GmailNativeReadError,
)


class Bindings:
    def __init__(self, path):
        self.path = str(path)
        self.events = []
        self.action = None
        self.rows = [
            (("encrypt",), None, "invented-encryption-label", 0),
            (("decrypt",), (), "invented-sensitive-label", 0),
            (("change_acl",), (), "invented-owner-label", 0),
        ]
        self.service = None
        self.persistent = b"invented-stable-persistent-native-item-reference"

    def record(self, name, *args):
        self.events.append((name, *args))
        if self.action:
            self.action(name)

    def keychain_open(self, path):
        self.record("open", path)
        assert path == self.path
        return 101

    def keychain_path(self, keychain):
        self.record("path", keychain)
        return self.path

    def find_item(self, keychain, service, account):
        self.record("find", keychain, service, account)
        self.service = service
        assert account == ACCOUNT
        return 202

    def item_keychain(self, item):
        self.record("item_keychain", item)
        return 303

    def persistent_reference(self, item):
        self.record("persistent", item)
        return self.persistent

    def attributes(self, item):
        self.record("attributes", item)
        return (int.from_bytes(b"genp", "big"), self.service.encode(), ACCOUNT.encode())

    def copy_access(self, item):
        self.record("access", item)
        return 404

    def acl_list(self, access):
        self.record("acl_list", access)
        return 505

    def acl_count(self, array):
        self.record("acl_count", array)
        return len(self.rows)

    def acl_at(self, array, index):
        self.record("acl_at", array, index)
        return 600 + index

    def acl_authorizations(self, acl):
        self.record("authorizations", acl)
        return self.rows[acl - 600][0]

    def acl_contents(self, acl):
        self.record("contents", acl)
        return self.rows[acl - 600][1:]

    def release(self, reference):
        self.record("release", reference)

    def read_item(self, item, maximum):
        self.record("read_item", item, maximum)
        return self.data


def with_fresh(tmp_path, monkeypatch, action):
    import zacai.interfaces.gmail_recovery_host as host_module

    f = Fixture(tmp_path, monkeypatch)
    actual_stage = HeldGmailNativeStage
    monkeypatch.setattr(
        host_module,
        "HeldGmailNativeStage",
        lambda **kwargs: actual_stage(**kwargs, bindings_factory=f.native_factory),
    )
    monkeypatch.setattr(host_module, "OAuthExchangeTransport", lambda: f.transport)
    plan = f.recovery_plan(monkeypatch)
    errors = []

    def browse(browser):
        sign_in(browser)
        for target in ("/connections/gmail/recover/pair", "/connections/gmail/quarantine"):
            assert browser.post(
                target, data=form(browser), headers={"origin": ORIGIN}
            ).status_code in (200, 303)
        response = browser.post(
            "/connections/gmail/recover/begin", data=form(browser), headers={"origin": ORIGIN}
        )
        assert response.status_code == 303
        state = parse_qs(urlsplit(response.headers["location"]).query)["state"][0]
        callback = browser.get(
            "/connections/gmail/callback", params={"state": state, "code": "invented-fresh-code"}
        )
        assert callback.status_code == 200 and callback.json()["profile_verified"] is True
        consumer = plan._consumer
        reconciliation = HeldGmailReconciliation(
            authority=consumer._authority, configuration=f.configuration
        )
        reference = reconciliation.inspect_fresh_recovery(admission=consumer._admission)
        bindings = Bindings(f.keychain)
        bindings.data = f.bindings.data
        reader = GmailNativeReader(
            configuration=f.configuration,
            reconciliation=reconciliation,
            keychain_path=f.keychain,
            keychain_file_policy="reviewed_login",
            preservation_check=consumer._check,
            bindings_factory=lambda: bindings,
        )
        try:
            action(f, consumer, reader, reference, bindings)
        except BaseException as error:  # noqa: BLE001 - report invented test failure outside host
            errors.append(error)
        f.both_leases()

    def guarded_browse(browser):
        try:
            browse(browser)
        except BaseException as error:  # noqa: BLE001 - preserve invented test diagnostics
            errors.append(error)

    f.browser_action = guarded_browse
    plan.run()
    if errors:
        raise errors[0]
    return f


def test_actual_fresh_read_private_issuance_exact_pair_and_native_identity(tmp_path, monkeypatch):
    def action(f, consumer, reader, reference, bindings):
        assert bindings.events == []  # constructor inert
        candidate = consumer._checked_fresh.candidate
        result = reader.read_once(
            reference=reference, admission=consumer._admission, candidate=candidate
        )
        assert type(result) is GmailNativeRead
        assert repr(result) == "GmailNativeRead(installed=False)"
        token = result.credential(
            reader=reader, reference=reference, admission=consumer._admission, candidate=candidate
        )
        assert token is candidate.access_token
        names = [event[0] for event in bindings.events]
        assert names.count("find") == 2 and names.count("read_item") == 1
        assert names.index("read_item") > names.index("contents")
        assert names.count("release") == 12
        assert all(
            event[2] == "zacai-brainstorm-gmail-stage-" + reference.generation
            for event in bindings.events
            if event[0] == "find"
        )
        with pytest.raises(GmailNativeReadError):
            reader.read_once(
                reference=reference, admission=consumer._admission, candidate=candidate
            )
        with pytest.raises(GmailNativeReadError):
            result.credential(
                reader=object(),
                reference=reference,
                admission=consumer._admission,
                candidate=candidate,
            )

    f = with_fresh(tmp_path, monkeypatch, action)
    assert len(f.provider_calls) == 3


@pytest.mark.parametrize("change", ["data", "item", "acl", "refresh", "host", "cancel", "release"])
def test_native_failure_revocation_cleanup_cannot_issue_read(tmp_path, monkeypatch, change):
    def action(f, consumer, reader, reference, bindings):
        candidate = consumer._checked_fresh.candidate
        if change == "data":
            bindings.data = b"invented foreign data"
        seen = []

        def hook(name):
            seen.append(name)
            if name == "read_item":
                if change == "item":
                    bindings.persistent = b"invented changed persistent item"
                if change == "acl":
                    bindings.rows[1] = (("decrypt",), (b"trusted foreign app",), "label", 0)
                if change == "refresh":
                    candidate.refresh_token._secret_value = "invented mutated refresh"
                if change == "host":
                    reader._preservation = lambda: True
                if change == "cancel":
                    raise KeyboardInterrupt("invented private cancellation")
            if change == "release" and name == "release":
                raise RuntimeError("invented private cleanup failure")

        bindings.action = hook
        expected = GmailNativeReadCancelled if change == "cancel" else GmailNativeReadError
        with pytest.raises(expected) as caught:
            reader.read_once(
                reference=reference, admission=consumer._admission, candidate=candidate
            )
        assert caught.value.__cause__ is None and caught.value.__context__ is None
        assert "invented private" not in str(caught.value)
        assert reader._issued is None
        assert [e[0] for e in bindings.events].count("release") >= 5
        if change == "host":
            reader._preservation = reader._original[4]

    with_fresh(tmp_path, monkeypatch, action)


@pytest.mark.parametrize("change", ["candidate_clone", "foreign_reference", "replaced_factory"])
def test_unissued_candidate_or_reference_and_replaced_composition_deny_before_native(
    tmp_path, monkeypatch, change
):
    from dataclasses import replace

    from zacai.connectors.gmail_held_reconciliation import HeldGmailReference

    def action(f, consumer, reader, reference, bindings):
        candidate = consumer._checked_fresh.candidate
        if change == "candidate_clone":
            candidate = replace(candidate)
        elif change == "foreign_reference":
            foreign = object.__new__(HeldGmailReference)
            for name in ("_generation", "_state_hash", "_row"):
                object.__setattr__(foreign, name, getattr(reference, name))
            object.__setattr__(foreign, "_issuer", object())
            reference = foreign
        else:
            reader._factory = lambda: bindings
        with pytest.raises(GmailNativeReadError):
            reader.read_once(
                reference=reference, admission=consumer._admission, candidate=candidate
            )
        assert bindings.events == [] and reader._issued is None

    with_fresh(tmp_path, monkeypatch, action)


def test_last_preservation_callback_cannot_mutate_profile_pair_before_native(tmp_path, monkeypatch):
    def action(f, consumer, reader, reference, bindings):
        candidate = consumer._checked_fresh.candidate
        original = candidate.refresh_token._secret_value
        calls = []

        def preserved():
            consumer._check()
            calls.append(True)
            if len(calls) == 4:
                candidate.refresh_token._secret_value = "invented terminal mutation"

        bounded = GmailNativeReader(
            configuration=f.configuration,
            reconciliation=reader._reconciliation,
            keychain_path=f.keychain,
            keychain_file_policy="reviewed_login",
            preservation_check=preserved,
            bindings_factory=lambda: bindings,
        )
        with pytest.raises(GmailNativeReadError):
            bounded.read_once(
                reference=reference, admission=consumer._admission, candidate=candidate
            )
        assert len(calls) == 4 and bindings.events == [] and bounded._issued is None
        candidate.refresh_token._secret_value = original

    with_fresh(tmp_path, monkeypatch, action)


def test_copied_host_installer_factory_inert_exact_consumer_and_one_publication(
    tmp_path, monkeypatch
):
    from zacai.connectors.gmail_installation import GmailInstallation
    from zacai.interfaces.gmail_recovery_host import GmailRecoveryHostError

    def action(f, consumer, reader, reference, bindings):
        host = consumer._host
        before = (
            len(f.shared_reads),
            len(f.secret_reads),
            len(f.provider_calls),
            len(f.native_factories),
        )
        with pytest.raises(GmailRecoveryHostError):
            host._make_gmail_installation(object())
        assert consumer._installer is None
        installation = host._make_gmail_installation(consumer)
        assert type(installation) is GmailInstallation
        assert consumer._installer is consumer._original_installer is installation
        assert type(installation._reader) is GmailNativeReader
        assert not installation._reader._spent and installation._reader._issued is None
        assert bindings.events == []
        assert before == (
            len(f.shared_reads),
            len(f.secret_reads),
            len(f.provider_calls),
            len(f.native_factories),
        )
        with pytest.raises(GmailRecoveryHostError):
            host._make_gmail_installation(consumer)

    with_fresh(tmp_path, monkeypatch, action)
