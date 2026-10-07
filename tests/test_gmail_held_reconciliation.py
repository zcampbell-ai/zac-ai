"""Read-only reconciliation against original disposable authenticated OAuth ledgers."""

from __future__ import annotations

import ctypes
import json
import os
import subprocess
from datetime import timedelta

import pytest

from tests.test_connector_authority import Fixture as Sessions
from tests.test_oauth_configuration import gmail
from tests.test_oauth_transactions import Fixture as Transactions
from tests.test_private_host import CONFIG
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.interfaces.named_session_binding import NamedSessionContinuity


class Fixture(Transactions):
    def __init__(self, temporary, monkeypatch):
        self.sessions = Sessions(temporary)
        self.directory = temporary / "provider-oauth"
        self.key = b"O" * 32
        self.configuration = gmail(private_origin="https://caz.example")
        self.rotation = None
        self.owner_client = CONFIG.client_id
        self.sessions.continuity = NamedSessionContinuity(
            sessions=self.sessions.sessions,
            owner=lambda: self.sessions.owner,
            clock=self.sessions.clock,
            key=b"S" * 32,
            origin=self.configuration.private_origin,
            client_id=self.owner_client,
        )
        from tests.test_oauth_transactions import Registration

        self.registration = Registration()
        self.authority = self.reopen()
        self.authority.initialize()
        self.operation = self.callback(self.state())
        self.operation.take_exchange()
        self.generation = self.operation.staging_generation()
        self.operation.hold()
        self.side_effects = []

        def forbidden(*args, **kwargs):
            self.side_effects.append(True)
            raise AssertionError("Live/native/credential/registration operations forbidden")

        monkeypatch.setattr(ctypes, "CDLL", forbidden)
        monkeypatch.setattr(subprocess, "run", forbidden)
        monkeypatch.setattr(self.registration, "attest", forbidden)
        monkeypatch.setattr(self.registration, "generation", forbidden)

    def snapshot(self):
        return {
            p: (p.stat().st_ino, p.stat().st_mode, p.read_bytes()) for p in self.directory.iterdir()
        }

    def row(self):
        with self.authority._locked():
            value = self.authority._read()
        return value, next(iter(value["rows"]))

    def change_row(self, **changes):
        value, state = self.row()
        value["rows"][state].update(changes)
        self.authority._write(value)


def safe(error, *private):
    assert error.__cause__ is None and error.__context__ is None
    assert all(value not in str(error) and value not in repr(error) for value in private)
    current = error.__traceback__
    while current:
        frame = current.tb_frame
        if frame.f_globals.get("__name__") == "zacai.connectors.gmail_held_reconciliation":
            assert frame.f_code.co_name == "call"
            assert "args" not in frame.f_locals and "kwargs" not in frame.f_locals
        current = current.tb_next


def inspector(f, **changes):
    from zacai.connectors.gmail_held_reconciliation import HeldGmailReconciliation

    fields = {"authority": f.authority, "configuration": f.configuration}
    fields.update(changes)
    return HeldGmailReconciliation(**fields)


def inspect(f, **changes):
    fields = {"generation": f.generation, "cookie": f.sessions.cookie}
    fields.update(changes)
    return inspector(f).inspect(**fields)


def test_original_authenticated_held_generation_readonly_and_receipt_only(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    before = f.snapshot()
    item = inspector(f)
    assert f.snapshot() == before and not f.side_effects
    receipt = item.inspect(generation=f.generation, cookie=f.sessions.cookie)
    assert receipt.generation == f.generation and receipt.held is True
    for flag in (
        "installed",
        "native_material_verified",
        "original_actor_verified",
        "source_subject_verified",
        "credential_authority",
        "processing_authorized",
        "execution_authorized",
    ):
        assert getattr(receipt, flag) is False
    value, state = f.row()
    assert all(
        private not in repr(receipt) and private not in repr(item)
        for private in (
            f.generation,
            state,
            f.sessions.cookie,
            str(f.directory),
            f.configuration.gmail_mailbox,
            value["rows"][state]["execution"],
        )
    )
    assert f.snapshot() == before and not f.side_effects
    assert not any(
        hasattr(item, method) for method in ("install", "resume", "release", "credential")
    )


def test_expired_original_cookie_row_with_fresh_actual_owner_login_is_receipt_only(
    tmp_path, monkeypatch
):
    from tests.test_connector_authority import OWNER

    f = Fixture(tmp_path, monkeypatch)
    f.sessions.now += timedelta(days=1)
    fresh = f.sessions.sessions.start_user(OWNER, f.sessions.now)
    before = f.snapshot()
    receipt = inspect(f, cookie=fresh)
    assert receipt.generation == f.generation and not receipt.original_actor_verified
    assert f.snapshot() == before and not f.side_effects


@pytest.mark.parametrize(
    "change", ["wrong", "revoked", "expired", "other_owner", "foreign_store", "no_hr"]
)
def test_current_actual_owner_scope_required_before_ledger_read(tmp_path, monkeypatch, change):
    from tests.test_connector_authority import OWNER
    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError
    from zacai.interfaces.private_web import BoundaryScope, OwnerGrant
    from zacai.interfaces.session_store import Identity
    from zacai.policy import DataClassification as C
    from zacai.policy import TrustBoundary as B

    f = Fixture(tmp_path, monkeypatch)
    cookie = f.sessions.cookie
    if change == "wrong":
        cookie = "x" * 43
    elif change == "revoked":
        f.sessions.sessions.revoke(cookie)
    elif change == "expired":
        f.sessions.now += timedelta(days=1)
    elif change == "other_owner":
        cookie = f.sessions.sessions.start_user(
            Identity(OWNER.issuer, "invented-other-owner"), f.sessions.now
        )
    elif change == "foreign_store":
        foreign = tmp_path / "foreign"
        foreign.mkdir()
        cookie = Sessions(foreign).cookie
    else:
        f.sessions.owner = OwnerGrant(
            OWNER, (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),)
        )
    reads = []
    original = OAuthTransactionAuthority._read

    def read(authority):
        reads.append(True)
        return original(authority)

    monkeypatch.setattr(OAuthTransactionAuthority, "_read", read)
    before = f.snapshot()
    with pytest.raises(GmailHeldReconciliationError) as raised:
        inspect(f, cookie=cookie)
    safe(raised.value, f.generation, cookie, str(f.directory))
    assert not reads and not f.side_effects and f.snapshot() == before


@pytest.mark.parametrize("missing", ["directory", "lock", "ledger"])
def test_missing_existing_state_denied_before_lock_and_never_recreated(
    tmp_path, monkeypatch, missing
):
    import shutil

    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError

    f = Fixture(tmp_path, monkeypatch)
    item = inspector(f)
    if missing == "directory":
        shutil.rmtree(f.directory)
    else:
        (f.authority._lock_path if missing == "lock" else f.authority._path).unlink()
    before = set(tmp_path.rglob("*"))
    locks = []
    original = OAuthTransactionAuthority._locked

    def locked(authority):
        locks.append(True)
        return original(authority)

    monkeypatch.setattr(OAuthTransactionAuthority, "_locked", locked)
    with pytest.raises(GmailHeldReconciliationError):
        item.inspect(generation=f.generation, cookie=f.sessions.cookie)
    assert not locks and set(tmp_path.rglob("*")) == before and not f.side_effects


@pytest.mark.parametrize(
    "field,value",
    [
        ("state", "exchange_started"),
        ("state", "exchange_pending"),
        ("state", "pending"),
        ("state", "denied"),
        ("loaded", False),
        ("execution", None),
        ("execution", "not-a-digest"),
        ("configuration", "f" * 64),
        ("account", "e" * 64),
        ("rotation", "rotating"),
        ("verifier", "invented-leftover-verifier"),
    ],
)
def test_authenticated_ledger_row_requires_exact_consumed_held_gmail_selection(
    tmp_path, monkeypatch, field, value
):
    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError

    f = Fixture(tmp_path, monkeypatch)
    f.change_row(**{field: value})
    before = f.snapshot()
    with pytest.raises(GmailHeldReconciliationError):
        inspect(f)
    assert f.snapshot() == before and not f.side_effects


@pytest.mark.parametrize(
    "change",
    ["cipher_key", "origin", "owner_client", "ciphertext", "json_duplicate", "schema", "watermark"],
)
def test_full_ledger_authentication_original_context_and_schema_required(
    tmp_path, monkeypatch, change
):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError

    f = Fixture(tmp_path, monkeypatch)
    if change == "cipher_key":
        f.authority._cipher = AESGCM(b"Z" * 32)
    elif change in {"origin", "owner_client"}:
        context = json.loads(f.sessions.continuity._context)
        context["origin" if change == "origin" else "client_id"] = (
            "https://other.example"
            if change == "origin"
            else "456-other.apps.googleusercontent.com"
        )
        f.authority._context = (
            b"zac-provider-oauth-transactions-v1\x00" + json.dumps(context).encode()
        )
    elif change == "ciphertext":
        f.authority._path.write_bytes(b"invented unauthenticated ciphertext" * 3)
    else:
        value, state = f.row()
        if change == "schema":
            value["rows"][state]["unexpected"] = "invented-private-schema"
        elif change == "watermark":
            value["watermark"] = "not-an-aware-time"
        raw = json.dumps(value).encode()
        if change == "json_duplicate":
            raw = raw.replace(b'"version": 1', b'"version": 1, "version": 1', 1)
        nonce = os.urandom(12)
        f.authority._path.write_bytes(
            nonce + f.authority._cipher.encrypt(nonce, raw, f.authority._context)
        )
    before = f.snapshot()
    with pytest.raises(GmailHeldReconciliationError) as raised:
        inspect(f)
    safe(raised.value, str(f.directory), f.generation, "invented-private-schema")
    assert f.snapshot() == before and not f.side_effects


@pytest.mark.parametrize("generation", ["0" * 32, "G" * 32, "a" * 31, "a" * 33, "../private", None])
def test_generation_requires_exact_original_correlation(tmp_path, monkeypatch, generation):
    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError

    f = Fixture(tmp_path, monkeypatch)
    before = f.snapshot()
    with pytest.raises(GmailHeldReconciliationError):
        inspect(f, generation=generation)
    assert f.snapshot() == before and not f.side_effects


def test_owner_revoked_during_authenticated_read_returns_no_receipt(tmp_path, monkeypatch):
    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError

    f = Fixture(tmp_path, monkeypatch)
    original = OAuthTransactionAuthority._read

    def read(authority):
        value = original(authority)
        f.sessions.sessions.revoke(f.sessions.cookie)
        return value

    monkeypatch.setattr(OAuthTransactionAuthority, "_read", read)
    before = f.snapshot()
    with pytest.raises(GmailHeldReconciliationError):
        inspect(f)
    assert f.snapshot() == before and not f.side_effects


@pytest.mark.parametrize("target", ["directory", "lock", "ledger"])
def test_existing_state_must_be_protected_before_lock(tmp_path, monkeypatch, target):
    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError

    f = Fixture(tmp_path, monkeypatch)
    item = inspector(f)
    path = {"directory": f.directory, "lock": f.authority._lock_path, "ledger": f.authority._path}[
        target
    ]
    path.chmod(0o755 if target == "directory" else 0o644)
    before = f.snapshot()
    locks = []
    original = OAuthTransactionAuthority._locked

    def locked(authority):
        locks.append(True)
        return original(authority)

    monkeypatch.setattr(OAuthTransactionAuthority, "_locked", locked)
    with pytest.raises(GmailHeldReconciliationError):
        item.inspect(generation=f.generation, cookie=f.sessions.cookie)
    assert not locks and f.snapshot() == before and not f.side_effects


@pytest.mark.parametrize("target", ["lock", "ledger"])
def test_symlink_namespace_denied_without_following_or_recreating(tmp_path, monkeypatch, target):
    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError

    f = Fixture(tmp_path, monkeypatch)
    path = f.authority._lock_path if target == "lock" else f.authority._path
    retained = tmp_path / (target + "-retained")
    path.rename(retained)
    path.symlink_to(retained)
    before = retained.read_bytes()
    with pytest.raises(GmailHeldReconciliationError):
        inspect(f)
    assert path.is_symlink() and retained.read_bytes() == before and not f.side_effects


@pytest.mark.parametrize("change", ["authority", "configuration", "slack", "write"])
def test_invalid_constructor_is_inert(tmp_path, monkeypatch, change):
    from tests.test_oauth_configuration import slack
    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError

    f = Fixture(tmp_path, monkeypatch)
    changes = {
        "authority": {"authority": object()},
        "configuration": {"configuration": object()},
        "slack": {"configuration": slack(private_origin=f.configuration.private_origin)},
        "write": {
            "configuration": gmail(
                private_origin=f.configuration.private_origin,
                grant_profile="approved_communications",
            )
        },
    }
    before = f.snapshot()
    with pytest.raises(GmailHeldReconciliationError):
        inspector(f, **changes[change])
    assert f.snapshot() == before and not f.side_effects


def test_ambiguous_generation_among_all_rows_is_not_first_match(tmp_path, monkeypatch):
    import hashlib
    from types import SimpleNamespace

    import zacai.connectors.gmail_held_reconciliation as module

    f = Fixture(tmp_path, monkeypatch)
    value, state = f.row()
    value["rows"]["f" * 64] = {
        **value["rows"][state],
        "state": "denied",
        "loaded": False,
        "execution": None,
    }
    f.authority._write(value)
    before = f.snapshot()
    original = hashlib.sha256

    def digest(data):
        if data.startswith(b"zac-gmail-held-generation-v1\x00"):
            return SimpleNamespace(hexdigest=lambda: f.generation + "0" * 32)
        return original(data)

    monkeypatch.setattr(module, "hashlib", SimpleNamespace(sha256=digest))
    with pytest.raises(module.GmailHeldReconciliationError):
        inspect(f)
    assert f.snapshot() == before and not f.side_effects


def test_other_nonmatching_rows_do_not_replace_selected_original_held_row(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    value, state = f.row()
    value["rows"]["f" * 64] = {
        **value["rows"][state],
        "state": "denied",
        "loaded": False,
        "execution": None,
    }
    f.authority._write(value)
    before = f.snapshot()
    assert inspect(f).generation == f.generation
    assert f.snapshot() == before and not f.side_effects


@pytest.mark.parametrize("target", ["lock", "ledger"])
def test_identical_bytes_replaced_inode_during_read_is_rejected(tmp_path, monkeypatch, target):
    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError

    f = Fixture(tmp_path, monkeypatch)
    original = OAuthTransactionAuthority._read

    def read(authority):
        value = original(authority)
        path = authority._path if target == "ledger" else authority._lock_path
        temporary = f.directory / "invented-replacement"
        temporary.write_bytes(path.read_bytes())
        temporary.chmod(0o600)
        temporary.replace(path)
        return value

    monkeypatch.setattr(OAuthTransactionAuthority, "_read", read)
    with pytest.raises(GmailHeldReconciliationError):
        inspect(f)
    assert not f.side_effects


def test_private_read_cancellation_has_no_chained_ledger_or_cookie_diagnostics(
    tmp_path, monkeypatch
):
    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationCancelled

    f = Fixture(tmp_path, monkeypatch)
    private = "invented-private-cancelled-held-read"

    def interrupted(authority):
        raise KeyboardInterrupt(private)

    monkeypatch.setattr(OAuthTransactionAuthority, "_read", interrupted)
    before = f.snapshot()
    with pytest.raises(GmailHeldReconciliationCancelled) as raised:
        inspect(f)
    safe(raised.value, private, f.generation, f.sessions.cookie, str(f.directory))
    assert f.snapshot() == before and not f.side_effects


def test_authenticated_ledger_future_watermark_denies_without_writing_time(tmp_path, monkeypatch):
    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError

    f = Fixture(tmp_path, monkeypatch)
    value, _ = f.row()
    value["watermark"] = (f.sessions.now + timedelta(minutes=1)).isoformat()
    f.authority._write(value)
    before = f.snapshot()
    with pytest.raises(GmailHeldReconciliationError):
        inspect(f)
    assert f.snapshot() == before and not f.side_effects


def test_constructor_does_not_observe_missing_storage_owner_or_clock(tmp_path, monkeypatch):
    import shutil

    import zacai.connectors.gmail_held_reconciliation as module

    f = Fixture(tmp_path, monkeypatch)
    shutil.rmtree(f.directory)
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("Inspector construction must remain inert")

    monkeypatch.setattr(module, "_guard", forbidden)
    monkeypatch.setattr(f.sessions.continuity, "_owner", forbidden)
    monkeypatch.setattr(f.sessions.clock, "_read", forbidden)
    monkeypatch.setattr(OAuthTransactionAuthority, "_read", forbidden)
    monkeypatch.setattr(OAuthTransactionAuthority, "_locked", forbidden)
    item = inspector(f)
    assert item is not None and not calls and not f.directory.exists()


@pytest.mark.parametrize("change", ["owner", "expiry"])
def test_owner_and_session_still_current_after_read(tmp_path, monkeypatch, change):
    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError
    from zacai.interfaces.private_web import OwnerGrant
    from zacai.interfaces.session_store import Identity

    f = Fixture(tmp_path, monkeypatch)
    original = OAuthTransactionAuthority._read

    def read(authority):
        value = original(authority)
        if change == "owner":
            f.sessions.owner = OwnerGrant(
                Identity("https://accounts.google.com", "invented-new-owner"),
                f.sessions.owner.scopes,
            )
        else:
            f.sessions.now += timedelta(days=1)
        return value

    monkeypatch.setattr(OAuthTransactionAuthority, "_read", read)
    before = f.snapshot()
    with pytest.raises(GmailHeldReconciliationError):
        inspect(f)
    assert f.snapshot() == before and not f.side_effects


def test_clock_callback_revoking_cookie_cannot_return_positive_reference(tmp_path, monkeypatch):
    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError

    f = Fixture(tmp_path, monkeypatch)
    item = inspector(f)
    original = OAuthTransactionAuthority._read

    def read(authority):
        value = original(authority)

        def revoke():
            f.sessions.sessions.revoke(f.sessions.cookie)
            return f.sessions.now

        f.sessions.clock._read = revoke
        return value

    monkeypatch.setattr(OAuthTransactionAuthority, "_read", read)
    before = f.snapshot()
    with pytest.raises(GmailHeldReconciliationError):
        item.inspect(generation=f.generation, cookie=f.sessions.cookie)
    assert f.snapshot() == before and not f.side_effects


@pytest.mark.parametrize("change", ["authority_cipher", "ledger_inode"])
def test_lock_cleanup_mutations_cannot_escape_final_original_state_audit(
    tmp_path, monkeypatch, change
):
    from contextlib import contextmanager

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError

    f = Fixture(tmp_path, monkeypatch)
    item = inspector(f)
    original = OAuthTransactionAuthority._locked

    @contextmanager
    def locked(authority):
        with original(authority):
            yield
        if change == "authority_cipher":
            authority._cipher = AESGCM(b"Z" * 32)
        else:
            replacement = f.directory / "invented-post-cleanup-replacement"
            replacement.write_bytes(authority._path.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(authority._path)

    monkeypatch.setattr(OAuthTransactionAuthority, "_locked", locked)
    with pytest.raises(GmailHeldReconciliationError):
        item.inspect(generation=f.generation, cookie=f.sessions.cookie)
    assert not f.side_effects


def test_private_selector_issues_original_reference_without_writes(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    item = inspector(f)
    before = f.snapshot()

    def forbidden(*args, **kwargs):
        raise AssertionError("selection cannot update or initialize operational storage")

    for method in ("_now", "_write", "_persist", "_ready", "initialize"):
        monkeypatch.setattr(OAuthTransactionAuthority, method, forbidden)
    receipt = item.select_only_held(cookie=f.sessions.cookie)
    assert receipt.generation == f.generation
    assert receipt._issuer is item._issuer
    assert receipt.original_actor_verified is False
    assert receipt.native_material_verified is False
    assert receipt.source_subject_verified is False
    assert f.snapshot() == before and not f.side_effects


def test_private_selector_expired_hold_with_new_current_owner_session(tmp_path, monkeypatch):
    from tests.test_connector_authority import OWNER

    f = Fixture(tmp_path, monkeypatch)
    f.sessions.now += timedelta(days=1)
    fresh = f.sessions.sessions.start_user(OWNER, f.sessions.now)
    before = f.snapshot()
    reference = inspector(f).select_only_held(cookie=fresh)
    assert reference.generation == f.generation and not reference.original_actor_verified
    assert f.snapshot() == before and not f.side_effects


@pytest.mark.parametrize("change", ["wrong", "revoked", "expired", "other_owner", "no_hr"])
def test_private_selector_rejects_noncurrent_owner_before_read(tmp_path, monkeypatch, change):
    from tests.test_connector_authority import OWNER
    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError
    from zacai.interfaces.private_web import BoundaryScope, OwnerGrant
    from zacai.interfaces.session_store import Identity
    from zacai.policy import DataClassification as C
    from zacai.policy import TrustBoundary as B

    f = Fixture(tmp_path, monkeypatch)
    cookie = f.sessions.cookie
    if change == "wrong":
        cookie = "x" * 43
    elif change == "revoked":
        f.sessions.sessions.revoke(cookie)
    elif change == "expired":
        f.sessions.now += timedelta(days=1)
    elif change == "other_owner":
        cookie = f.sessions.sessions.start_user(Identity(OWNER.issuer, "other"), f.sessions.now)
    else:
        f.sessions.owner = OwnerGrant(
            OWNER, (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),)
        )
    reads = []
    monkeypatch.setattr(OAuthTransactionAuthority, "_read", lambda _: reads.append(True))
    with pytest.raises(GmailHeldReconciliationError) as raised:
        inspector(f).select_only_held(cookie=cookie)
    safe(raised.value, cookie, f.generation)
    assert not reads and not f.side_effects


@pytest.mark.parametrize(
    "change", ["empty", "second_held", "second_denied", "second_config", "only_config"]
)
def test_private_selector_denies_ambiguity_or_configuration_conflict(tmp_path, monkeypatch, change):
    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError

    f = Fixture(tmp_path, monkeypatch)
    value, state = f.row()
    if change == "empty":
        value["rows"].clear()
    elif change == "only_config":
        value["rows"][state]["configuration"] = "f" * 64
    else:
        row = dict(value["rows"][state])
        if change == "second_denied":
            row.update(state="denied", loaded=False, execution=None)
        elif change == "second_config":
            row["configuration"] = "f" * 64
        value["rows"]["f" * 64] = row
    f.authority._write(value)
    before = f.snapshot()
    with pytest.raises(GmailHeldReconciliationError):
        inspector(f).select_only_held(cookie=f.sessions.cookie)
    assert f.snapshot() == before and not f.side_effects


def test_private_selector_foreign_account_row_is_not_selected(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    value, state = f.row()
    value["rows"]["f" * 64] = {**value["rows"][state], "account": "e" * 64}
    f.authority._write(value)
    before = f.snapshot()
    assert inspector(f).select_only_held(cookie=f.sessions.cookie).generation == f.generation
    assert f.snapshot() == before and not f.side_effects


@pytest.mark.parametrize(
    "field,value",
    [("state", "denied"), ("loaded", False), ("execution", None), ("rotation", "rotating")],
)
def test_private_selector_requires_loaded_consumed_held_row(tmp_path, monkeypatch, field, value):
    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError

    f = Fixture(tmp_path, monkeypatch)
    f.change_row(**{field: value})
    before = f.snapshot()
    with pytest.raises(GmailHeldReconciliationError):
        inspector(f).select_only_held(cookie=f.sessions.cookie)
    assert f.snapshot() == before and not f.side_effects


@pytest.mark.parametrize("stage", ["selection_cleanup", "inspection_cleanup"])
def test_private_selector_audits_both_lock_cleanup_boundaries(tmp_path, monkeypatch, stage):
    from contextlib import contextmanager

    from zacai.connectors.gmail_held_reconciliation import GmailHeldReconciliationError

    f = Fixture(tmp_path, monkeypatch)
    item = inspector(f)
    original = OAuthTransactionAuthority._locked
    exits = []

    @contextmanager
    def locked(authority):
        with original(authority) as lock_current:
            yield lock_current
        exits.append(True)
        if len(exits) == (1 if stage == "selection_cleanup" else 2):
            replacement = f.directory / "invented-replacement"
            replacement.write_bytes(authority._path.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(authority._path)

    monkeypatch.setattr(OAuthTransactionAuthority, "_locked", locked)
    with pytest.raises(GmailHeldReconciliationError):
        item.select_only_held(cookie=f.sessions.cookie)
    assert len(exits) == (1 if stage == "selection_cleanup" else 2)
    assert not f.side_effects


@pytest.mark.parametrize("change", ["issuer", "row", "state", "generation", "owner", "revoke"])
def test_private_selector_audits_returned_reference_and_owner_after_inspection(
    tmp_path, monkeypatch, change
):
    from zacai.connectors.gmail_held_reconciliation import (
        GmailHeldReconciliationError,
        HeldGmailReconciliation,
    )
    from zacai.interfaces.private_web import OwnerGrant
    from zacai.interfaces.session_store import Identity

    f = Fixture(tmp_path, monkeypatch)
    item = inspector(f)
    original = HeldGmailReconciliation.inspect

    def altered(self, **kwargs):
        reference = original(self, **kwargs)
        if change in {"issuer", "row", "state", "generation"}:
            field, value = {
                "issuer": ("_issuer", object()),
                "row": ("_row", b"invented-private-row"),
                "state": ("_state_hash", "e" * 64),
                "generation": ("_generation", "e" * 32),
            }[change]
            object.__setattr__(reference, field, value)
        elif change == "revoke":
            f.sessions.sessions.revoke(f.sessions.cookie)
        else:
            f.sessions.owner = OwnerGrant(
                Identity("https://accounts.google.com", "other"), f.sessions.owner.scopes
            )
        return reference

    monkeypatch.setattr(HeldGmailReconciliation, "inspect", altered)
    with pytest.raises(GmailHeldReconciliationError) as raised:
        item.select_only_held(cookie=f.sessions.cookie)
    safe(raised.value, f.sessions.cookie, f.generation, "invented-private-row")
    assert not f.side_effects


@pytest.mark.parametrize("cancel", [False, True])
def test_private_selector_discard_private_exception_frames(tmp_path, monkeypatch, cancel):
    from zacai.connectors.gmail_held_reconciliation import (
        GmailHeldReconciliationCancelled,
        GmailHeldReconciliationError,
    )

    f = Fixture(tmp_path, monkeypatch)
    private = "invented-private-selection-failure"

    def fail(authority):
        raise KeyboardInterrupt(private) if cancel else ValueError(private)

    monkeypatch.setattr(OAuthTransactionAuthority, "_read", fail)
    before = f.snapshot()
    kind = GmailHeldReconciliationCancelled if cancel else GmailHeldReconciliationError
    with pytest.raises(kind) as raised:
        inspector(f).select_only_held(cookie=f.sessions.cookie)
    safe(raised.value, private, f.generation, f.sessions.cookie)
    assert f.snapshot() == before and not f.side_effects
