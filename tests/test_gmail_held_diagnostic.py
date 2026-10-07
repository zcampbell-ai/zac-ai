"""Invented encrypted ledger counts; no native/provider or actual private state."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from tests.test_connector_authority import OWNER
from tests.test_gmail_held_reconciliation import Fixture, inspector
from zacai.connectors.gmail_held_diagnostic import (
    GmailHeldDiagnosticCancelled,
    GmailHeldDiagnosticError,
    HeldGmailDiagnostic,
)
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.interfaces.private_web import BoundaryScope, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


def diagnostic(f):
    return HeldGmailDiagnostic(reconciliation=inspector(f))


def deny_writes(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("Diagnostic must not mutate or renew OAuth state")

    for name in ("_now", "_write", "initialize", "begin", "consume_callback", "_persist"):
        monkeypatch.setattr(OAuthTransactionAuthority, name, forbidden)


def safe(error, f):
    assert error.__cause__ is None and error.__context__ is None
    assert all(
        p not in str(error) + repr(error)
        for p in (f.sessions.cookie, f.generation, str(f.directory))
    )
    tb = error.__traceback__
    while tb:
        if tb.tb_frame.f_globals.get("__name__") == "zacai.connectors.gmail_held_diagnostic":
            assert tb.tb_frame.f_code.co_name == "call"
            assert not {"args", "kwargs", "cookie", "ledger", "row"} & tb.tb_frame.f_locals.keys()
        tb = tb.tb_next


def test_all_states_counted_without_material_authority_or_writes(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    value, original = f.row()
    template = value["rows"][original]
    for n, state in enumerate(
        ("pending", "exchange_pending", "exchange_started", "denied", "held"), 1
    ):
        row = dict(template, state=state, loaded=state in {"exchange_started", "held"})
        row["execution"] = (
            "e" * 64 if state in {"exchange_pending", "exchange_started", "held"} else None
        )
        row["verifier"] = "v" * 43 if state == "pending" else None
        value["rows"][f"{n:064x}"] = row
    value["rows"]["f" * 64] = dict(template, account="a" * 64, configuration="b" * 64)
    f.authority._write(value)
    before = f.snapshot()
    item = diagnostic(f)
    deny_writes(monkeypatch)
    receipt = item.inspect(cookie=f.sessions.cookie)
    assert (
        receipt.pending,
        receipt.exchange_pending,
        receipt.exchange_started,
        receipt.denied,
        receipt.held,
        receipt.loaded,
        receipt.total,
    ) == (1, 1, 1, 1, 2, 3, 6)
    for flag in (
        "installed",
        "original_actor_verified",
        "source_subject_verified",
        "native_material_verified",
        "live_access_proven",
        "credential_authority",
        "processing_authorized",
        "execution_authorized",
    ):
        assert getattr(receipt, flag) is False
    assert repr(receipt) == "GmailHeldDiagnosticReceipt(installed=False)"
    assert not any(
        hasattr(receipt, name)
        for name in (
            "generation",
            "cookie",
            "identity",
            "state_hash",
            "execution",
            "credential",
            "access_token",
        )
    )
    assert f.snapshot() == before and not f.side_effects


def test_expired_row_accepts_fresh_current_saved_owner_cookie(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    f.sessions.now += timedelta(days=1)
    fresh = f.sessions.sessions.start_user(OWNER, f.sessions.now)
    before = f.snapshot()
    deny_writes(monkeypatch)
    receipt = diagnostic(f).inspect(cookie=fresh)
    assert receipt.held == receipt.loaded == receipt.total == 1
    assert not receipt.original_actor_verified
    assert f.snapshot() == before and not f.side_effects


@pytest.mark.parametrize("change", ["wrong", "revoked", "expired", "owner", "scope"])
def test_current_owner_required_before_authenticated_read(tmp_path, monkeypatch, change):
    f = Fixture(tmp_path, monkeypatch)
    item = diagnostic(f)
    cookie = f.sessions.cookie
    if change == "wrong":
        cookie = "x" * 43
    elif change == "revoked":
        f.sessions.sessions.revoke(cookie)
    elif change == "expired":
        f.sessions.now += timedelta(days=1)
    elif change == "owner":
        f.sessions.owner = OwnerGrant(
            Identity(OWNER.issuer, "invented-other"), f.sessions.owner.scopes
        )
    else:
        f.sessions.owner = OwnerGrant(
            OWNER, (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),)
        )
    reads = []
    monkeypatch.setattr(OAuthTransactionAuthority, "_read", lambda self: reads.append(True))
    with pytest.raises(GmailHeldDiagnosticError) as raised:
        item.inspect(cookie=cookie)
    safe(raised.value, f)
    assert not reads and not f.side_effects


@pytest.mark.parametrize("missing", ["ledger", "lock", "directory"])
def test_missing_state_not_recreated_or_locked(tmp_path, monkeypatch, missing):
    import shutil

    f = Fixture(tmp_path, monkeypatch)
    item = diagnostic(f)
    if missing == "directory":
        shutil.rmtree(f.directory)
    else:
        (f.authority._path if missing == "ledger" else f.authority._lock_path).unlink()
    called = []
    monkeypatch.setattr(OAuthTransactionAuthority, "_locked", lambda self: called.append(True))
    with pytest.raises(GmailHeldDiagnosticError):
        item.inspect(cookie=f.sessions.cookie)
    assert not called
    assert not (
        f.directory
        if missing == "directory"
        else f.authority._path
        if missing == "ledger"
        else f.authority._lock_path
    ).exists()


@pytest.mark.parametrize("field,value", [("configuration", "b" * 64), ("rotation", "rotating")])
def test_conflicting_selected_account_never_discloses_counts(tmp_path, monkeypatch, field, value):
    f = Fixture(tmp_path, monkeypatch)
    f.change_row(**{field: value})
    before = f.snapshot()
    with pytest.raises(GmailHeldDiagnosticError) as raised:
        diagnostic(f).inspect(cookie=f.sessions.cookie)
    safe(raised.value, f)
    assert f.snapshot() == before and not f.side_effects


@pytest.mark.parametrize("seam", ["read", "cleanup"])
@pytest.mark.parametrize("change", ["revoke", "owner", "clock", "cipher", "inode"])
def test_no_receipt_after_read_or_cleanup_changes(tmp_path, monkeypatch, seam, change):
    f = Fixture(tmp_path, monkeypatch)
    item = diagnostic(f)

    def mutate():
        if change == "revoke":
            f.sessions.sessions.revoke(f.sessions.cookie)
        elif change == "owner":
            f.sessions.owner = OwnerGrant(
                Identity(OWNER.issuer, "invented-other"), f.sessions.owner.scopes
            )
        elif change == "clock":
            f.sessions.now += timedelta(days=1)
        elif change == "cipher":
            f.authority._cipher = AESGCM(b"X" * 32)
        else:
            replacement = f.directory / "invented-replacement"
            replacement.write_bytes(f.authority._path.read_bytes())
            replacement.chmod(0o600)
            replacement.replace(f.authority._path)

    if seam == "read":
        original = OAuthTransactionAuthority._read

        def read(authority):
            result = original(authority)
            mutate()
            return result

        monkeypatch.setattr(OAuthTransactionAuthority, "_read", read)
    else:
        original = OAuthTransactionAuthority._locked

        @contextmanager
        def locked(authority):
            with original(authority):
                yield
            mutate()

        monkeypatch.setattr(OAuthTransactionAuthority, "_locked", locked)
    with pytest.raises(GmailHeldDiagnosticError) as raised:
        item.inspect(cookie=f.sessions.cookie)
    safe(raised.value, f)
    assert not f.side_effects


@pytest.mark.parametrize("fault", ["corrupt", "schema", "watermark", "cancel"])
def test_full_authentication_clock_and_cancellation_closed(tmp_path, monkeypatch, fault):
    f = Fixture(tmp_path, monkeypatch)
    item = diagnostic(f)
    if fault == "corrupt":
        raw = f.authority._path.read_bytes()
        f.authority._path.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    elif fault == "schema":
        f.change_row(loaded="invented-invalid")
    elif fault == "watermark":
        value, _ = f.row()
        value["watermark"] = (f.sessions.now + timedelta(days=1)).isoformat()
        f.authority._write(value)
    else:

        def cancelled(authority):
            raise KeyboardInterrupt("invented-private-cancellation")

        monkeypatch.setattr(OAuthTransactionAuthority, "_read", cancelled)
    before = f.snapshot()
    with pytest.raises(
        GmailHeldDiagnosticCancelled if fault == "cancel" else GmailHeldDiagnosticError
    ) as raised:
        item.inspect(cookie=f.sessions.cookie)
    safe(raised.value, f)
    assert "invented-private-cancellation" not in str(raised.value)
    assert f.snapshot() == before and not f.side_effects


def test_constructor_inert_with_missing_storage_and_poisoned_callbacks(tmp_path, monkeypatch):
    import shutil

    f = Fixture(tmp_path, monkeypatch)
    reconciliation = inspector(f)
    shutil.rmtree(f.directory)
    called = []
    monkeypatch.setattr(type(reconciliation), "_current", lambda self: called.append(True))
    monkeypatch.setattr(type(reconciliation), "_files", lambda self: called.append(True))
    item = HeldGmailDiagnostic(reconciliation=reconciliation)
    assert item._original is reconciliation and not called and not f.directory.exists()
    with pytest.raises(GmailHeldDiagnosticError):
        HeldGmailDiagnostic(reconciliation=object())
