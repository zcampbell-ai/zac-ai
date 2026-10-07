"""Offline actual encrypted held/session fixtures, never native/provider I/O."""

from __future__ import annotations

import json
import os
from urllib.parse import urlencode

import pytest

from tests.test_gmail_held_reconciliation import Fixture
from zacai.connectors.gmail_held_reconciliation import HeldGmailReconciliation
from zacai.connectors.gmail_quarantine_journal import (
    JOURNAL_NAME,
    STAGING_NAME,
    GmailQuarantineJournal,
    GmailQuarantineJournalCancellationUnconfirmed,
    GmailQuarantineJournalError,
    GmailQuarantineJournalUnconfirmed,
)


def compose(f, **changes):
    stopped = []
    preserved = []
    fields = {
        "authority": f.authority,
        "reconciliation": HeldGmailReconciliation(
            authority=f.authority, configuration=f.configuration
        ),
        "configuration": f.configuration,
        "key": b"S" * 32,
        "action_generation": "quarantine-invented-once",
        "preservation_check": lambda: preserved.append(True),
        "stop": lambda: stopped.append(True),
    }
    fields.update(changes)
    return GmailQuarantineJournal(**fields), stopped, preserved


def request(f, **changes):
    scope = {"path": "/connections/gmail/quarantine"}
    scope.update(changes)
    selected = f.sessions.request(**scope)
    selected.scope["headers"].append((b"content-type", b"application/x-www-form-urlencoded"))
    return selected


def body(f, **changes):
    fields = {
        "csrf": f.sessions.csrf,
        "reviewed_configuration_digest": f.configuration.configuration_digest,
        "action_generation": "quarantine-invented-once",
    }
    fields.update(changes)
    return urlencode(fields).encode("ascii")


def test_constructor_is_inert(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)

    def forbidden(*args, **kwargs):
        raise AssertionError("constructor filesystem")

    monkeypatch.setattr(os, "open", forbidden)
    helper, stopped, preserved = compose(f)
    assert repr(helper) == "GmailQuarantineJournal()"
    assert stopped == preserved == []


def test_one_encrypted_intent_preserves_original_and_grants_nothing(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    helper, stopped, preserved = compose(f)
    original = f.snapshot()
    preview = helper.preview(cookie=f.sessions.cookie)
    receipt = helper.write_once(request=request(f), body=body(f), preview=preview)
    assert receipt.status == "quarantine_intent_recorded"
    assert all(
        getattr(receipt, field) is False
        for field in (
            "installed",
            "quarantine_committed",
            "quarantine_authorized",
            "recovery_authorized",
            "original_actor_verified",
            "current_reviewer_verified",
            "source_subject_verified",
            "native_material_verified",
            "live_access_proven",
            "remote_grant_verified",
            "credential_authority",
            "processing_authorized",
            "execution_authorized",
        )
    )
    assert receipt.quarantine_committed is False and receipt.recovery_authorized is False
    assert f.snapshot().keys() == original.keys() | {f.directory / JOURNAL_NAME}
    assert all(f.snapshot()[path] == witness for path, witness in original.items())
    assert not (f.directory / STAGING_NAME).exists()
    encrypted = (f.directory / JOURNAL_NAME).read_bytes()
    assert b"quarantine_only" not in encrypted and b"invented" not in encrypted
    plain = helper._cipher.decrypt(encrypted[:12], encrypted[12:], helper._context)
    record = json.loads(plain)
    ledger, state = f.row()
    assert record["original_row"] == ledger["rows"][state]
    assert record["remote_grant_status"] == "unknown"
    assert record["reviewer"]["binding_digest"] == preview._binding
    assert record["reviewer"]["review_generation"] == "quarantine-invented-once"
    assert stopped == [] and preserved
    with pytest.raises(GmailQuarantineJournalError):
        helper.write_once(request=request(f), body=body(f), preview=preview)
    assert f.side_effects == []


@pytest.mark.parametrize(
    "field,value",
    [
        ("csrf", "wrong"),
        ("action_generation", "another"),
        ("reviewed_configuration_digest", "0" * 64),
    ],
)
def test_wrong_owner_form_spends_before_any_staging(tmp_path, monkeypatch, field, value):
    f = Fixture(tmp_path, monkeypatch)
    helper, stopped, _ = compose(f)
    original = f.snapshot()
    preview = helper.preview(cookie=f.sessions.cookie)
    with pytest.raises(GmailQuarantineJournalError):
        helper.write_once(request=request(f), body=body(f, **{field: value}), preview=preview)
    assert f.snapshot() == original and stopped == [True]
    with pytest.raises(GmailQuarantineJournalError):
        helper.write_once(request=request(f), body=body(f), preview=preview)
    assert f.snapshot() == original


@pytest.mark.parametrize(
    "change",
    [{"scheme": "http"}, {"method": "GET"}, {"query_string": b"hidden=1"}, {"path": "/other"}],
)
def test_request_boundaries(tmp_path, monkeypatch, change):
    f = Fixture(tmp_path, monkeypatch)
    helper, _, _ = compose(f)
    preview = helper.preview(cookie=f.sessions.cookie)
    with pytest.raises(GmailQuarantineJournalError):
        helper.write_once(request=request(f, **change), body=body(f), preview=preview)
    assert not (f.directory / STAGING_NAME).exists()


@pytest.mark.parametrize("name", [JOURNAL_NAME, STAGING_NAME])
def test_existing_journal_or_crash_residue_denies_preview(tmp_path, monkeypatch, name):
    f = Fixture(tmp_path, monkeypatch)
    helper, _, _ = compose(f)
    path = f.directory / name
    path.write_bytes(b"preserved existing evidence")
    path.chmod(0o600)
    before = f.snapshot()
    with pytest.raises(GmailQuarantineJournalError):
        helper.preview(cookie=f.sessions.cookie)
    assert f.snapshot() == before


def test_foreign_preview_and_mutated_original_row_deny(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    helper, _, _ = compose(f)
    foreign, _, _ = compose(f)
    preview = foreign.preview(cookie=f.sessions.cookie)
    with pytest.raises(GmailQuarantineJournalError):
        helper.write_once(request=request(f), body=body(f), preview=preview)
    assert not (f.directory / STAGING_NAME).exists()
    helper, _, _ = compose(f)
    preview = helper.preview(cookie=f.sessions.cookie)
    f.change_row(execution="a" * 64)
    with pytest.raises(GmailQuarantineJournalError):
        helper.write_once(request=request(f), body=body(f), preview=preview)
    assert not (f.directory / STAGING_NAME).exists()


def test_same_identity_new_session_cannot_replace_preview_owner_binding(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    helper, _, _ = compose(f)
    preview = helper.preview(cookie=f.sessions.cookie)
    new_cookie = f.sessions.sessions.start_user(f.sessions.owner.identity, f.sessions.now)
    csrf = f.sessions.sessions.peek_user(new_cookie, f.sessions.now).csrf
    with pytest.raises(GmailQuarantineJournalError):
        helper.write_once(
            request=request(f, cookie=new_cookie), body=body(f, csrf=csrf), preview=preview
        )
    assert not (f.directory / STAGING_NAME).exists()


@pytest.mark.parametrize("primitive", ["write", "link", "fsync", "pread"])
def test_publication_failure_retains_evidence_and_original_stop(tmp_path, monkeypatch, primitive):
    f = Fixture(tmp_path, monkeypatch)
    helper, stopped, _ = compose(f)
    original = f.snapshot()
    preview = helper.preview(cookie=f.sessions.cookie)

    real = getattr(os, primitive)

    def fail(*args, **kwargs):
        if primitive == "pread" and (
            helper._stage_inode is None
            or (os.fstat(args[0]).st_dev, os.fstat(args[0]).st_ino) != helper._stage_inode
        ):
            return real(*args, **kwargs)
        raise RuntimeError("invented-private-failure")

    monkeypatch.setattr(os, primitive, fail)
    with pytest.raises(GmailQuarantineJournalUnconfirmed) as caught:
        helper.write_once(request=request(f), body=body(f), preview=preview)
    assert stopped == [True]
    assert all(f.snapshot()[path] == witness for path, witness in original.items())
    assert (f.directory / STAGING_NAME).exists() or (f.directory / JOURNAL_NAME).exists()
    assert "invented-private-failure" not in str(caught.value)
    assert caught.value.__context__ is None and caught.value.__cause__ is None


def test_guard_cancellation_after_publication_retains_journal_and_stop(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    fired = False

    def guard():
        nonlocal fired
        if (f.directory / JOURNAL_NAME).exists() and not fired:
            fired = True
            raise KeyboardInterrupt("invented-private-cancel")

    helper, stopped, _ = compose(f, preservation_check=guard)
    preview = helper.preview(cookie=f.sessions.cookie)
    with pytest.raises(GmailQuarantineJournalCancellationUnconfirmed):
        helper.write_once(request=request(f), body=body(f), preview=preview)
    assert stopped == [True] and (f.directory / JOURNAL_NAME).exists()
    helper.namespace_current()


def test_namespace_final_witness_rejects_journal_replacement(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    helper, _, _ = compose(f)
    preview = helper.preview(cookie=f.sessions.cookie)
    helper.write_once(request=request(f), body=body(f), preview=preview)
    path = f.directory / JOURNAL_NAME
    path.unlink()
    path.write_bytes(b"replacement")
    path.chmod(0o600)
    with pytest.raises(ValueError):
        helper.namespace_current()


def test_observed_directory_links_and_posix_convention_are_narrow(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    helper, _, _ = compose(f)
    preview = helper.preview(cookie=f.sessions.cookie)
    baseline = preview._files[0][4]
    helper.write_once(request=request(f), body=body(f), preview=preview)
    actual = helper._files()
    assert actual[0][4] in (baseline, baseline + 1)
    original_files = helper._files

    def convention(links):
        observed = original_files()
        return (observed[0][:4] + (links,), observed[1])

    monkeypatch.setattr(helper, "_files", lambda: convention(baseline))
    helper.namespace_current()
    monkeypatch.setattr(helper, "_files", lambda: convention(baseline + 1))
    helper.namespace_current()
    monkeypatch.setattr(helper, "_files", lambda: convention(baseline + 2))
    with pytest.raises(ValueError):
        helper.namespace_current()


def test_stop_replacement_cannot_redirect_original_stop(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    helper, stopped, _ = compose(f)
    preview = helper.preview(cookie=f.sessions.cookie)
    replacement = []
    helper._original_stop = lambda: replacement.append(True)
    with pytest.raises(GmailQuarantineJournalError):
        helper.write_once(request=request(f), body=body(f, csrf="wrong"), preview=preview)
    assert stopped == [True] and replacement == []


def test_initial_unexpected_child_denied_before_content_read(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    helper, _, _ = compose(f)
    unexpected = f.directory / "outside-journal-scope.txt"
    unexpected.write_bytes(b"invented private data outside permitted namespace")
    unexpected.chmod(0o600)
    real_open = os.open
    unexpected_reads = []

    def observed(path, *args, **kwargs):
        if path == unexpected:
            unexpected_reads.append(True)
            raise AssertionError("unexpected content access")
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(os, "open", observed)
    with pytest.raises(GmailQuarantineJournalError):
        helper.preview(cookie=f.sessions.cookie)
    assert unexpected_reads == []


def test_namespace_substitution_denies_before_alternate_directory_read(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    helper, _, _ = compose(f)
    helper.preview(cookie=f.sessions.cookie)
    alternate = tmp_path / "alternate-private-directory"
    alternate.mkdir(mode=0o700)
    original_iterdir = type(alternate).iterdir
    unexpected_reads = []

    def observed(path):
        if path == alternate:
            unexpected_reads.append(True)
            raise AssertionError("alternate namespace access")
        return original_iterdir(path)

    monkeypatch.setattr(type(alternate), "iterdir", observed)
    f.authority._directory = alternate
    with pytest.raises(ValueError):
        helper.namespace_current()
    assert unexpected_reads == []
