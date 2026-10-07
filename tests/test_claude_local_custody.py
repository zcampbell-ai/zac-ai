"""Invented host orchestration: real signed owner/SQLite transactions/files.

Canonical PG capture/read are explicitly mocked; no Source, recovery or human
permission proof is asserted. TTY affirmation is simulated, never opened live.
"""

from datetime import UTC, datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from tests.test_claude_original_capture import inputs
from tests.test_private_host import CONFIG, OWNER, enroll
from zacai import claude_local_custody as m
from zacai.claude_original_capture import (
    ClaudeCustodyProposal,
    UncommittedClaudeCustody,
    observe_claude_artifact_root,
)
from zacai.claude_original_read import ReadClaudeCustody
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence.contracts import EvidenceReference
from zacai.interfaces.private_web import BoundaryScope
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


@pytest.fixture
def host(tmp_path, monkeypatch):
    directory = tmp_path / "owner-host"
    enrollment = enroll(directory, lambda: datetime.now(UTC), scopes=m._SCOPE)
    original, raw = inputs()
    proposal = ClaudeCustodyProposal.model_validate_json(raw)
    original_path, proposal_path = tmp_path / "original.json", tmp_path / "proposal.json"
    for path, data in ((original_path, original), (proposal_path, raw)):
        path.write_bytes(data)
        path.chmod(0o600)
    artifacts = LocalFilesystemArtifactStore(tmp_path / "artifacts")
    engine = create_engine("sqlite://")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE marker (id INTEGER)"))
    factory = sessionmaker(bind=engine)
    refs = tuple(
        EvidenceReference(
            source_id=uuid4(),
            content_hash=content_hash_of(data),
            trust_boundary=B.PERSONAL,
            effective_classification=C.HIGHLY_RESTRICTED,
        )
        for data in (original, b"invented companion")
    )
    events = []
    sessions = []

    def record(session, **kwargs):
        events.append("capture")
        sessions.append(session)
        assert kwargs["original_raw"] == original and kwargs["proposal_raw"] == raw
        assert kwargs["approved_proposal_hash"] == content_hash_of(raw)
        assert kwargs["requestor_boundaries"] == frozenset({B.PERSONAL})
        session.execute(text("INSERT INTO marker VALUES (1)"))
        return UncommittedClaudeCustody(*refs, content_hash_of(raw), proposal.captured_at, ())

    def load(session, **kwargs):
        events.append("reopen")
        assert session is not sessions[0]
        assert session.execute(text("SELECT count(*) FROM marker")).scalar_one() == 1
        return ReadClaudeCustody(
            *refs,
            content_hash_of(raw),
            proposal,
            original,
            b"invented companion",
            proposal.captured_at,
            *refs,
            b"invented envelope",
            C.HIGHLY_RESTRICTED,
            refs[0].source_id,
            False,
            True,
            False,
        )

    def approve(*args, **kwargs):
        assert kwargs["expected_proposal_hash"] == content_hash_of(raw)
        events.append("simulated-human-affirmation")
        with engine.connect() as connection:
            assert connection.execute(text("SELECT count(*) FROM marker")).scalar_one() == 0

    monkeypatch.setattr(m, "record_claude_original", record)
    monkeypatch.setattr(m, "load_claude_original", load)
    monkeypatch.setattr(m, "_approve_on_tty", approve)
    values = {
        "configuration": CONFIG,
        "owner_directory": directory,
        "expected_identity": OWNER,
        "escrow_confirmed_by_operator": True,
        "original_path": original_path,
        "expected_original_hash": content_hash_of(original),
        "proposal_path": proposal_path,
        "expected_proposal_hash": content_hash_of(raw),
        "session_factory": factory,
        "artifacts": artifacts,
        "expected_root": observe_claude_artifact_root(artifacts),
    }
    yield SimpleNamespace(
        values=values,
        events=events,
        owners=enrollment.owners,
        engine=engine,
        proposal=proposal,
        raw=raw,
        original=original,
    )
    engine.dispose()


def count(host):
    with host.engine.connect() as connection:
        return connection.execute(text("SELECT count(*) FROM marker")).scalar_one()


def test_reopen_after_commit_with_real_owner_and_no_listener(host):
    result = m.run_local_claude_custody(**host.values)
    assert host.events == ["simulated-human-affirmation", "capture", "reopen"]
    assert count(host) == 1
    assert result.status == "COMMITTED_REOPENED_RECOVERY_PENDING"
    assert not result.processing_authorized and not result.recovery_verified
    assert not result.current_facts_verified
    assert "original" not in repr(result)


@pytest.mark.parametrize("fault", ["scope", "hash", "original-mode", "proposal-noncanonical"])
def test_before_affirmation_holds_no_capture(host, fault):
    if fault == "scope":
        enroll(
            host.values["owner_directory"],
            lambda: datetime.now(UTC),
            scopes=(BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),),
        )
    elif fault == "hash":
        host.values["expected_original_hash"] = "0" * 64
    elif fault == "original-mode":
        host.values["original_path"].chmod(0o644)
    else:
        raw = host.raw + b"\n"
        host.values["proposal_path"].write_bytes(raw)
        host.values["expected_proposal_hash"] = content_hash_of(raw)
    with pytest.raises(m.LocalClaudeCustodyError, match="stop and reconcile") as caught:
        m.run_local_claude_custody(**host.values)
    assert host.events == [] and count(host) == 0
    assert caught.value.__cause__ is None and caught.value.__context__ is None


@pytest.mark.parametrize("phase", ["affirmation", "capture", "reopen"])
def test_actual_owner_revocation_at_callbacks_no_ack(host, monkeypatch, phase):
    name = {
        "affirmation": "_approve_on_tty",
        "capture": "record_claude_original",
        "reopen": "load_claude_original",
    }[phase]
    original = getattr(m, name)

    def revoke(*args, **kwargs):
        result = original(*args, **kwargs)
        host.owners.revoke()
        return result

    monkeypatch.setattr(m, name, revoke)
    with pytest.raises(m.LocalClaudeCustodyError):
        m.run_local_claude_custody(**host.values)
    assert count(host) == (1 if phase == "reopen" else 0)
    assert "reopen" not in host.events if phase != "reopen" else "reopen" in host.events


def test_simulated_human_refusal_before_db(host, monkeypatch):
    def refusal(*args, **kwargs):
        raise ValueError("invented refusal")

    monkeypatch.setattr(m, "_approve_on_tty", refusal)
    with pytest.raises(m.LocalClaudeCustodyError):
        m.run_local_claude_custody(**host.values)
    assert host.events == [] and count(host) == 0


@pytest.mark.parametrize("answer", ["correct", "wrong", "eof", "long"])
def test_tty_exact_hash_phrase_bounded_and_closed(host, monkeypatch, answer):
    # OS pipe endpoint simulated only; no actual /dev/tty or attended human.
    monkeypatch.undo()
    writes, closes = [], []
    phrase = "CAPTURE PERSONAL / HIGHLY_RESTRICTED " + content_hash_of(host.raw) + "\n"
    data = {"correct": phrase.encode(), "wrong": b"yes\n", "eof": b"", "long": b"x" * 200}[answer]
    remaining = bytearray(data)
    monkeypatch.setattr(m, "_tty_open", lambda *args: 123)
    monkeypatch.setattr(m.os, "isatty", lambda fd: True)
    monkeypatch.setattr(m.os, "tcgetpgrp", lambda fd: m.os.getpgrp())
    monkeypatch.setattr(m, "_tty_write", lambda fd, raw: writes.append(raw) or len(raw))
    monkeypatch.setattr(
        m, "_tty_read", lambda fd, size: bytes([remaining.pop(0)]) if remaining else b""
    )
    monkeypatch.setattr(m, "_tty_close", closes.append)
    monkeypatch.setattr(m, "_tty_flush", lambda fd, queue: None)
    if answer == "correct":
        m._approve_on_tty(
            host.proposal,
            host.values["original_path"],
            expected_proposal_hash=content_hash_of(host.raw),
        )
    else:
        with pytest.raises(ValueError):
            m._approve_on_tty(
                host.proposal,
                host.values["original_path"],
                expected_proposal_hash=content_hash_of(host.raw),
            )
    assert closes == [123] and len(writes) == 1
    assert host.original not in writes[0]
    if answer == "long":
        assert len(remaining) == 72


def test_file_symlink_hardlink_and_pre_read_size_hold(tmp_path):
    path = tmp_path / "raw"
    path.write_bytes(b"invented")
    path.chmod(0o600)
    digest = content_hash_of(b"invented")
    assert m._read_file(path, 8, digest) == b"invented"
    with pytest.raises(ValueError):
        m._read_file(path, 7, digest)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(ValueError):
        m._read_file(link, 8, digest)
    link.unlink()
    m.os.link(path, link)
    with pytest.raises(ValueError):
        m._read_file(path, 8, digest)


def test_outer_commit_failure_never_acknowledges(host):
    from sqlalchemy import event

    def fail_commit(session):
        raise RuntimeError("invented outer commit failure")

    event.listen(host.values["session_factory"], "before_commit", fail_commit)
    try:
        with pytest.raises(m.LocalClaudeCustodyError):
            m.run_local_claude_custody(**host.values)
    finally:
        event.remove(host.values["session_factory"], "before_commit", fail_commit)
    assert host.events == ["simulated-human-affirmation", "capture"]
    assert count(host) == 0


def test_reopen_mismatch_holds_committed_not_recovery(host, monkeypatch):
    from dataclasses import replace

    original = m.load_claude_original

    def wrong(*args, **kwargs):
        return replace(original(*args, **kwargs), proposal_hash="0" * 64)

    monkeypatch.setattr(m, "load_claude_original", wrong)
    with pytest.raises(m.LocalClaudeCustodyError):
        m.run_local_claude_custody(**host.values)
    assert count(host) == 1 and host.events[-1] == "reopen"


def test_wrong_owner_zero_private_file_reads(host, monkeypatch):
    from zacai.interfaces.session_store import Identity

    host.values["expected_identity"] = Identity(OWNER.issuer, "other-invented-owner")

    def forbidden(*args):
        raise AssertionError("private read reached")

    monkeypatch.setattr(m, "_read_file", forbidden)
    with pytest.raises(m.LocalClaudeCustodyError):
        m.run_local_claude_custody(**host.values)
    assert count(host) == 0 and host.events == []


@pytest.mark.parametrize("phase", ["serve-cleanup", "context-shutdown"])
def test_actual_owner_revoke_after_local_result_before_host_return(host, monkeypatch, phase):
    from contextlib import contextmanager

    from zacai.interfaces.private_operator import PrivateOperatorWindow

    if phase == "serve-cleanup":
        original = PrivateOperatorWindow.run_local

        def revoked(window, **kwargs):
            original(window, **kwargs)
            host.owners.revoke()

        monkeypatch.setattr(PrivateOperatorWindow, "run_local", revoked)
    else:
        original = m.open_private_operator

        @contextmanager
        def revoked(**kwargs):
            with original(**kwargs) as window:
                yield window
            host.owners.revoke()

        monkeypatch.setattr(m, "open_private_operator", revoked)
    with pytest.raises(m.LocalClaudeCustodyError):
        m.run_local_claude_custody(**host.values)
    assert count(host) == 1 and host.events[-1] == "reopen"


@pytest.mark.parametrize("callback_failure", [False, True])
def test_supported_local_lifecycle_drains_thread_and_restores_signals(
    host, monkeypatch, callback_failure
):
    import logging
    import signal
    import threading

    from zacai.interfaces import private_operator as operator

    entered, release = threading.Event(), threading.Event()
    thread = threading.Thread(target=lambda: (entered.set(), release.wait()))
    drained = []
    original_drain = operator._drain_threads

    def drain(baseline):
        if thread.ident is not None and thread.is_alive():
            drained.append(True)
            release.set()
        original_drain(baseline)

    monkeypatch.setattr(operator, "_drain_threads", drain)
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    disabled = logging.root.manager.disable

    async def unused(principal):
        raise AssertionError("listener view reached")

    def action():
        thread.start()
        assert entered.wait(1)
        if callback_failure:
            raise RuntimeError("invented local failure")

    try:
        with operator.open_private_operator(
            mode=operator.PrivateOperatorMode.OWNER,
            client_id=CONFIG.client_id,
            origin=CONFIG.origin,
            directory=host.values["owner_directory"],
            escrow_confirmed_by_operator=True,
            view=unused,
            startup_loader=lambda **kwargs: CONFIG,
        ) as window:
            if callback_failure:
                with pytest.raises(operator.PrivateOperatorError):
                    window.run_local(action=action)
            else:
                window.run_local(action=action)
            with pytest.raises(operator.PrivateOperatorError):
                window.run_local(action=lambda: pytest.fail("replay action reached"))
    finally:
        release.set()
        if thread.ident is not None:
            thread.join(1)
    assert drained == [True] and not thread.is_alive()
    assert handlers == {sig: signal.getsignal(sig) for sig in handlers}
    assert logging.root.manager.disable == disabled


@pytest.mark.parametrize("field", ["original_reference", "companion_reference", "captured_at"])
def test_reopen_binding_defense_explicitly_mocked_loader(host, monkeypatch, field):
    from dataclasses import replace
    from datetime import timedelta
    from uuid import uuid4

    original = m.load_claude_original

    def different(*args, **kwargs):
        read = original(*args, **kwargs)
        value = (
            read.captured_at + timedelta(microseconds=1)
            if field == "captured_at"
            else getattr(read, field).model_copy(update={"source_id": uuid4()})
        )
        return replace(read, **{field: value})

    monkeypatch.setattr(m, "load_claude_original", different)
    with pytest.raises(m.LocalClaudeCustodyError):
        m.run_local_claude_custody(**host.values)
    assert count(host) == 1 and host.events[-1] == "reopen"


@pytest.mark.parametrize("phase", ["after-local", "shutdown"])
def test_public_interrupt_cleanup_fixed_hold_after_commit(host, monkeypatch, phase):
    from contextlib import contextmanager

    from zacai.interfaces.private_operator import PrivateOperatorWindow

    if phase == "after-local":
        original = PrivateOperatorWindow.run_local

        def interrupted(window, **kwargs):
            original(window, **kwargs)
            raise KeyboardInterrupt

        monkeypatch.setattr(PrivateOperatorWindow, "run_local", interrupted)
    else:
        original = m.open_private_operator

        @contextmanager
        def interrupted(**kwargs):
            with original(**kwargs) as window:
                yield window
            raise KeyboardInterrupt

        monkeypatch.setattr(m, "open_private_operator", interrupted)
    with pytest.raises(m.LocalClaudeCustodyError) as caught:
        m.run_local_claude_custody(**host.values)
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert count(host) == 1 and host.events[-1] == "reopen"


def test_tty_digest_bound_before_open(host, monkeypatch):
    monkeypatch.undo()
    opened = []
    monkeypatch.setattr(m, "_tty_open", lambda *args: opened.append(True))
    with pytest.raises(ValueError, match="affirmed proposal digest differs"):
        m._approve_on_tty(
            host.proposal, host.values["original_path"], expected_proposal_hash="0" * 64
        )
    assert opened == []


@pytest.mark.parametrize("flush_failure", [False, True])
def test_tty_typeahead_and_leftovers_flushed_close_even_on_flush_failure(
    host, monkeypatch, flush_failure
):
    monkeypatch.undo()
    phrase = ("CAPTURE PERSONAL / HIGHLY_RESTRICTED " + content_hash_of(host.raw) + "\n").encode()
    queued = bytearray(phrase + b"invented queued shell leftovers\n")
    events, closes = [], []
    monkeypatch.setattr(m, "_tty_open", lambda *args: 123)
    monkeypatch.setattr(m.os, "isatty", lambda fd: True)
    monkeypatch.setattr(m.os, "tcgetpgrp", lambda fd: m.os.getpgrp())
    monkeypatch.setattr(
        m, "_tty_write", lambda fd, raw: events.append("review-written") or len(raw)
    )

    def flush(fd, queue):
        events.append("flush")
        queued.clear()
        if flush_failure and events.count("flush") == 2:
            raise OSError("invented cleanup flush failure")

    monkeypatch.setattr(m, "_tty_flush", flush)
    monkeypatch.setattr(m, "_tty_read", lambda fd, n: events.append("empty-after-flush") or b"")
    monkeypatch.setattr(m, "_tty_close", closes.append)
    # A complete old queued affirmation is discarded; no fresh attended input.
    with pytest.raises((ValueError, OSError)):
        m._approve_on_tty(
            host.proposal,
            host.values["original_path"],
            expected_proposal_hash=content_hash_of(host.raw),
        )
    assert events == ["review-written", "flush", "empty-after-flush", "flush"]
    assert queued == b"" and closes == [123]


def test_local_action_never_binds_listener(host, monkeypatch):
    import socket

    from zacai.interfaces import private_operator as operator

    def forbidden(*args, **kwargs):
        raise AssertionError("HTTP listener path reached")

    monkeypatch.setattr(socket.socket, "bind", forbidden)
    monkeypatch.setattr(operator, "_serve", forbidden)
    result = m.run_local_claude_custody(**host.values)
    assert result.status == "COMMITTED_REOPENED_RECOVERY_PENDING"
    assert host.events[-1] == "reopen"
