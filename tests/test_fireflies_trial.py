"""Synthetic trusted-host tests; no Keychain, API, B2 or production access."""

from __future__ import annotations

import json
import subprocess
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

import pytest
from pydantic import SecretStr, ValidationError
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from zacai.connectors import fireflies_trial as module
from zacai.connectors.fireflies_trial import (
    ProtectionEvidence,
    TrialApproval,
    TrialError,
    execute_trial,
    keychain_credential,
    record_trial_approval,
)
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.ingestion.fireflies_capture import CaptureReceipt
from zacai.state import IngestionRun, IngestionRunStatus, Source

NOW = datetime(2026, 10, 2, 14, tzinfo=UTC)


def scope() -> TrialApproval:
    return TrialApproval(
        id=uuid.uuid4(),
        transcript_id="synthetic-selected",
        expected_email="owner@example.invalid",
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=10),
        human_approval_reference="synthetic-human-reference",
        credential_recovery_reference="synthetic-escrow-drill",
        artifact_recovery_reference="synthetic-artifact-drill",
    )


class FakeTransport:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.email = "owner@example.invalid"
        self.fail = False

    def account_reply(self, key: SecretStr) -> bytes:
        self.calls.append("identity")
        if self.fail:
            raise RuntimeError("synthetic secret marker")
        return json.dumps(
            {"data": {"user": {"user_id": "synthetic-owner", "email": self.email}}}
        ).encode()

    def transcript_reply(self, key: SecretStr, transcript_id: str) -> bytes:
        self.calls.append(transcript_id)
        return json.dumps(
            {
                "data": {
                    "transcript": {
                        "id": transcript_id,
                        "title": "Synthetic trial",
                        "dateString": NOW.isoformat(),
                        "privacy": "owner",
                        "is_live": False,
                        "organizer_email": None,
                        "participants": [],
                        "user": {"user_id": "synthetic-owner", "email": self.email},
                        "meeting_attendees": [],
                        "sentences": [
                            {"index": 0, "speaker_name": None, "text": "Synthetic evidence"}
                        ],
                    }
                }
            }
        ).encode()


class FakeProtector:
    def __init__(self, factory: sessionmaker[Session]) -> None:
        self.factory = factory
        self.fail_preflight = False
        self.bad_proof = False
        self.calls: list[str] = []

    def preflight(self, approval: TrialApproval) -> None:
        self.calls.append("preflight")
        if self.fail_preflight:
            raise RuntimeError("synthetic backup prerequisite failure")

    def protect(
        self, approval_source_id: uuid.UUID, run_id: uuid.UUID, capture: CaptureReceipt
    ) -> ProtectionEvidence:
        self.calls.append("protect")
        with self.factory() as session:
            hashes = frozenset(
                session.scalars(
                    select(Source.content_hash).where(
                        Source.id.in_(
                            [
                                approval_source_id,
                                capture.account_source_id,
                                capture.raw_source_id,
                                capture.normalized_source_id,
                            ]
                        )
                    )
                )
            )
        return ProtectionEvidence(
            approval_source_id=approval_source_id,
            run_id=uuid.uuid4() if self.bad_proof else run_id,
            artifact_hashes=hashes,
            state_export_hash=content_hash_of(b"synthetic encrypted state"),
            verification_reference="synthetic verification only, no live backup",
        )


def register(
    factory: sessionmaker[Session], store: LocalFilesystemArtifactStore, approval: TrialApproval
) -> uuid.UUID:
    with factory() as session:
        source_id = record_trial_approval(session, store=store, scope=approval)
        session.commit()
        return source_id


def test_claim_is_atomic_under_two_simultaneous_connections(
    test_session_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    store = LocalFilesystemArtifactStore(tmp_path)
    approval_id = register(test_session_factory, store, scope())
    barrier = Barrier(2)

    def claim() -> bool:
        barrier.wait(timeout=5)
        try:
            module._claim(test_session_factory, store, approval_id, lambda: NOW)
            return True
        except TrialError:
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(lambda _: claim(), range(2)))
    assert sorted(outcomes) == [False, True]
    with test_session_factory() as session:
        runs = list(
            session.scalars(
                select(IngestionRun).where(
                    IngestionRun.connector == f"fireflies-trial/{approval_id}"
                )
            )
        )
        assert len(runs) == 1 and runs[0].status == IngestionRunStatus.STARTED


def test_full_synthetic_trial_and_replay_denial(
    test_session_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    store = LocalFilesystemArtifactStore(tmp_path)
    approval = scope().model_copy(update={"transcript_id": "synthetic-new-capture"})
    approval_id = register(test_session_factory, store, approval)
    transport = FakeTransport()
    protector = FakeProtector(test_session_factory)
    credentials: list[str] = []

    def credential(approval: TrialApproval) -> SecretStr:
        credentials.append("lookup")
        with test_session_factory() as session:
            run = session.scalar(
                select(IngestionRun).where(
                    IngestionRun.connector == f"fireflies-trial/{approval_id}"
                )
            )
            assert run is not None and run.status == IngestionRunStatus.STARTED
        return SecretStr("synthetic-test-only-credential")

    receipt, proof = execute_trial(
        test_session_factory,
        store=store,
        approval_source_id=approval_id,
        protector=protector,
        transport=transport,
        credential=credential,
        clock=lambda: NOW,
    )
    assert receipt.was_new and len(proof.artifact_hashes) == 4
    assert transport.calls == ["identity", "synthetic-new-capture"]
    assert protector.calls == ["preflight", "protect"]
    with pytest.raises(TrialError):
        execute_trial(
            test_session_factory,
            store=store,
            approval_source_id=approval_id,
            protector=protector,
            transport=transport,
            credential=credential,
            clock=lambda: NOW,
        )
    assert credentials == ["lookup"]
    assert transport.calls == ["identity", "synthetic-new-capture"]


@pytest.mark.parametrize("failure", ["preflight", "identity", "transport", "backup"])
def test_failure_consumes_approval_and_preserves_sanitized_audit(
    test_session_factory: sessionmaker[Session], tmp_path: Path, failure: str
) -> None:
    store = LocalFilesystemArtifactStore(tmp_path)
    approval_id = register(test_session_factory, store, scope())
    transport = FakeTransport()
    protector = FakeProtector(test_session_factory)
    credentials: list[str] = []
    protector.fail_preflight = failure == "preflight"
    protector.bad_proof = failure == "backup"
    transport.email = "other@example.invalid" if failure == "identity" else transport.email
    transport.fail = failure == "transport"

    def credential(approval: TrialApproval) -> SecretStr:
        credentials.append("lookup")
        return SecretStr("synthetic-test-only-credential")

    with pytest.raises(TrialError) as error:
        execute_trial(
            test_session_factory,
            store=store,
            approval_source_id=approval_id,
            protector=protector,
            transport=transport,
            credential=credential,
            clock=lambda: NOW,
        )
    assert "secret marker" not in str(error.value)
    if failure == "preflight":
        assert not credentials and not transport.calls
    if failure == "identity":
        assert transport.calls == ["identity"]
    with test_session_factory() as session:
        run = session.scalar(
            select(IngestionRun).where(IngestionRun.connector == f"fireflies-trial/{approval_id}")
        )
        assert run is not None and run.status == IngestionRunStatus.FAILED
        assert (
            run.error
            == f"FIREFLIES_TRIAL_{ {'preflight': 'PREFLIGHT', 'identity': 'ACCOUNT', 'transport': 'ACCOUNT', 'backup': 'PROTECTION'}[failure] }_FAILED"
        )
    with pytest.raises(TrialError):
        module._claim(test_session_factory, store, approval_id, lambda: NOW)


def test_expiry_after_identity_prevents_selected_query(
    test_session_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    store = LocalFilesystemArtifactStore(tmp_path)
    approval_id = register(test_session_factory, store, scope())
    transport = FakeTransport()
    moments = iter([NOW, NOW, NOW, NOW + timedelta(hours=1)])
    with pytest.raises(TrialError):
        execute_trial(
            test_session_factory,
            store=store,
            approval_source_id=approval_id,
            protector=FakeProtector(test_session_factory),
            transport=transport,
            credential=lambda _: SecretStr("synthetic-test-only-credential"),
            clock=lambda: next(moments),
        )
    assert transport.calls == ["identity"]


def test_approval_uuid_cannot_be_revised(
    test_session_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    store = LocalFilesystemArtifactStore(tmp_path)
    approval = scope()
    first = register(test_session_factory, store, approval)
    assert register(test_session_factory, store, approval) == first
    altered = approval.model_copy(update={"transcript_id": "different"})
    with pytest.raises(TrialError, match="revised"):
        register(test_session_factory, store, altered)


@pytest.mark.parametrize(
    "update",
    [
        {"expires_at": NOW},
        {"expires_at": NOW + timedelta(minutes=16)},
        {"expected_email": " owner@example.invalid"},
        {"human_approval_reference": " "},
        {"boundary": "PERSONAL"},
        {"classification": "INTERNAL"},
        {"approved": True},
    ],
)
def test_scope_rejects_authority_or_boundary_changes(update: dict[str, object]) -> None:
    raw = scope().model_dump()
    raw.update(update)
    with pytest.raises(ValidationError):
        TrialApproval.model_validate(raw)


def test_keychain_argv_and_output_stay_private(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: list[list[str]] = []

    def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        captured.append(args)
        assert kwargs["stderr"] == subprocess.DEVNULL and kwargs["timeout"] == 10
        return subprocess.CompletedProcess(args, 0, stdout=b"synthetic-test-only-credential\n")

    monkeypatch.setattr(module.subprocess, "run", run)
    value = keychain_credential(scope())
    assert value.get_secret_value() == "synthetic-test-only-credential"
    assert "synthetic-test-only-credential" not in repr(value)
    assert captured[0][0] == "/usr/bin/security"
    assert captured[0][-1] == "owner@example.invalid"
    assert "synthetic-test-only-credential" not in captured[0]


@pytest.mark.parametrize("reason", ["unknown", "expired", "elevated"])
def test_invalid_approval_never_reaches_preflight_or_credentials(
    test_session_factory: sessionmaker[Session], tmp_path: Path, reason: str
) -> None:
    from zacai.policy import DataClassification, TrustBoundary
    from zacai.state_repository import elevate_source_classification

    store = LocalFilesystemArtifactStore(tmp_path)
    approval_id = register(test_session_factory, store, scope())
    if reason == "unknown":
        approval_id = uuid.uuid4()
    if reason == "elevated":
        with test_session_factory() as session:
            elevate_source_classification(
                session,
                source_id=approval_id,
                trust_boundary=TrustBoundary.BRAINSTORM,
                new_classification=DataClassification.HIGHLY_RESTRICTED,
                reason="synthetic classification review",
                elevated_by="synthetic operator",
            )
            session.commit()
    transport = FakeTransport()
    protector = FakeProtector(test_session_factory)

    def credential(approval: TrialApproval) -> SecretStr:
        pytest.fail("no credential lookup allowed")

    with pytest.raises(TrialError):
        execute_trial(
            test_session_factory,
            store=store,
            approval_source_id=approval_id,
            protector=protector,
            transport=transport,
            credential=credential,
            clock=lambda: NOW + timedelta(hours=1) if reason == "expired" else NOW,
        )
    assert not transport.calls and not protector.calls


def test_approval_elevation_after_identity_blocks_transcript(
    test_session_factory: sessionmaker[Session], tmp_path: Path
) -> None:
    from zacai.policy import DataClassification, TrustBoundary
    from zacai.state_repository import elevate_source_classification

    store = LocalFilesystemArtifactStore(tmp_path)
    approval_id = register(test_session_factory, store, scope())

    class ElevatingTransport(FakeTransport):
        def account_reply(self, key: SecretStr) -> bytes:
            response = super().account_reply(key)
            with test_session_factory() as session:
                elevate_source_classification(
                    session,
                    source_id=approval_id,
                    trust_boundary=TrustBoundary.BRAINSTORM,
                    new_classification=DataClassification.HIGHLY_RESTRICTED,
                    reason="synthetic mid-run review",
                    elevated_by="synthetic operator",
                )
                session.commit()
            return response

    transport = ElevatingTransport()
    with pytest.raises(TrialError):
        execute_trial(
            test_session_factory,
            store=store,
            approval_source_id=approval_id,
            protector=FakeProtector(test_session_factory),
            transport=transport,
            credential=lambda _: SecretStr("synthetic-test-only-credential"),
            clock=lambda: NOW,
        )
    assert transport.calls == ["identity"]
