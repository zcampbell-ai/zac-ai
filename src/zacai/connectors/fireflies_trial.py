"""One-run trusted-operator Fireflies host. No public CLI/agent approval API.

Operator issuance requires a real human approval and independently verified
recovery prerequisites. This library cannot authenticate a chat message or defend
against hostile Python/DB administrators. Authority is canonical immutable
USER_INSTRUCTION evidence, never a boolean from a task/transcript. No approval
for gateway hard-denied actions is introduced. Real backup adapter remains an
explicit prerequisite: this module ships no permissive/default protector.
"""

from __future__ import annotations

import subprocess
import uuid
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, SecretStr, model_validator
from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from zacai.config import get_secret
from zacai.connectors.fireflies_identity import prepare_account_reply
from zacai.connectors.fireflies_transport import FirefliesReadTransport
from zacai.gateway import ActionRequest, ActionType, GatewayOutcome, evaluate_gateway
from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.ingestion.fireflies_capture import CaptureReceipt, capture_selected_transcript
from zacai.policy import AccessRequest, DataClassification, Destination, TrustBoundary
from zacai.state import IngestionRun, Source, SourceSystem
from zacai.state_repository import (
    complete_ingestion_run,
    fail_ingestion_run,
    get_effective_source_classification,
    record_source,
    start_ingestion_run,
)

_BOUNDARY = TrustBoundary.BRAINSTORM
_CLASSIFICATION = DataClassification.CONFIDENTIAL


class TrialError(RuntimeError):
    """Sanitized trial failure; approval remains consumed after a claimed run."""


class TrialApproval(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")
    format: Literal["zac-fireflies-trial-v1"] = "zac-fireflies-trial-v1"
    id: uuid.UUID
    transcript_id: str = Field(min_length=1, max_length=200, strict=True)
    expected_email: str = Field(
        min_length=3,
        max_length=254,
        strict=True,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._+\-]*@[A-Za-z0-9][A-Za-z0-9.\-]*$",
    )
    boundary: Literal[TrustBoundary.BRAINSTORM] = TrustBoundary.BRAINSTORM
    classification: Literal[DataClassification.CONFIDENTIAL] = DataClassification.CONFIDENTIAL
    approved_at: AwareDatetime
    expires_at: AwareDatetime
    human_approval_reference: str = Field(min_length=1, max_length=500, strict=True)
    credential_recovery_reference: str = Field(min_length=1, max_length=500, strict=True)
    artifact_recovery_reference: str = Field(min_length=1, max_length=500, strict=True)

    @model_validator(mode="after")
    def validate_window(self) -> TrialApproval:
        if not timedelta(0) < self.expires_at - self.approved_at <= timedelta(minutes=15):
            raise ValueError("approval lifetime must be positive and at most 15 minutes")
        if any(
            not value.strip()
            for value in (
                self.transcript_id,
                self.human_approval_reference,
                self.credential_recovery_reference,
                self.artifact_recovery_reference,
            )
        ):
            raise ValueError("scope references must not be blank")
        return self


class ProtectionEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")
    approval_source_id: uuid.UUID
    run_id: uuid.UUID
    artifact_hashes: frozenset[str] = Field(min_length=4)
    state_export_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    verification_reference: str = Field(min_length=1, max_length=500)


class BackupProtector(Protocol):
    def preflight(self, scope: TrialApproval) -> None:
        """Verify host's actual backup/recovery/escrow prerequisites or raise."""
        ...

    def protect(
        self, approval_source_id: uuid.UUID, run_id: uuid.UUID, capture: CaptureReceipt
    ) -> ProtectionEvidence:
        """Verify encrypted committed state and artifact coverage, not just upload intent."""
        ...


def _now() -> datetime:
    return datetime.now(UTC)


def _active(scope: TrialApproval, now: datetime) -> None:
    if now.utcoffset() is None or not scope.approved_at <= now < scope.expires_at:
        raise TrialError("approval is not active")


def record_trial_approval(
    session: Session, *, store: ArtifactStore, scope: TrialApproval
) -> uuid.UUID:
    """Trusted operator ONLY, after explicit human approval and recovery checks.

    No public issuance endpoint or automatic chat parser exists. The caller owns
    commit. This persists evidence of operator approval; it does not create or
    verify that human decision, escrow, or restore drill itself.
    """
    scope = TrialApproval.model_validate(scope)
    raw = scope.model_dump_json().encode()
    digest = content_hash_of(raw)
    # Serialize operator issuance by approval UUID, including first-ever insert.
    session.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": scope.id.int % (2**63)})
    prior = session.execute(
        select(Source).where(
            Source.system == SourceSystem.USER_INSTRUCTION,
            Source.trust_boundary == _BOUNDARY,
            Source.external_ref == f"fireflies-trial-approval/{scope.id}",
        )
    ).scalar_one_or_none()
    if prior is not None and prior.content_hash != digest:
        raise TrialError("approval UUID cannot be revised")
    location = store.put(_BOUNDARY, digest, raw)
    if content_hash_of(store.get(_BOUNDARY, location)) != digest:
        raise TrialError("approval artifact integrity failed")
    source, _ = record_source(
        session,
        trust_boundary=_BOUNDARY,
        data_classification=_CLASSIFICATION,
        system=SourceSystem.USER_INSTRUCTION,
        external_ref=f"fireflies-trial-approval/{scope.id}",
        captured_at=scope.approved_at,
        content_hash=digest,
        content_location=location,
    )
    return source.id


def _claim(
    factory: sessionmaker[Session],
    store: ArtifactStore,
    approval_id: uuid.UUID,
    clock: Callable[[], datetime],
) -> tuple[TrialApproval, uuid.UUID]:
    with factory() as session:
        source = session.execute(
            select(Source)
            .where(
                Source.id == approval_id,
                Source.trust_boundary == _BOUNDARY,
                Source.system == SourceSystem.USER_INSTRUCTION,
            )
            .with_for_update()
        ).scalar_one_or_none()
        if source is None or source.content_location is None or source.content_hash is None:
            raise TrialError("approval unavailable")
        raw = store.get(_BOUNDARY, source.content_location)
        if len(raw) > 10_000 or content_hash_of(raw) != source.content_hash:
            raise TrialError("approval artifact integrity failed")
        scope = TrialApproval.model_validate_json(raw)
        if (
            source.external_ref != f"fireflies-trial-approval/{scope.id}"
            or get_effective_source_classification(session, source_id=source.id) != _CLASSIFICATION
        ):
            raise TrialError("approval scope mismatch")
        _active(scope, clock())
        connector = f"fireflies-trial/{approval_id}"
        if (
            session.scalar(select(IngestionRun.id).where(IngestionRun.connector == connector))
            is not None
        ):
            raise TrialError("approval already consumed")
        access = AccessRequest(
            data_boundary=_BOUNDARY,
            data_classification=_CLASSIFICATION,
            requestor_boundaries=frozenset({_BOUNDARY}),
            destination=Destination.LOCAL,
        )
        if (
            evaluate_gateway(
                ActionRequest(
                    action_type=ActionType.READ_DATA,
                    access=access,
                    description="selected Fireflies capture",
                )
            ).outcome
            != GatewayOutcome.ALLOW
        ):
            raise TrialError("read gateway denied")
        run = start_ingestion_run(session, connector=connector, trust_boundary=_BOUNDARY)
        run_id = run.id
        session.commit()  # durable consume before any key lookup or external request
        return scope, run_id


def _recheck(
    factory: sessionmaker[Session],
    scope: TrialApproval,
    approval_id: uuid.UUID,
    clock: Callable[[], datetime],
) -> None:
    _active(scope, clock())
    with factory() as session:
        source = session.scalar(
            select(Source).where(
                Source.id == approval_id,
                Source.trust_boundary == _BOUNDARY,
                Source.system == SourceSystem.USER_INSTRUCTION,
            )
        )
        if (
            source is None
            or source.external_ref != f"fireflies-trial-approval/{scope.id}"
            or get_effective_source_classification(session, source_id=approval_id)
            != _CLASSIFICATION
        ):
            raise TrialError("approval classification changed or unavailable")


def keychain_credential(scope: TrialApproval) -> SecretStr:
    """Trusted startup seam, called only AFTER claim. Never prints subprocess output.

    Fixed service/account, no credential value in argv. A short-lived environment
    mapping feeds existing D017 get_secret; the global process env is untouched.
    This function never adds/modifies Keychain entries or records escrow evidence.
    """
    try:
        result = subprocess.run(
            [
                "/usr/bin/security",
                "find-generic-password",
                "-w",
                "-s",
                "zacai-brainstorm-fireflies-api-key",
                "-a",
                scope.expected_email,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=10,
        )
        value = result.stdout.decode("utf-8").removesuffix("\n")
        secret = get_secret(
            "BRAINSTORM_FIREFLIES_API_KEY", _BOUNDARY, env={"BRAINSTORM_FIREFLIES_API_KEY": value}
        )
        if not secret:
            raise TrialError("credential unavailable")
        return SecretStr(secret)
    except Exception:  # noqa: BLE001 - keychain stdout/exception details must never surface
        raise TrialError("credential unavailable") from None


def execute_trial(
    factory: sessionmaker[Session],
    *,
    store: ArtifactStore,
    approval_source_id: uuid.UUID,
    protector: BackupProtector,
    transport: FirefliesReadTransport,
    credential: Callable[[TrialApproval], SecretStr] = keychain_credential,
    clock: Callable[[], datetime] = _now,
) -> tuple[CaptureReceipt, ProtectionEvidence]:
    """One operator invocation; no scheduler, retries, or external model.

    IngestionRun success records capture commit, not backup success. Overall trial
    success is returned ONLY after protection evidence matches committed state.
    On later protection failure, audit becomes FAILED but committed evidence is
    retained. Audit-write failure propagates a sanitized error and never returns
    success. Crashes can leave STARTED; replay still denies, operator diagnoses.
    """
    run_id: uuid.UUID | None = None
    phase = "APPROVAL"
    try:
        scope, run_id = _claim(factory, store, approval_source_id, clock)
        phase = "PREFLIGHT"
        protector.preflight(scope)  # cannot proceed on missing actual backup prerequisites
        _recheck(factory, scope, approval_source_id, clock)
        phase = "CREDENTIAL"
        key = credential(scope)
        _recheck(factory, scope, approval_source_id, clock)
        phase = "ACCOUNT"
        account = transport.account_reply(key)
        prepare_account_reply(account, expected_email=scope.expected_email)
        _recheck(factory, scope, approval_source_id, clock)
        phase = "TRANSCRIPT"
        transcript = transport.transcript_reply(key, scope.transcript_id)
        _recheck(factory, scope, approval_source_id, clock)
        phase = "CAPTURE"
        with factory() as session:
            receipt = capture_selected_transcript(
                session,
                artifact_store=store,
                requestor_boundaries=frozenset({_BOUNDARY}),
                data_classification=_CLASSIFICATION,
                expected_email=scope.expected_email,
                expected_id=scope.transcript_id,
                account_response=account,
                transcript_response=transcript,
                captured_at=clock(),
            )
            session.commit()
        phase = "INGESTION_AUDIT"
        with factory() as session:
            complete_ingestion_run(
                session,
                run_id=run_id,
                items_fetched=1,
                items_ingested=int(receipt.was_new),
                items_skipped=int(not receipt.was_new),
                items_failed=0,
            )
            session.commit()
        phase = "PROTECTION"
        proof = ProtectionEvidence.model_validate(
            protector.protect(approval_source_id, run_id, receipt)
        )
        with factory() as session:
            expected = set(
                session.scalars(
                    select(Source.content_hash).where(
                        Source.id.in_(
                            [
                                approval_source_id,
                                receipt.account_source_id,
                                receipt.raw_source_id,
                                receipt.normalized_source_id,
                            ]
                        ),
                        Source.trust_boundary == _BOUNDARY,
                    )
                )
            )
        if (
            proof.run_id != run_id
            or proof.approval_source_id != approval_source_id
            or None in expected
            or len(expected) != 4
            or not expected <= proof.artifact_hashes
        ):
            raise TrialError("backup coverage evidence mismatch")
        return receipt, proof
    except Exception:  # noqa: BLE001 - suppress potentially secret-bearing backend errors
        if run_id is not None:
            try:
                with factory() as session:
                    fail_ingestion_run(
                        session, run_id=run_id, error=f"FIREFLIES_TRIAL_{phase}_FAILED"
                    )
                    session.commit()
            except Exception:  # noqa: BLE001 - audit failure cannot leak backend details
                raise TrialError("trial failed; audit update also failed") from None
        raise TrialError("trial failed; no retry under this approval") from None
