"""Read-only BRAINSTORM review recovery gate, outside agents.

No infrastructure selection, credential loader, uploader or model call. Trusted
operators pin a protected checkpoint and the prior independently recovered-key
receipt. Synthetic clients do not establish real off-device durability or escrow.
"""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from zacai.backup_artifacts import (
    BackupObjectStore,
    age_decrypt,
    backup_object_key_for,
)
from zacai.brainstorm_identity_recovery import (
    assert_brainstorm_recovery_state_key as _state_key,
)
from zacai.brainstorm_identity_recovery import verify_brainstorm_recovered_identity
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence.contracts import classification_covers
from zacai.intelligence.evidence import resolve_evidence_reference
from zacai.intelligence.review_context import decode_normalized_review_envelope
from zacai.intelligence.review_host import _snapshot
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import ReviewConsent
from zacai.review_protection import DisposableStateRestoreVerifier, assert_local_review_state_engine
from zacai.state import EvidenceStance, MeetingSource, ProjectEvidence, Source, SourceSystem
from zacai.state_repository import get_meeting, get_meeting_project_context

_DIGEST = r"^[0-9a-f]{64}$"
_BOUNDARIES = frozenset({B.BRAINSTORM})
_LABELS = frozenset({C.PUBLIC, C.INTERNAL, C.CONFIDENTIAL})


class ReviewRecoveryError(RuntimeError):
    """Fixed diagnostics; decrypted evidence/keys/provider text stay private."""


class ReviewRecoveryCheckpoint(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid", revalidate_instances="always")
    state_object: str = Field(min_length=1, max_length=250)
    ciphertext_hash: str = Field(pattern=_DIGEST)
    plaintext_hash: str = Field(pattern=_DIGEST)
    recovered_key_receipt_hash: str = Field(pattern=_DIGEST)

    @property
    def state_reference(self) -> str:
        return f"state:{self.state_object}"

    @property
    def artifact_reference(self) -> str:
        return f"checkpoint-artifacts:{self.plaintext_hash}"

    @property
    def credential_reference(self) -> str:
        return f"age-escrow:{self.recovered_key_receipt_hash}"


class BrainstormReviewRecoveryGate:
    """Verify protected pre-existing business evidence before local context reads.

    The pinned receipt attests the previously performed independent key recovery;
    it is operator evidence, not cryptographic proof of a password-manager UI.
    Each call also decrypts that receipt's original object with the current local
    identity, tests its recipient, independently recovers required artifacts and
    fully restores the pinned current checkpoint. No receipt alone passes a gate.

    Every business table and original Source field must still match. Additional
    Sources alone (including consent/claim/audit) are permitted; required selected
    and dependency Sources must exist in the checkpoint. Unrelated business
    changes conservatively demand a new checkpoint. Post-run protection captures
    the review's new authority/audit records; this gate cannot pre-protect them.
    """

    def __init__(
        self,
        *,
        factory: sessionmaker[Session],
        engine: Engine,
        verification_objects: BackupObjectStore,
        recipient: str,
        identity_path: Path,
        recovered_key_receipt: Path,
        checkpoint: ReviewRecoveryCheckpoint,
        restoration: DisposableStateRestoreVerifier,
    ) -> None:
        assert_local_review_state_engine(engine)
        if factory.kw.get("bind") is not engine or not isinstance(
            restoration, DisposableStateRestoreVerifier
        ):
            raise ReviewRecoveryError("bound state and actual recovery verifier required")
        self._factory, self._engine = factory, engine
        self._objects, self._recipient, self._identity = (
            verification_objects,
            recipient,
            identity_path,
        )
        self._receipt = recovered_key_receipt
        self._checkpoint = ReviewRecoveryCheckpoint.model_validate(checkpoint)
        self._restoration = restoration

    def _recover(self, key: str, *, limit: int, digest: str | None = None) -> bytes:
        size = self._objects.stat(key).size
        if not 0 < size <= limit:
            raise ValueError("recovery object outside capacity")
        raw = self._objects.get_object(key)
        if len(raw) != size or digest is not None and content_hash_of(raw) != digest:
            raise ValueError("recovery ciphertext changed")
        return age_decrypt(raw, self._identity)

    def _verify_recovered_identity(self) -> None:
        verify_brainstorm_recovered_identity(
            verification_objects=self._objects,
            recipient=self._recipient,
            identity_path=self._identity,
            recovered_key_receipt=self._receipt,
            expected_receipt_hash=self._checkpoint.recovered_key_receipt_hash,
        )

    def preflight(
        self, consent: ReviewConsent, *, additional_sources: dict[UUID, str] | None = None
    ) -> None:
        try:
            consent = ReviewConsent.model_validate(consent)
            checkpoint = self._checkpoint
            _state_key(checkpoint.state_object, checkpoint.ciphertext_hash)
            if (
                consent.state_recovery_reference != checkpoint.state_reference
                or consent.artifact_recovery_reference != checkpoint.artifact_reference
                or consent.credential_recovery_reference != checkpoint.credential_reference
            ):
                raise ValueError("operator checkpoint binding mismatch")
            self._verify_recovered_identity()
            state = self._recover(
                checkpoint.state_object, limit=65_000_000, digest=checkpoint.ciphertext_hash
            )
            if content_hash_of(state) != checkpoint.plaintext_hash or not state.startswith(
                (
                    b"zacai-state-backup-v2\n0004\nBRAINSTORM\n",
                    b"zacai-state-backup-v2\n0005\nBRAINSTORM\n",
                )
            ):
                raise ValueError("current checkpoint unavailable")
            hashes = self._required_artifacts(consent, additional_sources=additional_sources)
            self._restoration.verify(state, hashes, current_business_state=self._engine)
        except Exception:  # noqa: BLE001 - never expose receipt/artifact/backend text
            raise ReviewRecoveryError("review recovery prerequisites unavailable") from None

    def _required_artifacts(
        self, consent: ReviewConsent, *, additional_sources: dict[UUID, str] | None = None
    ) -> dict[UUID, str]:
        hashes: dict[UUID, str] = {}
        with _snapshot(self._factory) as session:
            if session.scalar(text("SELECT current_database()")) != self._engine.url.database:
                raise ValueError("canonical recovery metadata target mismatch")

            def recover(sid: UUID) -> tuple[Source, bytes]:
                ref = resolve_evidence_reference(
                    session, source_id=sid, requestor_boundaries=_BOUNDARIES
                )
                source = session.get(Source, sid)
                if (
                    source is None
                    or not source.content_location
                    or ref.trust_boundary != B.BRAINSTORM
                    or not classification_covers(
                        consent.classification, ref.effective_classification
                    )
                ):
                    raise ValueError("recovery Source outside scope")
                hashes[sid] = ref.content_hash
                if len(hashes) > 64:
                    raise ValueError("recovery provenance outside capacity")
                raw = self._recover(
                    backup_object_key_for(B.BRAINSTORM, ref.content_hash), limit=2_001_000
                )
                if len(raw) > 2_000_000 or content_hash_of(raw) != ref.content_hash:
                    raise ValueError("remote artifact recovery mismatch")
                return source, raw

            if additional_sources is not None:
                if not 1 <= len(additional_sources) <= 11:
                    raise ValueError("additional recovery scope outside capacity")
                for sid, expected in additional_sources.items():
                    source, _ = recover(sid)
                    if source.content_hash != expected or source.system != SourceSystem.MANUAL:
                        raise ValueError("additional recovery source changed")
            meetings = (consent.selection.selected, *consent.selection.earlier)
            if len({m.meeting_id for m in meetings}) != len(meetings):
                raise ValueError("duplicate selected meeting")
            for item in meetings:
                meeting = get_meeting(
                    session, meeting_id=item.meeting_id, requestor_boundaries=_BOUNDARIES
                )
                if meeting is None or not classification_covers(
                    consent.classification, meeting.data_classification
                ):
                    raise ValueError("selected meeting unavailable")
                linked = set(
                    session.scalars(
                        select(MeetingSource.source_id).where(
                            MeetingSource.meeting_id == item.meeting_id,
                            MeetingSource.trust_boundary == B.BRAINSTORM,
                        )
                    )
                )
                if item.source_id not in linked:
                    raise ValueError("selected Source is not linked")
                source, raw = recover(item.source_id)
                envelope = decode_normalized_review_envelope(raw)
                payload_id = envelope["payload"]["id"]
                if (
                    source.system != SourceSystem.FIREFLIES
                    or source.external_ref != f"normalized-v1/transcript/{payload_id}"
                ):
                    raise ValueError("unsupported normalized Source")
                for name in ("raw_source", "account_source"):
                    dependency = envelope[name]
                    sid = UUID(dependency["id"])
                    dep_source, _ = recover(sid)
                    if (
                        sid == source.id
                        or hashes[sid] != dependency["sha256"]
                        or dep_source.system != SourceSystem.FIREFLIES
                    ):
                        raise ValueError("dependency identity mismatch")
                    if name == "raw_source":
                        if (
                            sid not in linked
                            or dep_source.external_ref != f"wire/transcript/{payload_id}"
                        ):
                            raise ValueError("raw Source role mismatch")
                    elif not (dep_source.external_ref or "").startswith("wire/account/"):
                        raise ValueError("account Source role mismatch")
                if consent.selection.projects:
                    for sid in linked - hashes.keys():
                        recover(sid)

            if consent.selection.projects:
                primary = get_meeting_project_context(
                    session,
                    meeting_id=consent.selection.selected.meeting_id,
                    requestor_boundaries=_BOUNDARIES,
                    allowed_classifications=_LABELS,
                )
                by_id = {link.association_id: link for link in primary}
                chosen = [by_id[p.association_id] for p in consent.selection.projects]
                project_ids = {link.project_id for link in chosen}
                used = list(chosen)
                for item in consent.selection.earlier:
                    shared = [
                        link
                        for link in get_meeting_project_context(
                            session,
                            meeting_id=item.meeting_id,
                            requestor_boundaries=_BOUNDARIES,
                            allowed_classifications=_LABELS,
                        )
                        if link.project_id in project_ids
                    ]
                    if not shared:
                        raise ValueError("earlier meeting lacks reviewed project context")
                    used.extend(shared)
                for link in used:
                    recover(link.confirmation_source_id)
                    for version in {link.reviewed_project_version, link.current_project_version}:
                        supporting = list(
                            session.scalars(
                                select(ProjectEvidence.source_id).where(
                                    ProjectEvidence.project_entity_id == link.project_id,
                                    ProjectEvidence.project_version == version,
                                    ProjectEvidence.trust_boundary == B.BRAINSTORM,
                                    ProjectEvidence.stance == EvidenceStance.SUPPORTS,
                                )
                            )
                        )
                        if not supporting:
                            raise ValueError("project lacks recoverable supporting evidence")
                        for sid in supporting:
                            recover(sid)
                for project_selection in consent.selection.projects:
                    source, _ = recover(project_selection.source_id)
                    if source.system != SourceSystem.MANUAL:
                        raise ValueError("unsupported project Source")
        return hashes
