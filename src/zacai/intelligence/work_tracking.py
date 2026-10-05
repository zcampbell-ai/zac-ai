"""Replayable work observations, never execution authority or proof of completion.

The journal is an immutable artifact candidate for canonical Zac State storage.
Each snapshot binds one exact proposal and protected contextual packet. Sources
accompany observations; they do not authenticate a human choice or verify business
outcomes. Only the separately trusted host may capture/load it with current ACLs.
No status here is VERIFIED_COMPLETE; reported completion remains an open check.
"""

from __future__ import annotations

import hashlib
import json
import re
from enum import Enum
from typing import Literal, Self
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from zacai.intelligence.contextual_evaluation import ContextualPacket
from zacai.intelligence.contracts import (
    Contract,
    Digest,
    EvidenceReference,
    classification_covers,
)
from zacai.intelligence.meeting_review import ItemKind
from zacai.intelligence.work_proposals import PlanText, WorkProposal, packet_fingerprint
from zacai.policy import DataClassification, TrustBoundary


class WorkStatus(str, Enum):
    PROPOSED = "PROPOSED"
    AWAITING_USER = "AWAITING_USER"
    IN_PROGRESS_REPORTED = "IN_PROGRESS_REPORTED"
    BLOCKED_REPORTED = "BLOCKED_REPORTED"
    REVIEW_READY_REPORTED = "REVIEW_READY_REPORTED"
    USER_HANDLING_REPORTED = "USER_HANDLING_REPORTED"
    COMPLETION_REPORTED = "COMPLETION_REPORTED"
    REOPENED = "REOPENED"


class WorkObservation(Contract):
    observation_id: UUID
    sequence: int = Field(ge=1, le=256, strict=True)
    previous_digest: Digest
    status: WorkStatus
    reason: PlanText
    observed_at: AwareDatetime
    recorded_at: AwareDatetime
    evidence: tuple[EvidenceReference, ...] = Field(min_length=1, max_length=8)

    @model_validator(mode="after")
    def valid_observation(self) -> Self:
        if self.status == WorkStatus.PROPOSED or self.observed_at > self.recorded_at:
            raise ValueError("invalid observation")
        if len({ref.source_id for ref in self.evidence}) != len(self.evidence):
            raise ValueError("duplicate observation evidence")
        return self


def _encoded(model: Contract) -> bytes:
    return json.dumps(
        model.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode()


def observation_fingerprint(observation: WorkObservation) -> str:
    return hashlib.sha256(_encoded(WorkObservation.model_validate(observation))).hexdigest()


class WorkJournal(Contract):
    contract_version: Literal[1] = 1
    work_id: UUID
    trust_boundary: TrustBoundary
    data_classification: DataClassification
    packet_reference: EvidenceReference
    proposal: WorkProposal
    created_at: AwareDatetime
    observations: tuple[WorkObservation, ...] = Field(default=(), max_length=256)

    @model_validator(mode="after")
    def replay(self) -> Self:
        if self.packet_reference.content_hash != self.proposal.packet_digest:
            raise ValueError("proposal packet mismatch")
        refs = (self.packet_reference,) + tuple(
            ref for observation in self.observations for ref in observation.evidence
        )
        for ref in refs:
            if ref.trust_boundary != self.trust_boundary or not classification_covers(
                self.data_classification, ref.effective_classification
            ):
                raise ValueError("journal evidence boundary/classification mismatch")
        previous = self.initial_digest()
        last_recorded = self.created_at
        last_observed = self.created_at
        ids: set[UUID] = set()
        current = WorkStatus.PROPOSED
        for index, observation in enumerate(self.observations, start=1):
            if (
                observation.sequence != index
                or observation.previous_digest != previous
                or observation.observation_id in ids
                or observation.recorded_at < last_recorded
                or observation.observed_at < last_observed
                or (
                    current == WorkStatus.COMPLETION_REPORTED
                    and observation.status != WorkStatus.REOPENED
                )
                or (
                    observation.status == WorkStatus.REOPENED
                    and current != WorkStatus.COMPLETION_REPORTED
                )
            ):
                raise ValueError("journal sequence or transition mismatch")
            ids.add(observation.observation_id)
            previous = observation_fingerprint(observation)
            last_recorded, last_observed = observation.recorded_at, observation.observed_at
            current = observation.status
        return self

    def initial_digest(self) -> str:
        header = self.model_dump(mode="json", exclude={"observations"})
        return hashlib.sha256(
            json.dumps(
                header,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            ).encode()
        ).hexdigest()

    @property
    def tip_digest(self) -> str:
        return (
            observation_fingerprint(self.observations[-1])
            if self.observations
            else self.initial_digest()
        )

    @property
    def status(self) -> WorkStatus:
        return self.observations[-1].status if self.observations else WorkStatus.PROPOSED


def validate_journal_packet(journal: WorkJournal, packet: ContextualPacket) -> WorkJournal:
    """Exact proposal/item binding; caller still refreshes ACLs and recovery."""
    try:
        journal = WorkJournal.model_validate(journal)
        packet = ContextualPacket.model_validate(packet)
        proposal = journal.proposal
        if (
            proposal.packet_digest != packet_fingerprint(packet)
            or journal.trust_boundary != packet.task.event.trust_boundary
            or not classification_covers(
                journal.data_classification, packet.review.data_classification
            )
            or journal.created_at < packet.created_at
            or proposal.item_index >= len(packet.review.items)
            or packet.review.items[proposal.item_index].kind
            not in (ItemKind.COMMITMENT, ItemKind.FOLLOW_UP)
            or packet.review.conflicts
            or packet.review.clarifications
        ):
            raise ValueError("work binding mismatch or material context gap")
        return journal
    except Exception:  # noqa: BLE001, S110 - fixed private-safe diagnostics
        pass
    raise ValueError("work journal unavailable or mismatched")


def encode_work_journal(journal: WorkJournal) -> bytes:
    try:
        return _encoded(WorkJournal.model_validate(journal))
    except Exception:  # noqa: BLE001, S110
        pass
    raise ValueError("work journal unavailable or mismatched")


def decode_work_journal(payload: bytes) -> WorkJournal:
    try:
        if type(payload) is not bytes or len(payload) > 2_000_000:
            raise ValueError("invalid payload")
        journal = WorkJournal.model_validate_json(payload)
        if _encoded(journal) != payload:
            raise ValueError("noncanonical journal")
        return journal
    except Exception:  # noqa: BLE001, S110
        pass
    raise ValueError("work journal unavailable or mismatched")


def append_work_observation(
    journal: WorkJournal,
    observation: WorkObservation,
    *,
    expected_tip_digest: str,
) -> WorkJournal:
    """Return a new exact snapshot; no mutable write or global CAS guarantee.

    A host checks its retained tip before calling and serializes persistence.
    Concurrent independent snapshots can still branch and require reconciliation.
    """
    try:
        journal = WorkJournal.model_validate(journal)
        observation = WorkObservation.model_validate(observation)
        if (
            type(expected_tip_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", expected_tip_digest) is None
            or expected_tip_digest != journal.tip_digest
            or observation.previous_digest != expected_tip_digest
        ):
            raise ValueError("stale retained journal tip")
        return WorkJournal.model_validate(
            journal.model_copy(update={"observations": journal.observations + (observation,)})
        )
    except Exception:  # noqa: BLE001, S110
        pass
    raise ValueError("work observation append unavailable or mismatched")
