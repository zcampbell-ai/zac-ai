"""Current canonical EMAIL app-observation pair reader and candidate-spec join.

A trusted caller supplies actual read authority, retained/protected references and
instruction Task. This reader checks rows/bytes/revisions, not acquisition identity,
capture permission, encrypted recovery or processing. No source writes or dispatch.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from sqlalchemy import text
from sqlalchemy.orm import Session

from zacai.claude_original_read import _read_only
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.ingestion.gmail_app_observation import (
    MAX_COMPANION_BYTES,
    MAX_OBSERVATION_BYTES,
    GmailAppObservationCompanionV1,
    GmailAppObservationPreparationV1,
    prepare_gmail_app_observation,
)
from zacai.intelligence.contracts import ContextItem, EvidenceReference, IntelligenceTask
from zacai.intelligence.email_draft import (
    EmailDraftSpecificationV1,
    EmailRecipientComparisonV1,
    EmailSourceMetadataV1,
    _load,
    prepare_email_draft_specification,
)
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.intelligence.local_followup_runtime import _raise_interruption
from zacai.interfaces.email_input import _current_rows
from zacai.policy import AccessRequest, Destination, evaluate_access
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem


class GmailAppEmailSourceError(ValueError):
    """Fixed reader/spec diagnostics; suppress traceback-local capture."""


@dataclass(frozen=True, repr=False)
class GmailAppEmailSourceV1:
    original_reference: EvidenceReference
    companion_reference: EvidenceReference
    preparation: GmailAppObservationPreparationV1
    source_rows: tuple[tuple[tuple[str, object], ...], ...]
    raw_source_captured_at: datetime
    companion_source_captured_at: datetime
    checked_at: datetime
    processing_authorized: Literal[False] = field(default=False, init=False)
    recovery_verified: Literal[False] = field(default=False, init=False)
    acquisition_account_verified: Literal[False] = field(default=False, init=False)

    def context_items(self) -> tuple[ContextItem, ContextItem]:
        # Fixed data-only framing preserves every selected body character despite
        # the unchanged canonical Text contract trimming outer whitespace. These
        # labels are untrusted passage text, not an injection/security boundary.
        text = (
            "Unverified app body begins:\n"
            + self.preparation.literal_text
            + "\nUnverified app body ends."
        )
        companion = self.preparation.artifacts[1].original_bytes.decode("utf-8")
        items = (
            ContextItem(reference=self.original_reference, untrusted_text=text),
            ContextItem(reference=self.companion_reference, untrusted_text=companion),
        )
        if items[0].untrusted_text != text or items[1].untrusted_text != companion:
            raise ValueError("literal app observation projection normalization forbidden")
        return items


def _scope(authorized: frozenset[B], classifications: frozenset[C]) -> None:
    if (
        type(authorized) is not frozenset
        or type(classifications) is not frozenset
        or any(type(b) is not B for b in authorized)
        or any(type(c) is not C for c in classifications)
        or C.CONFIDENTIAL not in classifications
        or not evaluate_access(
            AccessRequest(
                data_boundary=B.BRAINSTORM,
                data_classification=C.CONFIDENTIAL,
                requestor_boundaries=authorized,
                destination=Destination.LOCAL,
            )
        ).allowed
    ):
        raise ValueError("declared business read scope denied")


def _read(
    session: Session,
    artifacts: LocalFilesystemArtifactStore,
    *,
    original_reference: EvidenceReference,
    companion_reference: EvidenceReference,
    as_of: datetime,
    authorized_boundaries: frozenset[B],
    allowed_classifications: frozenset[C],
) -> GmailAppEmailSourceV1:
    _scope(authorized_boundaries, allowed_classifications)
    if (
        type(artifacts) is not LocalFilesystemArtifactStore
        or type(as_of) is not datetime
        or as_of.utcoffset() is None
        or type(original_reference) is not EvidenceReference
        or type(companion_reference) is not EvidenceReference
        or original_reference.source_id == companion_reference.source_id
    ):
        raise ValueError("exact canonical app pair/time required")
    # Enforce the existing reader's real physical READ COMMITTED/no-write contract.
    session.execute(text("SET TRANSACTION ISOLATION LEVEL READ COMMITTED, READ ONLY"))
    _read_only(session)
    physical = _physical(session)
    refs = (original_reference, companion_reference)
    before = _current_rows(session, refs)
    rows = {
        r.source_id: [dict(row) for row in before if dict(row)["id"] == r.source_id] for r in refs
    }
    for ref in refs:
        if any(
            row["system"] is not SourceSystem.EMAIL
            or type(row["captured_at"]) is not datetime
            or row["captured_at"].utcoffset() is None
            or row["captured_at"] > as_of
            for row in rows[ref.source_id]
        ):
            raise ValueError("current canonical business EMAIL custody required")
    own = rows[companion_reference.source_id][0]
    raw_row = rows[original_reference.source_id][0]
    own_location, raw_location = own["content_location"], raw_row["content_location"]
    own_captured, raw_captured = own["captured_at"], raw_row["captured_at"]
    if (
        type(own_location) is not str
        or type(raw_location) is not str
        or type(own_captured) is not datetime
        or type(raw_captured) is not datetime
    ):
        raise ValueError("exact canonical artifact location/custody dates required")
    companion_raw = artifacts.get_bounded(B.BRAINSTORM, own_location, max_bytes=MAX_COMPANION_BYTES)
    _same(session, physical)
    _read_only(session)
    companion = GmailAppObservationCompanionV1.model_validate(
        _load(companion_raw, MAX_COMPANION_BYTES)
    )
    if (
        content_hash_of(companion_raw) != companion_reference.content_hash
        or canonical_bytes(companion.model_dump(mode="json")) != companion_raw
        or own["external_ref"] != companion.companion_namespace()
        or raw_row["external_ref"] != companion.raw_namespace
        or original_reference.content_hash != companion.raw_digest
        or not companion.scope.inspected_at <= own_captured <= as_of
    ):
        raise ValueError("exact app companion/source/time bindings required")
    raw = artifacts.get_bounded(B.BRAINSTORM, raw_location, max_bytes=MAX_OBSERVATION_BYTES)
    _same(session, physical)
    _read_only(session)
    prepared = prepare_gmail_app_observation(
        raw=raw,
        scope=companion.scope,
        requestor_boundaries=authorized_boundaries,
        allowed_classifications=allowed_classifications,
    )
    if prepared.companion != companion or prepared.artifacts[1].original_bytes != companion_raw:
        raise ValueError("complete app observation companion reconstruction differs")
    if _current_rows(session, refs) != before:
        raise ValueError(
            "verified app Source/ACL/revision preimages changed after artifact callbacks"
        )
    _same(session, physical)
    _read_only(session)
    return GmailAppEmailSourceV1(
        original_reference,
        companion_reference,
        prepared,
        before,
        raw_captured,
        own_captured,
        as_of,
    )


def load_gmail_app_email_source(
    session: Session,
    artifacts: LocalFilesystemArtifactStore,
    *,
    original_reference: EvidenceReference,
    companion_reference: EvidenceReference,
    as_of: datetime,
    authorized_boundaries: frozenset[B],
    allowed_classifications: frozenset[C],
) -> GmailAppEmailSourceV1:
    result = None
    interruption: type[BaseException] | None = None
    exit_code: int | None = 1
    try:
        result = _read(
            session,
            artifacts,
            original_reference=original_reference,
            companion_reference=companion_reference,
            as_of=as_of,
            authorized_boundaries=authorized_boundaries,
            allowed_classifications=allowed_classifications,
        )
    except BaseException as error:  # noqa: BLE001 - sanitized artifact/private/interruption diagnostics
        interruption = type(error)
        if isinstance(error, SystemExit):
            exit_code = error.code if error.code is None or type(error.code) is int else 1
    _raise_interruption(interruption, exit_code)
    if result is None:
        raise GmailAppEmailSourceError("canonical Gmail app observation source unavailable")
    return result


def prepare_gmail_app_email_specification(
    *,
    task: IntelligenceTask,
    observations: tuple[GmailAppEmailSourceV1, ...],
    recipient: EmailRecipientComparisonV1 | None,
) -> EmailDraftSpecificationV1:
    """Existing email schema receives literal evidence AND untrusted coverage sidecars.

    Caller supplies the exact already prepared owner Task; no instruction/capability/
    event/date is manufactured here. This shape cannot enter the current processing
    host until its closed canonical input/protection/admission variant is integrated.
    """
    try:
        if (
            type(task) is not IntelligenceTask
            or type(observations) is not tuple
            or not 1 <= len(observations) <= 2
        ):
            raise ValueError("finite exact task and app observation pair selection required")
        items: list[ContextItem] = []
        metadata: list[EmailSourceMetadataV1] = []
        refs: list[EvidenceReference] = []
        for observation in observations:
            if type(observation) is not GmailAppEmailSourceV1:
                raise ValueError("closed canonical app source family required")
            pair = observation.context_items()
            items.extend(pair)
            refs.extend((observation.original_reference, observation.companion_reference))
            metadata.extend(
                (
                    EmailSourceMetadataV1(
                        reference=pair[0].reference,
                        reported_role="UNKNOWN",
                        reported_at=observation.preparation.companion.reported_message_at,
                    ),
                    EmailSourceMetadataV1(
                        reference=pair[1].reference, reported_role="UNKNOWN", reported_at=None
                    ),
                )
            )
        if (
            len({o.preparation.companion.scope.view_digest() for o in observations}) != 1
            or len({o.preparation.companion.scope.expected_message_id for o in observations})
            != len(observations)
            or len({r.source_id for r in refs}) != len(refs)
            or task.context != tuple(items)
            or not set(refs) <= set(task.event.provenance)
            or task.event.trust_boundary is not B.BRAINSTORM
            or task.event.data_classification is not C.CONFIDENTIAL
            or task.required_capabilities != frozenset({"email_draft"})
            or any(o.checked_at > task.event.observed_at for o in observations)
        ):
            raise ValueError(
                "exact ordered literal contexts/complete provenance/host task required"
            )
        return prepare_email_draft_specification(
            task=task, recipient=recipient, sources=tuple(metadata)
        )
    except Exception:  # noqa: BLE001,S110 - fixed no-private-content boundary
        pass
    raise GmailAppEmailSourceError("Gmail app email specification unavailable")
