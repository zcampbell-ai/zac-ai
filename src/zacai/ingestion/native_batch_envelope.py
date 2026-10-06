"""Pure native batch evidence composition; declared refs are not canonical proof.

The trusted caller must resolve current actual rows/ACL and authenticate the
exact human-approved proposal before any write. No authority issuance, provider
read, ArtifactStore operation, Source commit, recovery or dispatch occurs here.
"""
from __future__ import annotations

from datetime import datetime
from uuid import UUID

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.ingestion.native_source_preparation import NativeSourcePreparation
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


class NativeBatchEnvelopeError(ValueError):
    """Sanitized composition error without retained private cause."""


def compose_native_batch_envelope(
    *, batch_id: UUID, proposal_digest: str, approval_reference: EvidenceReference,
    prepared: tuple[NativeSourcePreparation, ...],
    artifact_references: tuple[tuple[EvidenceReference, ...], ...],
    observed_at: datetime,
) -> bytes:
    """Candidate evidence only. Neither supplied approval nor refs grant effects.

    Rows must be resolved/rechecked by the external writer; matching hash/shape
    here does not authenticate caller, approve a scope or prove database rows.
    """
    result = None
    try:
        if (type(batch_id) is not UUID or type(observed_at) is not datetime
            or observed_at.utcoffset() is None or type(proposal_digest) is not str
            or len(proposal_digest) != 64 or any(c not in '0123456789abcdef' for c in proposal_digest)
            or type(prepared) is not tuple or not 2 <= len(prepared) <= 8
            or type(artifact_references) is not tuple or len(artifact_references) != len(prepared)):
            raise ValueError('closed batch')
        approval = _reference(approval_reference)
        if {item.provider for item in prepared} != {'gmail', 'slack'}:
            raise ValueError('both selected providers required')
        if sum(item.provider == 'gmail' for item in prepared) > 6 or sum(item.provider == 'slack' for item in prepared) > 2:
            raise ValueError('batch bounds')
        if sum(len(item.artifacts) - 2 for item in prepared if item.provider == 'slack') > 50:
            raise ValueError('message count')
        if sum(len(a.original_bytes) for item in prepared for a in item.artifacts) > 4 * 1024 * 1024:
            raise ValueError('byte bound')
        selections = []
        identities: dict[UUID, str] = {approval_reference.source_id: approval_reference.content_hash}
        for item, refs in zip(prepared, artifact_references, strict=True):
            if (type(item) is not NativeSourcePreparation or type(refs) is not tuple
                or len(refs) != len(item.artifacts) or item.captured_at > observed_at):
                raise ValueError('prepared observation')
            resolved = {}
            for plan, ref in zip(item.artifacts, refs, strict=True):
                _reference(ref)
                if (plan.content_hash != content_hash_of(plan.original_bytes)
                    or ref.content_hash != plan.content_hash
                    or ref.source_id == approval_reference.source_id
                    or (ref.source_id in identities and identities[ref.source_id] != ref.content_hash)
                    or (plan.source_occurred_at is not None and plan.source_occurred_at > item.captured_at)):
                    raise ValueError('declared artifact mismatch')
                identities[ref.source_id] = ref.content_hash
                key = (plan.external_ref, plan.content_hash)
                if key in resolved:
                    raise ValueError('ambiguous artifact observation')
                resolved[key] = ref
            artifacts = []
            for plan, ref in zip(item.artifacts, refs, strict=True):
                origin = None
                if plan.derives_from is not None:
                    upstream = resolved[(plan.derives_from.external_ref, plan.derives_from.content_hash)]
                    if upstream.source_id == ref.source_id:
                        raise ValueError('self derivation')
                    origin = _reference(upstream)
                artifacts.append({'reference': _reference(ref), 'system': plan.system.value,
                    'external_ref': plan.external_ref, 'artifact_kind': plan.artifact_kind,
                    'derives_from_wire': origin,
                    'provider_occurred_at': plan.source_occurred_at.isoformat() if plan.source_occurred_at else None})
            selections.append({'provider': item.provider, 'host_observed_at': item.captured_at.isoformat(),
                'declared_selection_utf8': item.declared_selection_bytes.decode('utf-8'),
                'declared_selection_digest': content_hash_of(item.declared_selection_bytes),
                'artifacts': artifacts, 'next_cursor': item.next_cursor,
                'selected_page_exhausted': item.selected_page_exhausted, 'retention_limited': item.retention_limited})
        result = canonical_bytes({'format': 'zac-native-selected-batch-evidence-v1', 'batch_id': str(batch_id),
            'proposal_digest': proposal_digest, 'approval_reference': approval,
            'boundary': B.BRAINSTORM.value, 'classification': C.CONFIDENTIAL.value,
            'observed_at': observed_at.isoformat(), 'selections': selections,
            'role': 'CANDIDATE_CONTEXT', 'facts_confirmed': False, 'permission_granted': False,
            'recovery_verified': False, 'complete_history_verified': False})
    except Exception:  # noqa: BLE001,S110 - private-safe error outside exception handler
        pass
    if result is None:
        raise NativeBatchEnvelopeError('native selected batch composition held')
    return result


def _reference(value: EvidenceReference) -> dict[str, object]:
    if type(value) is not EvidenceReference:
        raise ValueError('exact reference')
    value = EvidenceReference.model_validate(value)
    if value.trust_boundary is not B.BRAINSTORM or value.effective_classification is not C.CONFIDENTIAL:
        raise ValueError('fixed evidence family')
    return value.model_dump(mode='json')
