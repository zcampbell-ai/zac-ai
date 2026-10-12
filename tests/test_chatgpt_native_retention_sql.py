"""Root-only actual PostgreSQL native retention; every source/owner invented.

Real signed owner, original observed custody POST, current canonical pair/task,
real tiny tokenizer, lock/physical/source/commit/load. No inference or recovery
receipt minting. Fault wrappers call actual producers, no authority bridges.
"""

from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from tests.test_chatgpt_native_task_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_chatgpt_native_task_sql import (
    installed as installed,  # noqa: PLC0414
)
from tests.test_chatgpt_native_task_sql import (
    native_custody_case as native_custody_case,  # noqa: PLC0414
)
from tests.test_chatgpt_native_task_sql import (
    task_case as task_case,  # noqa: PLC0414
)
from zacai.claude_original_capture import observe_claude_artifact_root
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import chatgpt_native_retention as m
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source


@pytest.fixture
def retention_case(task_case):
    x = task_case()
    declaration = x.declare(x.load())
    first, second = uuid4(), uuid4()

    def capture():
        return m.capture_chatgpt_native_task_declaration(
            factory=x.f.factory,
            artifacts=x.f.artifacts,
            expected_root=observe_claude_artifact_root(x.f.artifacts),
            declaration=declaration,
            declaration_source_id=first,
            association_source_id=second,
            inputs=x.f.inputs,
            operation=x.f.operation,
        )

    def rows():
        with x.f.factory() as session, session.begin():
            return tuple(
                SimpleNamespace(
                    id=row.id, system=row.system, supersedes_source_id=row.supersedes_source_id
                )
                for row in session.scalars(select(Source).where(Source.id.in_((first, second))))
            )

    def load(result):
        # Standalone loader is custody comparison, not signed owner authority.
        # Genuine signed original operation checks are deliberately outside SQL.
        m._owner(x.f.inputs, x.f.operation, declaration)
        with x.f.factory() as session, session.begin():
            returned = m.load_retained_chatgpt_native_task(
                session,
                artifacts=x.f.artifacts,
                declaration_reference=result.declaration_reference,
                association_reference=result.association_reference,
                expected_declaration=declaration,
                authorized_boundaries=m.BOUNDS,
                allowed_classifications=m.LABELS,
            )
        m._owner(x.f.inputs, x.f.operation, declaration)
        return returned

    return SimpleNamespace(
        x=x,
        declaration=declaration,
        first=first,
        second=second,
        capture=capture,
        rows=rows,
        load=load,
    )


def test_actual_atomic_capture_clean_reload_and_current_owner(retention_case):
    f = retention_case
    result = f.capture()
    assert {row.id for row in f.rows()} == {f.first, f.second}
    assert all(
        row.system is SourceSystem.MANUAL and row.supersedes_source_id is None for row in f.rows()
    )
    assert f.load(result) == result
    assert result.association.native_capture_id == f.x.loaded.capture_id
    assert result.association.source_references == m.native_task_references(f.x.request)
    assert (
        m.decode_chatgpt_native_task_request(
            result.declaration.request_json.encode()
        ).profile.companion.selected_field.reported_role
        == "USER"
    )
    assert not any(
        (
            result.processing_authorized,
            result.owner_admitted,
            result.runtime_ready,
            result.reviewer_ready,
        )
    )
    f.x.f.owners.revoke()
    with pytest.raises(ValueError):
        f.load(result)  # genuine current signed owner denied, custody remains
    assert len(f.rows()) == 2


def test_actual_commit_ack_loss_preserves_custody_no_retry(retention_case, monkeypatch):
    f = retention_case
    actual = Session.commit
    milestones = []

    def commit(session):
        actual(session)
        milestones.append("real-commit-returned-before-invented-ack-loss")
        raise RuntimeError("invented lost acknowledgment")

    monkeypatch.setattr(Session, "commit", commit)
    with pytest.raises(m.NativeTaskRetentionUncertain) as e:
        f.capture()
    assert milestones == ["real-commit-returned-before-invented-ack-loss"]
    assert e.value.__context__ is None and len(f.rows()) == 2
    monkeypatch.setattr(Session, "commit", actual)
    with pytest.raises(m.NativeTaskRetentionError):
        f.capture()  # occupied capture cannot repair or recapture
    raw = m.encode_chatgpt_native_task_declaration(f.declaration)
    from zacai.intelligence.contracts import EvidenceReference

    first = EvidenceReference(
        source_id=f.first,
        trust_boundary=m.B.PERSONAL,
        effective_classification=m.C.HIGHLY_RESTRICTED,
        content_hash=content_hash_of(raw),
    )
    associated = m._association(f.declaration, first)
    second = EvidenceReference(
        source_id=f.second,
        trust_boundary=m.B.PERSONAL,
        effective_classification=m.C.HIGHLY_RESTRICTED,
        content_hash=content_hash_of(m._association_raw(associated)),
    )
    known = m.RetainedChatGPTNativeTaskV1(first, second, f.declaration, associated, f.x.f.now)
    assert f.load(known) == known  # explicit custody comparison, no reissued action


def test_actual_association_revision_holds_before_any_body(retention_case, monkeypatch):
    f = retention_case
    result = f.capture()
    ref = result.association_reference
    changed = m._association_raw(result.association) + b" "
    digest = content_hash_of(changed)
    location = f.x.f.artifacts.put(m.B.PERSONAL, digest, changed)
    with f.x.f.factory() as session, session.begin():
        original = session.get(Source, ref.source_id)
        row, new = record_source(
            session,
            trust_boundary=m.B.PERSONAL,
            data_classification=m.C.HIGHLY_RESTRICTED,
            system=SourceSystem.MANUAL,
            content_hash=digest,
            content_location=location,
            external_ref=original.external_ref,
            captured_at=f.x.f.now,
        )
        assert new and row.supersedes_source_id == ref.source_id
    actual = f.x.f.artifacts.get_bounded
    reads = []

    def read(*a, **kw):
        reads.append(a)
        return actual(*a, **kw)

    monkeypatch.setattr(f.x.f.artifacts, "get_bounded", read)
    with pytest.raises(m.NativeTaskRetentionError):
        f.load(result)
    assert reads == []  # real committed conflicting immutable namespace


def test_actual_artifact_callback_owner_revocation_prevents_write(retention_case, monkeypatch):
    f = retention_case
    actual = f.x.f.artifacts.put_durable
    milestones = []

    def put(*a, **kw):
        location = actual(*a, **kw)
        f.x.f.owners.revoke()
        milestones.append("real-artifact-put-then-actual-owner-revoke")
        return location

    monkeypatch.setattr(f.x.f.artifacts, "put_durable", put)
    with pytest.raises(m.NativeTaskRetentionError) as e:
        f.capture()
    assert milestones and not f.rows() and e.value.__context__ is None
