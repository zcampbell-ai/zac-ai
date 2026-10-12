"""Root-only genuine observed POST/canonical admission; invented history only.

Actual signed owner/session, complete factory native recovery, canonical SQL and
bounded loaders are unchanged. HTTP Request is invented attendance; declared
reviewer pins are not measured availability. No model transport or permission.
"""

from datetime import timedelta
from urllib.parse import urlencode

import pytest
from sqlalchemy import select
from starlette.requests import Request

from tests.test_personal_history_factory_sql import actual_case as actual_case  # noqa: PLC0414
from tests.test_personal_history_factory_sql import all_sources
from tests.test_personal_history_factory_sql import clean_factory as clean_factory  # noqa: PLC0414
from tests.test_personal_history_factory_sql import (
    history_factory_case as history_factory_case,  # noqa: PLC0414
)
from tests.test_personal_history_factory_sql import installed as installed  # noqa: PLC0414
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.intelligence import history_publication_admission as r
from zacai.intelligence.history_generation_review_declaration import decode_history_consent
from zacai.intelligence.history_review_retention import HistoryDeclarationContext
from zacai.interfaces import history_publication_action as web
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source


@pytest.fixture
def admission_case(history_factory_case, actual_case):
    f = history_factory_case
    f.cookie = actual_case[8]  # Actual in-process fixture cookie, never persisted.
    return f


def action(f, value):
    # Real original signed cookie/current CSRF; no private token constructor.
    continuity = f.operation._source
    cookie = continuity._sessions.peek_user(f.cookie, f.inputs.clock())
    assert cookie is not None
    fields = {
        "action": "approve_history_generation_and_review",
        "csrf": cookie.csrf,
        "publication_digest": value.retained.publication_digest,
        "source_id": str(value.retained.reference.source_id),
    }
    origin = f.inputs.origin
    request = Request(
        {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "scheme": "https",
            "server": ("owner.example", 443),
            "path": "/ask-caz-locally",
            "query_string": b"",
            "headers": [
                (b"host", origin.removeprefix("https://").encode()),
                (b"origin", origin.encode()),
                (b"content-type", b"application/x-www-form-urlencoded"),
                (b"cookie", (web._USER + "=" + f.cookie).encode()),
            ],
        }
    )
    return web._observe_history_http_post(
        request=request,
        body=urlencode(fields).encode(),
        continuity=continuity,
        publication=value.retained.declaration,
        reference=value.retained.reference,
        operation=f.operation,
    )


def context(f):
    return HistoryDeclarationContext(
        f.c.expected_root, f.c.expected_account_ref, f.c.expected_exported_at
    )


def write(f, value, token):
    return r._record_posted_history_admission(
        factory=f.c.factory,
        artifacts=f.c.artifacts,
        action=token,
        clock=f.inputs.clock,
        context=context(f),
    )


def load(f, value, saved):
    with f.c.factory() as session, session.begin():
        return r.load_history_publication_admission(
            session,
            artifacts=f.c.artifacts,
            reference=saved.reference,
            expected_admission=saved.admission,
            expected_declaration=value.retained.declaration,
            context=context(f),
        )


def test_actual_original_post_user_instruction_exact_parent_and_reopen(admission_case):
    f = admission_case
    value = f.prepare()
    before = all_sources(f)
    token = action(f, value)
    saved = write(f, value, token)
    assert load(f, value, saved) == saved.retained
    g = decode_history_consent(value.retained.declaration.generation_consent_json.encode())
    assert saved.admission.publication_reference == value.retained.reference
    assert saved.admission.generation_wire_digest == g.generation_wire_digest
    assert saved.admission.request_digest == g.request_digest
    assert saved.admission.original_session_binding == f.owner.binding_digest
    assert saved.admission.expires_at == g.expires_at == f.c.expires_at
    assert saved.admission.processing_authorized is saved.admission.reviewer_authenticated is False
    with f.c.factory() as session:
        own = session.get(Source, saved.reference.source_id)
        assert own.system is SourceSystem.USER_INSTRUCTION and own.trust_boundary is B.PERSONAL
        assert own.data_classification is C.HIGHLY_RESTRICTED
        assert own.external_ref == r._namespace(saved.admission)
        assert own.content_hash == content_hash_of(
            r.encode_history_publication_admission(saved.admission)
        )
    after = all_sources(f)
    assert type(saved) is r.AcknowledgedHistoryPublicationAdmission
    import copy

    with pytest.raises(r.HistoryPublicationAdmissionError):
        copy.copy(saved)
    reduction = object.__reduce_ex__(saved, 4)
    recreate, args, state, *_ = reduction
    clone = recreate(*args)
    for key, item in state.items():
        object.__setattr__(clone, key, item)
    with pytest.raises(r.HistoryPublicationAdmissionError):
        r._consume_history_admission_acknowledgment(
            clone,
            operation=f.operation,
            clock=f.inputs.clock,
            expected_declaration=value.retained.declaration,
        )
    assert not saved._used
    assert (
        r._consume_history_admission_acknowledgment(
            saved,
            operation=f.operation,
            clock=f.inputs.clock,
            expected_declaration=value.retained.declaration,
        )
        is saved.retained
    )
    with pytest.raises(r.HistoryPublicationAdmissionError):
        r._consume_history_admission_acknowledgment(
            saved,
            operation=f.operation,
            clock=f.inputs.clock,
            expected_declaration=value.retained.declaration,
        )
    assert len(after) == len(before) + 1
    with pytest.raises(r.HistoryPublicationAdmissionError):
        write(f, value, token)
    assert all_sources(f) == after and not f.attempts


def test_original_expiry_cannot_record_observed_token_or_renew_window(admission_case, monkeypatch):
    f = admission_case
    value = f.prepare()
    token = action(f, value)
    before = all_sources(f)
    monkeypatch.setattr(f.inputs.clock, "_read", lambda: f.c.expires_at)
    with pytest.raises(r.HistoryPublicationAdmissionError):
        write(f, value, token)
    assert all_sources(f) == before and not f.attempts
    with pytest.raises(r.HistoryPublicationAdmissionError):
        write(f, value, token)


def test_real_parent_get_commits_own_source_revision_before_own_body_hold(
    admission_case, monkeypatch
):
    f = admission_case
    value = f.prepare()
    saved = write(f, value, action(f, value))
    parent = f.c.artifacts.location_for(value.retained.reference.content_hash)
    own = f.c.artifacts.location_for(saved.reference.content_hash)
    actual = LocalFilesystemArtifactStore.get_bounded
    fired = []
    own_reads = []

    def get(store, boundary, location, **kw):
        returned = actual(store, boundary, location, **kw)
        if location == parent and not fired:
            fired.append(True)
            changed = saved.admission.model_copy(
                update={
                    "observed_action_at": saved.admission.observed_action_at + timedelta(seconds=1)
                }
            )
            raw = r.encode_history_publication_admission(changed)
            digest = content_hash_of(raw)
            path = f.c.artifacts.put(B.PERSONAL, digest, raw)
            with f.c.factory() as separate, separate.begin():
                revised, _ = record_source(
                    separate,
                    trust_boundary=B.PERSONAL,
                    data_classification=C.HIGHLY_RESTRICTED,
                    system=SourceSystem.USER_INSTRUCTION,
                    external_ref=r._namespace(saved.admission),
                    content_hash=digest,
                    content_location=path,
                    captured_at=changed.observed_action_at,
                )
                assert revised.id != saved.reference.source_id
        if location == own:
            own_reads.append(True)
        return returned

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    with pytest.raises(r.HistoryPublicationAdmissionError):
        load(f, value, saved)
    assert fired == [True] and own_reads == []
    with f.c.factory() as session:
        ids = tuple(
            session.scalars(
                select(Source.id).where(Source.external_ref == r._namespace(saved.admission))
            )
        )
    assert len(ids) == 2 and saved.reference.source_id in ids and not f.attempts


def test_actual_canonical_withdrawal_namespace_denies_admission_without_new_writer(admission_case):
    from zacai.intelligence.fragment_review_withdrawal import _withdrawal_namespace

    f = admission_case
    value = f.prepare()
    token = action(f, value)
    generation = decode_history_consent(value.retained.declaration.generation_consent_json.encode())
    # This is deliberately only a malformed canonical negative locator, not a
    # claimed complete-family withdrawal action or signed cancellation proof.
    raw = b'{"invented_negative_locator":true}'
    digest = content_hash_of(raw)
    path = f.c.artifacts.put(B.PERSONAL, digest, raw)
    with f.c.factory() as session, session.begin():
        record_source(
            session,
            trust_boundary=B.PERSONAL,
            data_classification=C.HIGHLY_RESTRICTED,
            system=SourceSystem.USER_INSTRUCTION,
            external_ref=_withdrawal_namespace(generation.id),
            content_hash=digest,
            content_location=path,
            captured_at=f.inputs.clock._last,
        )
    before = all_sources(f)
    with pytest.raises(r.HistoryPublicationAdmissionError):
        write(f, value, token)
    assert all_sources(f) == before and not f.attempts


def test_real_postcommit_owner_revoke_retains_custody_without_capability(
    admission_case, monkeypatch
):
    from zacai.intelligence.contracts import EvidenceReference

    f = admission_case
    value = f.prepare()
    token = action(f, value)
    actual_commit = f.c.factory.class_.commit
    fired = []

    def commit(session):
        returned = actual_commit(session)
        if not fired:
            fired.append(True)
            f.inputs.owners.revoke()
        return returned

    monkeypatch.setattr(f.c.factory.class_, "commit", commit)
    returned = None
    with pytest.raises(r.HistoryPublicationAdmissionUncertain) as error:
        returned = write(f, value, token)
    assert returned is None and fired == [True]
    assert error.value.__cause__ is error.value.__context__ is None
    generation = decode_history_consent(value.retained.declaration.generation_consent_json.encode())
    with f.c.factory() as session:
        own = session.scalars(
            select(Source).where(
                Source.trust_boundary == B.PERSONAL,
                Source.system == SourceSystem.USER_INSTRUCTION,
                Source.external_ref.like(
                    f"personal-history-complete-publication-admission/{generation.id}/%"
                ),
            )
        ).one()
        raw = f.c.artifacts.get_bounded(
            B.PERSONAL, own.content_location, max_bytes=r.MAX_ADMISSION_BYTES
        )
        retained = r.RetainedHistoryPublicationAdmission(
            EvidenceReference(
                source_id=own.id,
                content_hash=own.content_hash,
                trust_boundary=B.PERSONAL,
                effective_classification=C.HIGHLY_RESTRICTED,
            ),
            r.decode_history_publication_admission(raw),
            own.captured_at,
        )
    custody = load(f, value, retained)
    assert type(custody) is r.RetainedHistoryPublicationAdmission
    with pytest.raises(r.HistoryPublicationAdmissionError):
        r._consume_history_admission_acknowledgment(
            custody,
            operation=f.operation,
            clock=f.inputs.clock,
            expected_declaration=value.retained.declaration,
        )
    assert not f.attempts
