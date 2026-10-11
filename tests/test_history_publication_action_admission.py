"""Genuine invented signed owner/ASGI/FS, explicitly simulated canonical SQL."""

from types import SimpleNamespace
from urllib.parse import urlencode
from uuid import uuid4

import pytest
from sqlalchemy.orm import sessionmaker
from starlette.requests import Request

from tests.test_personal_history_factory import case as case  # noqa: PLC0414
from tests.test_personal_history_factory import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_personal_history_factory import factory_case as factory_case  # noqa: PLC0414
from tests.test_personal_history_factory import host as host  # noqa: PLC0414
from tests.test_personal_history_factory import installed as installed  # noqa: PLC0414
from tests.test_personal_history_factory import loader_case as loader_case  # noqa: PLC0414
from tests.test_personal_history_factory import post_case as post_case  # noqa: PLC0414
from tests.test_personal_history_factory import setup as setup  # noqa: PLC0414
from zacai.intelligence import history_publication_admission as r
from zacai.intelligence.history_review_retention import HistoryDeclarationContext
from zacai.interfaces import history_publication_action as web
from zacai.interfaces.named_session_binding import NamedSessionOperation
from zacai.state import SourceSystem


@pytest.fixture
def action_case(loader_case, monkeypatch):
    s = loader_case
    f = s.f
    before = f.operation.establish()
    continuity = f.operation._source
    original = f.s.f.cookie
    current = continuity._sessions.peek_user(original, continuity._clock())
    target = s.out.retained

    def action(**changes):
        fields = {
            "action": "approve_history_generation_and_review",
            "csrf": current.csrf,
            "publication_digest": target.publication_digest,
            "source_id": str(target.reference.source_id),
        }
        fields.update(changes.pop("fields", {}))
        cookie = changes.pop("cookie", original)
        headers = [
            (b"host", b"owner.example"),
            (b"origin", b"https://owner.example"),
            (b"content-type", b"application/x-www-form-urlencoded"),
            (b"cookie", (web._USER + "=" + cookie).encode()),
        ]
        headers = changes.pop("headers", headers)
        request = Request(
            {
                "type": "http",
                "http_version": "1.1",
                "method": "POST",
                "scheme": "https",
                "server": ("owner.example", 443),
                "path": "/ask-caz-locally",
                "query_string": b"",
                "headers": headers,
                **changes,
            }
        )
        body = urlencode(fields).encode()
        return web._observe_history_http_post(
            request=request,
            body=body,
            continuity=continuity,
            publication=target.declaration,
            reference=target.reference,
            operation=f.operation,
        )

    return SimpleNamespace(
        s=s,
        f=f,
        before=before,
        continuity=continuity,
        target=target,
        action=action,
        original=original,
    )


def test_actual_asgi_original_cookie_exact_target_consumed_once(action_case):
    f = action_case
    token = f.action()
    observation = web._consume_history_post(token, purpose="APPROVE")
    assert observation.operation is f.f.operation
    assert observation.reference == f.target.reference
    assert observation.publication == f.target.declaration
    assert observation.current_session == f.before
    with pytest.raises(web.HistoryPublicationWebError):
        web._consume_history_post(token, purpose="APPROVE")
    with pytest.raises(web.HistoryPublicationWebError):
        web._PostedHistoryAction()


@pytest.mark.parametrize(
    "fields",
    [
        {"csrf": "x" * 43},
        {"source_id": str(uuid4())},
        {"publication_digest": "e" * 64},
        {"action": "approve_fragment_generation_and_review"},
    ],
)
def test_form_cannot_replace_server_target_or_purpose(action_case, fields):
    with pytest.raises(web.HistoryPublicationWebError):
        action_case.action(fields=fields)


@pytest.mark.parametrize(
    "changes",
    [
        {"method": "GET"},
        {"query_string": b"extra=1"},
        {"headers": [(b"host", b"owner.example"), (b"origin", b"https://foreign.example")]},
    ],
)
def test_request_boundary_denies_before_action(action_case, changes):
    with pytest.raises(web.HistoryPublicationWebError):
        action_case.action(**changes)


def test_equal_owner_fresh_cookie_is_not_original_approval(action_case):
    f = action_case
    cookie = f.continuity._sessions.start_user(f.before.principal.identity, f.continuity._clock())
    with pytest.raises(web.HistoryPublicationWebError):
        f.action(cookie=cookie)


def test_final_clock_revocation_cannot_mint_or_consume_action(action_case, monkeypatch):
    f = action_case
    read = f.continuity._clock._read
    parts = web._parts
    armed = []
    fired = []

    def validated_parts(publication):
        value = parts(publication)
        armed.append(True)
        return value

    monkeypatch.setattr(web, "_parts", validated_parts)

    def revoke():
        if armed and not fired:
            fired.append(True)
            f.f.s.inputs.owners.revoke()
        return read()

    monkeypatch.setattr(f.continuity._clock, "_read", revoke)
    with pytest.raises(web.HistoryPublicationWebError):
        f.action()
    assert fired


@pytest.fixture
def canonical_case(action_case, monkeypatch):
    a = action_case
    s = a.s
    state = SimpleNamespace(
        a=a,
        events=[],
        ids=(),
        cancelled=False,
        source_changed=False,
        admission_id=uuid4(),
        publication_ids=(a.target.reference.source_id,),
        session=None,
        fault=None,
    )

    class Session:
        def __enter__(self):
            state.session = self
            s.session = self
            state.events.append("open")
            return self

        def begin(self):
            state.events.append("begin")

        def commit(self):
            state.events.append("commit")

        def __exit__(self, *args):
            state.events.append("close")

    monkeypatch.setattr(sessionmaker, "__call__", lambda factory: Session())
    monkeypatch.setattr(r, "_lock", lambda *args: state.events.append("parent lock simulated"))
    monkeypatch.setattr(r, "_physical", lambda session: session)

    def same(session, entry):
        assert session is entry
        if state.source_changed:
            raise ValueError("simulated physical drift")

    monkeypatch.setattr(r, "_same", same)
    monkeypatch.setattr(r, "_same_commit", same)
    monkeypatch.setattr(r, "_ids", lambda session, prefix, **kw: state.ids)
    monkeypatch.setattr(r, "_publication_ids", lambda session, gid: state.publication_ids)

    def not_withdrawn(*args):
        if state.cancelled:
            raise ValueError("canonical cancellation simulated")

    monkeypatch.setattr(r, "_not_withdrawn", not_withdrawn)
    monkeypatch.setattr(r.auth, "_assert_fragment_generation_unconsumed", lambda *args: None)
    monkeypatch.setattr(r, "_assert_personal_custody_append_capacity", lambda *args: None)

    def rows(session, selected, *scope):
        assert session is state.session
        result = []
        for ref in selected:
            row = s.rows[ref.source_id]
            if row["content_hash"] != ref.content_hash:
                raise ValueError("actual expected source hash changed")
            result.append(dict(row))
        return tuple(result)

    monkeypatch.setattr(r, "_fragment_rows", rows)

    def record(session, **kw):
        state.events.append("record simulated")
        s.rows[state.admission_id] = {
            "id": state.admission_id,
            "lineage_id": state.admission_id,
            "supersedes_source_id": None,
            **kw,
        }
        s.rows[state.admission_id]["data_classification"] = kw["data_classification"]
        state.ids = (state.admission_id,)
        return SimpleNamespace(id=state.admission_id), True

    monkeypatch.setattr(r, "record_source", record)
    state.context = HistoryDeclarationContext(
        a.f.c.expected_root, a.f.c.expected_account_ref, a.f.c.expected_exported_at
    )
    state.write = lambda token: r._record_posted_history_admission(
        factory=a.f.c.factory,
        artifacts=a.f.c.artifacts,
        action=token,
        clock=a.f.s.inputs.clock,
        context=state.context,
    )
    return state


def test_actual_observed_post_records_user_instruction_then_reopens(canonical_case):
    f = canonical_case
    token = f.a.action()
    saved = f.write(token)
    row = f.a.s.rows[saved.reference.source_id]
    assert row["system"] is SourceSystem.USER_INSTRUCTION
    assert row["captured_at"] == saved.admission.observed_action_at
    assert saved.admission.publication_reference == f.a.target.reference
    assert saved.admission.processing_authorized is False
    assert saved.admission.reviewer_authenticated is False
    assert "csrf" not in r.encode_history_publication_admission(saved.admission).decode()
    assert f.a.original not in r.encode_history_publication_admission(saved.admission).decode()
    assert f.events.count("commit") == 1
    with pytest.raises(r.HistoryPublicationAdmissionError):
        f.write(token)
    assert f.events.count("commit") == 1


def test_real_owner_callbacks_outside_canonical_lease(canonical_case, monkeypatch):
    f = canonical_case
    owner = NamedSessionOperation.recheck
    calls = []

    def recheck(operation, *args, **kw):
        assert f.events.count("open") == f.events.count("close")
        calls.append(True)
        return owner(operation, *args, **kw)

    monkeypatch.setattr(NamedSessionOperation, "recheck", recheck)
    assert f.write(f.a.action()).admission.processing_authorized is False
    assert calls


def test_revocation_by_prepared_artifact_clock_holds_before_commit(canonical_case, monkeypatch):
    f = canonical_case
    token = f.a.action()
    original = f.a.continuity._clock._read
    fired = []

    def read():
        if f.events.count("close") and not fired:
            fired.append(True)
            f.a.f.s.inputs.owners.revoke()
        return original()

    monkeypatch.setattr(f.a.continuity._clock, "_read", read)
    with pytest.raises(r.HistoryPublicationAdmissionError):
        f.write(token)
    assert fired and "record simulated" not in f.events and "commit" not in f.events


def test_canonical_cancellation_before_capture_holds(canonical_case):
    f = canonical_case
    token = f.a.action()
    f.cancelled = True
    with pytest.raises(r.HistoryPublicationAdmissionError):
        f.write(token)
    assert "record simulated" not in f.events and "commit" not in f.events


def load_saved(f, saved):
    with f.a.f.c.factory() as session:
        session.begin()
        return r.load_history_publication_admission(
            session,
            artifacts=f.a.f.c.artifacts,
            reference=saved.reference,
            expected_admission=saved.admission,
            expected_declaration=f.a.target.declaration,
            context=f.context,
        )


def test_own_source_wrong_namespace_holds_before_private_body(canonical_case, monkeypatch):
    from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore

    f = canonical_case
    saved = f.write(f.a.action())
    f.a.s.rows[saved.reference.source_id]["external_ref"] += "-foreign"
    reads = []
    actual = LocalFilesystemArtifactStore.get_bounded

    def get(store, *args, **kw):
        reads.append(True)
        return actual(store, *args, **kw)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    with pytest.raises(r.HistoryPublicationAdmissionError):
        load_saved(f, saved)
    assert reads == []


def test_missing_own_source_holds_before_parent_body(canonical_case, monkeypatch):
    from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore

    f = canonical_case
    saved = f.write(f.a.action())
    f.a.s.rows.pop(saved.reference.source_id)
    reads = []
    actual = LocalFilesystemArtifactStore.get_bounded

    def get(store, *args, **kw):
        reads.append(True)
        return actual(store, *args, **kw)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    with pytest.raises(r.HistoryPublicationAdmissionError):
        load_saved(f, saved)
    assert reads == []


def test_parent_sibling_namespace_after_own_body_callback_holds(canonical_case, monkeypatch):
    from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore

    f = canonical_case
    saved = f.write(f.a.action())
    location = f.a.s.rows[saved.reference.source_id]["content_location"]
    actual = LocalFilesystemArtifactStore.get_bounded
    fired = []

    def get(store, boundary, path, **kw):
        value = actual(store, boundary, path, **kw)
        if path == location:
            fired.append(True)
            f.publication_ids = (*f.publication_ids, uuid4())
        return value

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    with pytest.raises(r.HistoryPublicationAdmissionError):
        load_saved(f, saved)
    assert fired == [True]


def test_body_exception_keeps_fixed_error_without_sensitive_chain(canonical_case, monkeypatch):
    from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore

    f = canonical_case
    saved = f.write(f.a.action())
    location = f.a.s.rows[saved.reference.source_id]["content_location"]
    actual = LocalFilesystemArtifactStore.get_bounded

    def get(store, boundary, path, **kw):
        if path == location:
            raise RuntimeError("INVENTED PRIVATE SENTINEL")
        return actual(store, boundary, path, **kw)

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    with pytest.raises(r.HistoryPublicationAdmissionError) as err:
        load_saved(f, saved)
    assert str(err.value) == "history publication action unavailable"
    assert err.value.__cause__ is None and err.value.__context__ is None


def test_parent_artifact_sibling_admission_holds_before_own_body(canonical_case, monkeypatch):
    from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore

    f = canonical_case
    saved = f.write(f.a.action())
    parent_path = f.a.s.rows[f.a.target.reference.source_id]["content_location"]
    own_path = f.a.s.rows[saved.reference.source_id]["content_location"]
    actual = LocalFilesystemArtifactStore.get_bounded
    fired, own_reads = [], []

    def get(store, boundary, path, **kw):
        value = actual(store, boundary, path, **kw)
        if path == parent_path:
            fired.append(True)
            f.ids = (*f.ids, uuid4())
        if path == own_path:
            own_reads.append(True)
        return value

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", get)
    with pytest.raises(r.HistoryPublicationAdmissionError):
        load_saved(f, saved)
    assert fired == [True]
    assert own_reads == [], "parent callback drift must hold BEFORE own private body"


def test_postcommit_owner_revoke_preserves_custody_but_no_success_capability(
    canonical_case, monkeypatch
):
    f = canonical_case
    original = f.a.f.s.inputs.clock._read
    revoked = []

    def read():
        if "commit" in f.events and not revoked:
            revoked.append(True)
            f.a.f.s.inputs.owners.revoke()
        return original()

    monkeypatch.setattr(f.a.f.s.inputs.clock, "_read", read)
    returned = None
    with pytest.raises(r.HistoryPublicationAdmissionError) as error:
        returned = f.write(f.a.action())
    assert revoked == [True] and f.events.count("commit") == 1
    assert returned is None
    assert (
        str(error.value)
        == "history publication custody possibly committed; action held without acknowledgment"
    )
    assert error.value.__cause__ is error.value.__context__ is None
    own = f.a.s.rows[f.ids[0]]
    raw = f.a.f.c.artifacts.get_bounded(
        web.B.PERSONAL, own["content_location"], max_bytes=r.MAX_ADMISSION_BYTES
    )
    from zacai.intelligence.contracts import EvidenceReference
    from zacai.policy import DataClassification, TrustBoundary

    ref = EvidenceReference(
        source_id=f.ids[0],
        content_hash=own["content_hash"],
        trust_boundary=TrustBoundary.PERSONAL,
        effective_classification=DataClassification.HIGHLY_RESTRICTED,
    )
    custody = r.RetainedHistoryPublicationAdmission(
        ref, r.decode_history_publication_admission(raw), own["captured_at"]
    )
    loaded = load_saved(f, custody)
    assert type(loaded) is r.RetainedHistoryPublicationAdmission
    with pytest.raises(r.HistoryPublicationAdmissionError):
        r._consume_history_admission_acknowledgment(
            loaded,
            operation=f.a.f.operation,
            clock=f.a.f.s.inputs.clock,
            expected_declaration=f.a.target.declaration,
        )
    # Even restoring the actual signed grant cannot issue an acknowledgment
    # through the plain loader or renew the already-consumed browser action.
    assert not hasattr(loaded, "original_deadline_monotonic")


def test_only_successful_writer_capability_consumes_once_with_original_identity(canonical_case):
    f = canonical_case
    acknowledged = f.write(f.a.action())
    assert type(acknowledged) is r.AcknowledgedHistoryPublicationAdmission
    assert acknowledged.processing_authorized is False
    assert type(load_saved(f, acknowledged)) is r.RetainedHistoryPublicationAdmission
    retained = r._consume_history_admission_acknowledgment(
        acknowledged,
        operation=f.a.f.operation,
        clock=f.a.f.s.inputs.clock,
        expected_declaration=f.a.target.declaration,
    )
    assert retained is acknowledged.retained
    assert acknowledged.original_deadline_monotonic > 0
    with pytest.raises(r.HistoryPublicationAdmissionError):
        r._consume_history_admission_acknowledgment(
            acknowledged,
            operation=f.a.f.operation,
            clock=f.a.f.s.inputs.clock,
            expected_declaration=f.a.target.declaration,
        )
    with pytest.raises(r.HistoryPublicationAdmissionError):
        r.AcknowledgedHistoryPublicationAdmission()


@pytest.mark.parametrize("fault", ["lineage_id", "data_classification"])
def test_pending_own_lineage_classification_hold_before_commit(canonical_case, monkeypatch, fault):
    from zacai.policy import DataClassification

    f = canonical_case
    actual = r.record_source

    def record(*args, **kwargs):
        value = actual(*args, **kwargs)
        own = f.a.s.rows[value[0].id]
        own[fault] = uuid4() if fault == "lineage_id" else DataClassification.CONFIDENTIAL
        return value

    monkeypatch.setattr(r, "record_source", record)
    with pytest.raises(r.HistoryPublicationAdmissionError):
        f.write(f.a.action())
    assert "commit" not in f.events


def test_generation_consumed_during_postcommit_read_prevents_ack(canonical_case, monkeypatch):
    f = canonical_case
    from zacai import contextual_authorization

    def unconsumed(*args):
        if "commit" in f.events:
            raise ValueError("invented committed shared claim")

    monkeypatch.setattr(
        contextual_authorization, "_assert_fragment_generation_unconsumed", unconsumed
    )
    with pytest.raises(r.HistoryPublicationAdmissionUncertain):
        f.write(f.a.action())
    assert f.events.count("commit") == 1
