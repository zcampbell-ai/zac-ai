"""Actual canonical codecs/files, simulated SQL/owner/age/restoration only.

No connection, native process, human admission or genuine recovery proof.
"""

import json
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy.orm import Session, sessionmaker

from tests.test_fragment_review_declaration import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_fragment_review_declaration import declared
from tests.test_history_fragment_authority_protection import authority as authority  # noqa: PLC0414
from tests.test_history_fragment_authority_protection import (
    consent_case as consent_case,  # noqa: PLC0414
)
from tests.test_history_fragment_authority_protection import (
    packet_case as packet_case,  # noqa: PLC0414
)
from tests.test_history_fragment_consent_records import case as case  # noqa: PLC0414
from zacai import contextual_authorization as auth
from zacai import contextual_protection as protection
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import fragment_review_declaration as d
from zacai.intelligence import fragment_review_retention as m
from zacai.intelligence.contracts import EvidenceReference
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem


@pytest.fixture
def retained(declaration_case, case, monkeypatch):
    declaration = declared(declaration_case)
    raw, g, q = m._parts(declaration)
    store = case[2]
    sid = uuid4()
    own = EvidenceReference(
        source_id=sid,
        content_hash=content_hash_of(raw),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    location = store.put(B.PERSONAL, own.content_hash, raw)
    rows = [{"id": r.source_id, "content_hash": r.content_hash} for r in g.provenance]
    rows.append(
        {
            "id": sid,
            "content_hash": own.content_hash,
            "system": SourceSystem.MANUAL,
            "external_ref": m._namespace(declaration),
            "supersedes_source_id": None,
            "captured_at": g.approved_at,
            "lineage_id": sid,
            "content_location": location,
        }
    )
    current = {"rows": rows, "ids": (sid,)}
    session = Session()
    session.begin()
    events = []
    monkeypatch.setattr(
        m, "_physical", lambda s: (s.get_transaction(), s.get_nested_transaction(), None, None)
    )

    def same(s, entry):
        assert s.get_transaction() is entry[0] and s.get_nested_transaction() is entry[1]
        assert entry[0].is_active and not s.dirty and not s.new and not s.deleted

    monkeypatch.setattr(m, "_fragment_same_transaction", lambda s, e: same(s, (*e, None, None)))

    def selected(s, refs, *args):
        known = {row["id"]: row["content_hash"] for row in current["rows"]}
        if any(known.get(r.source_id) != r.content_hash for r in refs):
            raise ValueError("missing selected row")
        return tuple(tuple(row.items()) for row in current["rows"])

    monkeypatch.setattr(m, "_fragment_rows", selected)
    monkeypatch.setattr(m, "_fragment_profile_lineage", lambda *a: None)
    monkeypatch.setattr(session, "scalars", lambda statement: iter(current["ids"]))
    get = store.get_bounded

    def observed(*a, **kw):
        events.append("body")
        return get(*a, **kw)

    monkeypatch.setattr(store, "get_bounded", observed)
    try:
        yield SimpleNamespace(
            declaration=declaration,
            g=g,
            q=q,
            store=store,
            session=session,
            own=own,
            current=current,
            events=events,
        )
    finally:
        session.close()


def load(f, **kw):
    args = {
        "session": f.session,
        "artifacts": f.store,
        "reference": f.own,
        "expected_declaration": f.declaration,
    }
    args.update(kw)
    return m.load_fragment_review_declaration(**args)


def test_exact_full_bytes_reopen_no_human_or_claim_authority(retained):
    f = retained
    result = load(f)
    assert result.declaration == f.declaration and result.reference == f.own
    assert result.publication_digest == d.fragment_generation_review_declaration_digest(
        f.declaration
    )
    assert result.captured_at == f.g.approved_at and result.declaration.expires_at == f.g.expires_at
    assert (
        result.owner_admitted
        is result.processing_authorized
        is result.reviewer_authenticated
        is False
    )
    assert not hasattr(result, "human_action") and "invented-owner" not in repr(result)
    with pytest.raises(auth.ContextualAuthorizationError):
        auth.decode_history_fragment_consent(
            d.encode_fragment_generation_review_declaration(f.declaration)
        )
    assert f.events == ["body"]


@pytest.mark.parametrize(
    "fault",
    [
        "wrong-full",
        "wrong-request",
        "wrong-profile",
        "missing-own",
        "missing-input",
        "wrong-namespace",
        "wrong-system",
        "naive-date",
        "renewed-date",
        "supersedes",
        "conflict",
        "boundary",
        "label",
        "hash",
    ],
)
def test_full_binding_and_union_holds_before_real_body(retained, fault):
    f = retained
    kw = {}
    if fault == "wrong-full":
        kw["expected_declaration"] = f.declaration.model_copy(
            update={"generation_consent_digest": "0" * 64}
        )
    elif fault == "wrong-request":
        kw["expected_declaration"] = f.declaration.model_copy(
            update={"generation_request_digest": "0" * 64}
        )
    elif fault == "wrong-profile":
        p = f.declaration.review.model_copy(update={"rubric_digest": "9" * 64})
        kw["expected_declaration"] = d.prepare_fragment_generation_review_declaration(
            f.g, f.q, review=p
        )
    elif fault == "missing-own":
        f.current["rows"] = f.current["rows"][:-1]
    elif fault == "missing-input":
        f.current["rows"] = f.current["rows"][1:]
    elif fault == "conflict":
        f.current["ids"] = (f.own.source_id, uuid4())
    elif fault in ("boundary", "label", "hash"):
        kw["reference"] = f.own.model_copy(
            update={"trust_boundary": B.BRAINSTORM}
            if fault == "boundary"
            else {"effective_classification": C.CONFIDENTIAL}
            if fault == "label"
            else {"content_hash": "0" * 64}
        )
    else:
        name, val = {
            "wrong-namespace": ("external_ref", "personal-history-fragment-consent/foreign"),
            "wrong-system": ("system", SourceSystem.USER_INSTRUCTION),
            "naive-date": ("captured_at", f.g.approved_at.replace(tzinfo=None)),
            "renewed-date": ("captured_at", f.g.expires_at),
            "supersedes": ("supersedes_source_id", uuid4()),
        }[fault]
        f.current["rows"][-1][name] = val
    with pytest.raises(m.FragmentDeclarationRetentionError) as error:
        load(f, **kw)
    assert not f.events and error.value.__context__ is None


@pytest.mark.parametrize("fault", ["transaction", "metadata", "bytes"])
def test_real_bounded_file_callback_drift_holds(retained, monkeypatch, fault):
    f = retained
    get = f.store.get_bounded

    def changed(*a, **kw):
        raw = get(*a, **kw)
        f.events.append("fault-fired")
        if fault == "transaction":
            f.session.commit()
            f.session.begin()
        elif fault == "metadata":
            f.current["rows"][-1]["captured_at"] += timedelta(seconds=1)
        else:
            raw = b" " + raw
        return raw

    monkeypatch.setattr(f.store, "get_bounded", changed)
    with pytest.raises(m.FragmentDeclarationRetentionError):
        load(f)
    assert f.events == ["body", "fault-fired"]


def test_namespace_query_is_bounded_before_body(retained, monkeypatch):
    f = retained
    limits = []
    consumed = []

    def hostile(statement):
        limit = statement._limit_clause.value
        limits.append(limit)
        for i in range(min(1000, limit)):
            consumed.append(i)
            yield uuid4()

    monkeypatch.setattr(f.session, "scalars", hostile)
    with pytest.raises(m.FragmentDeclarationRetentionError):
        load(f)
    assert limits == [2] and consumed == [0, 1] and not f.events


@pytest.fixture
def declaration_protection(authority, declaration_case, monkeypatch):
    f = authority
    g = f.consent.model_copy(
        update={
            "body_digest": content_hash_of(f.q.prompt_body.encode()),
            "max_output_tokens": f.q.task.max_output_tokens,
        }
    )
    f.declaration = d.prepare_fragment_generation_review_declaration(
        g, f.q, review=declaration_case[2]
    )
    f.own = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(
            d.encode_fragment_generation_review_declaration(f.declaration)
        ),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    f.plan = replace(
        f.plan,
        rows=canonical_bytes(
            [
                {"id": str(r.source_id), "content_hash": r.content_hash}
                for r in (*g.provenance, f.own)
            ]
        ),
    )
    f.current_plan["value"] = f.plan
    monkeypatch.setattr(
        m, "load_fragment_review_declaration", lambda *a, **kw: f.events.append("declaration-load")
    )
    return f


def protect(f, existing=False, **kw):
    args = {"reference": f.own, "expected_declaration": f.declaration}
    args.update(kw)
    return (f.p.recheck_declaration if existing else f.p.protect_declaration)(**args)


def test_concrete_adapter_first_and_read_existing_complete_false_flags(
    declaration_protection, monkeypatch
):
    f = declaration_protection
    result = protect(f)
    assert result.publication_reference == f.own
    assert result.publication_digest == d.fragment_generation_review_declaration_digest(
        f.declaration
    )
    assert result.review_profile_digest == f.declaration.review_profile_digest
    assert result.review_profile_digest is not None
    assert (
        result.owner_admitted
        is result.processing_authorized
        is result.reviewer_authenticated
        is result.recovery_verified
        is False
    )
    assert f.events.index("owner") < f.events.index("declaration-load")
    assert f.events.count("backup") == f.events.count("restore") == 1
    assert f.own.source_id in f.restored[0][1]
    puts = []
    monkeypatch.setattr(f.writer, "put_object", lambda *a: puts.append(a))
    assert (
        protect(f, True) == result
        and not puts
        and f.events.count("backup") == 1
        and f.events.count("restore") == 2
    )
    with pytest.raises(ValueError):
        protection.decode_personal_fragment_authority_receipt(
            m.encode_fragment_declaration_receipt(result)
        )


@pytest.mark.parametrize("fault", ["missing-own", "missing-input", "digest", "owner", "expiry"])
def test_protection_zero_loader_backup_on_wrong_current_binding(
    declaration_protection, fault, monkeypatch
):
    f = declaration_protection
    kw = {}
    if fault.startswith("missing"):
        rows = json.loads(f.plan.rows)
        rows.pop(-1 if fault == "missing-own" else 0)
        f.current_plan["value"] = replace(f.plan, rows=canonical_bytes(rows))
    elif fault == "digest":
        kw["reference"] = f.own.model_copy(update={"content_hash": "0" * 64})
    elif fault == "owner":
        f.owner["value"] = None
    else:
        monkeypatch.setattr(f.p._clock, "_read", lambda: f.declaration.expires_at)
    with pytest.raises(protection.ContextualProtectionError):
        protect(f, **kw)
    assert "declaration-load" not in f.events and "backup" not in f.events


def test_missing_receipt_read_existing_never_repairs(declaration_protection, monkeypatch):
    f = declaration_protection
    puts = []
    monkeypatch.setattr(f.writer, "put_object", lambda *a: puts.append(a))
    with pytest.raises(protection.ContextualProtectionError):
        protect(f, True)
    assert not puts and "backup" not in f.events and "restore" not in f.events


def test_full_source_append_stales_proof_no_restore(declaration_protection):
    f = declaration_protection
    protect(f)
    rows = json.loads(f.plan.rows)
    rows.append({"id": str(uuid4()), "content_hash": "8" * 64})
    f.current_plan["value"] = replace(f.plan, rows=canonical_bytes(rows))
    with pytest.raises(protection.ContextualProtectionError):
        protect(f, True)
    assert f.events.count("restore") == 1 and f.events.count("backup") == 1


def test_restore_owner_revoke_holds_before_receipt_publication(declaration_protection, monkeypatch):
    f = declaration_protection
    original = protection.DisposableStateRestoreVerifier.verify_personal
    fired = []

    def revoke(self, *a, **kw):
        original(self, *a, **kw)
        fired.append(True)
        f.owner["value"] = None

    monkeypatch.setattr(protection.DisposableStateRestoreVerifier, "verify_personal", revoke)
    with pytest.raises(protection.ContextualProtectionError):
        protect(f)
    assert fired and f.events.count("restore") == 1
    assert not any(p.name.startswith("receipt-") for p in f.writer._root.rglob("*.age"))


@pytest.mark.parametrize("fault", ["extra", "duplicate", "whitespace", "expiry", "own", "kind"])
def test_closed_receipt_codec_no_authority_injection(declaration_protection, fault):
    f = declaration_protection
    raw = m.encode_fragment_declaration_receipt(protect(f))
    v = json.loads(raw)
    if fault == "extra":
        v["owner_admitted"] = True
    elif fault == "duplicate":
        raw = raw[:-1] + b',"format":"zac-personal-history-fragment-declaration-recovery-v2"}'
    elif fault == "whitespace":
        raw = b" " + raw
    elif fault == "expiry":
        v["expires_at"] = v["verified_at"]
    elif fault == "own":
        v["publication_reference"]["source_id"] = str(uuid4())
    else:
        v["format"] = "zac-personal-history-fragment-authority-recovery-v1"
    if fault not in ("duplicate", "whitespace"):
        raw = canonical_bytes(v)
    with pytest.raises(ValueError):
        m.decode_fragment_declaration_receipt(raw)


@pytest.fixture
def writer(retained, monkeypatch):
    """Real files/Session lifecycle; SQL lock/rows/owner are explicitly simulated."""
    f = retained
    from zacai.interfaces.host_clock import HostObservedClock

    f.active = 0
    f.pending = []
    f.commit_fault = False
    f.current["ids"] = ()
    f.current["rows"] = f.current["rows"][:-1]
    original_row = {
        "id": f.own.source_id,
        "content_hash": f.own.content_hash,
        "system": SourceSystem.MANUAL,
        "external_ref": m._namespace(f.declaration),
        "supersedes_source_id": None,
        "captured_at": f.g.approved_at,
        "lineage_id": f.own.source_id,
        "content_location": f.store.location_for(f.own.content_hash),
    }

    class Tracked(Session):
        def __enter__(self):
            f.active += 1
            return super().__enter__()

        def __exit__(self, *a):
            try:
                return super().__exit__(*a)
            finally:
                f.active -= 1

        def scalars(self, statement, *a, **kw):
            assert statement._limit_clause.value == 2
            if any(str(v).startswith("personal-history-fragment-claim/")
                   for v in statement.compile().params.values()):
                return iter(f.current.get("consumed", ()))
            return iter((*f.current["ids"], *(x["id"] for x in f.pending)))

        def commit(self):
            super().commit()
            f.current["ids"] = (*f.current["ids"], *(x["id"] for x in f.pending))
            f.pending.clear()
            f.events.append("commit")
            if f.commit_fault:
                raise RuntimeError("invented commit acknowledgement loss")

    f.factory = sessionmaker(class_=Tracked)

    def owner(*a):
        assert f.active == 0
        f.events.append("owner")

    monkeypatch.setattr(auth, "_fragment_decision_owner", owner)
    monkeypatch.setattr(m, "_lock", lambda *a: f.events.append("lock"))

    def record(session, **kw):
        assert (
            kw["trust_boundary"] is B.PERSONAL and kw["data_classification"] is C.HIGHLY_RESTRICTED
        )
        assert kw["external_ref"] == m._namespace(f.declaration)
        assert kw["captured_at"] == f.g.approved_at
        assert f.store.get_bounded(
            B.PERSONAL, kw["content_location"], max_bytes=d.MAX_DECLARATION_BYTES
        ) == d.encode_fragment_generation_review_declaration(f.declaration)
        f.events.append("record")
        row = {**original_row, **{k: kw[k] for k in ("content_location", "captured_at")}}
        f.current["rows"].append(row)
        f.pending.append(row)
        return SimpleNamespace(id=f.own.source_id), True

    monkeypatch.setattr(m, "record_source", record)
    # Production capacity query observes the same complete invented Source
    # inventory as this SQL-simulated fixture. The real capacity helper remains.
    import zacai.backup_artifacts as backup

    monkeypatch.setattr(backup, "_personal_backup_rows", lambda session, **kw: (
        canonical_bytes([{"id": str(row["id"])} for row in f.current["rows"]]), ()
    ))
    f.clock = HostObservedClock(lambda: f.g.approved_at)
    return f


def capture(f):
    return m.capture_fragment_review_declaration(
        factory=f.factory,
        artifacts=f.store,
        declaration=f.declaration,
        operation=object(),
        clock=f.clock,
    )


def test_owned_capture_commit_reopen_and_exact_replay_no_new_source(writer):
    f = writer
    result = capture(f)
    assert result.reference == f.own and result.declaration == f.declaration
    assert (
        f.events.index("owner")
        < f.events.index("lock")
        < f.events.index("record")
        < f.events.index("commit")
    )
    assert f.active == 0 and f.events.count("record") == 1
    old = result.captured_at
    assert capture(f) == result and f.events.count("record") == 1 and result.captured_at == old


def test_committed_ack_failure_preserves_record_no_retry_or_renewal(writer):
    f = writer
    f.commit_fault = True
    with pytest.raises(m.FragmentDeclarationRetentionError):
        capture(f)
    assert f.current["ids"] == (f.own.source_id,) and f.events.count("record") == 1
    f.commit_fault = False
    result = capture(f)
    assert result.captured_at == f.g.approved_at and f.events.count("record") == 1
    assert result.owner_admitted is False


def test_wrong_purpose_same_original_id_no_overwrite(writer, monkeypatch):
    f = writer
    capture(f)
    events = []
    # Different declared human-reference remains data, same original UUID.
    changed = f.g.model_copy(update={"human_reference": "different declared data"})
    f.declaration = d.prepare_fragment_generation_review_declaration(changed, f.q, review=None)
    monkeypatch.setattr(f.store, "put", lambda *a: events.append("put"))
    with pytest.raises(m.FragmentDeclarationRetentionError):
        capture(f)
    assert not events and f.events.count("record") == 1


@pytest.mark.parametrize("fault", ["transaction", "clock-drift"])
def test_capture_callback_hold_before_any_source_write(writer, monkeypatch, fault):
    f = writer
    fired = []
    if fault == "clock-drift":

        def clock():
            fired.append(True)
            f.current["rows"][0]["content_hash"] = "0" * 64
            return f.g.approved_at

        monkeypatch.setattr(f.clock, "_read", clock)
    else:
        original = f.store.put

        def put(*a):
            location = original(*a)
            fired.append(True)
            # Replace exactly the caller-owned transaction after artifact callback.
            # Capture actual session through the physical boundary observation.
            f.writing_session.commit()
            f.writing_session.begin()
            return location

        original_physical = m._physical

        def physical(session):
            f.writing_session = session
            return original_physical(session)

        monkeypatch.setattr(m, "_physical", physical)
        monkeypatch.setattr(f.store, "put", put)
    with pytest.raises(m.FragmentDeclarationRetentionError):
        capture(f)
    assert fired and "record" not in f.events


def test_missing_genuine_owner_denies_before_private_io(retained, monkeypatch):
    f = retained
    events = []
    monkeypatch.setattr(f.store, "put", lambda *a: events.append("put"))
    with pytest.raises(m.FragmentDeclarationRetentionError):
        m.capture_fragment_review_declaration(
            factory=sessionmaker(),
            artifacts=f.store,
            declaration=f.declaration,
            operation=object(),
            clock=object(),
        )
    assert not events


@pytest.mark.parametrize(
    "autocommit,status,expected",
    [(False, "INTRANS", True), (True, "INTRANS", False), (False, "IDLE", False)],
)
def test_exact_physical_driver_admission(monkeypatch, autocommit, status, expected):
    import psycopg
    from psycopg.pq import TransactionStatus

    class InventedDriver:
        pass

    driver = InventedDriver()
    driver.autocommit = autocommit
    driver.closed = False
    driver.broken = False
    driver.info = SimpleNamespace(transaction_status=getattr(TransactionStatus, status))
    conn = SimpleNamespace(
        connection=SimpleNamespace(driver_connection=driver), in_transaction=lambda: True
    )
    session = SimpleNamespace(connection=lambda: conn)
    outer = object()
    monkeypatch.setattr(m, "_fragment_transaction", lambda s: (outer, None))
    monkeypatch.setattr(psycopg, "Connection", InventedDriver)
    if expected:
        assert m._physical(session) == (outer, None, conn, driver)
    else:
        with pytest.raises(ValueError):
            m._physical(session)


def test_mechanical_manual_source_cannot_be_loaded_as_human_consent(retained, monkeypatch):
    f = retained
    monkeypatch.setattr(
        auth, "_fragment_transaction", lambda s: (s.get_transaction(), s.get_nested_transaction())
    )
    monkeypatch.setattr(auth, "_fragment_rows", m._fragment_rows)
    monkeypatch.setattr(auth, "_fragment_profile_lineage", lambda *a: None)
    # Exact immutable wrapper hash is distinct from inner consent hash; no cast.
    with pytest.raises(auth.ContextualAuthorizationError):
        auth.load_history_fragment_consent(
            f.session,
            artifacts=f.store,
            reference=f.own,
            expected_consent=f.g,
            expected_request=f.q,
        )
    assert not f.events


def test_actual_file_oversize_denied_bounded_no_unbounded_fallback(retained, monkeypatch):
    f = retained
    path = f.store._path_for(B.PERSONAL, f.own.content_hash)
    path.write_bytes(b"x" * (d.MAX_DECLARATION_BYTES + 1))
    monkeypatch.setattr(f.store, "get", lambda *a: pytest.fail("unbounded fallback"))
    with pytest.raises(m.FragmentDeclarationRetentionError):
        load(f)
    assert f.events == ["body"]


def test_cleanup_uncertain_preserved_without_receipt(declaration_protection, monkeypatch):
    f = declaration_protection
    from zacai.review_protection import ReviewProtectionCleanupUncertain

    fired = []

    def uncertain(*a, **kw):
        fired.append(True)
        raise ReviewProtectionCleanupUncertain("invented")

    monkeypatch.setattr(protection.DisposableStateRestoreVerifier, "verify_personal", uncertain)
    with pytest.raises(protection.PersonalFragmentCleanupUncertain) as error:
        protect(f)
    assert fired and error.value.__context__ is None
    assert not any(p.name.startswith("receipt-") for p in f.writer._root.rglob("*.age"))


def test_none_review_is_preserved_as_data_not_upgraded(declaration_protection):
    f = declaration_protection
    _, g, _ = m._parts(f.declaration)
    f.declaration = d.prepare_fragment_generation_review_declaration(g, f.q, review=None)
    f.own = f.own.model_copy(
        update={
            "content_hash": content_hash_of(
                d.encode_fragment_generation_review_declaration(f.declaration)
            )
        }
    )
    f.current_plan["value"] = replace(
        f.plan,
        rows=canonical_bytes(
            [
                {"id": str(r.source_id), "content_hash": r.content_hash}
                for r in (*g.provenance, f.own)
            ]
        ),
    )
    result = protect(f)
    assert result.review_profile_digest is None and not result.owner_admitted


def test_restored_ciphertext_mutation_holds_before_receipt_publication(
    declaration_protection, monkeypatch
):
    f = declaration_protection
    original = protection.DisposableStateRestoreVerifier.verify_personal
    fired = []

    def mutate(self, *a, **kw):
        original(self, *a, **kw)
        files = list(f.reader._root.rglob("state-*.age"))
        assert len(files) == 1
        files[0].write_bytes(b"invented changed ciphertext after restore")
        fired.append(True)

    monkeypatch.setattr(protection.DisposableStateRestoreVerifier, "verify_personal", mutate)
    with pytest.raises(protection.ContextualProtectionError):
        protect(f)
    assert fired and f.events.count("restore") == 1
    assert not any(p.name.startswith("receipt-") for p in f.writer._root.rglob("*.age"))


def test_existing_receipt_cannot_be_overwritten_by_second_protect(declaration_protection):
    f = declaration_protection
    first = protect(f)
    before = f.events.count("backup")
    with pytest.raises(protection.ContextualProtectionError):
        protect(f)
    assert f.events.count("backup") == before and protect(f, True) == first
