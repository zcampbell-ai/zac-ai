"""Actual closed codecs and bounded files; SQL/owner/recovery explicitly mocked."""

from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_fragment_review_retention import case as case  # noqa: PLC0414
from tests.test_fragment_review_retention import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_fragment_review_retention import retained as retained  # noqa: PLC0414
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import fragment_publication_admission as m
from zacai.intelligence import fragment_review_retention as old
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.fragment_review_declaration import (
    fragment_generation_review_declaration_digest,
)
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem


@pytest.fixture
def admitted(retained, monkeypatch):
    f = retained
    g = f.g
    value = m.FragmentPublicationAdmissionV1(
        publication_reference=f.own,
        publication_digest=fragment_generation_review_declaration_digest(f.declaration),
        generation_id=g.id,
        task_id=g.task_id,
        builder_id=g.builder_id,
        request_digest=g.request_digest,
        review_profile_digest=f.declaration.review_profile_digest,
        actor_issuer=g.owner_issuer,
        actor_subject=g.owner_subject,
        original_session_binding=g.original_session_binding,
        original_session_issued_at=g.original_session_issued_at,
        original_session_expires_at=g.original_session_expires_at,
        original_approved_at=g.approved_at,
        expires_at=g.expires_at,
        observed_action_at=g.approved_at,
    )
    raw = m.encode_fragment_publication_admission(value)
    own = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(raw),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    loc = f.store.put(B.PERSONAL, own.content_hash, raw)
    f.current["rows"].append(
        {
            "id": own.source_id,
            "content_hash": own.content_hash,
            "system": SourceSystem.USER_INSTRUCTION,
            "external_ref": m._namespace(value),
            "supersedes_source_id": None,
            "captured_at": value.observed_action_at,
            "content_location": loc,
            "lineage_id": own.source_id,
        }
    )
    ids = [(own.source_id,)]
    monkeypatch.setattr(m, "_physical", old._physical)
    monkeypatch.setattr(m, "_fragment_rows", old._fragment_rows)
    monkeypatch.setattr(m, "_fragment_profile_lineage", lambda *a: None)
    monkeypatch.setattr(m, "_not_withdrawn", lambda *a: None)
    monkeypatch.setattr(
        m,
        "_ids",
        lambda s, p, system=SourceSystem.USER_INSTRUCTION: (
            f.current["ids"] if system is SourceSystem.MANUAL else ids[0]
        ),
    )
    return SimpleNamespace(f=f, value=value, raw=raw, own=own, loc=loc, ids=ids)


def load(a):
    return m.load_fragment_publication_admission(
        a.f.session,
        artifacts=a.f.store,
        reference=a.own,
        expected_admission=a.value,
        expected_publication=a.f.declaration,
    )


def test_exact_action_body_reopens_and_is_not_dispatch_authority(admitted):
    a = admitted
    result = load(a)
    assert result.admission == a.value and result.reference == a.own
    assert m.decode_fragment_publication_admission(a.raw) == a.value
    assert a.value.processing_authorized is a.value.reviewer_authenticated is False
    assert result.captured_at == a.value.observed_action_at


@pytest.mark.parametrize("kind", ["parent", "action", "row", "transaction"])
def test_last_own_body_callback_changed_scalar_or_prefix_holds(admitted, monkeypatch, kind):
    a = admitted
    get = a.f.store.get_bounded
    milestones = []

    def changed(*args, **kwargs):
        raw = get(*args, **kwargs)
        if args[1] == a.loc:
            milestones.append("own bounded body completed")
            if kind == "parent":
                a.f.current["ids"] = (a.f.own.source_id, uuid4())
            elif kind == "action":
                a.ids[0] = (a.own.source_id, uuid4())
            elif kind == "row":
                a.f.current["rows"][-1]["captured_at"] += timedelta(seconds=1)
            else:
                a.f.session.commit()
        return raw

    monkeypatch.setattr(a.f.store, "get_bounded", changed)
    with pytest.raises(m.FragmentPublicationAdmissionError):
        load(a)
    assert milestones == ["own bounded body completed"]


@pytest.mark.parametrize("kind", ["source", "parent", "scope"])
def test_prebody_bad_exact_locator_holds(admitted, kind):
    a = admitted
    if kind == "source":
        a.own = a.own.model_copy(update={"source_id": uuid4()})
    elif kind == "scope":
        a.own = a.own.model_copy(update={"effective_classification": C.CONFIDENTIAL})
    else:
        a.f.current["ids"] = (a.f.own.source_id, uuid4())
    with pytest.raises(m.FragmentPublicationAdmissionError):
        load(a)
    assert a.f.events == []


@pytest.mark.parametrize(
    "field",
    [
        "publication_digest",
        "request_digest",
        "review_profile_digest",
        "actor_subject",
        "original_session_binding",
    ],
)
def test_same_canonical_codec_does_not_make_changed_original_binding_valid(admitted, field):
    a = admitted
    changed = "wrong actor" if field == "actor_subject" else "f" * 64
    value = a.value.model_copy(update={field: changed})
    # Canonical declaration bytes alone never issue; exact publication binding
    # must still reject before private bodies or canonical record writes.
    with pytest.raises(ValueError):
        m._binding(value, a.f.declaration)
    assert a.f.events == []


import json
from dataclasses import replace

from tests.test_fragment_review_retention import authority as authority  # noqa: PLC0414
from tests.test_fragment_review_retention import consent_case as consent_case  # noqa: PLC0414
from tests.test_fragment_review_retention import (
    declaration_protection as declaration_protection,  # noqa: PLC0414
)
from tests.test_fragment_review_retention import packet_case as packet_case  # noqa: PLC0414
from zacai import contextual_protection as protection
from zacai.ingestion.artifact_store import canonical_bytes


@pytest.fixture
def action_protection(declaration_protection, monkeypatch):
    f = declaration_protection
    _, g, _ = old._parts(f.declaration)
    v = m.FragmentPublicationAdmissionV1(
        publication_reference=f.own,
        publication_digest=fragment_generation_review_declaration_digest(f.declaration),
        generation_id=g.id,
        task_id=g.task_id,
        builder_id=g.builder_id,
        request_digest=g.request_digest,
        review_profile_digest=f.declaration.review_profile_digest,
        actor_issuer=g.owner_issuer,
        actor_subject=g.owner_subject,
        original_session_binding=g.original_session_binding,
        original_session_issued_at=g.original_session_issued_at,
        original_session_expires_at=g.original_session_expires_at,
        original_approved_at=g.approved_at,
        expires_at=g.expires_at,
        observed_action_at=g.approved_at,
    )
    f.action = v
    f.actionref = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(m.encode_fragment_publication_admission(v)),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    rows = json.loads(f.plan.rows)
    rows.append({"id": str(f.actionref.source_id), "content_hash": f.actionref.content_hash})
    f.plan = replace(f.plan, rows=canonical_bytes(rows))
    f.current_plan["value"] = f.plan
    monkeypatch.setattr(
        m, "load_fragment_publication_admission", lambda *a, **kw: f.events.append("action-load")
    )
    return f


def protect_action(f, existing=False):
    return (f.p.recheck_publication_admission if existing else f.p.protect_publication_admission)(
        reference=f.actionref, expected_admission=f.action, expected_publication=f.declaration
    )


def test_exact_action_checkpoint_and_read_existing_never_renew_or_write(
    action_protection, monkeypatch
):
    f = action_protection
    result = protect_action(f)
    assert (
        result.admission_reference == f.actionref
        and result.admission_digest == f.actionref.content_hash
    )
    assert result.observed_action_at == f.action.observed_action_at
    assert (
        result.owner_admitted
        is result.processing_authorized
        is result.reviewer_authenticated
        is False
    )
    assert {f.actionref, f.own} <= set(result.selected_references)
    assert f.events.index("owner") < f.events.index("action-load")
    puts = []
    monkeypatch.setattr(f.writer, "put_object", lambda *a: puts.append(a))
    assert protect_action(f, True) == result
    assert puts == [] and f.events.count("backup") == 1 and f.events.count("restore") == 2
    with pytest.raises(ValueError):
        old.decode_fragment_declaration_receipt(
            m.encode_fragment_publication_admission_receipt(result)
        )


@pytest.mark.parametrize("fault", ["own", "input", "parent", "owner"])
def test_missing_full_selected_membership_or_owner_denies_before_body_backup(
    action_protection, fault
):
    f = action_protection
    if fault == "owner":
        f.owner["value"] = None
    else:
        rows = json.loads(f.plan.rows)
        rows.pop(-1 if fault == "own" else -2 if fault == "parent" else 0)
        f.current_plan["value"] = replace(f.plan, rows=canonical_bytes(rows))
    with pytest.raises(protection.ContextualProtectionError):
        protect_action(f)
    assert "action-load" not in f.events and "backup" not in f.events and "restore" not in f.events


def test_admission_source_append_stales_old_declaration_proof(action_protection):
    f = action_protection
    result = protect_action(f)
    rows = json.loads(f.plan.rows)
    rows.append({"id": str(uuid4()), "content_hash": "9" * 64})
    f.current_plan["value"] = replace(f.plan, rows=canonical_bytes(rows))
    with pytest.raises(protection.ContextualProtectionError):
        protect_action(f, True)
    assert result.expires_at == f.declaration.expires_at and f.events.count("restore") == 1


def test_terminal_clock_revocation_holds_after_actual_receipt_reobservation(
    action_protection, monkeypatch
):
    """Real adapter/receipt codec; signed owner, SQL and age are simulated."""
    import inspect

    f = action_protection
    armed = []
    fired = []
    original_observe = f.p._reobserve_objects
    original_clock = f.p._clock._read

    def reobserve(observations, access):
        original_observe(observations, access)
        if "/receipt-" in observations[-1][0]:
            armed.append(True)

    def clock():
        frame = inspect.currentframe()
        caller = frame.f_back.f_back if frame and frame.f_back else None
        if armed and not fired and caller and caller.f_code.co_name in {
            "_authority_access", "_admission_execute"
        }:
            fired.append("terminal clock revoked original owner")
            f.owner["value"] = None
        return original_clock()

    monkeypatch.setattr(f.p, "_reobserve_objects", reobserve)
    monkeypatch.setattr(f.p._clock, "_read", clock)
    with pytest.raises(protection.ContextualProtectionError):
        protect_action(f)
    assert fired == ["terminal clock revoked original owner"]
    assert f.events.count("restore") == 1
    assert armed and "action-load" in f.events
