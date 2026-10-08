"""ROOT ONLY: real ASGI/encrypted sessions/signed owner/PG, invented publications.

No generator/reviewer inference. Standalone test handler is not production route
activation. Fixture OAuth attendance is simulated; signed owner storage and
current encrypted cookie verification are real. Declarations themselves confer
no permission. Root must guard exact final source/support before collection.
"""

from datetime import timedelta
from uuid import UUID

import pytest
from sqlalchemy import select
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from tests.test_fragment_review_declaration_sql import (
    capture,
)
from tests.test_fragment_review_declaration_sql import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_fragment_review_declaration_sql import (
    original_fixture_budget as original_fixture_budget,  # noqa: PLC0414
)
from tests.test_ollama_token_counter import installed as installed  # noqa: PLC0414
from tests.test_personal_fragment_claim_issuer_sql import (
    exact_issuer_qwen_profile as exact_issuer_qwen_profile,  # noqa: PLC0414
)
from tests.test_personal_fragment_protection_sql import (
    actual_case as actual_case,  # noqa: PLC0414
)
from tests.test_personal_fragment_protection_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_private_host import ORIGIN, OWNER
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import fragment_publication_admission as admission
from zacai.intelligence import fragment_review_declaration as declaration
from zacai.intelligence import fragment_review_retention as retention
from zacai.interfaces import fragment_publication_web as web
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem
from zacai.state_repository import record_source


@pytest.fixture
def http_case(declaration_case):
    f = declaration_case
    f.parent = capture(f)
    # Recover the actual constructor source from the accepted fixture's closure,
    # never synthesize an owner grant or replace encrypted session operations.
    closure = f.p._operation._read.__closure__
    assert closure is not None
    sources = [
        cell.cell_contents for cell in closure if type(cell.cell_contents) is NamedSessionContinuity
    ]
    assert len(sources) == 1
    f.continuity = sources[0]
    f.receipts = []
    f.failures = []

    async def actual_post(request: Request):
        try:
            body = await request.body()
            token = web._observe_fragment_http_post(
                request=request,
                body=body,
                continuity=f.continuity,
                publication=f.d,
                reference=f.parent.reference,
            )
            retained = admission._record_posted_fragment_admission(
                factory=f.p._factory, artifacts=f.p._artifacts, action=token, clock=f.p._clock
            )
            f.receipts.append(retained)
            return JSONResponse({"source_id": str(retained.reference.source_id)})
        except (
            web.FragmentPublicationWebError,
            admission.FragmentPublicationAdmissionError,
        ) as error:
            f.failures.append(type(error).__name__)
            return JSONResponse({"held": True}, status_code=409)

    app = Starlette(routes=[Route("/ask-caz-locally", actual_post, methods=["POST"])])
    with TestClient(app, base_url=ORIGIN) as client:
        f.client = client
        yield f


def post(f, *, cookie=None, csrf=None):
    selected = f.cookie if cookie is None else cookie
    current = f.sessions.peek_user(selected, f.p._clock())
    assert current is not None
    return f.client.post(
        "/ask-caz-locally",
        headers={"Origin": ORIGIN, "Cookie": f"__Host-zac-session={selected}"},
        data={
            "action": "approve_fragment_publication",
            "csrf": current.csrf if csrf is None else csrf,
            "publication_digest": declaration.fragment_generation_review_declaration_digest(f.d),
            "source_id": str(f.parent.reference.source_id),
        },
    )


def action_ids(f):
    with f.p._factory() as session:
        return tuple(
            session.scalars(
                select(Source.id).where(
                    Source.trust_boundary == B.PERSONAL,
                    Source.system == SourceSystem.USER_INSTRUCTION,
                    Source.external_ref.like(
                        f"personal-history-fragment-publication-admission/{f.g.id}/%"
                    ),
                )
            )
        )


def test_actual_asgi_csrf_signed_owner_commit_and_reopen(http_case):
    f = http_case
    response = post(f)
    assert response.status_code == 200 and len(f.receipts) == 1 and not f.failures
    retained = f.receipts[0]
    assert action_ids(f) == (retained.reference.source_id,)
    with f.p._factory() as session:
        session.begin()
        loaded = admission.load_fragment_publication_admission(
            session,
            artifacts=f.p._artifacts,
            reference=retained.reference,
            expected_admission=retained.admission,
            expected_publication=f.d,
        )
        row = session.get(Source, retained.reference.source_id)
        assert (
            row.system == SourceSystem.USER_INSTRUCTION
            and row.captured_at == retained.admission.observed_action_at
        )
    assert (
        loaded == retained
        and retained.admission.original_session_binding == f.g.original_session_binding
    )
    assert retained.admission.expires_at == f.g.expires_at
    assert (
        retained.admission.processing_authorized
        is retained.admission.reviewer_authenticated
        is False
    )
    assert f.active == {"canonical": 0, "admin": 0}


@pytest.mark.parametrize("fault", ["expiry", "session", "csrf"])
def test_actual_wrong_original_http_binding_zero_artifact_and_source_writes(
    http_case, monkeypatch, fault
):
    f = http_case
    puts = []
    original = f.p._artifacts.put

    def observed(*args, **kwargs):
        puts.append(True)
        return original(*args, **kwargs)

    monkeypatch.setattr(f.p._artifacts, "put", observed)
    cookie = None
    csrf = None
    if fault == "expiry":
        monkeypatch.setattr(
            f.continuity, "_clock", HostObservedClock(lambda: f.g.expires_at + timedelta(seconds=1))
        )
    elif fault == "session":
        cookie = f.sessions.start_user(OWNER, f.p._clock())
    else:
        csrf = "z" * 43
    result = post(f, cookie=cookie, csrf=csrf)
    assert result.status_code == 409 and f.receipts == [] and puts == [] and action_ids(f) == ()


def test_actual_sibling_parent_during_parent_body_read_holds_before_action_write(
    http_case, monkeypatch
):
    f = http_case
    original = f.p._artifacts.get_bounded
    fired = []
    with f.p._factory() as session:
        location = session.get(Source, f.parent.reference.source_id).content_location
    sibling = declaration.prepare_fragment_generation_review_declaration(
        f.g, f.q, review=f.d.review.model_copy(update={"rubric_digest": "9" * 64})
    )
    raw = declaration.encode_fragment_generation_review_declaration(sibling)

    def append_sibling(*args, **kwargs):
        returned = original(*args, **kwargs)
        if args[1] == location and not fired:
            loc = f.p._artifacts.put(B.PERSONAL, content_hash_of(raw), raw)
            with f.p._factory() as session:
                row, new = record_source(
                    session,
                    trust_boundary=B.PERSONAL,
                    data_classification=C.HIGHLY_RESTRICTED,
                    system=SourceSystem.MANUAL,
                    external_ref=retention._namespace(sibling),
                    content_hash=content_hash_of(raw),
                    content_location=loc,
                    captured_at=f.p._clock(),
                )
                assert new
                sid = row.id
                session.commit()
            fired.append(sid)
        return returned

    monkeypatch.setattr(f.p._artifacts, "get_bounded", append_sibling)
    result = post(f)
    with f.p._factory() as session:
        parents = tuple(
            session.scalars(
                select(Source.id).where(
                    Source.external_ref.like(f"personal-history-fragment-declaration-v2/{f.g.id}/%")
                )
            )
        )
    assert len(fired) == 1 and set(parents) == {f.parent.reference.source_id, fired[0]}
    assert result.status_code == 409 and f.receipts == [] and action_ids(f) == ()


def test_actual_custody_revision_at_final_owner_callback_withholds_ack(http_case, monkeypatch):
    from tests.personal_fragment_sql_support import record
    from tests.test_claude_original_capture_sql import prepared
    from zacai.claude_original_capture import ClaudeCustodyProposal, prepare_claude_custody_proposal
    from zacai.state_repository import get_effective_source_classification

    f = http_case
    with f.p._factory() as session:
        old = session.scalar(select(Source).where(Source.external_ref.like("claude-original/%")))
        assert old is not None
        oldid = old.id
        custody = UUID(old.external_ref.split("/")[1])
        oldref = next(ref for ref in f.g.provenance if ref.source_id == oldid)
        effective = get_effective_source_classification(session, source_id=oldid)
        assert oldref.content_hash == old.content_hash
        assert oldref.effective_classification is effective is C.HIGHLY_RESTRICTED
        revision_at = old.captured_at + timedelta(seconds=1)
    _, newraw, proposal = prepared(
        custody,
        text="Invented supported subsequent original revision",
        at=revision_at,
    )
    declared = ClaudeCustodyProposal.model_validate_json(proposal)
    proposal = prepare_claude_custody_proposal(
        custody_id=custody,
        original_raw=newraw,
        account_ref=declared.account_ref,
        exported_at=declared.exported_at,
        acquired_at=declared.acquired_at,
        captured_at=revision_at,
        boundary=oldref.trust_boundary,
        classification=effective,
        selections=declared.selections,
    )
    original_load = admission.load_fragment_publication_admission
    reopened = []
    revised = []

    def load(*args, **kwargs):
        result = original_load(*args, **kwargs)
        if action_ids(f):
            reopened.append(result.reference.source_id)
        return result

    monkeypatch.setattr(admission, "load_fragment_publication_admission", load)
    original_owner = f.continuity._owner

    def owner():
        current = original_owner()
        if reopened and not revised:
            assert f.active == {"canonical": 0, "admin": 0}
            with f.p._factory() as session:
                saved = record(session, f.p._artifacts, newraw, proposal)
                assert saved.original_reference.source_id != oldid
                newid = saved.original_reference.source_id
                session.commit()
            revised.append(newid)
        return current

    monkeypatch.setattr(f.continuity, "_owner", owner)
    response = post(f)
    assert len(reopened) == 1 and len(revised) == 1
    with f.p._factory() as session:
        assert session.get(Source, revised[0]).supersedes_source_id == oldid
    assert response.status_code == 409 and f.receipts == [] and len(action_ids(f)) == 1


def test_actual_commit_ack_loss_permanent_source_no_second_write(http_case, monkeypatch):
    f = http_case
    cls = f.p._factory.class_
    original = cls.commit
    committed = []

    def lost(session):
        original(session)
        ids = action_ids(f)
        assert len(ids) == 1
        committed.append(ids[0])
        raise RuntimeError("Invented acknowledgement lost after genuine commit")

    with monkeypatch.context() as patch:
        patch.setattr(cls, "commit", lost)
        response = post(f)
    assert response.status_code == 409 and len(committed) == 1 and action_ids(f) == tuple(committed)
    writes = []
    put = f.p._artifacts.put

    def observe(*args, **kwargs):
        writes.append(True)
        return put(*args, **kwargs)

    monkeypatch.setattr(f.p._artifacts, "put", observe)
    second = post(f)
    assert (
        second.status_code == 409
        and f.receipts == []
        and writes == []
        and action_ids(f) == tuple(committed)
    )
