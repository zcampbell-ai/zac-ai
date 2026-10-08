"""Finite source-corrective controls; canonical SQL/owner authority simulated."""

# ruff: noqa: PLC0414
import time
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_personal_fragment_factory import (
    case as case,
)
from tests.test_personal_fragment_factory import (
    controller as controller,
)
from tests.test_personal_fragment_factory import (
    declaration_case as declaration_case,
)
from tests.test_personal_fragment_factory import (
    factory_case as factory_case,
)
from tests.test_personal_fragment_factory import (
    installed as installed,
)
from tests.test_personal_fragment_factory import (
    owner_case as owner_case,
)
from tests.test_personal_fragment_factory import (
    post_case as post_case,
)
from zacai import review_authorization
from zacai.intelligence import fragment_publication_generation as generation
from zacai.intelligence import fragment_publication_review as review
from zacai.intelligence.contracts import EvidenceReference
from zacai.interfaces import personal_fragment_factory as factory
from zacai.interfaces.host_clock import HostObservedClock
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


@pytest.mark.parametrize("delay", [False, True])
def test_generation_terminal_lock_cannot_cross_original_expiry(monkeypatch, delay):
    # Actual terminal implementation, trusted builtin elapsed time; no real grant
    # or SQL. Scalar/owner/journal seams explicitly simulated.
    from datetime import UTC, datetime

    now = datetime(2026, 10, 8, tzinfo=UTC)
    g = object.__new__(generation.CanonicalPersonalFragmentPublicationAuthorization)
    g._consent = SimpleNamespace(
        id=uuid4(),
        approved_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(seconds=0.035),
    )
    g._clock = HostObservedClock(lambda: now)
    g._admission_reference = object()
    g._admission = object()
    g._publication = object()
    g._claim = object()
    g._claim_reference = object()
    g._protector = SimpleNamespace(_run_row=lambda _: b"journal")
    g._graph_check = lambda: None
    g._owner = lambda: None

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def begin(self):
            pass

    g._factory = Session
    g._physical_transaction = lambda _: object()
    g._same_physical_transaction = lambda *a: None
    g._receipt_plan = lambda *a: None
    fired = []

    def locked(*a):
        fired.append("terminal-lock")
        if delay:
            time.sleep(0.055)

    monkeypatch.setattr(review_authorization, "_lock", locked)
    monkeypatch.setattr(generation, "_current", lambda *a: None)
    receipt = SimpleNamespace(
        artifact_backup_run_id=uuid4(), live_journal_digest=generation.content_hash_of(b"journal")
    )
    if delay:
        with pytest.raises(ValueError, match="processing expired"):
            g._final_claim(receipt)
    else:
        g._final_claim(receipt)
    assert fired == ["terminal-lock"]


@pytest.mark.parametrize("count", [89, 90])
def test_factory_review_provenance_reserves_seven_before_capture(factory_case, monkeypatch, count):
    f = factory_case
    refs = tuple(
        EvidenceReference(
            source_id=uuid4(),
            content_hash="a" * 64,
            trust_boundary=B.PERSONAL,
            effective_classification=C.HIGHLY_RESTRICTED,
        )
        for _ in range(count)
    )
    fired = []
    monkeypatch.setattr(factory, "_fragment_request_provenance", lambda _: refs)

    # Only assert threshold in actual factory sequence; count89 cannot forge
    # request provenance and must hold later, so stop at next real token-counter seam.
    def count_tokens(*a):
        fired.append("after-provenance")
        raise RuntimeError("explicit stop before capture")

    monkeypatch.setattr(f.c.generation_counter, "count_prompt_tokens", count_tokens)
    with pytest.raises(factory.PersonalFragmentFactoryError):
        factory.prepare_personal_fragment_task(f.c, inputs=f.s.inputs, operation=f.operation,
            instruction=f.c.original_context.task.instruction)
    assert fired == (["after-provenance"] if count == 89 else [])
    assert f.retained == []


def test_authenticated_graph_includes_both_actual_producers():
    files = review._AUTHENTICATED_GRAPH_FILES
    assert "zacai/interfaces/fragment_preparation_web.py" in files
    assert "zacai/interfaces/personal_fragment_factory.py" in files
    assert len(set(files)) == len(files)
    assert len(review.fragment_publication_review_graph_digest()) == 64


@pytest.mark.parametrize("kind", ["CLAIM", "ASSESSMENT"])
@pytest.mark.parametrize("delay", [False, True])
def test_reviewer_terminal_sql_cannot_cross_original_deadline(monkeypatch, kind, delay):
    # Direct concrete terminal routine only, intentionally no authorization
    # constructor/real grant or SQL. Does not claim reviewer admission.
    g = object.__new__(review.CanonicalFragmentPublicationReviewAuthorization)

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            pass

        def begin(self):
            pass

    journal = b"journal"
    g._generation = SimpleNamespace(
        _factory=Session,
        _consent=SimpleNamespace(id=uuid4()),
        _protector=SimpleNamespace(_run_row=lambda _: journal),
        _owner=lambda: None,
    )
    g._runtime = SimpleNamespace(_observe_authenticated_clock=lambda: None)
    g._claim_reference = object()
    g._graph_check = lambda: None
    g._deadline_monotonic = time.monotonic() + 0.035
    monkeypatch.setattr(review_authorization, "_lock", lambda *a: None)
    monkeypatch.setattr(review, "_physical", lambda _: object())
    monkeypatch.setattr(review, "_same", lambda *a: None)
    monkeypatch.setattr(review, "_receipt_binding", lambda *a: {})
    monkeypatch.setattr(
        review,
        "prepare_personal_encrypted_custody_backup_plan",
        lambda _: SimpleNamespace(rows=b"[]"),
    )
    fired = []

    def final_sql(*a):
        fired.append("last-canonical-query")
        if delay:
            time.sleep(0.055)

    monkeypatch.setattr(review, "_review_current", final_sql)
    receipt = SimpleNamespace(
        artifact_backup_run_id=uuid4(),
        live_journal_digest=generation.content_hash_of(journal),
        full_plan_digest=generation.content_hash_of(b"[]"),
        full_boundary_source_hashes=(),
        full_boundary_source_fingerprints=(),
    )
    if delay:
        with pytest.raises(ValueError, match="reviewer interval exhausted"):
            g._terminal(receipt, object(), kind)
    else:
        g._terminal(receipt, object(), kind)
    assert fired == ["last-canonical-query"]
