# ruff: noqa: PLC0414 - actual pytest fixture exports, not permission substitutes
"""Root-only invented host orchestration, real SQL/age; model HTTP only mocked.

Exact corrected host source/runner closure is frozen; root alone executes.
PASS judgments are invented transport fixtures, not model-quality evidence.
"""

import http.client
import json
import time
from concurrent.futures import ThreadPoolExecutor
from queue import Empty, Queue
from threading import Event

import pytest
from sqlalchemy import create_engine, select, text
from starlette.applications import Starlette
from starlette.responses import HTMLResponse, Response
from starlette.routing import Route
from starlette.testclient import TestClient

from tests.test_fragment_publication_review_sql import (
    RUBRIC,
    TEMPLATE,
)
from tests.test_fragment_publication_review_sql import (
    actual_case as actual_case,
)
from tests.test_fragment_publication_review_sql import (
    clean_factory as clean_factory,
)
from tests.test_fragment_publication_review_sql import (
    declaration_case as declaration_case,
)
from tests.test_fragment_publication_review_sql import (
    exact_issuer_qwen_profile as exact_issuer_qwen_profile,
)
from tests.test_fragment_publication_review_sql import (
    http_case as http_case,
)
from tests.test_fragment_publication_review_sql import (
    installed as installed,
)
from tests.test_fragment_publication_review_sql import (
    original_fixture_budget as original_fixture_budget,
)
from tests.test_private_host import ORIGIN
from zacai import contextual_protection, review_authorization
from zacai.ingestion.artifact_store import canonical_bytes
from zacai.intelligence import contextual_generation as generation
from zacai.intelligence import fragment_publication_review as publication_review
from zacai.intelligence import fragment_review_runtime as engine
from zacai.intelligence import fragment_review_wire as wire
from zacai.intelligence.contextual_evaluation import ContextualCriterion
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.interfaces.fragment_publication_web import (
    FragmentPublicationWeb,
    FragmentPublicationWebError,
    _RetainedFragmentTask,
)
from zacai.state import Source


@pytest.fixture
def owner_task(http_case, installed, monkeypatch):
    f = http_case
    f.p.protect_declaration(reference=f.parent.reference, expected_declaration=f.d)
    counter = OllamaQwenContextualTokenCounter(models_root=installed[0], model_digest=installed[2])
    f.controller = FragmentPublicationWeb(
        continuity=f.continuity,
        publication=f.d,
        reference=f.parent.reference,
        protector=f.p,
        generation_counter=counter,
        review_counter=f.review_counter,
        review_runtime_profile=engine.FragmentReviewRuntimeProfile(
            wire.RUNTIME,
            engine.fragment_review_runtime_digest(),
            f.review_counter.model_digest,
            f.review_counter.tokenizer_digest,
            f.review_counter.template_digest,
            f.review_counter.renderer_digest,
        ),
        rubric_utf8=RUBRIC,
        template_utf8=TEMPLATE,
        run_approved_task=True,
    )
    f.host_posts, f.host_results, f.host_errors = [], [], []
    f.judgment = "PASS"

    class Reply:
        status = 200

        def __init__(self, raw):
            self.raw = raw

        def getheader(self, name, default=None):
            return default

        def read(self, bound):
            assert len(self.raw) <= bound
            return self.raw

    class ModelHTTP:
        def __init__(self, host, port, timeout):
            assert (host, port) == ("127.0.0.1", 11434) and timeout > 0

        def request(self, method, path, body=None, headers=None):
            self.method, self.path, self.body = method, path, body

        def getresponse(self):
            if self.path == "/api/version":
                return Reply(canonical_bytes({"version": "0.35.1"}))
            if self.path == "/api/tags":
                return Reply(
                    canonical_bytes({"models": [{"name": wire.MODEL, "digest": installed[2]}]})
                )
            if self.path == "/api/show":
                return Reply(canonical_bytes({"details": {"family": "qwen"}}))
            assert (self.method, self.path) == ("POST", "/api/chat")
            assert f.active == {"canonical": 0, "admin": 0}
            body = json.loads(self.body)
            is_review = body["format"].get("title") == "FragmentReviewJudgments"
            f.host_posts.append("REVIEW" if is_review else "GENERATION")
            if is_review:
                content = {
                    "format": "zac-history-fragment-review-judgments-v1",
                    "assessments": [
                        {"criterion": criterion.value, "judgment": f.judgment}
                        for criterion in ContextualCriterion
                    ],
                }
                count = f.review_counter.count_prompt_tokens(self.body)
            else:
                assert self.body == f.q.prompt_body.encode()
                catalog = generation._prepare_contextual_catalog(f.q.context())
                content = {
                    "format": "zac-contextual-draft-v2",
                    "overview": [
                        {
                            "text": "Historical fragment is dated evidence, not current truth.",
                            "evidence_ids": [catalog.quotes[0][0]],
                            "inferred": False,
                        }
                    ],
                    "background": [],
                    "continuity": [],
                    "items": [],
                    "conflicts": [],
                    "clarifications": [],
                }
                count = counter.count_prompt_tokens(self.body)
            return Reply(
                canonical_bytes(
                    {
                        "model": wire.MODEL,
                        "done": True,
                        "done_reason": "stop",
                        "message": {"role": "assistant", "content": json.dumps(content)},
                        "prompt_eval_count": count,
                        "eval_count": 100,
                    }
                )
            )

        def close(self):
            pass

    monkeypatch.setattr(http.client, "HTTPConnection", ModelHTTP)

    async def actual_host(request):
        try:
            result = f.controller.submit(request=request, body=await request.body())
            f.host_results.append(result)
            returned = f.controller.recheck_result(cookie=f.cookie, result=result)
            f.controller.scalar_response(returned)
            assert type(returned) is _RetainedFragmentTask
            return HTMLResponse(returned.html)
        except Exception as error:  # noqa: BLE001 - HTTP hold matches actual route; no repair
            f.host_errors.append(type(error).__name__)
            return Response("held; do not retry", status_code=503)

    with TestClient(
        Starlette(routes=[Route("/ask-caz-locally", actual_host, methods=["POST"])]),
        base_url=ORIGIN,
    ) as client:
        f.host_client = client
        yield f


def approve(f):
    from zacai.intelligence.fragment_review_declaration import (
        fragment_generation_review_declaration_digest,
    )

    current = f.sessions.peek_user(f.cookie, f.p._clock())
    assert current is not None
    return f.host_client.post(
        "/ask-caz-locally",
        headers={"Origin": ORIGIN, "Cookie": f"__Host-zac-session={f.cookie}"},
        data={
            "action": "approve_fragment_publication",
            "csrf": current.csrf,
            "publication_digest": fragment_generation_review_declaration_digest(f.d),
            "source_id": str(f.parent.reference.source_id),
        },
    )


@pytest.mark.parametrize("judgment", ["PASS", "UNREVIEWED"])
def test_actual_owner_task_reviewed_or_withheld(owner_task, judgment):
    f = owner_task
    f.judgment = judgment
    response = approve(f)
    assert f.host_posts == ["GENERATION", "REVIEW"]
    with f.p._factory() as session:
        ids = tuple(
            session.scalars(
                select(Source.id).where(
                    Source.external_ref.like(
                        f"personal-history-fragment-publication-assessment/{f.g.id}/%"
                    )
                )
            )
        )
    assert len(ids) == 1  # Real committed assessment even if answer remains held.
    if judgment == "UNREVIEWED":
        assert response.status_code == 503 and f.controller._task_result is None
        assert not f.host_results
    else:
        assert response.status_code == 200 and len(f.host_results) == 1
        result = f.host_results[0]
        assert result is f.controller._task_result
        assert result.authorization._generation._operation is f.p._operation
        assert result.assessment.reference.source_id == ids[0]
        hashes = dict(result.assessment.recovery_receipt.full_boundary_source_hashes)
        assert result.assessment.reference.source_id in hashes
        assert result.authorization._generation._admission_reference.source_id in hashes
        assert (
            result.authorization._generation._associated_result.association_reference.source_id
            in hashes
        )
        assert "Reviewed reply" in response.text
    assert approve(f).status_code == 503
    assert f.host_posts == ["GENERATION", "REVIEW"]  # No retry or second generation.


def test_actual_original_operation_substitution_holds(owner_task):
    f = owner_task
    response = approve(f)
    assert response.status_code == 200
    result = f.host_results[0]
    original = f.p._operation
    replacement = f.continuity.for_cookie(f.cookie)
    assert replacement is not original and replacement.establish() == original.establish()
    f.p._operation = replacement
    with pytest.raises(
        (
            contextual_protection.ContextualProtectionError,
            publication_review.FragmentPublicationReviewError,
            FragmentPublicationWebError,
            ValueError,
        )
    ):
        f.controller.recheck_result(cookie=f.cookie, result=result)
    assert f.host_posts == ["GENERATION", "REVIEW"]


def test_actual_terminal_parent_lock_delay_expiry_holds(owner_task, monkeypatch):
    f = owner_task
    response = approve(f)
    assert response.status_code == 200
    result = f.host_results[0]
    deadline = result.authorization._deadline_monotonic
    assert deadline is not None and time.monotonic() < deadline
    # Independent real transaction: does not count another thread's canonical
    # lease as a lease on the signed-owner calling thread.
    lock_engine = create_engine(f.p._engine.url)
    entered = Event()
    waiter_pid = Queue()
    real_lock = review_authorization._lock

    def observed_lock(session, approval_id):
        assert approval_id == f.g.id
        waiter_pid.put(session.scalar(text("SELECT pg_backend_pid()")))
        real_lock(session, approval_id)

    monkeypatch.setattr(review_authorization, "_lock", observed_lock)
    with ThreadPoolExecutor(max_workers=1) as pool, lock_engine.connect() as connection:
        transaction = connection.begin()
        holder_pid = connection.scalar(text("SELECT pg_backend_pid()"))
        connection.execute(
            text("SELECT pg_advisory_xact_lock(:key)"), {"key": f.g.id.int % 2**63}
        )

        def release_check():
            entered.set()
            f.controller.scalar_response(result)

        future = pool.submit(release_check)
        assert entered.wait(5)
        try:
            pid = waiter_pid.get(timeout=5)
        except Empty:
            if future.done():
                future.result()
            raise AssertionError("terminal did not reach actual lock") from None
        observed_wait = False
        wait_deadline = time.monotonic() + 5
        # A third independent engine connection observes the actual matching
        # PostgreSQL lock, not a thread-start event presented as a lock.
        while time.monotonic() < wait_deadline:
            with lock_engine.connect() as observer:
                locks = observer.execute(
                    text(
                        "SELECT pid,classid,objid,objsubid,granted FROM pg_locks "
                        "WHERE locktype='advisory' AND pid IN (:holder,:waiter)"
                    ),
                    {"holder": holder_pid, "waiter": pid},
                ).all()
            held = [row for row in locks if row.pid == holder_pid and row.granted]
            waiting = [row for row in locks if row.pid == pid and not row.granted]
            if any(tuple(a)[1:4] == tuple(b)[1:4] for a in held for b in waiting):
                observed_wait = True
                break
            if future.done():
                future.result()
            time.sleep(0.01)
        assert observed_wait, "actual matching parent advisory lock required"
        # Original fixed reviewer window is never extended or shortened.
        while time.monotonic() <= deadline:
            assert not future.done()
            time.sleep(min(0.1, max(0.001, deadline - time.monotonic())))
        transaction.commit()
        with pytest.raises(ValueError) as refusal:
            future.result(timeout=10)
        assert type(refusal.value) is ValueError
        assert str(refusal.value) == "original reviewer interval exhausted"
    lock_engine.dispose()
    assert f.host_posts == ["GENERATION", "REVIEW"]
