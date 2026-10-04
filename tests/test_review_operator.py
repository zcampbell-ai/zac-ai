"""All concrete adapters together; invented state, age keys and in-process model."""

import json
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlalchemy import select

from tests import test_review_recovery as recovery_tests
from tests.test_review_host import NOW
from tests.test_review_recovery import scope_for
from zacai import backup_artifacts
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import local_review_runtime
from zacai.intelligence.review_generation import DraftClaim, ReviewDraft
from zacai.intelligence.review_host import ReviewHostError
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import record_review_consent
from zacai.review_operator import BrainstormReviewOperator, ReviewOperatorError
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source


class Counter:
    model_digest = "a" * 64

    def count_prompt_tokens(self, body):
        assert json.loads(body)["messages"][1]["content"]
        return 19

    def verify_runtime(self):
        pass


recovered_state = recovery_tests.recovery


@pytest.fixture
def complete(recovered_state, tmp_path, monkeypatch):
    issued, _, point, reader, writer, identity, receipt, _ = recovered_state
    factory, store, captured, _ = issued[0]
    with factory() as session:
        baseline = set(session.scalars(select(Source.id)))
    own = {captured.account_source_id, captured.raw_source_id, captured.normalized_source_id}

    # Other tests committed fixtures in different ephemeral artifact roots. Only
    # exclude those unrelated roots; production has no such fixture-only filter.
    def rows(session, *, trust_boundary):
        return [
            (h, loc)
            for sid, h, loc in session.execute(
                select(Source.id, Source.content_hash, Source.content_location).where(
                    Source.trust_boundary == trust_boundary,
                    Source.content_hash.is_not(None),
                )
            )
            if sid not in baseline or sid in own
        ]

    monkeypatch.setattr(backup_artifacts, "_source_rows_for_boundary", rows)
    scope = scope_for(issued[1], point)
    with factory() as session:
        approval = record_review_consent(session, store=store, consent=scope)
        session.commit()
    clock = [NOW]
    restoration = DisposableStateRestoreVerifier()
    original_verify = restoration.verify
    restored = []

    def verify(*args, **kwargs):
        original_verify(*args, **kwargs)
        restored.append((content_hash_of(args[0]), calls.count("/api/chat")))

    monkeypatch.setattr(restoration, "verify", verify)
    options = {
        "factory": factory,
        "engine": factory.kw["bind"],
        "artifacts": store,
        "objects": writer,
        "verification_objects": reader,
        "recipient": writer.recipient,
        "identity_path": identity,
        "recovered_key_receipt": receipt,
        "checkpoint": point,
        "manifest_cache": tmp_path / "manifest.cache",
        "approval_id": approval,
        "route": scope.route,
        "model_digest": scope.model_digest,
        "token_counter": Counter(),
        "restoration": restoration,
        "clock": lambda: clock[0],
    }
    calls = []
    behavior = {"bad_usage": False, "callback": None, "owned_sources": own}

    def http(method, path, body=None):
        calls.append(path)
        if path == "/api/tags":
            return {
                "models": [{"name": scope.route.identity.model_id, "digest": scope.model_digest}]
            }
        if path == "/api/show":
            return {}
        assert path == "/api/chat"
        # Before first model dispatch, all three recovery checks passed and the
        # canonical dispatch audit is visible through an independent connection.
        assert len(restored) == 3
        with factory() as session:
            sources = session.scalars(
                select(Source).where(
                    Source.external_ref.startswith("meeting-review-audit/"),
                    Source.id.not_in(baseline),
                )
            ).all()
            assert any(
                json.loads(store.get(B.BRAINSTORM, s.content_location))["stage"]
                == "DISPATCH_STARTED"
                for s in sources
            )
        if behavior["callback"]:
            behavior["callback"]()
        draft = ReviewDraft(
            summary=(
                DraftClaim(text="The reporting fix is still being tested.", evidence_ids=("e1",)),
            )
        )
        return {
            "model": scope.route.identity.model_id,
            "done": True,
            "done_reason": "stop",
            "message": {"role": "assistant", "content": draft.model_dump_json()},
            "prompt_eval_count": 20 if behavior["bad_usage"] else 19,
            "eval_count": 12,
        }

    monkeypatch.setattr(local_review_runtime, "_http", http)
    return options, scope.selection, calls, behavior, restored, clock


def assert_claimed(options):
    with options["factory"]() as session:
        rows = session.scalars(
            select(Source).where(Source.external_ref == f"review-claim/{options['approval_id']}")
        ).all()
        assert len(rows) == 1
        body = json.loads(options["artifacts"].get(B.BRAINSTORM, rows[0].content_location))
        assert body["format"] == "zac-review-claim-v1"
        assert body["approval_id"] == str(options["approval_id"])


def test_full_concrete_operator_recovers_audits_and_returns_one_unevaluated_draft(complete):
    options, selection, calls, _, restored, _ = complete
    operator = BrainstormReviewOperator(**options)
    result = operator.execute(selection)
    assert result.review.summary
    assert len(result.audit_source_ids) == 3
    assert calls.count("/api/chat") == 1
    # preflight, claim and pre-dispatch recovery occur before generation. After
    # generation: authority recheck, post-run protection, final authority recheck.
    original = options["checkpoint"].plaintext_hash
    assert [item[1] for item in restored] == [0, 0, 0, 1, 1, 1]
    assert [item[0] for item in restored[:4]] == [original] * 4
    assert restored[4][0] != original  # full post-run authority/audit snapshot
    assert restored[5][0] == original
    with options["factory"]() as session:
        assert all(session.get(Source, sid) is not None for sid in result.audit_source_ids)
    assert not hasattr(result, "approved")
    with pytest.raises(ReviewOperatorError, match="already consumed"):
        operator.execute(selection)
    assert_claimed(options)
    before = len(restored)
    with pytest.raises(ReviewHostError, match="no draft released"):
        BrainstormReviewOperator(**options).execute(selection)
    assert len(restored) == before
    assert_claimed(options)
    assert calls.count("/api/chat") == 1


@pytest.mark.parametrize("failure", ["state", "authority", "tokenizer", "route", "model_pin"])
def test_failure_before_dispatch_never_calls_model(complete, failure):
    options, selection, calls, _, restored, _ = complete
    if failure == "state":
        options["objects"].put_object(options["checkpoint"].state_object, b"invented corrupt state")
    elif failure == "authority":
        options["approval_id"] = uuid4()
    elif failure == "tokenizer":
        options["token_counter"].model_digest = "b" * 64
    elif failure == "route":
        raw = options["route"].model_dump()
        raw["identity"]["model_id"] = "other:fixture"
        options["route"] = options["route"].model_validate(raw)
    else:
        options["model_digest"] = "b" * 64
        options["token_counter"].model_digest = "b" * 64
    exception = ReviewOperatorError if failure == "tokenizer" else ReviewHostError
    message = "configuration rejected" if failure == "tokenizer" else "no draft released"
    with pytest.raises(exception, match=message):
        BrainstormReviewOperator(**options).execute(selection)
    assert not restored and "/api/chat" not in calls
    if failure in ("route", "model_pin"):
        assert "/api/tags" not in calls  # canonical binding denies before runtime checks


def test_bad_runtime_usage_consumes_authority_without_draft_or_retry(complete):
    options, selection, calls, behavior, restored, _ = complete
    behavior["bad_usage"] = True
    with pytest.raises(ReviewHostError, match="no draft released"):
        BrainstormReviewOperator(**options).execute(selection)
    assert_claimed(options)
    before = len(restored)
    with pytest.raises(ReviewHostError, match="no draft released"):
        BrainstormReviewOperator(**options).execute(selection)
    assert len(restored) == before
    assert_claimed(options)
    assert calls.count("/api/chat") == 1


def test_post_run_remote_corruption_never_releases_generated_draft(complete, monkeypatch):
    options, selection, calls, _, _, _ = complete
    reader = options["verification_objects"]
    original = reader.get_object

    def get(key):
        if "/state/review-" in key:
            return b"invented post-run corruption"
        return original(key)

    monkeypatch.setattr(reader, "get_object", get)
    with pytest.raises(ReviewHostError, match="no draft released"):
        BrainstormReviewOperator(**options).execute(selection)
    assert calls.count("/api/chat") == 1
    assert_claimed(options)
    before = len(calls)
    with pytest.raises(ReviewHostError, match="no draft released"):
        BrainstormReviewOperator(**options).execute(selection)
    assert len(calls) == before


def test_recovery_time_does_not_silently_extend_request_lifetime(complete, monkeypatch):
    options, selection, calls, _, _, clock = complete
    verifier = options["restoration"]
    original = verifier.verify
    count = 0

    def verify(*a, **kw):
        nonlocal count
        original(*a, **kw)
        count += 1
        if count == 2:
            clock[0] += timedelta(seconds=121)

    monkeypatch.setattr(verifier, "verify", verify)
    with pytest.raises(ReviewHostError, match="no draft released"):
        BrainstormReviewOperator(**options).execute(selection)
    assert "/api/chat" not in calls


@pytest.mark.parametrize("failure", ["database", "schema"])
def test_wrong_connected_target_stops_before_host_actions(complete, failure):
    options, selection, calls, _, restored, _ = complete
    # A different actual database is a configuration failure, not a private host
    # attempt; it must not read selected context, journal or contact any model.
    engine = options["engine"]
    from sqlalchemy import event

    def replace(conn, cursor, statement, parameters, context, executemany):
        if failure == "schema" and "SELECT version_num FROM public.alembic_version" in statement:
            return "SELECT '0004'", parameters
        if failure == "database" and "pg_catalog.current_database()" in statement:
            return "SELECT 'wrong', 5432, '127.0.0.1'", parameters
        return statement, parameters

    event.listen(engine, "before_cursor_execute", replace, retval=True)
    try:
        with pytest.raises(ReviewOperatorError, match="target rejected"):
            BrainstormReviewOperator(**options).execute(selection)
    finally:
        event.remove(engine, "before_cursor_execute", replace)
    assert not calls and not restored


def test_confirmed_project_context_through_all_concrete_adapters(complete):
    from tests import test_project_review_context as projects
    from tests.test_review_recovery import checkpoint, export
    from zacai.backup_artifacts import age_encrypt, backup_object_key_for
    from zacai.intelligence.project_review_context import (
        ReviewedProjectEvidence,
        assemble_project_review_context,
    )
    from zacai.intelligence.review_generation import prepare_review_request
    from zacai.intelligence.review_host import ReviewSelection
    from zacai.policy import DataClassification as C
    from zacai.review_authorization import ReviewConsent, prepared_review_digest

    options, selection, calls, behavior, restored, _ = complete
    factory, store, objects = options["factory"], options["artifacts"], options["objects"]
    with factory() as session:
        company = projects._make_company(session)
        brief = projects._source(session, store, projects.BRIEF)
        confirmation = projects._source(
            session, store, "Invented operator confirms this meeting's project."
        )
        project = projects._project(session, company, brief)
        link = projects._link(session, project, selection.selected, confirmation)
        session.commit()
        behavior["owned_sources"].update({brief.id, confirmation.id})
        for source in (brief, confirmation):
            objects.put_object(
                backup_object_key_for(B.BRAINSTORM, source.content_hash),
                age_encrypt(store.get(B.BRAINSTORM, source.content_location), objects.recipient),
            )
        selection = ReviewSelection(
            selection.selected, projects=(ReviewedProjectEvidence(link.id, brief.id),)
        )
        context = assemble_project_review_context(
            session,
            artifacts=store,
            selected=selection.selected,
            projects=selection.projects,
            authorized_boundaries=frozenset({B.BRAINSTORM}),
            allowed_classifications=frozenset({C.CONFIDENTIAL}),
            observed_at=NOW,
        )
        original = session.get(Source, options["approval_id"])
        consent = ReviewConsent.model_validate_json(
            store.get(B.BRAINSTORM, original.content_location)
        )
        brief_id, project_id = brief.id, project.entity_id
    point = checkpoint(objects, export(factory), options["checkpoint"].recovered_key_receipt_hash)
    scope = scope_for(consent, point).model_copy(
        update={
            "selection": selection,
            "prepared_digest": prepared_review_digest(prepare_review_request(context)),
        }
    )
    with factory() as session:
        approval = record_review_consent(session, store=store, consent=scope)
        session.commit()
    options.update(approval_id=approval, checkpoint=point)
    result = BrainstormReviewOperator(**options).execute(selection)
    assert brief_id in result.context.related_source_ids
    assert any(
        e.entity_type == "Project" and e.entity_id == project_id
        for e in result.context.task.event.related_entities
    )
    assert calls.count("/api/chat") == 1 and len(restored) == 6


def test_concurrent_calls_share_one_operator_attempt(complete):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier

    options, selection, calls, _, _, _ = complete
    operator = BrainstormReviewOperator(**options)
    start = Barrier(2)

    def execute():
        start.wait(timeout=5)
        try:
            return operator.execute(selection)
        except ReviewOperatorError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(execute), pool.submit(execute)]
        results = [future.result(timeout=30) for future in futures]
    assert sum(isinstance(result, ReviewOperatorError) for result in results) == 1
    assert any(getattr(result, "review", None) for result in results)
    assert calls.count("/api/chat") == 1
    assert_claimed(options)


def test_tokenizer_pin_changed_after_construction_denies_before_runtime_dispatch(complete):
    options, selection, calls, _, _, _ = complete
    operator = BrainstormReviewOperator(**options)
    options["token_counter"].model_digest = "b" * 64
    with pytest.raises(ReviewHostError, match="no draft released"):
        operator.execute(selection)
    assert not calls
