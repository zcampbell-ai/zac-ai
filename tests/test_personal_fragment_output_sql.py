"""Root-only genuine output retention/recovery with invented attendance and text.

Only model metadata and one loopback response are mocked. Actual canonical
capture/commit/reopen, signed owner/cookie, tokenizer count, issuer, independent
age identity, encrypted artifacts and full disposable State/journal are real.
No human processing consent, model quality or authenticated review is inferred.
"""

import json
from dataclasses import replace
from uuid import UUID

import pytest
from sqlalchemy import select

from tests.test_personal_fragment_claim_issuer_sql import (
    exact_issuer_qwen_profile as exact_issuer_qwen_profile,  # noqa: PLC0414
)
from tests.test_personal_fragment_claim_issuer_sql import (
    installed as installed,  # noqa: PLC0414
)
from tests.test_personal_fragment_claim_issuer_sql import (
    issuer_case as issuer_case,  # noqa: PLC0414
)
from tests.test_personal_fragment_protection_sql import (
    actual_case as actual_case,  # noqa: PLC0414
)
from tests.test_personal_fragment_protection_sql import assert_balanced_restoration_leases
from tests.test_personal_fragment_protection_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from zacai import contextual_protection as protection
from zacai.backup_artifacts import prepare_personal_encrypted_custody_backup_plan
from zacai.ingestion.artifact_store import content_hash_of
from zacai.intelligence import contextual_generation as generation
from zacai.intelligence import local_contextual_runtime as local
from zacai.intelligence import personal_fragment_output as output
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source


@pytest.fixture(autouse=True)
def original_fixture_budget(monkeypatch):
    import tests.personal_fragment_sql_support as support

    original = support.__dict__["base"]

    def declared():
        value = original()
        return replace(value, task=value.task.model_copy(update={"max_latency_ms": 300000}))

    # This is declared before genuine_packet builds and canonically captures
    # request/body/provenance. No captured request or production clock is patched.
    monkeypatch.setattr(support, "base", declared)


def output_rows(f):
    with f.p._factory() as session:
        return tuple(
            session.execute(
                select(Source.id, Source.content_hash).where(
                    Source.external_ref.like("history-fragment-contextual-packet/%")
                )
            ).all()
        )


@pytest.fixture
def released(issuer_case, monkeypatch):
    f = issuer_case
    f.posts = []
    f.original_rows = output_rows(f)
    counter = f.runtime._token_counter
    monkeypatch.setattr(counter, "verify_runtime", lambda: None)
    monkeypatch.setattr(local, "verify_model", lambda *args: None)

    def mock_loopback(body, remaining):
        assert f.active == {"canonical": 0, "admin": 0}
        assert f.gate._phase == "DISPATCHED"
        assert body == f.q.prompt_body.encode() and 0 < remaining <= 300
        f.posts.append(body)
        catalog = generation._prepare_contextual_catalog(f.q.context())
        draft = {
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
        return {
            "model": f.q.route.identity.model_id,
            "done": True,
            "done_reason": "stop",
            "message": {"role": "assistant", "content": json.dumps(draft)},
            "prompt_eval_count": counter.count_prompt_tokens(body),
            "eval_count": 100,
        }

    monkeypatch.setattr(local, "_fragment_http_post", mock_loopback)
    f.runtime.preflight_fragment(f.q)
    f.draft = f.runtime.generate_fragment(f.q)
    assert f.gate._phase == "RELEASED" and f.runtime.did_transport_attempt
    assert f.posts == [f.q.prompt_body.encode()]
    f.claim_receipt = f.gate._receipt
    return f


def retain(f, draft=None):
    return output.retain_personal_history_fragment_output(
        f.gate, runtime=f.runtime, request=f.q, draft=f.draft if draft is None else draft
    )


def test_actual_output_retained_needs_review_fresh_full_union(released):
    f = released
    result = retain(f)
    assert f.gate._phase == "OUTPUT_RETAINED" and result.outcome == "NEEDS_REVIEW"
    assert result.authenticated_review is result.delivered is False
    assert result.packet.request() == f.q and result.usage == f.runtime.usage
    assert result.packet.review.overview[0].quotes
    with f.p._factory() as session:
        plan = prepare_personal_encrypted_custody_backup_plan(session)
    assert content_hash_of(plan.rows) == result.recovery_receipt.full_plan_digest
    assert dict(result.recovery_receipt.full_boundary_source_hashes) == {
        UUID(row["id"]): row["content_hash"] for row in json.loads(plan.rows)
    }
    refs = result.recovery_receipt.selected_references
    assert f.own not in refs and f.gate._claim_reference not in refs
    full_hashes = dict(result.recovery_receipt.full_boundary_source_hashes)
    full_fingerprints = dict(result.recovery_receipt.full_boundary_source_fingerprints)
    for reference in (f.own, f.gate._claim_reference):
        assert full_hashes[reference.source_id] == reference.content_hash
        assert reference.source_id in full_fingerprints
    assert result.source_id == result.recovery_receipt.packet_reference.source_id
    assert len(output_rows(f)) == len(f.original_rows) + 1
    assert f.claim_receipt.full_plan_digest != result.recovery_receipt.full_plan_digest
    with pytest.raises(protection.ContextualProtectionError):
        f.p.recheck_claim(
            reference=f.gate._claim_reference,
            expected_claim=f.gate._claim,
            expected_consent=f.c,
            expected_request=f.q,
        )
    reopened = f.make("output-independent-cold").recheck(
        source_id=result.source_id, expected_digest=result.packet_digest, expected_request=f.q
    )
    assert reopened == result.recovery_receipt
    assert f.active == {"canonical": 0, "admin": 0}
    assert_balanced_restoration_leases(f.leases, expected_restorations=6)
    with pytest.raises(output.PersonalFragmentOutputError):
        retain(f)
    assert f.posts == [f.q.prompt_body.encode()]


def test_actual_fabricated_released_draft_before_writes(released, monkeypatch):
    f = released
    fired = []

    def forbidden(*args, **kwargs):
        fired.append("capture")
        raise AssertionError("fabricated draft cannot enter capture")

    monkeypatch.setattr(output, "capture_history_fragment_contextual_packet", forbidden)
    raw = f.draft.model_dump(mode="json")
    raw["overview"][0]["text"] = "Invented fabricated released overview."
    fake = generation.ContextualDraft.model_validate(raw)
    assert fake != f.draft
    with pytest.raises(output.PersonalFragmentOutputError):
        retain(f, fake)
    assert not fired and f.gate._phase == "OUTPUT_HELD"
    assert output_rows(f) == f.original_rows and len(f.posts) == 1


def test_actual_output_commit_survives_protection_failure_no_repair(released, monkeypatch):
    f = released
    milestones = []

    def failed(**kwargs):
        assert f.active == {"canonical": 0, "admin": 0}
        assert (kwargs["source_id"], kwargs["expected_digest"]) in output_rows(f)
        milestones.append("independently-visible-output-commit-before-protect")
        raise RuntimeError("invented protection failure")

    monkeypatch.setattr(f.p, "protect", failed)
    with pytest.raises(output.PersonalFragmentOutputError):
        retain(f)
    assert milestones == ["independently-visible-output-commit-before-protect"]
    rows = output_rows(f)
    assert len(rows) == len(f.original_rows) + 1 and f.gate._phase == "OUTPUT_HELD"
    with pytest.raises(output.PersonalFragmentOutputError):
        retain(f)
    assert output_rows(f) == rows and len(milestones) == 1 and len(f.posts) == 1


@pytest.mark.parametrize("fault", ["cookie-revoke", "state-cipher-corruption"])
def test_actual_final_output_restore_mutation_withholds(released, monkeypatch, fault):
    f = released
    actual = DisposableStateRestoreVerifier.verify_personal
    milestones = []

    def changed(verifier, *args, **kwargs):
        value = actual(verifier, *args, **kwargs)
        assert f.gate._phase == "OUTPUT_ENTERED"
        assert f.active == {"canonical": 0, "admin": 0}
        new_rows = set(output_rows(f)) - set(f.original_rows)
        assert len(new_rows) == 1
        sid, _digest = next(iter(new_rows))
        milestones.append("actual-output-restore-complete-and-source-committed")
        if fault == "cookie-revoke":
            f.sessions.revoke(f.cookie)
            milestones.append("original-signed-cookie-revoked")
        else:
            paths = tuple(
                f.writer._path(f"PERSONAL/state/history-fragment-{sid}").glob("state-*.age")
            )
            assert len(paths) == 1
            before = content_hash_of(paths[0].read_bytes())
            paths[0].write_bytes(b"invented tampered encrypted State")
            assert content_hash_of(paths[0].read_bytes()) != before
            milestones.append("encrypted-output-state-changed-after-real-restore")
        return value

    monkeypatch.setattr(DisposableStateRestoreVerifier, "verify_personal", changed)
    with pytest.raises(output.PersonalFragmentOutputError):
        retain(f)
    assert milestones == [
        "actual-output-restore-complete-and-source-committed",
        "original-signed-cookie-revoked"
        if fault == "cookie-revoke"
        else "encrypted-output-state-changed-after-real-restore",
    ]
    assert f.gate._phase == "OUTPUT_HELD" and len(output_rows(f)) == len(f.original_rows) + 1
    assert f.active == {"canonical": 0, "admin": 0} and len(f.posts) == 1
