"""Real codecs/files/runtime construction, simulated SQL/owner/crypto/transport.

No model, canonical action, PostgreSQL or genuine recovered protection is proven.
"""

# ruff: noqa: PLC0414
import json
from dataclasses import replace
from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_fragment_review_declaration import declaration_case as declaration_case
from tests.test_personal_fragment_claim_issuer import (
    authority as baseline_authority,  # noqa: F401
)
from tests.test_personal_fragment_claim_issuer import (
    case as case,
)
from tests.test_personal_fragment_claim_issuer import (
    consent_case as consent_case,
)
from tests.test_personal_fragment_claim_issuer import (
    installed as installed,
)
from tests.test_personal_fragment_claim_issuer import (
    issuer as issuer,
)
from tests.test_personal_fragment_claim_issuer import (
    packet_case as packet_case,
)
from zacai import contextual_protection as protection
from zacai import review_authorization, state_repository
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence import contextual_generation as generation
from zacai.intelligence import fragment_publication_generation as m
from zacai.intelligence.contracts import EvidenceReference, UsageObservation
from zacai.intelligence.fragment_review_declaration import (
    prepare_fragment_generation_review_declaration,
)
from zacai.intelligence.history_fragment_contextual_codec import (
    decode_history_fragment_contextual_packet,
)
from zacai.intelligence.local_contextual_runtime import FragmentLocalContextualRuntime
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import ArtifactBackupRunStatus, SourceSystem


@pytest.fixture
def authority(baseline_authority, installed):  # noqa: F811
    # Fix candidate route BEFORE canonical consent/issuer construction; real counter.
    from zacai.intelligence import history_fragment_contextual_codec as codec
    from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter

    f = baseline_authority
    route = f.q.route.model_copy(
        update={"identity": f.q.route.identity.model_copy(update={"model_id": "qwen3.8:27b-mlx"})}
    )
    body = codec._body(
        f.q.context(), codec._profile(f.q.profile_json, f.q.observation), f.q.observation, route
    )
    f.q = codec.HistoryFragmentContextualRequestV1.model_validate(
        {
            **f.q.model_dump(),
            "route": route,
            "prompt_body": body.decode(),
            "prompt_digest": content_hash_of(body),
        }
    )
    counter = OllamaQwenContextualTokenCounter(models_root=installed[0], model_digest=installed[2])
    f.consent = m.auth.HistoryFragmentConsentV1.model_validate(
        {
            **f.consent.model_dump(),
            "route": route,
            "request_digest": content_hash_of(
                codec.encode_history_fragment_contextual_request(f.q)
            ),
            "body_digest": content_hash_of(body),
            "prompt_tokens": counter.count_prompt_tokens(body),
        }
    )
    return f


@pytest.fixture
def publication_issuer(issuer, declaration_case, monkeypatch):
    f = issuer
    _, _, profile = declaration_case
    d = prepare_fragment_generation_review_declaration(f.consent, f.q, review=profile)
    pubraw = m._parts(d)[0]
    pub = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(pubraw),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    c = f.consent
    a = m.FragmentPublicationAdmissionV1(
        publication_reference=pub,
        publication_digest=m.fragment_generation_review_declaration_digest(d),
        generation_id=c.id,
        task_id=c.task_id,
        builder_id=c.builder_id,
        request_digest=c.request_digest,
        review_profile_digest=d.review_profile_digest,
        actor_issuer=c.owner_issuer,
        actor_subject=c.owner_subject,
        original_session_binding=c.original_session_binding,
        original_session_issued_at=c.original_session_issued_at,
        original_session_expires_at=c.original_session_expires_at,
        original_approved_at=c.approved_at,
        expires_at=c.expires_at,
        observed_action_at=c.approved_at,
    )
    araw = m.encode_fragment_publication_admission(a)
    ref = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(araw),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    f.rows = {
        r.source_id: {
            "id": r.source_id,
            "content_hash": r.content_hash,
            "content_location": "invented",
        }
        for r in c.provenance
    }
    for r, raw, system, namespace, at in [
        (pub, pubraw, SourceSystem.MANUAL, "publication", c.approved_at),
        (ref, araw, SourceSystem.USER_INSTRUCTION, "admission", a.observed_action_at),
    ]:
        loc = f.p._artifacts.put(B.PERSONAL, r.content_hash, raw)
        f.rows[r.source_id] = {
            "id": r.source_id,
            "content_hash": r.content_hash,
            "content_location": loc,
            "system": system,
            "external_ref": namespace,
            "supersedes_source_id": None,
            "captured_at": at,
            "lineage_id": r.source_id,
        }
    f.withdrawn = False
    f.extra_claim = False

    def rows(s, refs, *args):
        assert all(f.rows[r.source_id]["content_hash"] == r.content_hash for r in refs)
        return tuple(tuple(f.rows[r.source_id].items()) for r in refs)

    def ids(s, prefix, system=SourceSystem.USER_INSTRUCTION):
        if prefix.startswith("personal-history-fragment-declaration"):
            return (pub.source_id,)
        if prefix.startswith("personal-history-fragment-claim"):
            return (
                (uuid4(),)
                if f.extra_claim
                else tuple(
                    v.id
                    for v in (*f.ledger, *f.pending)
                    if f.rows[v.id]["external_ref"].startswith("personal-history-fragment-claim/")
                )
            )
        if prefix.startswith("personal-history-fragment-publication-output/"):
            return tuple(
                v.id
                for v in (*f.ledger, *f.pending)
                if f.rows[v.id]["external_ref"].startswith(prefix)
            )
        return (ref.source_id,)

    def active(*args, **kwargs):
        if f.withdrawn:
            raise ValueError("invented committed withdrawal")

    monkeypatch.setattr(m, "_fragment_rows", rows)
    monkeypatch.setattr(m, "_fragment_profile_lineage", lambda *a: None)
    monkeypatch.setattr(m, "_ids", ids)
    monkeypatch.setattr(m, "assert_fragment_publication_not_withdrawn", active)
    monkeypatch.setattr(m, "_physical", lambda s: ("simulated", None, None, None))
    monkeypatch.setattr(m, "_same", lambda *a: None)
    monkeypatch.setattr(m, "load_fragment_publication_admission", lambda *a, **kw: None)
    monkeypatch.setattr(
        m.CanonicalPersonalFragmentPublicationAuthorization,
        "_physical_transaction",
        lambda *a: ("simulated", None, None, None),
    )
    monkeypatch.setattr(
        m.CanonicalPersonalFragmentPublicationAuthorization,
        "_same_physical_transaction",
        lambda *a: None,
    )
    monkeypatch.setattr(review_authorization, "_lock", lambda *a: f.events.append("parent-lock"))

    def record(session, **kwargs):
        f.events.append("record")
        raw = f.p._artifacts.get_bounded(B.PERSONAL, kwargs["content_location"], max_bytes=16000)
        if kwargs["external_ref"].startswith("personal-history-fragment-publication-output/"):
            association = m.decode_fragment_publication_output_association(raw)
            assert kwargs["external_ref"] == m._association_namespace(association)
        else:
            claim = m.decode_fragment_publication_claim(raw)
            assert kwargs["external_ref"] == m._claim_namespace(claim)
            assert kwargs["external_ref"].startswith(m._claim_prefix(c.id))
        source = SimpleNamespace(id=uuid4(), supersedes_source_id=None)
        f.pending.append(source)
        f.rows[source.id] = dict(
            kwargs, id=source.id, supersedes_source_id=None, lineage_id=source.id
        )
        rows = json.loads(f.current_plan["value"].rows)
        rows.append({"id": str(source.id), "content_hash": kwargs["content_hash"]})
        f.current_plan["value"] = replace(f.plan, rows=canonical_bytes(rows))
        return source, True

    monkeypatch.setattr(state_repository, "record_source", record)
    monkeypatch.setattr(
        m,
        "run_artifact_backup",
        lambda *a, **kw: (
            f.events.append("backup")
            or SimpleNamespace(id=f.run, status=ArtifactBackupRunStatus.SUCCEEDED)
        ),
    )
    f.plan = replace(
        f.plan,
        rows=canonical_bytes(
            [{"id": str(sid), "content_hash": r["content_hash"]} for sid, r in f.rows.items()]
        ),
    )
    f.current_plan["value"] = f.plan

    def admission_checkpoint(**kw):
        # Concrete producer mocked at its declared SQL/native seam in this pure
        # fixture. New claim protector executes actual orchestration/codecs/files.
        refs = m._union(a, ref, d)
        rows = json.loads(f.plan.rows)
        return m.PersonalFragmentPublicationAdmissionReceiptV1(
            admission_reference=ref,
            admission_digest=ref.content_hash,
            observed_action_at=a.observed_action_at,
            publication_reference=pub,
            publication_digest=a.publication_digest,
            request_digest=c.request_digest,
            review_profile_digest=d.review_profile_digest,
            selected_references=refs,
            full_plan_digest=content_hash_of(f.plan.rows),
            full_boundary_source_hashes=tuple(
                sorted(
                    ((uuid_from(v["id"]), v["content_hash"]) for v in rows), key=lambda v: str(v[0])
                )
            ),
            full_boundary_source_fingerprints=tuple(
                sorted(
                    ((uuid_from(v["id"]), content_hash_of(canonical_bytes(v))) for v in rows),
                    key=lambda v: str(v[0]),
                )
            ),
            task_id=c.task_id,
            builder_id=c.builder_id,
            original_observed_at=f.q.observed_at,
            declared_window_started_at=c.approved_at,
            expires_at=c.expires_at,
            original_session_binding=c.original_session_binding,
            original_session_issued_at=c.original_session_issued_at,
            original_session_expires_at=c.original_session_expires_at,
            verified_at=f.p._clock(),
            artifact_backup_run_id=f.run,
            live_journal_digest=content_hash_of(f.p._run_row(f.run)),
            state_ciphertext_hash="1" * 64,
            state_plaintext_hash="2" * 64,
            journal_ciphertext_hash="3" * 64,
            journal_plaintext_hash="4" * 64,
        )

    monkeypatch.setattr(f.p, "recheck_publication_admission", admission_checkpoint)
    gate = m.CanonicalPersonalFragmentPublicationAuthorization(
        factory=f.p._factory,
        artifacts=f.p._artifacts,
        publication=d,
        admission_reference=ref,
        admission=a,
        request=f.q,
        protector=f.p,
        operation=f.p._operation,
        clock=f.p._clock,
    )
    runtime = FragmentLocalContextualRuntime(
        route=f.q.route,
        model_digest=c.model_digest,
        tokenizer_digest=c.tokenizer_digest,
        runtime_digest=c.runtime_digest,
        template_digest=c.template_digest,
        renderer_digest=c.renderer_digest,
        token_counter=f.runtime._token_counter,
        recheck=gate.recheck,
    )
    gate.bind_runtime(runtime)
    f.gate, f.runtime, f.d, f.admission, f.admission_ref, f.pub = gate, runtime, d, a, ref, pub
    f.events.clear()
    return f


def uuid_from(value):
    from uuid import UUID

    return UUID(value)


def pre(f):
    f.gate.recheck(f.q, f.descriptor)


def released(f):
    pre(f)
    catalog = generation._prepare_contextual_catalog(f.q.context())
    f.draft = generation.ContextualDraft.model_validate(
        {
            "format": "zac-contextual-draft-v2",
            "overview": [
                {
                    "text": "Dated literal evidence, incomplete context.",
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
    )
    usage = UsageObservation(input_tokens=f.consent.prompt_tokens, output_tokens=2, latency_ms=1)
    descriptor = replace(
        f.descriptor,
        phase="RELEASE",
        output_digest=content_hash_of(canonical_bytes(f.draft.model_dump(mode="json"))),
        usage_digest=content_hash_of(canonical_bytes(usage.model_dump(mode="json"))),
    )
    f.gate.recheck(f.q, descriptor)
    f.runtime._usage = usage
    f.runtime._attempted = True
    f.runtime._did_transport_attempt = True
    f.runtime._prepared = None


def test_claim_commit_new_recovery_release_once(publication_issuer):
    f = publication_issuer
    pre(f)
    assert f.gate._phase == "DISPATCHED" and len(f.ledger) == 1
    assert f.events.index("commit") < f.events.index("backup")
    assert f.gate._receipt.claim_reference == f.gate._claim_reference
    assert {f.pub, f.admission_ref, f.gate._claim_reference} <= set(
        f.gate._receipt.selected_references
    )
    assert (
        m.decode_fragment_publication_claim(m.encode_fragment_publication_claim(f.gate._claim))
        == f.gate._claim
    )
    old = list(f.events)
    with pytest.raises(m.FragmentPublicationGenerationError):
        pre(f)
    assert f.gate._phase == "HELD" and f.events == old


@pytest.mark.parametrize(
    "fault", ["withdrawal", "existing-legacy-claim", "commit", "restore", "owner"]
)
def test_failures_burn_and_no_repair(publication_issuer, monkeypatch, fault):
    f = publication_issuer
    if fault == "withdrawal":
        f.withdrawn = True
    elif fault == "existing-legacy-claim":
        f.extra_claim = True
    elif fault == "commit":
        f.commit_fault = True
    elif fault == "restore":
        monkeypatch.setattr(
            f.p._restoration,
            "verify_personal",
            lambda *a, **k: (_ for _ in ()).throw(ValueError("invented restore failure")),
        )
    else:
        f.owner["value"] = None
    with pytest.raises(m.FragmentPublicationGenerationError):
        pre(f)
    count = len(f.ledger)
    events = list(f.events)
    assert f.gate._phase == "HELD"
    with pytest.raises(m.FragmentPublicationGenerationError):
        pre(f)
    assert len(f.ledger) == count and f.events == events
    if fault in ["withdrawal", "existing-legacy-claim", "owner"]:
        assert count == 0
    else:
        assert count == 1


def test_withdrawal_after_recovery_before_post_holds(publication_issuer, monkeypatch):
    f = publication_issuer
    original = f.p._restoration.verify_personal
    milestones = []

    def cancel(*a, **kw):
        original(*a, **kw)
        f.withdrawn = True
        milestones.append("restore-completed-then-withdrawn")

    monkeypatch.setattr(f.p._restoration, "verify_personal", cancel)
    with pytest.raises(m.FragmentPublicationGenerationError):
        pre(f)
    assert milestones == ["restore-completed-then-withdrawn"] and len(f.ledger) == 1
    assert f.gate._phase == "HELD"


def test_release_after_separate_withdrawal_denied(publication_issuer):
    f = publication_issuer
    pre(f)
    f.withdrawn = True
    with pytest.raises(m.FragmentPublicationGenerationError):
        f.gate.recheck(
            f.q,
            replace(f.descriptor, phase="RELEASE", output_digest="8" * 64, usage_digest="9" * 64),
        )
    assert f.gate._phase == "HELD" and len(f.ledger) == 1


def test_full_output_new_checkpoint_contains_publication_admission_claim(
    publication_issuer, monkeypatch
):
    f = publication_issuer
    released(f)
    sid = uuid4()
    packet = [None]

    def capture(s, **kw):
        f.events.append("capture")
        packet[0] = decode_history_fragment_contextual_packet(kw["payload"])
        f.rows[sid] = {
            "id": sid,
            "content_hash": content_hash_of(kw["payload"]),
            "captured_at": packet[0].created_at,
        }
        rows = json.loads(f.current_plan["value"].rows)
        rows.append({"id": str(sid), "content_hash": content_hash_of(kw["payload"])})
        f.current_plan["value"] = replace(f.plan, rows=canonical_bytes(rows))
        return sid

    monkeypatch.setattr(m, "capture_history_fragment_contextual_packet", capture)
    monkeypatch.setattr(m, "load_history_fragment_contextual_packet", lambda *a, **kw: packet[0])
    monkeypatch.setattr(
        m, "prepare_personal_encrypted_custody_backup_plan", lambda s: f.current_plan["value"]
    )
    monkeypatch.setattr(f.p, "_packet", lambda *a: packet[0])
    # SQLAlchemy/psycopg transaction state is explicitly simulated in this fixture.
    monkeypatch.setattr(m, "_same_output_commit_transaction", lambda *a: None)
    old = f.gate._receipt
    result = m.retain_personal_fragment_publication_output(
        f.gate, runtime=f.runtime, request=f.q, draft=f.draft
    )
    hashes = dict(result.retained.recovery_receipt.full_boundary_source_hashes)
    assert {
        f.pub.source_id,
        f.admission_ref.source_id,
        f.gate._claim_reference.source_id,
        sid,
        result.association_reference.source_id,
    } <= hashes.keys()
    assert (
        result.retained.outcome.value == "NEEDS_REVIEW"
        and result.retained.authenticated_review is result.retained.delivered is False
    )
    assert result.association.packet_reference.source_id == sid
    assert result.association.claim_reference == f.gate._claim_reference
    assert result.association.output_digest == f.gate._released.output_digest
    assert result.association.usage_digest == f.gate._released.usage_digest
    assert not result.association.processing_authorized
    assert f.gate._phase == "OUTPUT_RETAINED" and f.gate._receipt == old
    assert f.gate._associated_result is result
    with pytest.raises(m.FragmentPublicationGenerationError):
        m.retain_personal_fragment_publication_output(
            f.gate, runtime=f.runtime, request=f.q, draft=f.draft
        )


@pytest.mark.parametrize("kind", ["draft", "usage", "request"])
def test_fabricated_output_burns_before_capture(publication_issuer, kind):
    f = publication_issuer
    released(f)
    events = list(f.events)
    draft = f.draft
    request = f.q
    if kind == "draft":
        draft = draft.model_copy(update={"overview": ()})
    elif kind == "usage":
        f.runtime._usage = f.runtime.usage.model_copy(update={"latency_ms": 2})
    else:
        request = request.model_copy()
    with pytest.raises(m.FragmentPublicationGenerationError):
        m.retain_personal_fragment_publication_output(
            f.gate, runtime=f.runtime, request=request, draft=draft
        )
    assert f.gate._phase == "OUTPUT_HELD" and f.events == events
    assert f.gate._associated_result is None


def test_new_claim_blocks_existing_legacy_consumer(publication_issuer):
    from tests.test_personal_fragment_claim_issuer import fresh
    from zacai.contextual_authorization import ContextualAuthorizationError

    f = publication_issuer
    pre(f)
    old = fresh(f)
    events = list(f.events)
    with pytest.raises(ContextualAuthorizationError):
        old.recheck(f.q, f.descriptor)
    assert len(f.ledger) == 1 and old._phase == "HELD"
    assert f.events.count("record") == events.count("record")


@pytest.mark.parametrize(
    "field",
    ["request_digest", "publication_digest", "review_profile_digest", "task_id", "builder_id"],
)
def test_wrong_exact_admission_before_claim(publication_issuer, field):
    f = publication_issuer
    value = uuid4() if field.endswith("_id") else "f" * 64
    bad = f.admission.model_copy(update={field: value})
    with pytest.raises(m.FragmentPublicationGenerationError):
        m.CanonicalPersonalFragmentPublicationAuthorization(
            factory=f.p._factory,
            artifacts=f.p._artifacts,
            publication=f.d,
            admission_reference=f.admission_ref,
            admission=bad,
            request=f.q,
            protector=f.p,
            operation=f.p._operation,
            clock=f.p._clock,
        )
    assert not f.ledger and not f.events


def test_generation_only_hold_and_old_output_exact_type_unchanged(publication_issuer):
    from zacai.intelligence import personal_fragment_output as old

    f = publication_issuer
    no_review = prepare_fragment_generation_review_declaration(f.consent, f.q, review=None)
    with pytest.raises(m.FragmentPublicationGenerationError):
        m.CanonicalPersonalFragmentPublicationAuthorization(
            factory=f.p._factory,
            artifacts=f.p._artifacts,
            publication=no_review,
            admission_reference=f.admission_ref,
            admission=f.admission,
            request=f.q,
            protector=f.p,
            operation=f.p._operation,
            clock=f.p._clock,
        )
    released(f)
    phase = f.gate._phase
    with pytest.raises(old.PersonalFragmentOutputError):
        old.retain_personal_history_fragment_output(
            f.gate, runtime=f.runtime, request=f.q, draft=f.draft
        )
    assert f.gate._phase == phase


@pytest.mark.parametrize(
    "mutation", ["unknown", "duplicate", "whitespace", "wrong-family", "oversize"]
)
def test_claim_wire_strict_roundtrip_and_negative(publication_issuer, mutation):
    f = publication_issuer
    pre(f)
    raw = m.encode_fragment_publication_claim(f.gate._claim)
    assert m.decode_fragment_publication_claim(raw) == f.gate._claim
    data = json.loads(raw)
    if mutation == "unknown":
        data["owner_authenticated"] = True
        bad = canonical_bytes(data)
    elif mutation == "duplicate":
        bad = b'{"attempt_id":' + json.dumps(data["attempt_id"]).encode() + b"," + raw[1:]
    elif mutation == "whitespace":
        bad = b" " + raw
    elif mutation == "wrong-family":
        data["format"] = "zac-personal-history-fragment-claim-v1"
        bad = canonical_bytes(data)
    else:
        bad = b"x" * 16001
    with pytest.raises(m.FragmentPublicationGenerationError) as exc:
        m.decode_fragment_publication_claim(bad)
    assert exc.value.__context__ is None


def test_last_claim_body_callback_withdrawal_or_prefix_holds(publication_issuer, monkeypatch):
    f = publication_issuer
    pre(f)
    original = f.p._artifacts.get_bounded
    milestones = []

    def changed(*a, **kw):
        raw = original(*a, **kw)
        if raw == m.encode_fragment_publication_claim(f.gate._claim):
            f.extra_claim = True
            milestones.append("actual-claim-body-returned")
        return raw

    monkeypatch.setattr(f.p._artifacts, "get_bounded", changed)
    with pytest.raises(m.FragmentPublicationGenerationError):
        f.gate._reopen_claim()
    assert milestones == ["actual-claim-body-returned"]


def test_cleanup_uncertainty_and_interruption_burn(publication_issuer, monkeypatch):
    f = publication_issuer
    milestone = []

    def uncertain(*a, **kw):
        milestone.append("claim-protector-entered")
        raise protection.PersonalFragmentCleanupUncertain("invented private message")

    monkeypatch.setattr(m, "protect_publication_claim", uncertain)
    with pytest.raises(protection.PersonalFragmentCleanupUncertain) as exc:
        pre(f)
    assert milestone == ["claim-protector-entered"] and f.gate._phase == "HELD"
    assert str(exc.value) == "PERSONAL recovery cleanup uncertain; operator review required"
    assert exc.value.__context__ is None
    with pytest.raises(m.FragmentPublicationGenerationError):
        pre(f)


def test_interrupted_artifact_burn_no_repair(publication_issuer, monkeypatch):
    f = publication_issuer
    original = f.p._artifacts.put
    milestones = []

    def stopped(*a, **kw):
        original(*a, **kw)
        milestones.append("artifact-put-completed")
        raise KeyboardInterrupt()

    monkeypatch.setattr(f.p._artifacts, "put", stopped)
    with pytest.raises(KeyboardInterrupt):
        pre(f)
    assert milestones == ["artifact-put-completed"] and f.gate._phase == "HELD" and not f.ledger
    with pytest.raises(m.FragmentPublicationGenerationError):
        pre(f)


def arm_owner_revocation_at_clock(f, monkeypatch):
    actual = f.p._clock._read
    milestones = []

    def revoked():
        value = actual()
        if not milestones:
            f.owner["value"] = None
            milestones.append("final-clock-read-owner-revoked")
        return value

    monkeypatch.setattr(f.p._clock, "_read", revoked)
    return milestones


def test_actual_runtime_final_pre_clock_revocation_zero_post(publication_issuer, monkeypatch):
    from zacai.intelligence import local_contextual_runtime as runtime_module

    f = publication_issuer
    posts = []
    milestones = []
    monkeypatch.setattr(runtime_module, "_fragment_verify_runtime", lambda *a: None)
    monkeypatch.setattr(runtime_module, "verify_model", lambda *a: None)
    monkeypatch.setattr(runtime_module, "_fragment_http_post", lambda *a: posts.append(True) or {})
    final = f.gate._final_claim

    def guarded(receipt):
        milestones.extend(["claim-protection-completed"])
        revoked = arm_owner_revocation_at_clock(f, monkeypatch)
        try:
            final(receipt)
        finally:
            milestones.extend(revoked)

    monkeypatch.setattr(f.gate, "_final_claim", guarded)
    body, _ = f.runtime._bytes(f.q)
    f.runtime._count(body, f.q)
    f.runtime.preflight_fragment(f.q)
    with pytest.raises(runtime_module.FragmentLocalContextualRuntimeError):
        f.runtime.generate_fragment(f.q)
    assert milestones == ["claim-protection-completed", "final-clock-read-owner-revoked"]
    assert not posts and not f.runtime.did_transport_attempt
    assert f.gate._phase == "HELD" and len(f.ledger) == 1


def test_final_release_clock_revocation_withholds_released_descriptor(
    publication_issuer, monkeypatch
):
    f = publication_issuer
    pre(f)
    final = f.gate._final_claim
    milestones = []

    def guarded(receipt):
        revoked = arm_owner_revocation_at_clock(f, monkeypatch)
        try:
            final(receipt)
        finally:
            milestones.extend(revoked)

    monkeypatch.setattr(f.gate, "_final_claim", guarded)
    with pytest.raises(m.FragmentPublicationGenerationError):
        f.gate.recheck(
            f.q,
            replace(f.descriptor, phase="RELEASE", output_digest="8" * 64, usage_digest="9" * 64),
        )
    assert milestones == ["final-clock-read-owner-revoked"] and f.gate._released is None
    assert f.gate._phase == "HELD" and len(f.ledger) == 1


def test_final_output_clock_revocation_after_fresh_recovery_withholds_ack(
    publication_issuer, monkeypatch
):
    f = publication_issuer
    released(f)
    sid = uuid4()
    packet = [None]
    milestones = []

    def capture(s, **kw):
        packet[0] = decode_history_fragment_contextual_packet(kw["payload"])
        f.rows[sid] = {
            "id": sid,
            "content_hash": content_hash_of(kw["payload"]),
            "captured_at": packet[0].created_at,
        }
        rows = json.loads(f.current_plan["value"].rows)
        rows.append({"id": str(sid), "content_hash": content_hash_of(kw["payload"])})
        f.current_plan["value"] = replace(f.plan, rows=canonical_bytes(rows))
        return sid

    monkeypatch.setattr(m, "capture_history_fragment_contextual_packet", capture)
    monkeypatch.setattr(m, "load_history_fragment_contextual_packet", lambda *a, **kw: packet[0])
    monkeypatch.setattr(
        m, "prepare_personal_encrypted_custody_backup_plan", lambda s: f.current_plan["value"]
    )
    monkeypatch.setattr(f.p, "_packet", lambda *a: packet[0])
    terminal = m._terminal_publication_output

    def guarded(*args):
        milestones.append("fresh-output-protection-returned")
        revoked = arm_owner_revocation_at_clock(f, monkeypatch)
        try:
            terminal(*args)
        finally:
            milestones.extend(revoked)

    monkeypatch.setattr(m, "_terminal_publication_output", guarded)
    with pytest.raises(m.FragmentPublicationGenerationError):
        m.retain_personal_fragment_publication_output(
            f.gate, runtime=f.runtime, request=f.q, draft=f.draft
        )
    assert milestones == ["fresh-output-protection-returned", "final-clock-read-owner-revoked"]
    assert f.gate._phase == "OUTPUT_HELD" and packet[0] is not None


def test_reentrant_pre_caught_by_owner_cannot_repair_phase(publication_issuer, monkeypatch):
    f = publication_issuer
    owner = f.gate._owner
    milestones = []

    def recursive():
        if not milestones:
            milestones.append("outer-owner-callback")
            with pytest.raises(m.FragmentPublicationGenerationError):
                pre(f)
            assert f.gate._phase == "HELD"
            milestones.append("inner-held-caught")
        return owner()

    monkeypatch.setattr(f.gate, "_owner", recursive)
    with pytest.raises(m.FragmentPublicationGenerationError):
        pre(f)
    assert milestones == ["outer-owner-callback", "inner-held-caught"]
    assert f.gate._phase == "HELD" and not f.ledger
    assert "backup" not in f.events


def test_reentrant_output_caught_by_resolver_cannot_repair_phase(publication_issuer, monkeypatch):
    f = publication_issuer
    released(f)
    resolve = f.runtime.resolve_fragment
    milestones = []

    def recursive(draft, request):
        milestones.append("outer-resolver-callback")
        with pytest.raises(m.FragmentPublicationGenerationError):
            m.retain_personal_fragment_publication_output(
                f.gate, runtime=f.runtime, request=f.q, draft=f.draft
            )
        assert f.gate._phase == "OUTPUT_HELD"
        milestones.append("inner-output-held-caught")
        return resolve(draft, request)

    monkeypatch.setattr(f.runtime, "resolve_fragment", recursive)
    monkeypatch.setattr(
        m,
        "capture_history_fragment_contextual_packet",
        lambda *a, **k: milestones.append("UNEXPECTED-capture"),
    )
    with pytest.raises(m.FragmentPublicationGenerationError):
        m.retain_personal_fragment_publication_output(
            f.gate, runtime=f.runtime, request=f.q, draft=f.draft
        )
    assert milestones == ["outer-resolver-callback", "inner-output-held-caught"]
    assert f.gate._phase == "OUTPUT_HELD"


@pytest.fixture
def association_case(publication_issuer, monkeypatch):
    f = publication_issuer
    released(f)
    packet_raw = m.encode_history_fragment_contextual_packet(
        f.runtime.resolve_fragment(f.draft, f.q),
        f.q,
        builder_id=f.consent.builder_id,
        created_at=f.consent.approved_at,
    )
    packet_location = f.p._artifacts.put(B.PERSONAL, content_hash_of(packet_raw), packet_raw)
    f.packet_path = f.p._artifacts.root / B.PERSONAL.value / packet_location
    f.packet_reads = []

    def load_packet(session, **kwargs):
        f.packet_reads.append("bounded-packet-read-entered")
        assert kwargs["expected_digest"] == content_hash_of(packet_raw)
        assert kwargs["expected_request"] is f.q
        returned = f.p._artifacts.get_bounded(B.PERSONAL, packet_location, max_bytes=128000)
        return decode_history_fragment_contextual_packet(returned)

    monkeypatch.setattr(m, "load_history_fragment_contextual_packet", load_packet)
    packet_ref = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(packet_raw),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    f.rows[packet_ref.source_id] = {
        "id": packet_ref.source_id,
        "content_hash": packet_ref.content_hash,
        "captured_at": f.consent.approved_at,
    }
    association = m._associated_output(f.gate, packet_ref, f.consent.approved_at)
    raw = m.encode_fragment_publication_output_association(association)
    ref = EvidenceReference(
        source_id=uuid4(),
        content_hash=content_hash_of(raw),
        trust_boundary=B.PERSONAL,
        effective_classification=C.HIGHLY_RESTRICTED,
    )
    location = f.p._artifacts.put(B.PERSONAL, ref.content_hash, raw)
    f.rows[ref.source_id] = {
        "id": ref.source_id,
        "content_hash": ref.content_hash,
        "content_location": location,
        "system": SourceSystem.MANUAL,
        "trust_boundary": B.PERSONAL,
        "data_classification": C.HIGHLY_RESTRICTED,
        "external_ref": m._association_namespace(association),
        "captured_at": association.packet_created_at,
        "supersedes_source_id": None,
        "lineage_id": ref.source_id,
    }
    f.ledger.append(SimpleNamespace(id=ref.source_id))
    return f, association, ref, raw


def test_association_exact_reconstruction_positive(association_case):
    f, association, ref, raw = association_case
    assert m.decode_fragment_publication_output_association(raw) == association
    with f.p._factory() as session:
        packet, observed = m.load_fragment_publication_output_association(
            session, authorization=f.gate, reference=ref, expected=association
        )
        assert observed == association
        assert packet.request() == f.q
        assert packet.builder_id == f.consent.builder_id
        assert packet.created_at == association.packet_created_at
    assert association.publication_reference == f.pub
    assert association.admission_reference == f.admission_ref
    assert association.claim_reference == f.gate._claim_reference


@pytest.mark.parametrize(
    "field", ["output_digest", "usage_digest", "request_digest", "attempt_id", "publication_digest"]
)
def test_association_changed_release_binding_holds_before_body(
    association_case, monkeypatch, field
):
    f, association, ref, _ = association_case
    changed = association.model_copy(update={field: uuid4() if field == "attempt_id" else "0" * 64})
    reads = []
    monkeypatch.setattr(f.p._artifacts, "get_bounded", lambda *a, **k: reads.append(True))
    with f.p._factory() as session, pytest.raises(m.FragmentPublicationGenerationError):
        m.load_fragment_publication_output_association(
            session, authorization=f.gate, reference=ref, expected=changed
        )
    assert not reads


def test_association_sibling_namespace_after_body_holds(association_case, monkeypatch):
    f, association, ref, _ = association_case
    original = f.p._artifacts.get_bounded
    milestones = []

    def drift(*args, **kwargs):
        value = original(*args, **kwargs)
        if content_hash_of(value) == ref.content_hash:
            sid = uuid4()
            f.rows[sid] = {"external_ref": m._association_prefix(f.consent.id) + str(uuid4())}
            f.ledger.append(SimpleNamespace(id=sid))
            milestones.append("bounded-association-body-returned-sibling-added")
        return value

    monkeypatch.setattr(f.p._artifacts, "get_bounded", drift)
    with f.p._factory() as session, pytest.raises(m.FragmentPublicationGenerationError):
        m.load_fragment_publication_output_association(
            session, authorization=f.gate, reference=ref, expected=association
        )
    assert milestones == ["bounded-association-body-returned-sibling-added"]


@pytest.mark.parametrize(
    "field,value",
    [
        ("system", SourceSystem.USER_INSTRUCTION),
        ("data_classification", C.CONFIDENTIAL),
        ("captured_at", None),
        ("supersedes_source_id", uuid4()),
    ],
)
def test_association_noncanonical_own_metadata_holds(association_case, monkeypatch, field, value):
    f, association, ref, _ = association_case
    f.rows[ref.source_id][field] = value
    reads = []
    monkeypatch.setattr(f.p._artifacts, "get_bounded", lambda *a, **k: reads.append(True))
    with f.p._factory() as session, pytest.raises(m.FragmentPublicationGenerationError):
        m.load_fragment_publication_output_association(
            session, authorization=f.gate, reference=ref, expected=association
        )
    assert not reads


@pytest.mark.parametrize("fault", ["missing", "changed"])
def test_association_reopens_actual_packet_body_and_holds_mutation(association_case, fault):
    f, association, ref, _ = association_case
    if fault == "missing":
        f.packet_path.unlink()
    else:
        raw = f.packet_path.read_bytes()
        f.packet_path.write_bytes(raw[:-1] + b" ")
    with f.p._factory() as session, pytest.raises(m.FragmentPublicationGenerationError):
        m.load_fragment_publication_output_association(
            session, authorization=f.gate, reference=ref, expected=association
        )
    assert f.packet_reads == ["bounded-packet-read-entered"]
