"""Invented canonical rows and session read; real historical API, no SQL proof."""

from types import SimpleNamespace
from uuid import uuid4

import pytest

from tests.test_text_reply_history import fixture as history_fixture
from tests.test_text_reply_history import rewrite_original
from zacai.interfaces import reply_final_snapshot as snapshot
from zacai.interfaces import text_reply_capture as m
from zacai.policy import DataClassification as C
from zacai.state import SourceSystem


@pytest.fixture
def fixture(monkeypatch):
    s = history_fixture.__wrapped__(monkeypatch)
    s.final_queries = 0
    s.final_mutation = None
    s.mutations = 0
    s.projections = []
    original = s.client._factory
    monkeypatch.setattr(snapshot, "_assert_ledger_isolation", lambda session: None)

    class Factory:
        def __enter__(self):
            session = original().__enter__()
            base = session.execute

            def execute(statement, parameters=None):
                if parameters is not None:
                    return base(statement, parameters)
                params = statement.compile().params
                ids = next(v for v in params.values() if isinstance(v, list))
                cancelled = next(
                    v
                    for v in params.values()
                    if isinstance(v, str) and v.startswith("packet-followup-revocation/")
                )
                if s.final_mutation:
                    s.final_mutation()
                    s.mutations += 1
                rows = [
                    r
                    for r in s.sources.values()
                    if r.id in ids
                    or (r.system == SourceSystem.USER_INSTRUCTION and r.external_ref == cancelled)
                ]
                projection = [
                    (r.id, r.system, r.external_ref, r.content_hash, r.content_location,
                     r.captured_at, r.trust_boundary, r.data_classification,
                     getattr(r, "effective", r.data_classification)) for r in rows
                ]
                s.projections.append(projection)
                s.final_queries += 1  # Only a completely parsed/projected query counts.
                return SimpleNamespace(all=lambda: projection)

            session.execute = execute
            self.session = session
            return session

        def __exit__(self, *args):
            return self.session.__exit__(*args)

    s.client._factory = Factory
    return s


@pytest.mark.parametrize("missing", [False, True])
def test_historical_read_holds_elevation_after_last_detailed_acl_read(fixture, missing):
    s = fixture
    args = {**s.history, "recovery_receipt": None} if missing else s.history
    baseline = s.replies.load_history(**args)
    assert type(baseline) is (m.HistoricalReplyStatus if missing else m.SavedHistoricalTextReply)
    assert s.final_queries == 1 and s.mutations == 0
    s.final_queries = 0

    def elevate():
        row = next(r for r in s.sources.values() if r.id == s.saved.source_id)
        row.effective = C.HIGHLY_RESTRICTED

    s.final_mutation = elevate
    with pytest.raises(m.TextReplyCaptureError):
        s.replies.load_history(**args)
    assert s.final_queries == 1 and s.mutations == 1
    assert any(row[-1] is C.HIGHLY_RESTRICTED for row in s.projections[-1])


@pytest.mark.parametrize("missing", [False, True])
def test_historical_cancellation_label_is_from_final_combined_snapshot(fixture, missing):
    s = fixture

    def revoke():
        row = SimpleNamespace(
            id=uuid4(),
            system=SourceSystem.USER_INSTRUCTION,
            external_ref=f"packet-followup-revocation/{s.saved.reply.claim.consent_reference.source_id}",
            content_hash="f" * 64,
            content_location="invented-revocation",
            captured_at=s.now,
            trust_boundary=s.saved.reference.trust_boundary,
            data_classification=C.CONFIDENTIAL,
        )
        s.sources[row.external_ref] = row

    args = {**s.history, "recovery_receipt": None} if missing else s.history
    baseline = s.replies.load_history(**args)
    assert not baseline.original_permission_revoked
    assert s.final_queries == 1 and s.mutations == 0
    s.final_queries = 0
    s.final_mutation = revoke
    loaded = s.replies.load_history(**args)
    assert type(loaded) is (m.HistoricalReplyStatus if missing else m.SavedHistoricalTextReply)
    assert loaded.original_permission_revoked and not loaded.processing_authorized
    assert s.final_queries == 1 and s.mutations == 1


def named_history(s, monkeypatch):
    """Actual V2 canonical consent/claim/reply codecs, mocked named inventory/proofs."""
    rewrite_original(s, named=True, monkeypatch=monkeypatch)
    from zacai.interfaces.followup_authorization import ClaimedFollowup
    def recheck(actual, request):
        expected = ClaimedFollowup(s.saved.reply.claim, s.saved.reply.claim_reference)
        assert actual == expected and request.digest == expected.claim.request_digest
        if s.claim_denied:
            raise ValueError('invented current processing hold')
    monkeypatch.setattr(s.replies._authorization, 'recheck', recheck)
    return {k: v for k, v in s.history.items() if k != 'operation'}


@pytest.mark.parametrize('mutation', ['elevation', 'revocation'])
def test_active_v2_load_final_query_holds_after_same_fixture_positive_control(fixture, monkeypatch, mutation):
    s = fixture
    args = named_history(s, monkeypatch)
    assert s.replies.load(**args) == s.saved
    assert s.final_queries == 1 and s.mutations == 0
    s.final_queries = 0
    def mutate():
        if mutation == 'elevation':
            row = next(r for r in s.sources.values() if r.id == s.saved.reply.claim.run_scope.user_reference.source_id)
            row.effective = C.HIGHLY_RESTRICTED
        else:
            row = SimpleNamespace(id=uuid4(), system=SourceSystem.USER_INSTRUCTION,
                external_ref=f'packet-followup-revocation/{s.saved.reply.claim.consent_reference.source_id}',
                content_hash='f' * 64, content_location='invented-revocation', captured_at=s.now,
                trust_boundary=s.saved.reference.trust_boundary, data_classification=C.CONFIDENTIAL)
            s.sources[row.external_ref] = row
    s.final_mutation = mutate
    with pytest.raises(m.TextReplyCaptureError):
        s.replies.load(**args)
    assert s.final_queries == 1 and s.mutations == 1
    if mutation == 'elevation':
        assert any(row[-1] is C.HIGHLY_RESTRICTED for row in s.projections[-1])
    else:
        assert any(row[2].startswith('packet-followup-revocation/') for row in s.projections[-1])


def test_pending_v2_receipt_repair_final_snapshot_holds_acl_after_positive_control(fixture, monkeypatch):
    from datetime import timedelta
    s = fixture
    named_history(s, monkeypatch)
    # Historical named dependency inventory is invented by the existing fixture;
    # the final combined row projection/helper remain real and are not replaced.
    monkeypatch.setattr(m, 'checked_named_consent_inventory', lambda *args, **kwargs: s.named_rows)
    s.now += timedelta(minutes=6)
    args = {'principal': s.history['principal'], 'source_id': s.saved.source_id,
            'expected_reply_digest': s.saved.reply_digest}
    assert s.replies.protect_pending(**args) == s.saved.recovery_receipt
    assert s.final_queries == 1 and s.mutations == 0
    s.final_queries = 0
    def elevate():
        row = next(r for r in s.sources.values() if r.id == s.saved.reply.claim.run_scope.user_reference.source_id)
        row.effective = C.HIGHLY_RESTRICTED
    s.final_mutation = elevate
    with pytest.raises(m.TextReplyCaptureError):
        s.replies.protect_pending(**args)
    assert s.final_queries == 1 and s.mutations == 1
    assert any(row[-1] is C.HIGHLY_RESTRICTED for row in s.projections[-1])
