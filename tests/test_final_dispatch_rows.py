"""Invented memory rows; single SQL statement shape observed, no PostgreSQL proof.

Runs against the full staged source overlay (or integrated exact module),
not extracted methods; canonical fixtures remain explicitly invented.
"""

from types import SimpleNamespace

import pytest

from tests.test_followup_authorization_v2 import fixture as authority_fixture
from zacai.interfaces import followup_authorization as auth
from zacai.interfaces import named_candidate_rows
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import Source, SourceSystem


@pytest.fixture
def fixture(monkeypatch):
    s = authority_fixture.__wrapped__(monkeypatch)
    approval = s.authority.record(s.consent)
    s.claimed = s.authority.claim(approval_id=approval, scope=s.scope, request=s.request)
    s.named_inventory.hashes = ()
    s.named_inventory.decision.bound_at = s.consent.approved_at
    monkeypatch.setattr(
        named_candidate_rows,
        "verify_named_candidate_rows",
        lambda *args, **kwargs: SimpleNamespace(
            hashes=tuple((row.id, row.content_hash) for row in s.sources.values())
        ),
    )
    # The upstream named inventory is intentionally sparse. Actual final scope
    # references must still select all dependencies, including this decision.
    decision_ref = s.consent.decision_reference
    s.sources["invented-decision"] = Source(
        id=decision_ref.source_id,
        content_hash=decision_ref.content_hash,
        system=SourceSystem.USER_INSTRUCTION,
        external_ref="invented-decision",
        content_location="invented-local",
        captured_at=s.consent.approved_at,
        trust_boundary=B.BRAINSTORM,
        data_classification=C.CONFIDENTIAL,
    )
    s.candidate_hashes = ()
    monkeypatch.setattr(
        named_candidate_rows,
        "verify_named_candidate_rows",
        lambda *args, **kwargs: SimpleNamespace(hashes=s.candidate_hashes),
    )
    s.check = s.authority.recheck_dispatch_rows
    base_factory = s.authority._factory
    s.after_snapshot_start = None
    s.snapshot_calls = 0

    class Factory:
        def __enter__(self):
            self.session = base_factory().__enter__()
            original = self.session.execute

            def execute(statement, parameters=None):
                if parameters is not None:
                    return original(statement, parameters)
                s.snapshot_calls += 1
                sql = str(statement)
                assert "source_classification_elevation" in sql and "coalesce" in sql
                assert "packet-followup-revocation" in str(statement.compile().params)
                if s.after_snapshot_start:
                    s.after_snapshot_start()
                s.final_params = statement.compile().params
                rows = [
                    (
                        row.id,
                        row.system,
                        row.external_ref,
                        row.content_hash,
                        row.content_location,
                        row.captured_at,
                        row.trust_boundary,
                        row.data_classification,
                        getattr(row, "effective", row.data_classification),
                    )
                    for row in s.sources.values()
                ]
                return SimpleNamespace(all=lambda: rows)

            self.session.execute = execute
            return self.session

        def __exit__(self, *args):
            return self.session.__exit__(*args)

    s.authority._factory = Factory
    return s


def test_final_rows_have_no_owner_runtime_session_or_recovery_callbacks(fixture):
    s = fixture

    def forbidden(*args, **kwargs):
        raise AssertionError("no external callbacks after canonical read begins")

    s.authority._refresh = s.authority._owner = forbidden
    s.binding.verify_fresh = s.binding.verify_rows = forbidden
    s.check(s.claimed, s.request)
    assert s.snapshot_calls == 1


@pytest.mark.parametrize("change", ["acl", "revocation", "hash"])
def test_mutation_during_final_combined_statement_holds_dispatch(fixture, change):
    s = fixture

    def mutate():
        row = next(iter(s.sources.values()))
        if change == "acl":
            row.effective = C.HIGHLY_RESTRICTED
        elif change == "hash":
            row.content_hash = "f" * 64
        else:
            from uuid import uuid4

            clone = SimpleNamespace(
                **{
                    name: getattr(row, name)
                    for name in (
                        "system",
                        "external_ref",
                        "content_hash",
                        "content_location",
                        "captured_at",
                        "trust_boundary",
                        "data_classification",
                    )
                }
            )
            clone.id = uuid4()
            clone.system = SourceSystem.USER_INSTRUCTION
            clone.external_ref = (
                f"packet-followup-revocation/{s.claimed.claim.consent_reference.source_id}"
            )
            s.sources[clone.external_ref] = clone

    s.after_snapshot_start = mutate
    with pytest.raises(auth.FollowupAuthorizationError):
        s.check(s.claimed, s.request)
    assert s.snapshot_calls == 1


def test_sparse_inventories_still_include_every_explicit_scope_reference(fixture):
    s = fixture
    s.check(s.claimed, s.request)
    selected = next(v for v in s.final_params.values() if isinstance(v, list))
    expected = {
        r.source_id
        for r in (
            s.scope.packet_reference,
            *s.scope.context_references,
            s.scope.user_reference,
            *s.scope.parent_references,
            s.consent.decision_reference,
            s.claimed.reference,
            s.claimed.claim.consent_reference,
        )
    }
    assert set(selected) == expected


@pytest.mark.parametrize("kind", ["scope", "consent", "claim"])
def test_conflicting_inventory_hash_cannot_be_overwritten(fixture, kind):
    s = fixture
    ref = {
        "scope": s.scope.packet_reference,
        "consent": s.claimed.claim.consent_reference,
        "claim": s.claimed.reference,
    }[kind]
    s.candidate_hashes = ((ref.source_id, "f" * 64),)
    with pytest.raises(auth.FollowupAuthorizationError):
        s.check(s.claimed, s.request)
    assert s.snapshot_calls == 0


@pytest.mark.parametrize(
    "field,value",
    [
        ("trust_boundary", B.PERSONAL),
        ("data_classification", C.HIGHLY_RESTRICTED),
        ("data_classification", C.INTERNAL),
    ],
)
def test_selected_rows_cannot_self_validate_wrong_raw_boundary_or_classification(
    fixture, field, value
):
    s = fixture
    setattr(s.sources["invented-decision"], field, value)
    with pytest.raises(auth.FollowupAuthorizationError):
        s.check(s.claimed, s.request)
    assert s.snapshot_calls == 0
