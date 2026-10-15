"""Invented reopened values only, no database, crypto, source I/O or model.

These fixtures do not simulate or prove real owner/recovery acceptance. The pure
lookup has no authority; production must obtain its input via actual reopen.
"""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

from zacai.ingestion.managed_app_catalog_observation import (
    ManagedAppCatalogObservationScopeV1,
    ManagedAppToolDeclarationV1,
    prepare_managed_app_catalog_observation,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.managed_catalog_navigation import CatalogNavigationError, lookup_catalog_navigation
from zacai.managed_catalog_recovery import CatalogRecoveryReceiptV1, ReopenedCatalog
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

NOW = datetime(2026, 10, 15, 18, tzinfo=UTC)


def observation(data, classification=C.HIGHLY_RESTRICTED, raw=None):
    scope = ManagedAppCatalogObservationScopeV1(
        observation_id=uuid4(),
        representation="ASSEMBLED_NAVIGATION_CATALOG",
        classification=classification,
        tools=(
            ManagedAppToolDeclarationV1(
                provider="CLICKUP",
                reported_tool_name="clickup.list",
                declared_account_label="invented workspace",
            ),
        ),
        declared_navigation_selection="invented returned selected lists",
        reported_acquired_at=NOW - timedelta(days=1),
        inspected_at=NOW,
        reported_entry_count=None,
        reported_pagination="MORE_PAGES_REPORTED",
        coverage_notes="One bounded dated navigation observation. No task bodies.",
        declared_input_hashes=(),
    )
    p = prepare_managed_app_catalog_observation(
        raw=raw if raw is not None else json.dumps(data, ensure_ascii=False).encode(),
        scope=scope,
        requestor_boundaries=frozenset({B.BRAINSTORM}),
        allowed_classifications=frozenset({classification}),
    )
    refs = tuple(
        EvidenceReference(
            source_id=uuid4(),
            content_hash=a.content_hash,
            trust_boundary=B.BRAINSTORM,
            effective_classification=classification,
        )
        for a in p.artifacts
    )
    refs = (
        *refs,
        EvidenceReference(
            source_id=uuid4(),
            content_hash="f" * 64,
            trust_boundary=B.BRAINSTORM,
            effective_classification=classification,
        ),
    )
    receipt = CatalogRecoveryReceiptV1(
        request_id=uuid4(),
        selection_digest="e" * 64,
        references=refs,
        captured_at=NOW,
        verified_at=NOW + timedelta(seconds=1),
        full_source_inventory_digest="a" * 64,
        historical_source_hashes=tuple(
            sorted(((r.source_id, r.content_hash) for r in refs), key=lambda x: str(x[0]))
        ),
        artifact_backup_run_id=uuid4(),
        state_ciphertext_hash="b" * 64,
        state_plaintext_hash="c" * 64,
        journal_ciphertext_hash="d" * 64,
        journal_plaintext_hash="e" * 64,
    )
    return ReopenedCatalog(p, refs, receipt, NOW + timedelta(seconds=2))


def lookup(value, name="Example Client"):
    return lookup_catalog_navigation(reopened=value, exact_name=name)


def held(value, name="Example Client"):
    with pytest.raises(
        CatalogNavigationError, match="^catalog navigation lookup unavailable$"
    ) as error:
        lookup(value, name)
    assert error.value.__context__ is None


@pytest.mark.parametrize("classification", [C.CONFIDENTIAL, C.HIGHLY_RESTRICTED])
def test_literal_observed_object_retains_exact_provenance_dates_and_limits(classification):
    value = observation(
        {
            "lists": [
                {
                    "id": "list-1",
                    "name": "Example Client",
                    "url": "javascript:untrusted()",
                    "status": "active",
                }
            ]
        },
        classification,
    )
    result = lookup(value)
    assert result.status == "ONE_OBSERVED_OBJECT"
    (candidate,) = result.candidates
    assert candidate.object_pointer == "/lists/0"
    assert candidate.matching_fields == ("name",)
    assert dict(candidate.observed_scalar_hints) == {
        "id": "list-1",
        "name": "Example Client",
        "url": "javascript:untrusted()",
    }
    assert result.references == value.references and result.receipt is value.receipt
    assert result.observation == value.preparation.companion.scope
    assert result.checked_at == value.checked_at
    assert (
        result.observation.reported_acquired_at
        < result.observation.inspected_at
        < result.checked_at
    )
    assert all(r.effective_classification is classification for r in result.references)
    assert (
        result.processing_authorized
        is result.execution_authorized
        is result.current_facts_verified
        is result.complete_history_verified
        is False
    )
    assert "BOUNDED_DATED_OBSERVATION_ONLY" in result.absence_means


def test_duplicate_name_requires_disambiguation_not_merged_entity():
    value = observation(
        {"folders": [{"name": "Example Client", "id": "a"}, {"name": "Example Client", "id": "b"}]}
    )
    result = lookup(value)
    assert result.status == "AMBIGUOUS_OBSERVED_OBJECTS"
    assert [c.object_pointer for c in result.candidates] == ["/folders/0", "/folders/1"]


def test_two_matching_fields_on_same_object_are_one_candidate():
    result = lookup(observation([{"name": "Example Client", "title": "Example Client"}]))
    assert len(result.candidates) == 1
    assert result.candidates[0].matching_fields == ("name", "title")


@pytest.mark.parametrize(
    "name", ["example client", "Example", "Example Client ", "", "\nExample Client"]
)
def test_no_fuzzy_case_or_whitespace_normalization(name):
    value = observation([{"name": "Example Client"}])
    if name != name.strip() or not name:
        held(value, name)
    else:
        assert lookup(value, name).status == "NOT_FOUND_IN_OBSERVATION"


def test_arbitrary_text_instructions_are_not_navigation_matches():
    result = lookup(
        observation({"instructions": "Example Client", "description": "Example Client"})
    )
    assert result.candidates == () and result.status == "NOT_FOUND_IN_OBSERVATION"


def test_unicode_escaped_strings_and_exact_json_pointer_are_preserved():
    value = observation(None, raw=b'{"a/b~c":[{"name":"caf\\u00e9"}]}')
    result = lookup(value, "caf\u00e9")
    assert result.candidates[0].object_pointer == "/a~1b~0c/0"
    assert dict(result.candidates[0].observed_scalar_hints)["name"] == "caf\u00e9"


@pytest.mark.parametrize(
    "change", ["receipt-refs", "raw", "classification", "time", "receipt-type"]
)
def test_changed_reopened_bindings_are_rejected(change):
    value = observation([{"name": "Example Client"}])
    if change == "receipt-refs":
        other = observation([{"name": "Example Client"}])
        value = replace(value, receipt=other.receipt)
    elif change == "raw":
        a = value.preparation.artifacts[0]
        value = replace(
            value,
            preparation=replace(
                value.preparation,
                artifacts=(replace(a, original_bytes=b"[]"), value.preparation.artifacts[1]),
            ),
        )
    elif change == "classification":
        ref = value.references[0].model_copy(update={"effective_classification": C.CONFIDENTIAL})
        value = replace(value, references=(ref, *value.references[1:]))
    elif change == "time":
        value = replace(value, checked_at=NOW - timedelta(seconds=1))
    else:
        value = replace(value, receipt=None)
    held(value)


@pytest.mark.parametrize("kind", ["matches", "hints", "depth", "nodes", "pointer"])
def test_capacity_refusal_never_returns_partial_candidates(kind):
    if kind == "matches":
        data = [{"name": "Example Client"}] * 17
    elif kind == "hints":
        data = [{"name": "Example Client", "url": "x" * 2001}]
    elif kind == "depth":
        data = {"name": "Example Client"}
        for _ in range(33):
            data = [data]
    elif kind == "nodes":
        data = {"name": "Example Client", "irrelevant": [None] * 10001}
    else:
        data = {"x" * 2001: {"name": "Example Client"}}
    held(observation(data))
