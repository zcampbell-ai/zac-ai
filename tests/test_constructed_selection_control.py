import pytest

from tests.test_native_evidence_context import CountingStore, choice, run
from tests.test_native_evidence_context import (
    fixture as fixture,  # noqa: PLC0414 - pytest fixture export
)
from zacai.intelligence import native_evidence_context as m


def test_constructed_negative_span_revalidated_before_artifact_read(fixture):
    _, args, sources, _, _ = fixture
    bad = choice(sources[-1], "Invented private body").model_copy(
        update={"spans": (m.NativeEvidenceSpan.model_construct(start=-5, end=3),)}
    )
    store = CountingStore(args["artifacts"])
    with pytest.raises(m.NativeEvidenceContextError):
        run(fixture, (bad,), artifacts=store)
    assert store.count == 0
