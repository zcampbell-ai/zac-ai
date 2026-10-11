"""Public copy/serialization and builtin reconstruction of actual issued cap."""

import copy
import pickle

import pytest

from tests.test_admission_copy_causal import action_case as action_case  # noqa: PLC0414
from tests.test_admission_copy_causal import canonical_case as canonical_case  # noqa: PLC0414
from tests.test_admission_copy_causal import case as case  # noqa: PLC0414
from tests.test_admission_copy_causal import declaration_case as declaration_case  # noqa: PLC0414
from tests.test_admission_copy_causal import factory_case as factory_case  # noqa: PLC0414
from tests.test_admission_copy_causal import host as host  # noqa: PLC0414
from tests.test_admission_copy_causal import installed as installed  # noqa: PLC0414
from tests.test_admission_copy_causal import loader_case as loader_case  # noqa: PLC0414
from tests.test_admission_copy_causal import post_case as post_case  # noqa: PLC0414
from tests.test_admission_copy_causal import setup as setup  # noqa: PLC0414
from zacai.intelligence import history_publication_admission as admission


def consume(f, cap):
    return admission._consume_history_admission_acknowledgment(
        cap,
        operation=f.a.f.operation,
        clock=f.a.f.s.inputs.clock,
        expected_declaration=f.a.target.declaration,
    )


@pytest.mark.parametrize(
    "operation", [copy.copy, copy.deepcopy, pickle.dumps], ids=["copy", "deepcopy", "pickle"]
)
def test_public_copy_or_serialization_refuses_without_burning_original(canonical_case, operation):
    f = canonical_case
    cap = f.write(f.a.action())
    with pytest.raises(admission.HistoryPublicationAdmissionError) as error:
        operation(cap)
    assert str(error.value) == "acknowledged history action unavailable"
    assert error.value.__cause__ is error.value.__context__ is None
    assert not cap._used
    assert consume(f, cap) is cap.retained


def test_builtin_reduce_reconstructed_state_is_not_the_issued_object(canonical_case):
    f = canonical_case
    cap = f.write(f.a.action())
    reduction = object.__reduce_ex__(cap, 4)  # Explicit bypass of guarded dunder.
    factory, args, state, *_ = reduction
    clone = factory(*args)
    for key, value in state.items():
        object.__setattr__(clone, key, value)
    assert type(clone) is type(cap) and clone is not cap
    assert clone.retained is cap.retained and clone._lock is cap._lock
    assert not clone._used and not cap._used
    with pytest.raises(admission.HistoryPublicationAdmissionError):
        consume(f, clone)
    assert not clone._used and not cap._used  # identity refusal precedes callbacks/burn
    assert consume(f, cap) is cap.retained
    with pytest.raises(admission.HistoryPublicationAdmissionError):
        consume(f, clone)
