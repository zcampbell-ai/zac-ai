"""Actual issued capability public-copy control, invented signed owner."""

import copy

import pytest

from tests.test_fragment_publication_controller import controller  # noqa: F401
from tests.test_history_publication_action_admission import (
    action_case,  # noqa: F401
)
from tests.test_history_publication_action_admission import (
    canonical_case as canonical_case,  # noqa: PLC0414
)
from tests.test_personal_history_factory import (  # noqa: F401
    case,
    declaration_case,
    factory_case,
    host,
    installed,
    loader_case,
    post_case,
    setup,
)
from zacai.intelligence import history_publication_admission as r


def test_public_copy_cannot_duplicate_successful_once_consumption(canonical_case):
    f = canonical_case
    ack = f.write(f.a.action())
    try:
        clone = copy.copy(ack)
    except r.HistoryPublicationAdmissionError:
        clone = None
    kw = dict(  # noqa: C408 - preserve exact root causal function AST
        operation=f.a.f.operation,
        clock=f.a.f.s.inputs.clock,
        expected_declaration=f.a.target.declaration,
    )
    assert r._consume_history_admission_acknowledgment(ack, **kw) is ack.retained
    if clone is not None:
        with pytest.raises(r.HistoryPublicationAdmissionError):
            r._consume_history_admission_acknowledgment(clone, **kw)
