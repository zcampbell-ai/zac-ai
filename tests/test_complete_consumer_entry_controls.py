"""Actual successful cap/owner primitives only; no fabricated generation issuer."""

import pytest

from tests.test_history_publication_action_admission import (
    action_case as action_case,  # noqa: PLC0414
)
from tests.test_history_publication_action_admission import (
    canonical_case as canonical_case,  # noqa: PLC0414
)
from tests.test_history_publication_action_admission import case as case  # noqa: PLC0414
from tests.test_history_publication_action_admission import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_history_publication_action_admission import (
    factory_case as factory_case,  # noqa: PLC0414
)
from tests.test_history_publication_action_admission import host as host  # noqa: PLC0414
from tests.test_history_publication_action_admission import installed as installed  # noqa: PLC0414
from tests.test_history_publication_action_admission import (
    loader_case as loader_case,  # noqa: PLC0414
)
from tests.test_history_publication_action_admission import post_case as post_case  # noqa: PLC0414
from tests.test_history_publication_action_admission import setup as setup  # noqa: PLC0414
from zacai.intelligence import history_publication_admission as admission


def consume(f, cap, operation):
    return admission._consume_history_admission_acknowledgment(
        cap,
        operation=operation,
        clock=f.a.f.s.inputs.clock,
        expected_declaration=f.a.target.declaration,
    )


def test_equal_verified_cookie_operation_cannot_replace_original_cap_graph(canonical_case):
    f = canonical_case
    cap = f.write(f.a.action())
    equal = f.a.continuity.for_cookie(f.a.original)
    assert equal is not f.a.f.operation
    assert equal.establish() == f.a.f.operation.establish()
    with pytest.raises(admission.HistoryPublicationAdmissionError):
        consume(f, cap, equal)
    # A rejected identity substitute cannot silently bind a new operation.
    assert cap._operation is f.a.f.operation and not cap._used
    assert consume(f, cap, f.a.f.operation) is cap.retained


def test_consume_owner_callback_failure_is_terminal_without_reentry(canonical_case, monkeypatch):
    f = canonical_case
    cap = f.write(f.a.action())
    clock = f.a.f.s.inputs.clock
    actual = clock._read
    observed = []

    def read():
        observed.append(True)
        f.a.f.s.inputs.owners.revoke()
        return actual()

    monkeypatch.setattr(clock, "_read", read)
    with pytest.raises(admission.HistoryPublicationAdmissionError):
        consume(f, cap, f.a.f.operation)
    assert cap._used and observed
    count = len(observed)
    with pytest.raises(admission.HistoryPublicationAdmissionError):
        consume(f, cap, f.a.f.operation)
    assert len(observed) == count  # Replay refuses BEFORE any owner/clock callback.
