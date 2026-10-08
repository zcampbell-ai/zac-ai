"""Actual bounded file callback, explicitly simulated separate SQL prefix rows."""

from uuid import uuid4

import pytest

from tests.test_fragment_review_retention import capture, load
from tests.test_fragment_review_retention import case as case  # noqa: PLC0414
from tests.test_fragment_review_retention import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_fragment_review_retention import retained as retained  # noqa: PLC0414
from tests.test_fragment_review_retention import writer as writer  # noqa: PLC0414
from zacai import contextual_authorization as auth
from zacai.intelligence import fragment_review_retention as m


def test_actual_bounded_body_callback_new_prefix_identity_withholds(retained, monkeypatch):
    f = retained
    original = f.store.get_bounded
    fired = []

    def added(*a, **kw):
        raw = original(*a, **kw)
        f.current["ids"] = (f.own.source_id, uuid4())
        fired.append("different-publication-same-generation-prefix")
        return raw

    monkeypatch.setattr(f.store, "get_bounded", added)
    with pytest.raises(m.FragmentDeclarationRetentionError):
        load(f)
    assert fired == ["different-publication-same-generation-prefix"]
    assert f.events == ["body"]


def test_capture_last_owner_callback_prefix_identity_withholds_ack(writer, monkeypatch):
    f = writer
    original = auth._fragment_decision_owner
    fired = []
    reads = []

    def added(*a, **kw):
        original(*a, **kw)
        reads.append(True)
        if len(reads) == 3:
            assert f.events.count("record") == f.events.count("commit") == 1
            f.current["ids"] = (f.own.source_id, uuid4())
            fired.append("after-owned-commit-reopen-last-owner-callback")

    monkeypatch.setattr(auth, "_fragment_decision_owner", added)
    with pytest.raises(m.FragmentDeclarationRetentionError):
        capture(f)
    assert fired == ["after-owned-commit-reopen-last-owner-callback"]
    assert f.active == 0 and f.events.count("record") == 1
    assert f.current["ids"][0] == f.own.source_id
