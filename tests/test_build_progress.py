"""Operational presentation fixtures only; no real acceptance/source evidence."""

from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta

import pytest

from zacai.interfaces.build_progress import (
    AcceptanceGate as G,
)
from zacai.interfaces.build_progress import (
    BuildProgressSnapshot,
    GateEvidence,
    GateProgress,
    render_build_progress,
)
from zacai.interfaces.build_progress import (
    GateStatus as S,
)

NOW = datetime(2026, 10, 5, tzinfo=UTC)


def snapshot(status=S.PENDING):
    evidence = (GateEvidence("Invented reference", "Built/tested fixture; not live acceptance", NOW),)
    return BuildProgressSnapshot(NOW, tuple(GateProgress(g, status, "Next reviewed check", evidence)
                                           for g in G))


def test_counts_only_explicitly_verified_existing_four_gates():
    original = snapshot(S.CURRENT)
    assert 'value="0" max="4"' in render_build_progress(original)
    records = list(original.gates)
    records[0] = replace(records[0], status=S.VERIFIED)
    records[1] = replace(records[1], status=S.NEEDS_OWNER)
    html = render_build_progress(replace(original, gates=tuple(records)))
    assert "1 of 4 acceptance gates verified" in html and 'value="1" max="4"' in html
    assert "Needs your input" in html and "In progress" in html
    assert "Built/tested fixture; not live acceptance" in html
    assert "%" not in html and "Full product complete" not in html
    assert "Broader roadmap</a>" not in html


def test_dated_escaped_evidence_and_next_steps_no_active_actions():
    original = snapshot()
    records = list(original.gates)
    records[0] = replace(records[0], next_step='<img src=x onerror="private">',
                         evidence=(GateEvidence('<script>fixture</script>', 'A & B "quoted"', NOW),))
    html = render_build_progress(replace(original, gates=tuple(records), broader_roadmap_href="/roadmap"))
    assert "Evidence as of " + NOW.isoformat() in html
    assert "Checked " + NOW.isoformat() in html
    assert "<img" not in html and "<script>" not in html
    assert "&lt;script&gt;fixture&lt;/script&gt;" in html and "A &amp; B" in html
    assert '<details><summary>' in html and '<a href="/roadmap">' in html
    assert "<form" not in html and "approve" not in html


@pytest.mark.parametrize("records", [(), (G.REVIEW,) * 4, tuple(reversed(tuple(G)))])
def test_missing_duplicate_and_reordered_gates_denied(records):
    with pytest.raises(ValueError):
        BuildProgressSnapshot(NOW, tuple(GateProgress(g, S.PENDING, "Pending check") for g in records))


def test_verified_gate_requires_evidence_and_no_raw_status_types():
    with pytest.raises(ValueError):
        GateProgress(G.REVIEW, S.VERIFIED, "Accepted")
    with pytest.raises(ValueError):
        GateProgress(G.REVIEW, "Verified complete", "Pending check")
    with pytest.raises(ValueError):
        GateProgress("review", S.PENDING, "Pending check")


def test_snapshot_evidence_cannot_postdate_as_of_or_use_naive_time():
    with pytest.raises(ValueError):
        replace(snapshot(), as_of=NOW - timedelta(seconds=1))
    with pytest.raises(ValueError):
        replace(snapshot(), as_of=NOW.replace(tzinfo=None))
    with pytest.raises(ValueError):
        GateEvidence("Fixture", "Checked", NOW.replace(tzinfo=None))


@pytest.mark.parametrize("href", ["//external.test", "https://external.test", '/roadmap?private=x', '/x\"onclick=x'])
def test_broader_link_is_only_host_reviewed_same_origin_path(href):
    with pytest.raises(ValueError):
        replace(snapshot(), broader_roadmap_href=href)


def test_immutable_snapshot_no_alternate_memory_or_runtime_clock():
    current = snapshot()
    with pytest.raises(FrozenInstanceError):
        current.as_of = NOW + timedelta(days=1)
    assert render_build_progress(current) == render_build_progress(current)
    with pytest.raises(TypeError):
        render_build_progress(object())
