"""Invented canonical capture composition only; no HTTP/DB/network or real recovery."""

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from html.parser import HTMLParser
from threading import Event

import pytest

from tests.test_work_choice_capture import fixture as capture_fixture  # noqa: F401
from zacai.intelligence.work_proposals import WorkChoice
from zacai.interfaces.private_web import BoundaryScope, InterfacePrincipal, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.interfaces.work_choice_web import HostWorkSelection, WorkChoiceWeb, WorkChoiceWebError
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


@pytest.fixture
def prepared(capture_fixture):  # noqa: F811 - imported pytest fixture
    state = capture_fixture
    state.selected = HostWorkSelection(
        state.receipt, state.inputs["expected_receipt_digest"], state.proposal
    )
    controller = WorkChoiceWeb(
        capture=state.client,
        factory=state.client._factory,
        artifacts=state.client._artifacts,
        owner=lambda: state.owner,
        selection=lambda principal: state.selected,
        clock=lambda: state.now,
    )
    return state, controller, state.inputs["principal"]


def closed(call):
    with pytest.raises(WorkChoiceWebError) as error:
        call()
    assert error.value.__context__ is None and error.value.__cause__ is None
    assert "PRIVATE" not in str(error.value)


def fields(handle, choice=WorkChoice.AS_PROPOSED, changes=None):
    values = {"handle": handle, "choice": choice.value}
    if changes is not None:
        values["changes"] = changes
    return values


@pytest.mark.parametrize("choice", list(WorkChoice))
def test_only_protected_canonical_capture_returns_acknowledgement(prepared, choice):
    state, web, principal = prepared
    handle = web.issue(principal)
    selected = fields(
        handle, choice, "PRIVATE revise wording" if choice == WorkChoice.WITH_CHANGES else ""
    )
    result = web.submit(principal=principal, fields=selected)
    assert result.source_id == next(iter(state.sources.values())).id
    assert state.protection_calls == 1 and state.rechecks == 1
    again = web.submit(principal=principal, fields=selected)
    assert again.source_id == result.source_id and again.choice_digest == result.choice_digest
    assert state.puts == 1
    assert "PRIVATE" not in repr(web) and state.owner.identity.subject not in repr(web)


def test_protection_failure_is_retryable_without_new_canonical_choice(prepared):
    state, web, principal = prepared
    handle = web.issue(principal)
    state.fail_protect = True
    closed(lambda: web.submit(principal=principal, fields=fields(handle)))
    assert len(state.sources) == 1
    state.fail_protect = False
    result = web.submit(principal=principal, fields=fields(handle))
    assert result.source_id == next(iter(state.sources.values())).id and state.puts == 1


def test_conflicting_replay_cannot_change_choice_or_request_uuid(prepared):
    state, web, principal = prepared
    handle = web.issue(principal)
    web.submit(principal=principal, fields=fields(handle))
    previous = dict(state.raw)
    closed(lambda: web.submit(principal=principal, fields=fields(handle, WorkChoice.MYSELF)))
    assert state.raw == previous and state.puts == 1


def test_inflight_duplicate_denies_without_blocking_registry_or_recapturing(prepared):
    state, web, principal = prepared
    handle = web.issue(principal)
    started, release = Event(), Event()
    original = state.client.capture

    def slow(**kwargs):
        started.set()
        assert release.wait(5)
        return original(**kwargs)

    state.client.capture = slow
    with ThreadPoolExecutor(max_workers=2) as pool:
        future = pool.submit(web.submit, principal=principal, fields=fields(handle))
        assert started.wait(5)
        try:
            other = web.issue(principal)  # Registry remains usable during protection.
            closed(lambda: web.submit(principal=principal, fields=fields(other)))
            assert not state.sources
        finally:
            release.set()
        first = future.result(5)
    second = web.submit(principal=principal, fields=fields(other))
    assert first.source_id == second.source_id and state.puts == 1


@pytest.mark.parametrize(
    "failure", ["identity", "scopes", "proposal", "receipt", "acl", "expiry", "rollback"]
)
def test_changed_or_expired_host_binding_never_captures(prepared, monkeypatch, failure):
    state, web, principal = prepared
    handle = web.issue(principal)
    if failure == "identity":
        state.owner = OwnerGrant(Identity(state.owner.identity.issuer, "other"), state.owner.scopes)
    elif failure == "scopes":
        state.owner = OwnerGrant(
            state.owner.identity,
            (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL, C.INTERNAL})),),
        )
        principal = InterfacePrincipal(state.owner.identity, state.owner.scopes)
    elif failure == "proposal":
        state.selected = HostWorkSelection(
            state.receipt,
            state.selected.receipt_digest,
            state.proposal.model_copy(update={"outcome": "Changed approach"}),
        )
    elif failure == "receipt":
        state.selected = HostWorkSelection(state.receipt, "0" * 64, state.proposal)
    elif failure == "acl":
        from zacai.intelligence import briefing_delivery

        def denied(*args, **kwargs):
            raise ValueError("PRIVATE ACL error")

        monkeypatch.setattr(briefing_delivery, "load_contextual_packet", denied)
    elif failure == "expiry":
        state.now += timedelta(minutes=5)
    else:
        state.now -= timedelta(seconds=1)
    closed(lambda: web.submit(principal=principal, fields=fields(handle)))
    assert not state.sources and state.protection_calls == 0


@pytest.mark.parametrize("extra", ["identity", "receipt", "proposal", "request_id", "csrf"])
def test_client_cannot_supply_host_authority_or_unknown_fields(prepared, extra):
    state, web, principal = prepared
    handle = web.issue(principal)
    closed(lambda: web.submit(principal=principal, fields={**fields(handle), extra: "untrusted"}))
    assert not state.sources


@pytest.mark.parametrize(
    "choice,changes",
    [
        (WorkChoice.WITH_CHANGES, ""),
        (WorkChoice.WITH_CHANGES, " " * 3),
        (WorkChoice.WITH_CHANGES, "x" * 401),
        (WorkChoice.MYSELF, "unwanted change"),
    ],
)
def test_changes_are_bounded_and_only_accepted_for_explicit_changes(prepared, choice, changes):
    state, web, principal = prepared
    handle = web.issue(principal)
    closed(lambda: web.submit(principal=principal, fields=fields(handle, choice, changes)))
    assert not state.sources


def test_bounded_capacity_preserves_active_handle_and_frees_expired_slots(prepared):
    state, web, principal = prepared
    web._capacity = 1  # Rehearsal configuration; real constructor caps at 128.
    handle = web.issue(principal)
    assert web.issue(principal) == handle
    original = state.selected
    state.selected = HostWorkSelection(
        state.receipt,
        original.receipt_digest,
        state.proposal.model_copy(update={"outcome": "Changed binding"}),
    )
    closed(lambda: web.issue(principal))
    state.selected = original
    assert web.render(handle=handle, principal=principal, csrf="c" * 43)
    state.now += timedelta(minutes=5)
    replacement = web.issue(principal)
    assert replacement != handle
    closed(lambda: web.submit(principal=principal, fields=fields(handle)))


def test_native_form_escapes_plan_and_has_no_client_grants_or_execution_claim(prepared):
    state, web, principal = prepared
    state.selected = HostWorkSelection(
        state.receipt,
        state.selected.receipt_digest,
        state.proposal.model_copy(update={"outcome": '<script>PRIVATE & "plan"</script>'}),
    )
    handle = web.issue(principal)
    html = web.render(handle=handle, principal=principal, csrf="c" * 43)
    assert "<script>" not in html and "&lt;script&gt;PRIVATE" in html
    assert "does not execute or send" in html and "saved" not in html.lower()

    class Form(HTMLParser):
        def __init__(self):
            super().__init__()
            self.forms = []
            self.fields = []

        def handle_starttag(self, tag, attrs):
            values = dict(attrs)
            if tag == "form":
                self.forms.append(values)
            if tag in ("input", "textarea"):
                self.fields.append(values)

    parsed = Form()
    parsed.feed(html)
    assert parsed.forms[0]["method"] == "post" and parsed.forms[0]["action"] == "/work-choice"
    assert {x["name"] for x in parsed.fields} == {"handle", "csrf", "choice", "changes"}
    choices = [x for x in parsed.fields if x["name"] == "choice"]
    assert {x["value"] for x in choices} == {c.value for c in WorkChoice}
    assert not any("checked" in x for x in choices)
    closed(lambda: web.render(handle=handle, principal=principal, csrf="unbounded untrusted"))
    assert not state.sources


@pytest.mark.parametrize(
    "configuration",
    [{"capacity": True}, {"capacity": 129}, {"ttl": timedelta(minutes=6)}, {"ttl": timedelta(0)}],
)
def test_configuration_rejects_unbounded_operational_registry(prepared, configuration):
    state, _, _ = prepared
    closed(
        lambda: WorkChoiceWeb(
            capture=state.client,
            factory=state.client._factory,
            artifacts=state.client._artifacts,
            owner=lambda: state.owner,
            selection=lambda p: state.selected,
            clock=lambda: state.now,
            **configuration,
        )
    )


@pytest.mark.parametrize("invalid", ["unknown", "", True, None])
def test_invalid_choice_never_reaches_canonical_capture(prepared, invalid):
    state, web, principal = prepared
    handle = web.issue(principal)
    closed(lambda: web.submit(principal=principal, fields={"handle": handle, "choice": invalid}))
    assert not state.sources


def test_denied_render_and_issue_cannot_disclose_changed_private_plan(prepared):
    state, web, principal = prepared
    handle = web.issue(principal)
    state.owner = OwnerGrant(
        state.owner.identity, (BoundaryScope(B.PERSONAL, frozenset({C.HIGHLY_RESTRICTED})),)
    )
    closed(lambda: web.render(handle=handle, principal=principal, csrf="c" * 43))
    closed(lambda: web.issue(principal))
    assert not state.sources


def test_reissued_same_plan_reuses_handle_and_denies_conflicting_choice(prepared):
    state, web, principal = prepared
    first, second = web.issue(principal), web.issue(principal)
    assert first == second
    a = web.submit(principal=principal, fields=fields(first))
    b = web.submit(principal=principal, fields=fields(second))
    assert a.source_id == b.source_id and state.puts == 1
    closed(lambda: web.submit(principal=principal, fields=fields(second, WorkChoice.MYSELF)))
    assert state.puts == 1


def test_changed_plan_has_new_request_identity(prepared):
    state, web, principal = prepared
    first = web.issue(principal)
    a = web.submit(principal=principal, fields=fields(first))
    state.selected = HostWorkSelection(
        state.receipt,
        state.selected.receipt_digest,
        state.proposal.model_copy(update={"outcome": "Different exact plan"}),
    )
    second = web.issue(principal)
    b = web.submit(principal=principal, fields=fields(second, WorkChoice.MYSELF))
    assert a.source_id != b.source_id and state.puts == 2


def test_new_controller_same_plan_retries_existing_canonical_choice(prepared):
    state, web, principal = prepared
    first = web.submit(principal=principal, fields=fields(web.issue(principal)))
    restarted = WorkChoiceWeb(
        capture=state.client,
        factory=state.client._factory,
        artifacts=state.client._artifacts,
        owner=lambda: state.owner,
        selection=lambda p: state.selected,
        clock=lambda: state.now,
    )
    second = restarted.submit(principal=principal, fields=fields(restarted.issue(principal)))
    assert first.source_id == second.source_id and state.puts == 1


def test_native_crlf_normalization_precedes_character_bound_and_canonical_replay(prepared):
    state, web, principal = prepared
    handle = web.issue(principal)
    changes = "x\r\n" * 200  # 600 browser bytes normalize to 400 characters.
    first = web.submit(principal=principal, fields=fields(handle, WorkChoice.WITH_CHANGES, changes))
    second = web.submit(
        principal=principal,
        fields=fields(handle, WorkChoice.WITH_CHANGES, changes.replace("\r\n", "\n")),
    )
    assert first.source_id == second.source_id and state.puts == 1


@pytest.mark.parametrize("failure", ["rollback", "selection", "owner"])
def test_changes_during_protection_withhold_acknowledgement_without_recapture(prepared, failure):
    state, web, principal = prepared
    handle = web.issue(principal)
    original = state.client.capture
    calls = []

    def completed(**kwargs):
        result = original(**kwargs)
        calls.append(True)
        if failure == "rollback":
            state.now -= timedelta(seconds=1)
        elif failure == "selection":
            state.selected = HostWorkSelection(
                state.receipt,
                state.selected.receipt_digest,
                state.proposal.model_copy(update={"outcome": "Changed while protecting"}),
            )
        else:
            state.owner = OwnerGrant(
                Identity(state.owner.identity.issuer, "other-owner"), state.owner.scopes
            )
        return result

    state.client.capture = completed
    closed(lambda: web.submit(principal=principal, fields=fields(handle)))
    assert len(calls) == 1 and state.puts == 1 and len(state.sources) == 1


def test_controller_denies_stale_transaction_isolation_before_private_packet_read(
    prepared, monkeypatch
):
    state, web, principal = prepared
    state.isolation = "repeatable read"
    from zacai.interfaces import work_choice_web

    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("private packet read must not happen")

    monkeypatch.setattr(work_choice_web, "load_retained_packet", forbidden)
    closed(lambda: web.issue(principal))
    assert not calls and not state.sources


def test_admitted_capture_past_form_ttl_acknowledges_if_authority_still_exact(prepared):
    state, web, principal = prepared
    handle = web.issue(principal)
    original = state.client.capture
    calls = []

    def slow(**kwargs):
        result = original(**kwargs)
        calls.append(True)
        state.now += timedelta(minutes=6)
        return result

    state.client.capture = slow
    saved = web.submit(principal=principal, fields=fields(handle))
    assert saved.source_id == next(iter(state.sources.values())).id
    assert len(calls) == 1 and state.puts == 1
    assert not web._inflight
    closed(lambda: web.submit(principal=principal, fields=fields(handle)))


def test_rotated_receipt_same_canonical_plan_cannot_create_conflicting_choice(prepared):
    from zacai.contextual_recovery_record import encode_recovery_receipt
    from zacai.ingestion.artifact_store import content_hash_of

    state, web, principal = prepared
    first = web.issue(principal)
    web.submit(principal=principal, fields=fields(first))
    state.now += timedelta(seconds=1)
    state.receipt = state.receipt.model_copy(update={"verified_at": state.now})
    state.selected = HostWorkSelection(
        state.receipt, content_hash_of(encode_recovery_receipt(state.receipt)), state.proposal
    )
    second = web.issue(principal)
    assert web._handles[first].request_id == web._handles[second].request_id
    # Existing capture guards retain original receipt provenance. Rotation needs
    # explicit reconciliation, not mutation or a new contradicting canonical row.
    closed(lambda: web.submit(principal=principal, fields=fields(second, WorkChoice.MYSELF)))
    closed(lambda: web.submit(principal=principal, fields=fields(second)))
    assert state.puts == 1 and len(state.sources) == 1 and not web._inflight


def test_exact_bound_plan_and_evidence_are_reviewable_and_escaped(prepared, monkeypatch):
    from html import escape

    from zacai.interfaces import work_choice_web

    state, web, principal = prepared
    steps = tuple(
        step.model_copy(
            update={
                "instruction": '<script>instruction & "x"</script>',
                "destination": '<img src=x onerror="bad">',
                "method": "<b>PRIVATE method</b>",
            }
        )
        for step in state.proposal.steps
    )
    state.selected = HostWorkSelection(
        state.receipt,
        state.selected.receipt_digest,
        state.proposal.model_copy(
            update={
                "steps": steps,
                "completion_check": "<svg>PRIVATE completion</svg>",
            }
        ),
    )
    handle = web.issue(principal)
    calls = []
    actual = work_choice_web.load_retained_packet

    def checked(*args, **kwargs):
        calls.append(True)
        return actual(*args, **kwargs)

    monkeypatch.setattr(work_choice_web, "load_retained_packet", checked)
    html = web.render(handle=handle, principal=principal, csrf="c" * 43)
    assert len(calls) == 1  # Evidence uses the already protected exact packet.
    assert "How Caz proposes getting it done" in html
    assert "<details><summary>" in html and "<details open" not in html
    assert "<script>" not in html and "<svg>" not in html and "<img" not in html
    for step in steps:
        assert escape(step.instruction) in html and escape(step.destination) in html
        assert escape(step.method) in html and escape(step.action_type.value) in html
    assert escape(state.selected.proposal.completion_check) in html
    assert "not eligible routes or completed work" in html
    item = state.packet.review.items[state.proposal.item_index]
    assert escape(item.text) in html
    for quote in item.quotes:
        assert escape(quote.text) in html and str(quote.source_id) in html
    assert html.index("How Caz proposes") < html.index("Your preferred approach")
    assert html.index("Evidence for this proposal") < html.index("Your preferred approach")
    assert not state.sources


def test_rotated_receipt_requires_new_exact_handle_despite_same_canonical_uuid(prepared):
    from zacai.contextual_recovery_record import encode_recovery_receipt
    from zacai.ingestion.artifact_store import content_hash_of

    state, web, principal = prepared
    original = web.issue(principal)
    state.now += timedelta(seconds=1)
    state.receipt = state.receipt.model_copy(update={"verified_at": state.now})
    state.selected = HostWorkSelection(
        state.receipt, content_hash_of(encode_recovery_receipt(state.receipt)), state.proposal
    )
    rotated = web.issue(principal)
    assert rotated != original
    assert web._handles[rotated].request_id == web._handles[original].request_id
    closed(lambda: web.render(handle=original, principal=principal, csrf="c" * 43))


def test_changed_scope_requires_new_handle_and_never_reuses_old_grant(prepared):
    state, web, principal = prepared
    original = web.issue(principal)
    state.owner = OwnerGrant(
        state.owner.identity,
        (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL, C.INTERNAL})),),
    )
    refreshed = InterfacePrincipal(state.owner.identity, state.owner.scopes)
    changed = web.issue(refreshed)
    assert changed != original
    closed(lambda: web.render(handle=original, principal=refreshed, csrf="c" * 43))


def test_changed_owner_requires_new_handle_bound_to_exact_identity(prepared):
    state, web, principal = prepared
    original = web.issue(principal)
    state.owner = OwnerGrant(
        Identity(state.owner.identity.issuer, "new-confirmed-owner"), state.owner.scopes
    )
    refreshed = InterfacePrincipal(state.owner.identity, state.owner.scopes)
    changed = web.issue(refreshed)
    assert changed != original
    assert web._handles[changed].request_id != web._handles[original].request_id
    closed(lambda: web.render(handle=original, principal=refreshed, csrf="c" * 43))
