"""Invented packet/foreground adapters; never SQL, Keychain, TLS or listeners."""

import asyncio
import threading
from contextlib import contextmanager
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime

import pytest

from tests.test_briefing_delivery import checkpoint, selected
from zacai.contextual_recovery_record import encode_recovery_receipt
from zacai.ingestion.artifact_store import content_hash_of
from zacai.interfaces import private_trial as trial
from zacai.interfaces.private_operator import PrivateOperatorMode
from zacai.interfaces.private_web import BoundaryScope, InterfacePrincipal, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

OWNER = Identity("https://accounts.google.com", "invented-owner")
GRANT = OwnerGrant(OWNER, (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),))
PRINCIPAL = InterfacePrincipal(OWNER, GRANT.scopes)


def selection():
    receipt = checkpoint(selected())  # Fabricated fixture, never recovery proof.
    return trial.RetainedCardSelection(receipt, content_hash_of(encode_recovery_receipt(receipt)))


@pytest.mark.parametrize("field,value", [("receipt_digest", "a" * 64), ("selected_item", True), ("selected_item", -1)])
def test_selection_exact_frozen_binding(field, value):
    current = selection()
    with pytest.raises(trial.PrivateTrialError):
        trial.RetainedCardSelection(**{
            "receipt": current.receipt, "receipt_digest": current.receipt_digest,
            "selected_item": current.selected_item, field: value,
        })
    with pytest.raises(FrozenInstanceError):
        current.selected_item = 1
    assert "invented" not in repr(current)


def test_view_own_worker_session_isolation_and_exact_protected_renderer(monkeypatch):
    chosen = selection()
    calls = []
    session = object()
    artifacts = object()

    @contextmanager
    def factory():
        assert threading.current_thread() is not threading.main_thread()
        calls.append("open")
        try:
            yield session
        finally:
            calls.append("closed")

    def isolation(actual):
        assert actual is session
        calls.append("isolation")

    def renderer(actual, **kwargs):
        assert actual is session and calls == ["open", "isolation"]
        assert kwargs["retained_receipt"] is chosen.receipt
        assert kwargs["expected_receipt_digest"] == chosen.receipt_digest
        assert kwargs["artifacts"] is artifacts and kwargs["principal"] is PRINCIPAL
        assert kwargs["selected_item"] == 0
        calls.append("render")
        return "<main>Invented protected card</main>"

    monkeypatch.setattr(trial, "_assert_ledger_isolation", isolation)
    monkeypatch.setattr(trial, "render_retained_decision_cards", renderer)
    view = trial.SelectedPacketView(factory=factory, artifacts=artifacts, selection=chosen,
                                   clock=lambda: chosen.receipt.verified_at)
    assert asyncio.run(view(PRINCIPAL)) == "<main>Invented protected card</main>"
    assert calls == ["open", "isolation", "render", "closed"]
    assert repr(view) == "SelectedPacketView()"


def test_view_isolation_denial_precedes_private_renderer_and_sanitizes(monkeypatch):
    chosen = selection()

    @contextmanager
    def factory():
        yield object()

    def deny(session):
        raise ValueError("INVENTED PRIVATE backend details")

    monkeypatch.setattr(trial, "_assert_ledger_isolation", deny)
    monkeypatch.setattr(trial, "render_retained_decision_cards", lambda *a, **k: pytest.fail("private read"))
    view = trial.SelectedPacketView(factory=factory, artifacts=object(), selection=chosen,
                                   clock=lambda: chosen.receipt.verified_at)
    with pytest.raises(trial.PrivateTrialError) as error:
        asyncio.run(view(PRINCIPAL))
    assert error.value.__context__ is None and "PRIVATE" not in str(error.value)


@pytest.mark.parametrize("principal", [object(), None])
def test_view_rejects_claimed_principal_before_session(principal):
    view = trial.SelectedPacketView(factory=lambda: pytest.fail("private read"), artifacts=object(),
                                   selection=selection(), clock=lambda: datetime.now(UTC))
    with pytest.raises(trial.PrivateTrialError):
        asyncio.run(view(principal))


def test_enrollment_stops_before_exact_separate_confirmation_and_closes(monkeypatch, tmp_path):
    calls = []
    pending = object()
    answer = trial.LocalOwnerConfirmation(OWNER, "invented-pairing", "CONFIRM BRAINSTORM / CONFIDENTIAL")

    class Window:
        def serve(self):
            calls.append("serve-stopped")

        def pending_owner(self):
            assert calls == ["opened", "serve-stopped"]
            calls.append("inspect")
            return pending

        def confirm_owner(self, **kwargs):
            assert calls[-1] == "local-confirm"
            assert kwargs == {"expected_identity": OWNER, "pairing_code": answer.pairing_code,
                              "confirmation": answer.confirmation}
            calls.append("save")
            return GRANT

    @contextmanager
    def operator(**kwargs):
        assert kwargs["mode"] is PrivateOperatorMode.ENROLLMENT
        assert "view" not in kwargs and "work_choices" not in kwargs
        calls.append("opened")
        try:
            yield Window()
        finally:
            calls.append("closed")

    def confirm(actual):
        assert actual is pending
        calls.append("local-confirm")
        return answer

    monkeypatch.setattr(trial, "open_private_operator", operator)
    assert trial.run_enrollment_trial(client_id="invented-public-id", origin="https://invented.test",
                                    directory=tmp_path, escrow_confirmed_by_operator=True,
                                    local_confirm=confirm) is GRANT
    assert calls == ["opened", "serve-stopped", "inspect", "local-confirm", "save", "closed"]


def test_owner_trial_uses_exact_protected_view_no_write_routes(monkeypatch, tmp_path):
    view = trial.SelectedPacketView(factory=lambda: None, artifacts=object(), selection=selection(),
                                   clock=lambda: datetime.now(UTC))
    seen = []

    class Window:
        def serve(self):
            seen.append("serve")

    @contextmanager
    def operator(**kwargs):
        assert kwargs["mode"] is PrivateOperatorMode.OWNER
        assert kwargs["view"] is view and "work_choices" not in kwargs
        assert kwargs["clock"] is view._clock  # Same watermark instance, not merely equal times.
        yield Window()
        seen.append("closed")

    monkeypatch.setattr(trial, "open_private_operator", operator)
    trial.run_owner_trial(client_id="invented-public-id", origin="https://invented.test",
                          directory=tmp_path, escrow_confirmed_by_operator=True, view=view)
    assert seen == ["serve", "closed"]


def test_cli_requires_real_local_terminal_before_startup(monkeypatch):
    monkeypatch.setattr("sys.argv", ["private_trial", "--client-id", "invented", "--origin",
                                    "https://invented.test", "--directory", "/invented",
                                    "--escrow-confirmed-by-operator"])
    monkeypatch.setattr(trial, "run_enrollment_trial", lambda **k: pytest.fail("startup"))
    with pytest.raises(SystemExit) as error:
        trial.main()
    assert error.value.code == 1


def progress_view(monkeypatch, *, html="<main>Invented protected card</main>", deny=False):
    from tests.test_build_progress import snapshot

    @contextmanager
    def factory():
        yield object()

    def render(*args, **kwargs):
        if deny:
            raise ValueError("INVENTED private current source denied")
        return html

    monkeypatch.setattr(trial, "_assert_ledger_isolation", lambda session: None)
    monkeypatch.setattr(trial, "render_retained_decision_cards", render)
    return trial.SelectedPacketView(factory=factory, artifacts=object(), selection=selection(),
                                   clock=lambda: datetime.now(UTC), progress=snapshot())


def test_optional_progress_after_protected_success_escaped_and_dated(monkeypatch):
    from dataclasses import replace

    from tests.test_build_progress import NOW, snapshot

    view = progress_view(monkeypatch)
    current = snapshot()
    records = list(current.gates)
    records[0] = replace(records[0], next_step='<img src=x onerror="spoof">')
    view._progress = replace(current, gates=tuple(records))  # Trusted invented host setup only.
    html = asyncio.run(view(PRINCIPAL))
    assert html.startswith("<main>Invented protected card")
    assert html.endswith("</section></main>")
    assert html.count("</main>") == 1
    assert "Evidence as of " + NOW.isoformat() in html
    assert "0 of 4 acceptance gates verified" in html  # No inferred completed status.
    assert "<img" not in html and "&lt;img" in html


@pytest.mark.parametrize("html", ["<p>no main</p>", "<main>x</main><main>y</main>"])
def test_progress_rejects_missing_or_ambiguous_protected_document(monkeypatch, html):
    view = progress_view(monkeypatch, html=html)
    with pytest.raises(trial.PrivateTrialError) as error:
        asyncio.run(view(PRINCIPAL))
    assert error.value.__context__ is None


def test_current_source_failure_prevents_progress_fragment_or_card_release(monkeypatch):
    view = progress_view(monkeypatch, deny=True)
    monkeypatch.setattr(trial, "render_build_progress", lambda snapshot: pytest.fail("premature progress"))
    with pytest.raises(trial.PrivateTrialError):
        asyncio.run(view(PRINCIPAL))


def test_claimed_progress_object_cannot_supply_html_or_status(monkeypatch):
    class Spoof:
        def __str__(self):
            return "<script>invented spoofed progress</script>"

    with pytest.raises(trial.PrivateTrialError):
        trial.SelectedPacketView(factory=lambda: None, artifacts=object(), selection=selection(),
                                 clock=lambda: datetime.now(UTC), progress=Spoof())


def test_integrated_progress_view_still_withheld_after_session_revocation(monkeypatch):
    from starlette.testclient import TestClient

    from tests.test_build_progress import snapshot
    from tests.test_private_web import ORIGIN, InventedProvider, sign_in
    from tests.test_private_web import OWNER as web_owner
    from zacai.interfaces.private_web import create_private_web
    from zacai.interfaces.session_store import InMemorySessionStore

    sessions = InMemorySessionStore()
    grant = OwnerGrant(web_owner, GRANT.scopes)

    @contextmanager
    def factory():
        yield object()

    def render(*args, **kwargs):
        sessions.revoke_identity(web_owner)
        return "<main>Invented private card and progress must be withheld</main>"

    monkeypatch.setattr(trial, "_assert_ledger_isolation", lambda session: None)
    monkeypatch.setattr(trial, "render_retained_decision_cards", render)
    view = trial.SelectedPacketView(factory=factory, artifacts=object(), selection=selection(),
                                   clock=lambda: datetime.now(UTC), progress=snapshot())
    app = create_private_web(origin=ORIGIN, identities=InventedProvider(), sessions=sessions,
                             owner=lambda: grant, view=view)
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as browser:
        sign_in(browser)
        response = browser.get("/")
    assert response.status_code == 403
    assert "Invented private card" not in response.text
    assert "acceptance gates verified" not in response.text
