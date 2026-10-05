"""Invented protected card release; no live HTTP/source/receipt or credentials."""

from datetime import timedelta
from html.parser import HTMLParser
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from tests.test_briefing_delivery import args, checkpoint, selected
from tests.test_contextual_storage import stored as stored_fixture
from tests.test_private_web import ORIGIN, OWNER, InventedProvider, sign_in
from zacai.intelligence import briefing_delivery
from zacai.intelligence.contextual_evaluation import decode_contextual_packet
from zacai.intelligence.decision_cards import DecisionCardRenderMode, render_decision_cards
from zacai.interfaces.private_web import (
    BoundaryScope,
    InterfacePrincipal,
    OwnerGrant,
    create_private_web,
)
from zacai.interfaces.session_store import InMemorySessionStore
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state_repository import elevate_source_classification


def inputs(receipt, scopes=None):
    values = args(receipt)
    values.pop("authorized_boundaries")
    values.pop("allowed_classifications")
    values["principal"] = InterfacePrincipal(
        OWNER, scopes or (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),)
    )
    return values


def test_release_derives_host_packet_and_uses_brainstorm_scope_only(monkeypatch):
    packet = selected()
    receipt = checkpoint(packet)
    scopes = (
        BoundaryScope(B.PERSONAL, frozenset({C.HIGHLY_RESTRICTED})),
        BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),
    )
    values = inputs(receipt, scopes)
    calls = []

    def load(session, **kwargs):
        calls.append(kwargs)
        return packet

    monkeypatch.setattr(briefing_delivery, "load_contextual_packet", load)
    html = briefing_delivery.render_retained_decision_cards(object(), **values)
    assert html == render_decision_cards(packet, render_mode=DecisionCardRenderMode.HOST_LOGOUT)
    assert calls[0]["source_id"] == receipt.locator.packet_source_id
    assert calls[0]["expected_digest"] == receipt.locator.packet_digest
    assert calls[0]["authorized_boundaries"] == frozenset({B.BRAINSTORM})
    assert calls[0]["allowed_classifications"] == frozenset({C.CONFIDENTIAL})


@pytest.mark.parametrize(
    "failure", ["digest", "future", "personal_only", "duck_scope", "duck_principal"]
)
def test_invalid_host_inputs_never_load_packet_or_render(monkeypatch, failure):
    receipt = checkpoint(selected())
    values = inputs(receipt)
    if failure == "digest":
        values["expected_receipt_digest"] = "0" * 64
    elif failure == "future":
        values["as_of"] = receipt.verified_at - timedelta(seconds=1)
    elif failure == "personal_only":
        values["principal"] = InterfacePrincipal(
            OWNER, (BoundaryScope(B.PERSONAL, frozenset({C.CONFIDENTIAL})),)
        )
    elif failure == "duck_scope":
        values["principal"] = InterfacePrincipal(
            OWNER,
            (SimpleNamespace(boundary=B.BRAINSTORM, classifications=frozenset({C.CONFIDENTIAL})),),
        )
    else:
        values["principal"] = SimpleNamespace(identity=OWNER, scopes=values["principal"].scopes)

    def never(*args, **kwargs):
        pytest.fail("invalid inputs must precede protected IO/render")

    monkeypatch.setattr(briefing_delivery, "load_contextual_packet", never)
    monkeypatch.setattr(briefing_delivery, "render_decision_cards", never)
    with pytest.raises(
        ValueError, match="^retained decision cards unavailable or mismatched$"
    ) as error:
        briefing_delivery.render_retained_decision_cards(object(), **values)
    assert error.value.__context__ is None


@pytest.mark.parametrize("family", ["personal", "public", "task"])
def test_wrong_packet_family_or_binding_never_renders(monkeypatch, family):
    packet = selected()
    receipt = checkpoint(packet)
    loaded = (
        selected(boundary=B.PERSONAL)
        if family == "personal"
        else selected(classification=C.PUBLIC)
        if family == "public"
        else packet.model_copy(update={"builder_id": "wrong-builder"})
    )
    monkeypatch.setattr(briefing_delivery, "load_contextual_packet", lambda *args, **kwargs: loaded)

    def never(*args, **kwargs):
        pytest.fail("packet binding must precede cards")

    monkeypatch.setattr(briefing_delivery, "render_decision_cards", never)
    with pytest.raises(ValueError, match="retained decision cards unavailable"):
        briefing_delivery.render_retained_decision_cards(object(), **inputs(receipt))


def test_auth_host_composes_logout_with_matching_csp_and_refreshes_scope(monkeypatch):
    import re

    packet = selected()
    receipt = checkpoint(packet)
    values = inputs(receipt)
    scopes = [values["principal"].scopes]

    def load(session, **kwargs):
        if C.CONFIDENTIAL not in kwargs["allowed_classifications"]:
            raise ValueError("private denial details")
        return packet

    monkeypatch.setattr(briefing_delivery, "load_contextual_packet", load)

    async def view(principal):
        return briefing_delivery.render_retained_decision_cards(
            object(), **{**values, "principal": principal}
        )

    app = create_private_web(
        origin=ORIGIN,
        identities=InventedProvider(),
        sessions=InMemorySessionStore(),
        owner=lambda: OwnerGrant(OWNER, scopes[0]),
        view=view,
        clock=lambda: receipt.verified_at,
    )
    with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
        sign_in(client)
        response = client.get("/?receipt=untrusted&source=untrusted")
        assert response.status_code == 200
        assert "form-action &#39;self&#39;" in response.text
        assert "form-action 'self'" in response.headers["content-security-policy"]

        class Forms(HTMLParser):
            def __init__(self):
                super().__init__()
                self.forms = []

            def handle_starttag(self, tag, attrs):
                if tag == "form":
                    self.forms.append(dict(attrs))

        parsed = Forms()
        parsed.feed(response.text)
        assert len(parsed.forms) == 1
        assert parsed.forms[0]["method"] == "post"
        assert parsed.forms[0]["action"] == "/logout"
        assert 'action="/approve"' not in response.text
        scopes[0] = (
            BoundaryScope(B.BRAINSTORM, frozenset({C.PUBLIC})),
            BoundaryScope(B.PERSONAL, frozenset({C.CONFIDENTIAL})),
        )
        denied = client.get("/")
        assert denied.status_code == 503 and "private denial details" not in denied.text
        scopes[0] = values["principal"].scopes
        html = client.get("/").text
        csrf = re.search(r'name="csrf" value="([^"]+)"', html).group(1)
        assert (
            client.post(
                "/logout",
                content="csrf=" + csrf,
                headers={"Origin": ORIGIN, "content-type": "application/x-www-form-urlencoded"},
            ).status_code
            == 303
        )
        assert client.get("/").headers["location"] == "/login"


@pytest.mark.parametrize(
    "scope",
    [SimpleNamespace(boundary=B.BRAINSTORM, classifications=frozenset({C.CONFIDENTIAL})), object()],
)
def test_owner_grant_rejects_ducktyped_scopes(scope):
    with pytest.raises(ValueError, match="owner enrollment unavailable"):
        OwnerGrant(OWNER, (scope,))


@pytest.fixture
def delivery_stored(test_session_factory, tmp_path):
    return stored_fixture.__wrapped__(test_session_factory, tmp_path)


@pytest.mark.parametrize("denial", [None, "boundary", "classification", "evidence_elevated"])
def test_canonical_acl_is_fresh_for_cards(delivery_stored, denial):
    factory, store, payload, sid, context, _ = delivery_stored
    packet = decode_contextual_packet(payload)
    receipt = checkpoint(packet, sid)
    values = inputs(receipt)
    values["artifacts"] = store
    if denial == "boundary":
        values["principal"] = InterfacePrincipal(
            OWNER, (BoundaryScope(B.PERSONAL, frozenset({C.CONFIDENTIAL})),)
        )
    elif denial == "classification":
        values["principal"] = InterfacePrincipal(
            OWNER, (BoundaryScope(B.BRAINSTORM, frozenset({C.PUBLIC})),)
        )
    with factory() as session:
        if denial == "evidence_elevated":
            elevate_source_classification(
                session,
                source_id=context.meeting_source_id,
                trust_boundary=B.BRAINSTORM,
                new_classification=C.HIGHLY_RESTRICTED,
                reason="invented correction",
                elevated_by="test",
            )
            session.commit()
        if denial is None:
            assert briefing_delivery.render_retained_decision_cards(
                session, **values
            ) == render_decision_cards(packet, render_mode=DecisionCardRenderMode.HOST_LOGOUT)
        else:
            with pytest.raises(ValueError, match="retained decision cards unavailable"):
                briefing_delivery.render_retained_decision_cards(session, **values)
        assert not session.new and not session.dirty and not session.deleted
