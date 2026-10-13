"""Pure escaping/default-route controls; no SQL/session disk/age or models."""

from html import unescape
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from tests.test_email_draft import case, encode
from tests.test_private_web import ORIGIN, OWNER, SCOPE, InventedProvider
from zacai.intelligence.email_draft import decode_email_draft_packet
from zacai.interfaces.email_workflow_web import _hidden, _packet_html
from zacai.interfaces.private_web import OwnerGrant, create_private_web
from zacai.interfaces.session_store import InMemorySessionStore


def test_closed_html_escapes_fields_without_rewriting_literal_value():
    value = '<script>invented</script>\n" & recipient@example.test'
    html = _hidden("csrf", value)
    assert "<script>" not in html and '" & ' not in html
    assert unescape(html.split('value="', 1)[1].rsplit('">', 1)[0]) == value
    packet = decode_email_draft_packet(encode(case.__wrapped__()))
    result = _packet_html(packet)
    assert packet.candidate.subject in result and "Supporting evidence" in result
    assert "Complete selected source context" in result


def test_email_routes_are_absent_by_default():
    async def view(principal):
        return "invented view"

    app = create_private_web(
        origin=ORIGIN,
        identities=InventedProvider(),
        sessions=InMemorySessionStore(),
        owner=lambda: OwnerGrant(OWNER, (SCOPE,)),
        view=view,
    )
    with TestClient(app, base_url=ORIGIN) as client:
        for path in (
            "/prepare-caz-email",
            "/generate-caz-email",
            "/review-caz-email",
            "/release-caz-email",
            "/caz-email-result",
        ):
            assert client.get(path).status_code == 404
            assert client.post(path, content=str(uuid4())).status_code == 404


@pytest.mark.parametrize(
    "sibling",
    [
        "named_questions",
        "gmail_connections",
        "fragment_publication",
        "fragment_preparation",
        "history_preparation",
    ],
)
def test_email_option_refuses_other_controller_families_before_any_callbacks(sibling):
    async def view(principal):
        raise AssertionError("configuration rejection never reads a view")

    def owner():
        raise AssertionError("configuration rejection never reads owner storage")

    # Pure presence sentinels prove the explicit policy branch, not controller
    # construction/authentication. Canonical mounted flow uses real root fixtures.
    with pytest.raises(ValueError, match="^exclusive email workflow host required$"):
        create_private_web(
            origin=ORIGIN,
            identities=InventedProvider(),
            sessions=InMemorySessionStore(),
            owner=owner,
            view=view,
            email_workflow=object(),
            **{sibling: object()},
        )
