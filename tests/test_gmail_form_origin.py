"""Invented ASGI regression: standards-derived form Origin, not browser proof."""

from __future__ import annotations

import re
from urllib.parse import urlsplit

import pytest

from tests.test_gmail_connection_web import Fixture, safe
from tests.test_private_host import ORIGIN, sign_in


def form_origin_for_policy(policy: str, source: str, target: str) -> str:
    """Simulate only Fetch §3.2's non-CORS same-origin POST Origin rule.

    https://fetch.spec.whatwg.org/#append-a-request-origin-header
    This does not run a browser or inject evidence of real browser behavior.
    """
    assert urlsplit(source).scheme == urlsplit(target).scheme == "https"
    assert urlsplit(source).netloc == urlsplit(target).netloc
    assert policy in {"same-origin", "no-referrer"}
    return "null" if policy == "no-referrer" else ORIGIN


def test_actual_consent_policy_supports_native_form_origin_without_weakening_guard(tmp_path):
    f = Fixture(tmp_path)
    with f.browser() as browser:
        sign_in(browser)
        page = browser.get("/connections/gmail")
        assert page.status_code == 200
        action = re.search(r'<form method="post" action="([^"]+)"', page.text)
        assert action is not None and action.group(1) == "/connections/gmail/begin"
        fields = dict(re.findall(r'name="([^"]+)" value="([^"]+)"', page.text))
        assert set(fields) == {"csrf", "reviewed_configuration_digest"}
        policy = page.headers["referrer-policy"]
        origin = form_origin_for_policy(
            policy, ORIGIN + "/connections/gmail", ORIGIN + action.group(1)
        )
        assert page.headers["cache-control"] == "no-store"
        assert (
            "form-action 'self' https://accounts.google.com;"
            in page.headers["content-security-policy"]
        )
        assert "frame-ancestors 'none'" in page.headers["content-security-policy"]
        started = browser.post(action.group(1), data=fields, headers={"origin": origin})
        assert started.status_code == 303  # Old policy produces Origin:null and 403.
        assert origin == ORIGIN and policy == "same-origin"
        assert urlsplit(started.headers["location"]).netloc == "accounts.google.com"
        safe(started)
        assert f.registration.calls > 0
        assert f.loads == 0 and not f.requests and not f.staged
        # Even a correctly authenticated form must not admit an opaque Origin.
        opaque = browser.post(action.group(1), data=fields, headers={"origin": "null"})
        assert opaque.status_code == 403
        safe(opaque)
        callback = browser.get(
            "/connections/gmail/callback?state=invented-invalid&code=invented-code"
        )
        assert callback.status_code == 303
        assert callback.headers["location"] == "/connections/gmail/status"
        safe(callback)
        status = browser.get(callback.headers["location"])
        assert status.status_code == 200
        safe(status)
        assert f.loads == 0 and not f.requests and not f.staged


@pytest.mark.parametrize("origin", [None, "null", "https://foreign.example.invalid"])
def test_valid_cookie_csrf_but_invalid_origin_denied_before_registration(tmp_path, origin):
    f = Fixture(tmp_path)
    with f.browser() as browser:
        sign_in(browser)
        fields = f.fields(browser)
        headers = {} if origin is None else {"origin": origin}
        response = browser.post("/connections/gmail/begin", data=fields, headers=headers)
        assert response.status_code == 403
        safe(response)
        assert f.registration.calls == f.loads == 0
        assert not f.requests and not f.staged


def test_denied_consent_document_keeps_no_referrer(tmp_path):
    f = Fixture(tmp_path)
    with f.browser() as browser:
        response = browser.get("/connections/gmail")
        assert response.status_code >= 400
        safe(response)
        assert "https://accounts.google.com" not in response.headers["content-security-policy"]
        assert f.registration.calls == f.loads == 0 and not f.requests
