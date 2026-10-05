"""Real Authlib validation of invented signed tokens; no live Google calls."""

import time
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from starlette.requests import Request

from zacai.interfaces.oidc_identity import GOOGLE_ISSUER, AuthlibGoogleIdentity
from zacai.interfaces.session_store import Identity


@pytest.fixture(autouse=True)
def no_external_auth_requests(monkeypatch):
    import httpx

    original = httpx.AsyncClient.request

    async def denied(*args, **kwargs):
        raise AssertionError("synthetic identity tests must not make network requests")

    monkeypatch.setattr(httpx.AsyncClient, "request", denied)
    return original


def request(query=b"", data=None):
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/auth/callback",
            "query_string": query,
            "headers": [(b"host", b"zac.example.test")],
            "scheme": "https",
            "server": ("zac.example.test", 443),
            "session": {} if data is None else data,
        }
    )


@pytest.mark.asyncio
async def test_real_library_generates_state_nonce_pkce_with_fixed_callback_and_endpoints():
    provider = AuthlibGoogleIdentity(client_id="invented-client", client_secret="invented-secret")
    req = request()
    response = await provider.begin(req, "https://zac.example.test/auth/callback")
    target = urlsplit(response.headers["location"])
    args = parse_qs(target.query)
    assert target.scheme == "https" and target.netloc == "accounts.google.com"
    assert args["redirect_uri"] == ["https://zac.example.test/auth/callback"]
    assert args["response_type"] == ["code"]
    assert args["code_challenge_method"] == ["S256"]
    assert len(args["state"][0]) >= 20
    assert args["nonce"] == [req.session["zac_nonce"]]
    assert set(args["scope"][0].split()) == {"openid", "email"}
    assert "invented-secret" not in response.headers["location"]


@pytest.mark.parametrize(
    "defect",
    [
        None,
        "legacy_issuer",
        "legacy_audience",
        "legacy_signature",
        "issuer",
        "audience",
        "nonce",
        "expired",
        "signature",
        "nonce_bypass",
        "missing_nonce",
        "state",
        "no_id_token_raw_userinfo",
        "invalid_id_token_raw_userinfo",
    ],
)
@pytest.mark.asyncio
async def test_real_library_rejects_signed_bad_claims_or_wrong_signature_without_network(
    monkeypatch, defect
):
    from joserfc import jwt
    from joserfc.jwk import RSAKey

    provider = AuthlibGoogleIdentity(client_id="invented-client", client_secret="invented-secret")
    start = request()
    response = await provider.begin(start, "https://zac.example.test/auth/callback")
    params = parse_qs(urlsplit(response.headers["location"]).query)
    nonce = params["nonce"][0]
    state = params["state"][0]
    key = RSAKey.generate_key(2048)
    provider._client.server_metadata["jwks"] = {"keys": [key.as_dict(private=False)]}
    claims = {
        "iss": GOOGLE_ISSUER,
        "sub": "invented-stable-subject",
        "aud": "invented-client",
        "iat": int(time.time()),
        "exp": int(time.time()) + 120,
        "nonce": nonce,
        "email": "administrator@example.test",
        "hd": "brainstormtech.io",
    }
    signing_key = key
    if defect in ("legacy_issuer", "legacy_audience", "legacy_signature"):
        claims["iss"] = "accounts.google.com"
    if defect == "issuer":
        claims["iss"] = "https://attacker.example.test"
    elif defect in ("audience", "legacy_audience"):
        claims["aud"] = "wrong-client"
    elif defect == "nonce":
        claims["nonce"] = "wrong-nonce"
    elif defect == "expired":
        claims["exp"] = int(time.time()) - 10
    elif defect in ("signature", "legacy_signature"):
        signing_key = RSAKey.generate_key(2048)
    elif defect == "nonce_bypass":
        claims["nonce_supported"] = False
        claims["nonce"] = "wrong-nonce"
    elif defect == "missing_nonce":
        claims.pop("nonce")
    token = jwt.encode({"alg": "RS256"}, claims, signing_key)
    exchanges = []

    async def fetch(**kwargs):
        exchanges.append(kwargs)
        assert kwargs["redirect_uri"] == "https://zac.example.test/auth/callback"
        assert isinstance(kwargs["code_verifier"], str) and len(kwargs["code_verifier"]) >= 43
        response = {
            "access_token": "invented-access-token",
            "token_type": "Bearer",
            "id_token": token,
        }
        if defect in ("no_id_token_raw_userinfo", "invalid_id_token_raw_userinfo"):
            response["userinfo"] = {"iss": GOOGLE_ISSUER, "sub": "forged-subject", "nonce": nonce}
            if defect == "no_id_token_raw_userinfo":
                response.pop("id_token")
            else:
                response["id_token"] = "invalid-not-signed"
        return response

    monkeypatch.setattr(provider._client, "fetch_access_token", fetch)
    callback = request(
        urlencode(
            {"code": "invented-code", "state": state if defect != "state" else "forged-state"}
        ).encode(),
        start.session,
    )
    if defect and defect != "legacy_issuer":
        with pytest.raises(ValueError, match="^identity unavailable$") as error:
            await provider.finish(callback)
        assert error.value.__context__ is None
        if defect == "state":
            assert not exchanges
    else:
        identity = await provider.finish(callback)
        assert identity.issuer == GOOGLE_ISSUER and identity.subject == "invented-stable-subject"
        assert not hasattr(identity, "email") and not hasattr(identity, "scopes")
        with pytest.raises(ValueError, match="identity unavailable"):
            await provider.finish(callback)
        assert len(exchanges) == 1


@pytest.mark.parametrize("expired", [False, True])
@pytest.mark.asyncio
async def test_actual_mocked_token_endpoint_consumes_leeway_before_fetch(
    monkeypatch, no_external_auth_requests, expired
):
    import httpx
    from joserfc import jwt
    from joserfc.jwk import RSAKey

    provider = AuthlibGoogleIdentity(client_id="invented-client", client_secret="invented-secret")
    start = request()
    response = await provider.begin(start, "https://zac.example.test/auth/callback")
    args = parse_qs(urlsplit(response.headers["location"]).query)
    signing_key = RSAKey.generate_key(2048)
    provider._client.server_metadata["jwks"] = {"keys": [signing_key.as_dict(private=False)]}
    signed = jwt.encode(
        {"alg": "RS256"},
        {
            "iss": GOOGLE_ISSUER,
            "sub": "invented-owner",
            "aud": "invented-client",
            "nonce": args["nonce"][0],
            "iat": int(time.time()) - 10,
            "exp": int(time.time()) - 1 if expired else int(time.time()) + 120,
        },
        signing_key,
    )
    exchanges = []

    def token_endpoint(req):
        assert str(req.url) == "https://oauth2.googleapis.com/token"
        assert req.method == "POST"
        fields = parse_qs(req.content.decode())
        assert fields["redirect_uri"] == ["https://zac.example.test/auth/callback"]
        assert fields["code"] == ["invented-code"]
        assert len(fields["code_verifier"][0]) >= 43
        assert "leeway" not in fields and "claims_options" not in fields
        exchanges.append(fields)
        return httpx.Response(
            200, json={"access_token": "invented-token", "token_type": "Bearer", "id_token": signed}
        )

    transport = httpx.MockTransport(token_endpoint)
    provider._client.client_kwargs["transport"] = transport

    async def isolated_request(self, *args, **kwargs):
        assert isinstance(self._transport, httpx.MockTransport), "external requests remain denied"
        return await no_external_auth_requests(self, *args, **kwargs)

    monkeypatch.setattr(httpx.AsyncClient, "request", isolated_request)
    callback = request(
        urlencode({"code": "invented-code", "state": args["state"][0]}).encode(), start.session
    )
    if expired:
        with pytest.raises(ValueError, match="identity unavailable"):
            await provider.finish(callback)
    else:
        assert await provider.finish(callback) == Identity(GOOGLE_ISSUER, "invented-owner")
    assert len(exchanges) == 1
