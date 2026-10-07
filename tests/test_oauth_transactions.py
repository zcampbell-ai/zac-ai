"""Invented consent transactions with actual disposable encrypted owner sessions."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import pytest
from starlette.requests import Request

from tests.test_connector_authority import OWNER
from tests.test_connector_authority import Fixture as Sessions
from tests.test_oauth_configuration import gmail, slack
from zacai.connectors.oauth_transactions import (
    OAuthTransactionAuthority,
    OAuthTransactionCancellationUnconfirmed,
    OAuthTransactionCancelled,
    OAuthTransactionError,
    OAuthTransactionUnconfirmed,
)
from zacai.connectors.provider_oauth_evidence import SlackRotation
from zacai.interfaces.private_web import BoundaryScope, OwnerGrant
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

PRIVATE = "invented-private-registration-diagnostic"
CODE = "invented-provider-authorization-code"


class Registration:
    def __init__(self) -> None:
        self.current = "invented-registration-generation-1"
        self.calls = 0
        self.failure: BaseException | None = None

    def attest(self, configuration: Any, rotation: Any) -> None:
        self.calls += 1
        if self.failure:
            raise self.failure

    def generation(self, configuration: Any, rotation: Any) -> str:
        if self.failure:
            raise self.failure
        return self.current


class Fixture:
    def __init__(self, temporary: Path) -> None:
        self.sessions = Sessions(temporary)
        self.directory = temporary / "provider-oauth"
        self.key = b"O" * 32
        self.registration = Registration()
        self.configuration = gmail(private_origin="https://caz.example")
        self.rotation: SlackRotation | None = None
        self.authority = self.reopen()
        self.authority.initialize()

    def reopen(self, **changes: Any) -> Any:
        fields = {
            "key": self.key,
            "continuity": self.sessions.continuity,
            "registration_backend": self.registration,
        }
        fields.update(changes)
        return OAuthTransactionAuthority(self.directory, **fields)

    def request(
        self, *, callback: bool = False, query: str | None = None, **changes: Any
    ) -> Request:
        provider = self.configuration.provider.value
        headers = [
            (b"host", b"caz.example"),
            (b"cookie", ("__Host-zac-session=" + self.sessions.cookie).encode()),
        ]
        if not callback:
            headers.append((b"origin", b"https://caz.example"))
        scope = {
            "type": "http",
            "method": "GET" if callback else "POST",
            "scheme": "https",
            "path": f"/connections/{provider}/" + ("callback" if callback else "begin"),
            "query_string": (query or "").encode(),
            "headers": headers,
            "server": ("caz.example", 443),
            "client": ("127.0.0.1", 1),
        }
        scope.update(changes)
        return Request(scope)

    def begin(self, **changes: Any) -> Any:
        fields = {
            "request": self.request(),
            "csrf": self.sessions.csrf,
            "reviewed_configuration_digest": self.configuration.configuration_digest,
            "slack_rotation": self.rotation,
        }
        fields.update(changes)
        return self.authority.begin(self.configuration, **fields)

    def state(self) -> str:
        consent = self.begin()
        assert consent.configuration_digest == self.configuration.configuration_digest
        return parse_qs(urlsplit(consent.url.get_secret_value()).query)["state"][0]

    def callback(
        self,
        state: str,
        *,
        authority: Any = None,
        query: str | None = None,
        configuration: Any = None,
        **changes: Any,
    ) -> Any:
        return (authority or self.authority).consume_callback(
            configuration or self.configuration,
            request=self.request(
                callback=True, query=query or urlencode({"state": state, "code": CODE}), **changes
            ),
            slack_rotation=self.rotation,
        )


@pytest.fixture
def fixture(tmp_path: Path) -> Fixture:
    return Fixture(tmp_path)


def safe(error: BaseException, *transients: str) -> None:
    assert error.__cause__ is None and error.__context__ is None
    current = error.__traceback__
    while current:
        frame = current.tb_frame
        if frame.f_globals.get("__name__") == "zacai.connectors.oauth_transactions":
            assert frame.f_code.co_name == "call"
            assert "args" not in frame.f_locals and "kwargs" not in frame.f_locals
            assert not any(isinstance(value, Request) for value in frame.f_locals.values())
        current = current.tb_next
    assert all(
        secret not in str(error) and secret not in repr(error)
        for secret in (PRIVATE, CODE, *transients)
    )


@pytest.mark.parametrize("provider", ["gmail", "slack"])
def test_actual_owner_begin_callback_one_attempt_and_no_install_authority(
    fixture: Fixture, provider: str
) -> None:
    if provider == "slack":
        fixture.configuration = slack(private_origin="https://caz.example")
        fixture.rotation = SlackRotation.ROTATING
    state = fixture.state()
    operation = fixture.callback(state)
    assert operation is not None
    operation.current()
    assert state not in repr(operation) and CODE not in repr(operation)
    assert not hasattr(operation, "install") and not hasattr(fixture.authority, "install")
    with pytest.raises(OAuthTransactionError) as raised:
        fixture.callback(state, authority=fixture.reopen())
    safe(raised.value, state)
    operation.hold()
    with pytest.raises(OAuthTransactionError):
        operation.current()
    with pytest.raises(OAuthTransactionError):
        fixture.begin()


@pytest.mark.parametrize(
    "changes",
    [
        {"method": "GET"},
        {"scheme": "http"},
        {"path": "/connections/gmail/callback"},
        {"query_string": b"unexpected=field"},
        {"headers": [(b"host", b"evil.example"), (b"origin", b"https://caz.example")]},
        {"headers": [(b"host", b"caz.example"), (b"origin", b"https://evil.example")]},
        {"headers": [(b"host", b"caz.example")]},
    ],
)
def test_begin_exact_request_identity_required(fixture: Fixture, changes: dict[str, Any]) -> None:
    with pytest.raises(OAuthTransactionError):
        fixture.begin(request=fixture.request(**changes))
    assert fixture.registration.calls == 0


@pytest.mark.parametrize("field", ["csrf", "reviewed_configuration_digest"])
def test_begin_exact_owner_review_digest_and_csrf(fixture: Fixture, field: str) -> None:
    with pytest.raises(OAuthTransactionError):
        fixture.begin(**{field: "invented-wrong-value"})


@pytest.mark.parametrize("scope", ["personal", "internal_only", "other_owner"])
def test_begin_requires_actual_original_brainstorm_highly_restricted_owner(
    fixture: Fixture, scope: str
) -> None:
    if scope == "personal":
        fixture.sessions.owner = OwnerGrant(
            OWNER, (BoundaryScope(B.PERSONAL, frozenset({C.HIGHLY_RESTRICTED})),)
        )
    elif scope == "internal_only":
        fixture.sessions.owner = OwnerGrant(
            OWNER, (BoundaryScope(B.BRAINSTORM, frozenset({C.INTERNAL})),)
        )
    else:
        fixture.sessions.sessions.revoke(fixture.sessions.cookie)
    with pytest.raises(OAuthTransactionError):
        fixture.begin()
    assert fixture.registration.calls == 0


@pytest.mark.parametrize("cancel", [False, True])
def test_registration_failure_is_secret_safe_before_consent(fixture: Fixture, cancel: bool) -> None:
    fixture.registration.failure = KeyboardInterrupt(PRIVATE) if cancel else RuntimeError(PRIVATE)
    with pytest.raises(OAuthTransactionCancelled if cancel else OAuthTransactionError) as raised:
        fixture.begin()
    safe(raised.value)
    assert "attest" not in [
        frame.name for frame in __import__("traceback").extract_tb(raised.value.__traceback__)
    ]


@pytest.mark.parametrize(
    "change", ["renewed_session", "revoked", "generation", "configuration", "expired"]
)
def test_callback_never_transfers_or_renews_original_transaction(
    fixture: Fixture, change: str
) -> None:
    state = fixture.state()
    configuration = fixture.configuration
    if change == "renewed_session":
        fixture.sessions.cookie = fixture.sessions.sessions.start_user(OWNER, fixture.sessions.now)
    elif change == "revoked":
        fixture.sessions.sessions.revoke(fixture.sessions.cookie)
    elif change == "generation":
        fixture.registration.current = "invented-registration-generation-2"
    elif change == "configuration":
        configuration = gmail(
            private_origin="https://caz.example", grant_profile="approved_communications"
        )
    else:
        fixture.sessions.now += timedelta(minutes=5, seconds=1)
    with pytest.raises(OAuthTransactionError) as raised:
        fixture.callback(state, configuration=configuration)
    safe(raised.value, state)


@pytest.mark.parametrize(
    "bad_query",
    [
        "state={state}",
        "state={state}&code=",
        "state={state}&code=x&code=y",
        "state={state}&state={state}&code=x",
        "state={state}&code=x&error=access_denied",
        "state={state}&code=%0D%0AInjected",
        "state={state}&code=" + "x" * 8193,
        "state=short&code=x",
        "state={state}&code=x%00",
        "state={state}&error=access_denied&error=other",
    ],
)
def test_callback_strict_bounded_unique_query(fixture: Fixture, bad_query: str) -> None:
    state = fixture.state()
    with pytest.raises(OAuthTransactionError) as raised:
        fixture.callback(state, query=bad_query.format(state=state))
    safe(raised.value, state)


@pytest.mark.parametrize(
    "changes",
    [
        {"method": "POST"},
        {"scheme": "http"},
        {"path": "/connections/slack/callback"},
        {"headers": [(b"host", b"caz.example")]},
    ],
)
def test_callback_exact_host_route_and_original_cookie(
    fixture: Fixture, changes: dict[str, Any]
) -> None:
    state = fixture.state()
    with pytest.raises(OAuthTransactionError):
        fixture.callback(state, **changes)


def test_provider_denial_terminal_consumes_without_exchange(fixture: Fixture) -> None:
    state = fixture.state()
    result = fixture.callback(state, query=urlencode({"state": state, "error": "access_denied"}))
    assert result is None
    with pytest.raises(OAuthTransactionError):
        fixture.callback(state, authority=fixture.reopen())


def test_concurrent_actual_callbacks_release_only_one_operation(fixture: Fixture) -> None:
    state = fixture.state()

    def consume(_: int) -> Any:
        try:
            return fixture.callback(state, authority=fixture.reopen())
        except OAuthTransactionError:
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        values = list(pool.map(consume, range(4)))
    assert sum(value is not None for value in values) == 1


def test_pending_and_consumed_account_block_other_client_and_restart(fixture: Fixture) -> None:
    state = fixture.state()
    fixture.configuration = gmail(
        private_origin="https://caz.example", client_id="rotated.apps.googleusercontent.com"
    )
    with pytest.raises(OAuthTransactionError):
        fixture.begin()
    fixture.configuration = gmail(private_origin="https://caz.example")
    fixture.callback(state)
    with pytest.raises(OAuthTransactionError):
        fixture.reopen().begin(
            fixture.configuration,
            request=fixture.request(),
            csrf=fixture.sessions.csrf,
            reviewed_configuration_digest=fixture.configuration.configuration_digest,
        )


def test_state_code_and_verifier_never_plaintext_in_durable_files(fixture: Fixture) -> None:
    consent = fixture.begin()
    params = parse_qs(urlsplit(consent.url.get_secret_value()).query)
    state = params["state"][0]
    operation = fixture.callback(state)
    for path in fixture.directory.iterdir():
        if path.is_file():
            data = path.read_bytes()
            assert state.encode() not in data and CODE.encode() not in data
    assert state not in repr(consent) and CODE not in repr(operation)


def test_missing_corrupt_and_wrong_key_ledgers_fail_closed(fixture: Fixture) -> None:
    state = fixture.state()
    with pytest.raises(OAuthTransactionError):
        fixture.callback(state, authority=fixture.reopen(key=b"Z" * 32))
    path = fixture.directory / "provider-oauth-transactions.bin"
    path.write_bytes(b"invented corrupted encrypted ledger")
    with pytest.raises(OAuthTransactionError):
        fixture.callback(state, authority=fixture.reopen())


@pytest.mark.parametrize("provider", ["gmail", "slack"])
def test_original_operation_releases_exchange_once_then_restart_cannot_resume(
    fixture: Fixture, provider: str
) -> None:
    if provider == "slack":
        fixture.configuration = slack(private_origin="https://caz.example")
        fixture.rotation = SlackRotation.ROTATING
    state = fixture.state()
    operation = fixture.callback(state)
    assert not hasattr(operation, "code") and not hasattr(operation, "google_code_verifier")
    material = operation.take_exchange()
    assert material.code.get_secret_value() == CODE
    verifier = material.google_code_verifier
    if provider == "gmail":
        assert verifier is not None and len(verifier.get_secret_value()) >= 43
        assert verifier.get_secret_value() not in repr(material)
    else:
        assert verifier is None
    assert CODE not in repr(material) and state not in repr(material)
    with pytest.raises(OAuthTransactionError):
        operation.take_exchange()
    with pytest.raises(OAuthTransactionError):
        fixture.callback(state, authority=fixture.reopen())
    for path in fixture.directory.iterdir():
        if path.is_file():
            data = path.read_bytes()
            assert CODE.encode() not in data and state.encode() not in data
            if verifier:
                assert verifier.get_secret_value().encode() not in data


@pytest.mark.parametrize("revoke", ["session", "registration", "owner"])
def test_current_registration_and_original_owner_required_at_secret_release(
    fixture: Fixture, revoke: str
) -> None:
    state = fixture.state()
    operation = fixture.callback(state)
    if revoke == "session":
        fixture.sessions.sessions.revoke(fixture.sessions.cookie)
    elif revoke == "registration":
        fixture.registration.current = "invented-registration-generation-2"
    else:
        fixture.sessions.owner = OwnerGrant(
            OWNER, (BoundaryScope(B.PERSONAL, frozenset({C.INTERNAL})),)
        )
    with pytest.raises(OAuthTransactionError) as raised:
        operation.take_exchange()
    safe(raised.value, state)


def test_callback_cross_site_origin_absent_or_provider_origin_allowed(fixture: Fixture) -> None:
    state = fixture.state()
    headers = [
        (b"host", b"caz.example"),
        (b"origin", b"https://accounts.google.com"),
        (b"cookie", ("__Host-zac-session=" + fixture.sessions.cookie).encode()),
    ]
    operation = fixture.callback(state, headers=headers)
    assert operation is not None


@pytest.mark.parametrize("header", ["cookie", "host", "origin"])
def test_begin_duplicate_security_headers_rejected(fixture: Fixture, header: str) -> None:
    request = fixture.request()
    headers = list(request.scope["headers"])
    existing = next(pair for pair in headers if pair[0] == header.encode())
    headers.append(existing)
    with pytest.raises(OAuthTransactionError):
        fixture.begin(request=fixture.request(headers=headers))
    assert fixture.registration.calls == 0


def test_copied_configuration_cannot_bypass_revalidation(fixture: Fixture) -> None:
    fixture.configuration = fixture.configuration.model_copy(
        update={"private_origin": "https://evil.example/path"}
    )
    with pytest.raises(OAuthTransactionError):
        fixture.authority.begin(
            fixture.configuration,
            request=fixture.request(),
            csrf=fixture.sessions.csrf,
            reviewed_configuration_digest="0" * 64,
        )


def test_slack_reviewed_rotation_bound_to_state(fixture: Fixture) -> None:
    fixture.configuration = slack(private_origin="https://caz.example")
    fixture.rotation = SlackRotation.ROTATING
    state = fixture.state()
    fixture.rotation = SlackRotation.NONROTATING
    with pytest.raises(OAuthTransactionError):
        fixture.callback(state)


def test_host_clock_rollback_cannot_extend_pending_transaction(fixture: Fixture) -> None:
    state = fixture.state()
    fixture.sessions.now -= timedelta(seconds=1)
    with pytest.raises(OAuthTransactionError):
        fixture.callback(state)


@pytest.mark.parametrize("stage", ["begin", "callback", "release"])
@pytest.mark.parametrize("cancel", [False, True])
def test_unconfirmed_persistence_never_releases_or_retries_and_sets_local_latch(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    cancel: bool,
) -> None:
    state = fixture.state() if stage != "begin" else None
    operation = fixture.callback(state) if stage == "release" else None

    def impossible_write(value: Any) -> None:
        raise KeyboardInterrupt(PRIVATE) if cancel else OSError(PRIVATE)

    monkeypatch.setattr(fixture.authority, "_write", impossible_write)
    kind = OAuthTransactionCancellationUnconfirmed if cancel else OAuthTransactionUnconfirmed
    with pytest.raises(kind) as raised:
        if stage == "begin":
            fixture.begin()
        elif stage == "callback":
            fixture.callback(state)
        else:
            operation.take_exchange()
    safe(raised.value, *([state] if state else []))
    with pytest.raises(OAuthTransactionUnconfirmed):
        fixture.begin()


@pytest.mark.parametrize("stage", ["callback", "release"])
def test_interrupted_write_recovery_holds_account_without_releasing_material(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    import hashlib

    state = fixture.state()
    operation = fixture.callback(state) if stage == "release" else None
    original = fixture.authority._write
    writes = 0

    def replaced_then_error(value: Any) -> None:
        nonlocal writes
        writes += 1
        original(value)
        if writes == 1:
            raise OSError(PRIVATE)

    monkeypatch.setattr(fixture.authority, "_write", replaced_then_error)
    with pytest.raises(OAuthTransactionError) as raised:
        if stage == "callback":
            fixture.callback(state)
        else:
            operation.take_exchange()
    assert type(raised.value) is OAuthTransactionError
    safe(raised.value, state)
    with fixture.authority._locked():
        row = fixture.authority._read()["rows"][hashlib.sha256(state.encode()).hexdigest()]
    assert row["state"] == "held" and row["verifier"] is None
    with pytest.raises(OAuthTransactionError):
        fixture.callback(state, authority=fixture.reopen())


@pytest.mark.parametrize(
    "target,unsafe",
    [
        (target, unsafe)
        for target in ["directory", "ledger", "lock"]
        for unsafe in ["mode", "symlink", "hardlink"]
        if not (target == "directory" and unsafe == "hardlink")
    ],
)
def test_operational_paths_and_modes_fail_closed(
    fixture: Fixture, tmp_path: Path, target: str, unsafe: str
) -> None:
    state = fixture.state()
    selected = (
        fixture.directory
        if target == "directory"
        else fixture.directory
        / (
            "provider-oauth-transactions.bin"
            if target == "ledger"
            else "provider-oauth-transactions.lock"
        )
    )
    if unsafe == "mode":
        selected.chmod(0o777)
    elif unsafe == "symlink":
        moved = tmp_path / ("moved-" + target)
        selected.rename(moved)
        selected.symlink_to(moved, target_is_directory=target == "directory")
    else:
        import os

        os.link(selected, tmp_path / ("extra-link-" + target))
    with pytest.raises(OAuthTransactionError):
        fixture.callback(state, authority=fixture.reopen())


def test_full_terminal_ledger_never_evicts_old_consumed_states(fixture: Fixture) -> None:
    import hashlib

    state = fixture.state()
    fixture.callback(state, query=urlencode({"state": state, "error": "access_denied"}))
    with fixture.authority._locked():
        value = fixture.authority._read()
        first = value["rows"][hashlib.sha256(state.encode()).hexdigest()]
        for index in range(255):
            key = hashlib.sha256(("invented terminal " + str(index)).encode()).hexdigest()
            value["rows"][key] = dict(first)
        fixture.authority._write(value)
    with pytest.raises(OAuthTransactionError):
        fixture.begin()
    fixture.sessions.now += timedelta(minutes=6)
    with pytest.raises(OAuthTransactionError):
        fixture.begin()
    with fixture.authority._locked():
        assert len(fixture.authority._read()["rows"]) == 256


def test_documented_google_callback_optional_hints_do_not_install_or_change_config(
    fixture: Fixture,
) -> None:
    state = fixture.state()
    query = urlencode(
        {
            "state": state,
            "code": CODE,
            "scope": "https://mail.google.com/",
            "authuser": "0",
            "hd": "invented.example",
            "prompt": "consent",
            "iss": "https://accounts.google.com",
            "invented_future_hint": "ignored-nonauthoritative",
        }
    )
    operation = fixture.callback(state, query=query)
    material = operation.take_exchange()
    assert material.configuration.configuration_digest == fixture.configuration.configuration_digest
    assert material.configuration.scopes == fixture.configuration.scopes
    assert not hasattr(material, "install")


def test_callback_wrong_present_issuer_never_releases(fixture: Fixture) -> None:
    state = fixture.state()
    with pytest.raises(OAuthTransactionError):
        fixture.callback(
            state, query=urlencode({"state": state, "code": CODE, "iss": "https://evil.example"})
        )


@pytest.mark.parametrize("stage", ["begin", "release"])
@pytest.mark.parametrize("revoke", ["session", "registration", "expiry"])
def test_durable_write_revocation_never_discloses_consent_or_exchange(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
    revoke: str,
) -> None:
    state = fixture.state() if stage == "release" else None
    operation = fixture.callback(state) if stage == "release" else None
    original = fixture.authority._write
    writes = 0

    def durable_then_revoked(value: Any) -> None:
        nonlocal writes
        writes += 1
        original(value)
        if writes == 1:
            if revoke == "session":
                fixture.sessions.sessions.revoke(fixture.sessions.cookie)
            elif revoke == "registration":
                fixture.registration.current = "invented-registration-generation-2"
            else:
                fixture.sessions.now += timedelta(minutes=6)

    monkeypatch.setattr(fixture.authority, "_write", durable_then_revoked)
    with pytest.raises(OAuthTransactionError):
        if stage == "begin":
            fixture.begin()
        else:
            operation.take_exchange()
    with fixture.authority._locked():
        rows = fixture.authority._read()["rows"]
    assert len(rows) == 1
    assert next(iter(rows.values()))["state"] == "held"


def test_durable_start_and_loaded_exist_before_any_exchange_material_disclosure(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import hashlib

    state = fixture.state()
    operation = fixture.callback(state)
    recorded = []
    original = fixture.authority._write

    def record_durable(value: Any) -> None:
        original(value)
        row = fixture.authority._read()["rows"][hashlib.sha256(state.encode()).hexdigest()]
        recorded.append((row["state"], row["loaded"], row["verifier"]))

    monkeypatch.setattr(fixture.authority, "_write", record_durable)
    material = operation.take_exchange()
    assert material.code.get_secret_value() == CODE
    assert recorded and all(row == ("exchange_started", True, None) for row in recorded)


@pytest.mark.parametrize("revoke", ["session", "registration", "expiry"])
def test_final_durable_release_write_revocation_never_returns_secrets(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
    revoke: str,
) -> None:
    state = fixture.state()
    operation = fixture.callback(state)
    original = fixture.authority._write
    writes = 0

    def final_durable_then_revoked(value: Any) -> None:
        nonlocal writes
        writes += 1
        original(value)
        if writes == 2:
            if revoke == "session":
                fixture.sessions.sessions.revoke(fixture.sessions.cookie)
            elif revoke == "registration":
                fixture.registration.current = "invented-registration-generation-2"
            else:
                fixture.sessions.now += timedelta(minutes=6)

    monkeypatch.setattr(fixture.authority, "_write", final_durable_then_revoked)
    with pytest.raises(OAuthTransactionError):
        operation.take_exchange()
    with fixture.authority._locked():
        assert next(iter(fixture.authority._read()["rows"].values()))["state"] == "held"


def test_missing_ledger_never_implicitly_reinitializes(fixture: Fixture) -> None:
    state = fixture.state()
    (fixture.directory / "provider-oauth-transactions.bin").unlink()
    with pytest.raises(OAuthTransactionError):
        fixture.callback(state, authority=fixture.reopen())
    assert not (fixture.directory / "provider-oauth-transactions.bin").exists()


def test_pending_encrypted_verifier_and_state_hash_bound_to_s256_challenge(
    fixture: Fixture,
) -> None:
    import base64
    import hashlib

    consent = fixture.begin()
    params = parse_qs(urlsplit(consent.url.get_secret_value()).query)
    state = params["state"][0]
    with fixture.authority._locked():
        row = fixture.authority._read()["rows"][hashlib.sha256(state.encode()).hexdigest()]
    verifier = row["verifier"]
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip("=")
    )
    assert params["code_challenge"] == [challenge]
    assert verifier not in consent.url.get_secret_value()
    data = (fixture.directory / "provider-oauth-transactions.bin").read_bytes()
    assert verifier.encode() not in data and state.encode() not in data


def test_registration_callback_expiry_advancement_denies_before_release(
    fixture: Fixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    state = fixture.state()
    original = fixture.registration.attest

    def checked_then_expired(configuration: Any, rotation: Any) -> None:
        original(configuration, rotation)
        fixture.sessions.now += timedelta(minutes=6)

    monkeypatch.setattr(fixture.registration, "attest", checked_then_expired)
    with pytest.raises(OAuthTransactionError) as raised:
        fixture.callback(state)
    safe(raised.value, state)


def test_documented_provider_denial_metadata_ignored_without_material(fixture: Fixture) -> None:
    state = fixture.state()
    assert (
        fixture.callback(
            state,
            query=urlencode(
                {
                    "state": state,
                    "error": "access_denied",
                    "error_description": "invented declined consent",
                    "error_uri": "https://invented.example/error",
                }
            ),
        )
        is None
    )
    with pytest.raises(OAuthTransactionError):
        fixture.callback(state)


@pytest.mark.parametrize("stage", ["begin", "callback", "release", "current"])
def test_queued_operation_rechecks_local_uncertainty_after_acquiring_flock(
    fixture: Fixture,
    monkeypatch: pytest.MonkeyPatch,
    stage: str,
) -> None:
    from contextlib import contextmanager

    state = fixture.state() if stage != "begin" else None
    operation = fixture.callback(state) if stage in {"release", "current"} else None
    original = fixture.authority._locked
    with original():
        before = fixture.authority._read()
    calls = fixture.registration.calls

    @contextmanager
    def queued_lock() -> Any:
        # The caller passed the pre-lock check. The current holder becomes
        # uncertain before this queued caller acquires the same flock.
        with original():
            fixture.authority._issuance_uncertain = True
            yield

    monkeypatch.setattr(fixture.authority, "_locked", queued_lock)
    with pytest.raises(OAuthTransactionUnconfirmed):
        if stage == "begin":
            fixture.begin()
        elif stage == "callback":
            fixture.callback(state)
        elif stage == "release":
            operation.take_exchange()
        else:
            operation.current()
    with original():
        assert fixture.authority._read() == before
    assert fixture.registration.calls == calls


def test_restarted_authority_watermark_guard_independent_of_valid_session_clock(
    fixture: Fixture,
) -> None:
    state = fixture.state()
    with fixture.authority._locked():
        before = fixture.authority._read()
        future = dict(before, watermark=(fixture.sessions.now + timedelta(minutes=1)).isoformat())
        fixture.authority._write(future)
    # Session and HostObservedClock still accept the unchanged actual host time.
    assert fixture.sessions.sessions.peek_user(fixture.sessions.cookie, fixture.sessions.now)
    assert fixture.sessions.continuity.for_cookie(fixture.sessions.cookie).establish()
    reopened = fixture.reopen()
    with pytest.raises(OAuthTransactionError):
        fixture.callback(state, authority=reopened)
    with reopened._locked():
        assert reopened._read() == future
        reopened._write(before)
    assert fixture.callback(state, authority=reopened) is not None


def test_other_actual_identity_cookie_cannot_begin_for_enrolled_owner(fixture: Fixture) -> None:
    from zacai.interfaces.session_store import Identity

    other = Identity("https://accounts.google.com", "invented-other-google-subject")
    fixture.sessions.cookie = fixture.sessions.sessions.start_user(other, fixture.sessions.now)
    fixture.sessions.csrf = fixture.sessions.sessions.peek_user(
        fixture.sessions.cookie, fixture.sessions.now
    ).csrf
    assert fixture.sessions.owner.identity == OWNER
    with pytest.raises(OAuthTransactionError):
        fixture.begin()
    assert fixture.registration.calls == 0


@pytest.mark.parametrize("extra", ["oversize_value", "too_many", "percent", "unicode"])
def test_bad_callback_bounds_do_not_attest_consume_or_mutate_and_valid_followup_works(
    fixture: Fixture,
    extra: str,
) -> None:
    state = fixture.state()
    query = urlencode({"state": state, "code": CODE})
    if extra == "oversize_value":
        query += "&hint=" + "x" * 2049
    elif extra == "too_many":
        query += "".join("&hint" + str(i) + "=x" for i in range(15))
    elif extra == "percent":
        query += "&hint=%ZZ"
    else:
        query += "&hint=%C3%A9"
    assert len(query) < 4096
    calls = fixture.registration.calls
    with fixture.authority._locked():
        before = fixture.authority._read()
    with pytest.raises(OAuthTransactionError) as raised:
        fixture.callback(state, query=query)
    safe(raised.value, state)
    assert fixture.registration.calls == calls
    with fixture.authority._locked():
        assert fixture.authority._read() == before
    assert fixture.callback(state) is not None


def test_actual_owner_cookie_helper_sets_secure_httponly_lax_callback_cookie() -> None:
    from starlette.responses import Response

    from zacai.interfaces.private_web import _set_cookie

    response = Response()
    _set_cookie(response, "__Host-zac-session", "invented-cookie", 300)
    cookie = response.headers["set-cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie
    assert "SameSite=lax" in cookie and "Path=/" in cookie
    assert "Domain=" not in cookie
