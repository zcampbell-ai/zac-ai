"""Genuine invented owner/signature/encrypted SQLite session POST boundary.

All files live in a fresh private /private/tmp directory. No PostgreSQL,
canonical custody/recovery, provider, native credential or model call occurs.
"""

import json
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from urllib.parse import urlencode
from uuid import UUID, uuid4

import pytest
from starlette.requests import Request

from zacai import managed_catalog_custody as core
from zacai.host_clock import HostObservedClock
from zacai.ingestion.artifact_store import content_hash_of
from zacai.ingestion.managed_app_catalog_observation import (
    ManagedAppCatalogObservationScopeV1,
    ManagedAppToolDeclarationV1,
    prepare_managed_app_catalog_observation,
)
from zacai.interfaces import managed_catalog_post as m
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.owner_enrollment import OwnerEnrollment
from zacai.interfaces.owner_store import OwnerGrantStore
from zacai.interfaces.sqlite_sessions import SqliteSessionStore
from zacai.owner_authority import BoundaryScope, Identity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

ORIGIN = "https://catalog.example.test"
CLIENT = "123456-invented.apps.googleusercontent.com"


def catalog_preparation(
    now, *, classification=C.HIGHLY_RESTRICTED, raw=b'{"items":[]}'
):
    scope = ManagedAppCatalogObservationScopeV1(
        observation_id=uuid4(),
        representation="AS_RETURNED_TOOL_RESPONSE",
        tools=(
            ManagedAppToolDeclarationV1(
                provider="CLICKUP",
                reported_tool_name="clickup.list",
                declared_account_label="invented account",
            ),
        ),
        declared_navigation_selection="invented page",
        reported_acquired_at=now,
        inspected_at=now,
        reported_entry_count=0,
        reported_pagination="NOT_REPORTED",
        coverage_notes="selected page only",
        declared_input_hashes=(),
        classification=classification,
    )
    return prepare_managed_app_catalog_observation(
        raw=raw,
        scope=scope,
        requestor_boundaries=frozenset({B.BRAINSTORM}),
        allowed_classifications=frozenset({classification}),
    )


def save_owner(f, *, scopes=None, identity=None):
    enrollment = OwnerEnrollment(opened_at=f.now)
    identity = f.identity if identity is None else identity
    pending = enrollment.capture(identity, f.now, origin=ORIGIN)
    return f.owners.confirm_and_save(
        enrollment=enrollment,
        candidate_id=pending.candidate_id,
        pairing_code=pending.pairing_code,
        origin=ORIGIN,
        identity=identity,
        scopes=f.scopes if scopes is None else scopes,
        now=f.now,
    )


def make_catalog_post_case(root, *, classification=C.HIGHLY_RESTRICTED, scopes=None):
    """Caller supplies a fresh private /private/tmp root; all values invented."""
    root = Path(root)
    assert root.is_relative_to(Path("/private/tmp"))
    assert root.stat().st_uid == os.getuid() and root.stat().st_mode & 0o777 == 0o700
    f = SimpleNamespace(
        root=root,
        now=datetime(2026, 10, 15, 12, tzinfo=UTC),
        key=b"I" * 32,
        identity=Identity("https://accounts.google.com", "invented-catalog-owner"),
        scopes=(BoundaryScope(B.BRAINSTORM, frozenset({classification})),)
        if scopes is None
        else scopes,
    )
    f.clock = HostObservedClock(lambda: f.now)
    f.owners = OwnerGrantStore(
        root / "owner", key=f.key, origin=ORIGIN, client_id=CLIENT
    )
    save_owner(f)
    f.sessions = SqliteSessionStore(root / "sessions", key=f.key)
    f.cookie = f.sessions.start_user(f.identity, f.now)
    f.continuity = NamedSessionContinuity(
        sessions=f.sessions,
        owner=f.owners.load,
        clock=f.clock,
        key=f.key,
        origin=ORIGIN,
        client_id=CLIENT,
    )
    f.operation = f.continuity.for_cookie(f.cookie)
    f.preparation = catalog_preparation(f.now, classification=classification)
    f.request_id, f.expires_at = uuid4(), f.now + timedelta(minutes=5)
    f.csrf = f.sessions.peek_user(f.cookie, f.now).csrf
    f.selection_digest = core.catalog_capture_review_digest(
        f.request_id,
        f.preparation,
        f.expires_at,
    )
    return f


@pytest.fixture
def post_case():
    with TemporaryDirectory(
        prefix="caz-managed-catalog-post-", dir="/private/tmp"
    ) as name:
        yield make_catalog_post_case(Path(name))


def request(f, **changes):
    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "POST",
        "scheme": "https",
        "server": ("catalog.example.test", 443),
        "path": "/capture-managed-catalog",
        "query_string": b"",
        "headers": [
            (b"host", b"catalog.example.test"),
            (b"origin", ORIGIN.encode()),
            (b"content-type", b"application/x-www-form-urlencoded"),
            (b"cookie", f"__Host-zac-session={f.cookie}".encode()),
        ],
    }
    scope.update(changes)
    return Request(scope)


def body(f, **changes):
    return urlencode(
        {
            "action": "capture",
            "csrf": f.csrf,
            "request_id": str(f.request_id),
            "selection_digest": f.selection_digest,
            **changes,
        }
    ).encode()


def observe(f, **changes):
    return m.observe_managed_catalog_post(
        changes.pop("request", request(f)),
        body=changes.pop("body", body(f)),
        **{
            "operation": f.operation,
            "request_id": f.request_id,
            "preparation": f.preparation,
            "expires_at": f.expires_at,
            **changes,
        },
    )


def held(f, **changes):
    with pytest.raises(
        m.ManagedCatalogPostError,
        match="^managed catalog capture action not acknowledged$",
    ) as error:
        observe(f, **changes)
    assert error.value.__context__ is None


def test_actual_signed_owner_session_and_observed_post_grant_no_capture(
    post_case, monkeypatch
):
    f = post_case
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("observer must never capture")

    monkeypatch.setattr(core.CanonicalManagedCatalogCapture, "capture", forbidden)
    original = f.operation.establish()
    assert original.principal.identity == f.owners.load().identity
    assert not original.processing_authorized and not original.execution_authorized
    before = {str(p.relative_to(f.root)) for p in f.root.rglob("*")}
    decision = observe(f)
    assert decision.owner == original and decision.operation is f.operation
    assert (
        decision.request_id == f.request_id
        and decision.selection_digest == f.selection_digest
    )
    assert decision.expires_at == f.expires_at and decision.observed_at == f.now
    assert decision._once == [False] and calls == []
    assert {str(p.relative_to(f.root)) for p in f.root.rglob("*")} == before
    assert f.cookie not in repr(decision) and f.identity.subject not in repr(decision)
    assert (
        f.preparation.capture_authorized is f.preparation.processing_authorized is False
    )


def test_observed_decision_consumes_once_not_reusable_login_authority(post_case):
    f = post_case
    decision = observe(f)
    decision.consume()
    with pytest.raises(ValueError, match="unobserved or consumed catalog decision"):
        decision.consume()
    # Observation of a duplicate POST is not canonical replay acceptance. The
    # core's separate custody tests must deny duplicate request capture durably.
    second = observe(f)
    assert (
        second is not decision and decision._once == [True] and second._once == [False]
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("action", "approve"),
        ("action", ""),
        ("csrf", "invented-wrong-csrf"),
        ("csrf", ""),
        ("request_id", str(uuid4())),
        ("selection_digest", "f" * 64),
        ("extra", "PRIVATE_INVENTED_FORM_TEXT"),
    ],
)
def test_exact_reviewed_form_values_required(post_case, field, value):
    held(post_case, body=body(post_case, **{field: value}))


@pytest.mark.parametrize("field", ["action", "csrf", "request_id", "selection_digest"])
def test_duplicate_even_identical_form_fields_deny(post_case, field):
    fields = {
        "action": "capture",
        "csrf": post_case.csrf,
        "request_id": str(post_case.request_id),
        "selection_digest": post_case.selection_digest,
    }
    held(
        post_case,
        body=body(post_case) + b"&" + urlencode({field: fields[field]}).encode(),
    )


@pytest.mark.parametrize(
    "raw",
    [
        b"",
        b"X" * 2049,
        b"\xff",
        b"csrf=%FF",
        b"bad-field",
        b"action=capture&csrf=%ZZ",
        "not-bytes",
    ],
)
def test_bounded_ascii_closed_form_required(post_case, raw):
    held(post_case, body=raw)


@pytest.mark.parametrize(
    "change",
    [
        {"method": "GET"},
        {"method": "PUT"},
        {"path": "/other"},
        {"query_string": b"approval=true"},
    ],
)
def test_wrong_request_shape_deny(post_case, change):
    held(post_case, request=request(post_case, **change))


def test_http_denied_despite_exact_https_host_origin_cookie_and_csrf(post_case):
    f = post_case
    https_request = request(f)
    http_request = request(f, scheme="http")
    assert http_request.scope["headers"] == https_request.scope["headers"]
    assert http_request.url.scheme == "http"
    assert https_request.url.scheme == "https"
    # Positive control uses the same genuine current session and exact form.
    assert (
        observe(f, request=https_request, body=body(f)).owner == f.operation.establish()
    )
    held(f, request=http_request, body=body(f))


@pytest.mark.parametrize(
    "fault",
    [
        "host",
        "origin",
        "content-type",
        "duplicate-host",
        "duplicate-origin",
        "duplicate-content-type",
        "missing-cookie",
        "duplicate-cookie",
    ],
)
def test_actual_host_origin_form_and_cookie_headers_required(post_case, fault):
    headers = list(request(post_case).scope["headers"])
    if fault == "missing-cookie":
        headers = [(k, v) for k, v in headers if k != b"cookie"]
    elif fault.startswith("duplicate-"):
        name = fault.removeprefix("duplicate-").encode()
        headers.append(next((k, v) for k, v in headers if k == name))
    else:
        headers = [
            (k, b"invented-wrong-value" if k == fault.encode() else v)
            for k, v in headers
        ]
    held(post_case, request=request(post_case, headers=headers))


def test_same_owner_new_cookie_cannot_answer_original_operation(post_case):
    f = post_case
    replacement = f.sessions.start_user(f.identity, f.now)
    headers = [
        (k, f"__Host-zac-session={replacement}".encode() if k == b"cookie" else v)
        for k, v in request(f).scope["headers"]
    ]
    held(f, request=request(f, headers=headers))


@pytest.mark.parametrize(
    "kind",
    [
        "raw",
        "scope",
        "artifact-hash",
        "companion-bytes",
        "classification",
        "swapped-pair",
    ],
)
def test_exact_reviewed_pair_and_classification_cannot_change(post_case, kind):
    f, p = post_case, post_case.preparation
    first, second = p.artifacts
    if kind == "raw":
        changed = prepare_managed_app_catalog_observation(
            raw=b'{"items":["INVENTED_NEW_ROW"]}',
            scope=p.companion.scope,
            requestor_boundaries=frozenset({B.BRAINSTORM}),
            allowed_classifications=frozenset({C.HIGHLY_RESTRICTED}),
        )
    elif kind == "scope":
        changed = prepare_managed_app_catalog_observation(
            raw=first.original_bytes,
            scope=p.companion.scope.model_copy(
                update={"coverage_notes": "different reviewed scope"}
            ),
            requestor_boundaries=frozenset({B.BRAINSTORM}),
            allowed_classifications=frozenset({C.HIGHLY_RESTRICTED}),
        )
    elif kind == "artifact-hash":
        changed = replace(p, artifacts=(replace(first, content_hash="0" * 64), second))
    elif kind == "companion-bytes":
        altered = second.original_bytes + b" "
        changed = replace(
            p,
            artifacts=(
                first,
                replace(
                    second,
                    original_bytes=altered,
                    content_hash=content_hash_of(altered),
                ),
            ),
        )
    elif kind == "classification":
        changed = replace(
            p, artifacts=(replace(first, classification=C.CONFIDENTIAL), second)
        )
    else:
        changed = replace(p, artifacts=(second, first))
    held(f, preparation=changed)


@pytest.mark.parametrize(
    "changed", ["request", "deadline", "zero-id", "naive-deadline"]
)
def test_exact_review_target_and_window_are_bound(post_case, changed):
    if changed == "request":
        held(post_case, request_id=uuid4())
    elif changed == "deadline":
        held(post_case, expires_at=post_case.expires_at + timedelta(seconds=1))
    elif changed == "zero-id":
        held(post_case, request_id=UUID(int=0))
    else:
        held(post_case, expires_at=post_case.expires_at.replace(tzinfo=None))


@pytest.mark.parametrize(
    "scope",
    [
        (BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),),
        (BoundaryScope(B.PERSONAL, frozenset({C.HIGHLY_RESTRICTED})),),
        (
            BoundaryScope(
                B.BRAINSTORM, frozenset({C.CONFIDENTIAL, C.HIGHLY_RESTRICTED})
            ),
        ),
    ],
)
def test_current_signed_owner_scope_must_exactly_match_preparation(post_case, scope):
    save_owner(post_case, scopes=scope)
    held(post_case)


@pytest.mark.parametrize(
    "kind",
    [
        "owner-revoked",
        "session-revoked",
        "owner-changed",
        "unsigned-owner-tamper",
        "session-expired",
        "capture-expired",
    ],
)
def test_actual_owner_session_and_capture_deadline_currentness(post_case, kind):
    f = post_case
    if kind == "owner-revoked":
        f.owners.revoke()
    elif kind == "session-revoked":
        f.sessions.revoke(f.cookie)
    elif kind == "owner-changed":
        save_owner(f, identity=Identity(f.identity.issuer, "invented-different-owner"))
    elif kind == "unsigned-owner-tamper":
        path = f.root / "owner" / "owner.json"
        envelope = json.loads(path.read_text())
        envelope["payload"]["owner"]["subject"] = "unsigned-invented-replacement"
        path.write_text(json.dumps(envelope))
    elif kind == "session-expired":
        f.now += timedelta(hours=8)
    else:
        f.now = f.expires_at
    held(f)


def test_deadline_cannot_exceed_original_session_or_fifteen_minutes(post_case):
    f = post_case
    for expiry in (
        f.now + timedelta(minutes=15, microseconds=1),
        f.operation.establish().effective_expires_at + timedelta(seconds=1),
    ):
        f.selection_digest = core.catalog_capture_review_digest(
            f.request_id, f.preparation, expiry
        )
        held(f, expires_at=expiry)


def test_final_owner_callback_revocation_holds_observer(post_case, monkeypatch):
    f, original = post_case, post_case.continuity._owner
    calls = []

    def changed():
        calls.append(True)
        if len(calls) == 7:  # Final operation.recheck begins after both establishments.
            f.sessions.revoke(f.cookie)
        return original()

    monkeypatch.setattr(f.continuity, "_owner", changed)
    held(f)
    assert len(calls) >= 7


def test_final_owner_callback_capture_expiry_holds_observer(post_case, monkeypatch):
    f, original = post_case, post_case.continuity._owner
    calls = []

    def changed():
        calls.append(True)
        if len(calls) == 7:
            f.now = f.expires_at
        return original()

    monkeypatch.setattr(f.continuity, "_owner", changed)
    held(f)
    assert len(calls) >= 7
