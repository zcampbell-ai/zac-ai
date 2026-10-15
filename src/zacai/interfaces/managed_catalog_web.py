"""Optional fixed owner catalog actions, using existing authentication only.

Trusted host supplies a reviewed exact observation and whole-BRAINSTORM recovery
configuration, OR an explicit pinned decision reference for read-existing mode.
No provider, credential discovery, processing, task generation or communication.
Mount only before serving. Host must preserve existing private ingress/log/thread
isolation and independent writer exclusion; this adapter does not configure them.
"""

from __future__ import annotations

import secrets
from datetime import datetime
from html import escape
from threading import RLock
from typing import Literal
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

from anyio.to_thread import run_sync
from fastapi import FastAPI
from starlette.requests import Request
from starlette.responses import HTMLResponse, Response

from zacai.contextual_protection import BrainstormContextualProtector
from zacai.ingestion.managed_app_catalog_observation import (
    ManagedAppCatalogObservationPreparationV1,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.interfaces.managed_catalog_post import observe_managed_catalog_post
from zacai.interfaces.named_session_binding import (
    NamedSessionContinuity,
    NamedSessionOperation,
    VerifiedNamedSession,
)
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.interfaces.private_web import _USER, _cookie
from zacai.interfaces.session_store import UserSession
from zacai.managed_catalog_admission import catalog_claim_root
from zacai.managed_catalog_custody import (
    CanonicalManagedCatalogCapture,
    catalog_capture_review_digest,
)
from zacai.managed_catalog_navigation import lookup_catalog_navigation
from zacai.managed_catalog_recovery import CanonicalManagedCatalogRecovery
from zacai.owner_authority import BoundaryScope, Identity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

_SCOPE = (BoundaryScope(B.BRAINSTORM, frozenset({C.HIGHLY_RESTRICTED})),)
_PATHS = frozenset({"/managed-catalog", "/capture-managed-catalog", "/lookup-managed-catalog"})


class ManagedCatalogWebError(ValueError):
    """Fixed transport/configuration failure without private request diagnostics."""


def _document(body: str) -> HTMLResponse:
    text = (
        '<!doctype html><html lang="en"><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        "<title>Caz AI context lookup</title><body><main>" + body + "</main></body></html>"
    )
    if len(text.encode("utf-8")) > 256000:
        raise ValueError("bounded complete page required")
    return HTMLResponse(text)


class ManagedCatalogWeb:
    """One configured capture attempt, or read-existing lookup of one exact ref.

    Reopened values are not authority. Each lookup creates an actual fresh
    recovery operation, reopens and uses its single source-owned release check.
    """

    def __init__(
        self,
        *,
        inputs: NamedOwnerHostInputs,
        protector: BrainstormContextualProtector,
        expected_identity: Identity,
        preparation: ManagedAppCatalogObservationPreparationV1 | None = None,
        request_id: UUID | None = None,
        expires_at: datetime | None = None,
        decision_reference: EvidenceReference | None = None,
    ) -> None:
        okay = False
        try:
            if (
                type(inputs) is not NamedOwnerHostInputs
                or type(protector) is not BrainstormContextualProtector
                or type(expected_identity) is not Identity
            ):
                raise ValueError("exact host dependencies required")
            capture = preparation is not None
            if capture:
                if (
                    type(preparation) is not ManagedAppCatalogObservationPreparationV1
                    or preparation.companion.scope.classification is not C.HIGHLY_RESTRICTED
                    or type(request_id) is not UUID
                    or not request_id.int
                    or type(expires_at) is not datetime
                    or expires_at.utcoffset() is None
                    or decision_reference is not None
                ):
                    raise ValueError("fixed highly restricted capture configuration required")
                digest = catalog_capture_review_digest(request_id, preparation, expires_at)
            else:
                if (
                    request_id is not None
                    or expires_at is not None
                    or type(decision_reference) is not EvidenceReference
                    or decision_reference.trust_boundary is not B.BRAINSTORM
                    or decision_reference.effective_classification is not C.HIGHLY_RESTRICTED
                ):
                    raise ValueError("explicit read-existing reference required")
                digest = None
            self._inputs, self._protector, self._identity = inputs, protector, expected_identity
            self._preparation, self._request_id, self._expires = preparation, request_id, expires_at
            self._decision_reference, self._digest = decision_reference, digest
            self._reference_pin = decision_reference
            self._mode: Literal["CAPTURE", "READ_EXISTING"] = (
                "CAPTURE" if capture else "READ_EXISTING"
            )
            self._continuity = NamedSessionContinuity(
                sessions=inputs.sessions,
                owner=inputs.owner,
                clock=inputs.clock,
                key=inputs.session_key,
                origin=inputs.origin,
                client_id=inputs.client_id,
            )
            self._pins = self._values()
            self._protector_pins = self._protection_values()
            self._lock = RLock()
            self._phase = "NEW" if capture else "READ_EXISTING"
            self._mounted = False
            self._configuration()
            okay = True
        except Exception:  # noqa: BLE001,S110
            pass
        if not okay:
            raise ManagedCatalogWebError("managed catalog host unavailable")

    def _values(self) -> tuple[object, ...]:
        return (
            self._inputs,
            self._protector,
            self._identity,
            self._preparation,
            self._request_id,
            self._expires,
            self._digest,
            self._mode,
        )

    def _protection_values(self) -> tuple[object, ...]:
        p = self._protector
        return (
            p._engine,
            p._factory,
            p._artifacts,
            p._objects,
            p._reader,
            p._recipient,
            p._identity,
            p._cache,
            p._restoration,
            p._approval_id,
        )

    def _configuration(self) -> None:
        if (
            self._values() != self._pins
            or self._protection_values() != self._protector_pins
            or self._decision_reference != self._reference_pin
        ):
            raise ValueError("original catalog configuration changed")
        self.assert_inputs(self._inputs)
        if self._mode == "CAPTURE":
            assert (
                self._request_id is not None
                and self._preparation is not None
                and self._expires is not None
            )
            if (
                catalog_capture_review_digest(self._request_id, self._preparation, self._expires)
                != self._digest
            ):
                raise ValueError("original exact pair changed")

    def assert_inputs(self, inputs: NamedOwnerHostInputs) -> None:
        expected = NamedSessionContinuity(
            sessions=inputs.sessions,
            owner=inputs.owner,
            clock=inputs.clock,
            key=inputs.session_key,
            origin=inputs.origin,
            client_id=inputs.client_id,
        )
        c = self._continuity
        if (
            inputs is not self._inputs
            or c._sessions is not inputs.sessions
            or c._owner is not inputs.owner
            or c._clock is not inputs.clock
            or c._context != expected._context
            or c._key != expected._key
        ):
            raise ValueError("original catalog host binding required")

    def _owner(
        self, request: Request
    ) -> tuple[NamedSessionOperation, VerifiedNamedSession, UserSession]:
        self._configuration()
        if (
            request.url.scheme != "https"
            or request.scope.get("query_string", b"")
            or request.headers.getlist("host") != [urlsplit(self._inputs.origin).netloc]
        ):
            raise ValueError("exact private HTTPS host required")
        cookie = _cookie(request, _USER)
        operation = self._continuity.for_cookie(cookie)
        owner = operation.establish()
        current = self._inputs.sessions.peek_user(cookie, self._inputs.clock())
        if (
            owner.principal.identity != self._identity
            or owner.principal.scopes != _SCOPE
            or current is None
            or current.identity != self._identity
        ):
            raise ValueError("current exact owner scope required")
        self._configuration()  # actual owner/session callbacks may change host inputs
        return operation, owner, current

    def _form(
        self, request: Request, body: bytes, fields: frozenset[str]
    ) -> tuple[NamedSessionOperation, VerifiedNamedSession, dict[str, str]]:
        operation, owner, current = self._owner(request)
        if (
            request.method != "POST"
            or request.headers.getlist("origin") != [self._inputs.origin]
            or request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]
            or type(body) is not bytes
            or not 0 < len(body) <= 4096
        ):
            raise ValueError("closed same-origin form required")
        values = parse_qs(
            body.decode("ascii", errors="strict"),
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
        )
        if (
            set(values) != fields
            or any(len(value) != 1 for value in values.values())
            or not secrets.compare_digest(values["csrf"][0], current.csrf)
        ):
            raise ValueError("exact owner form required")
        return operation, owner, {key: value[0] for key, value in values.items()}

    def _lookup_form(self, csrf: str) -> str:
        return (
            '<form method="post" action="/lookup-managed-catalog">'
            '<input type="hidden" name="action" value="lookup">'
            f'<input type="hidden" name="csrf" value="{escape(csrf, quote=True)}">'
            '<label>Exact account or project name <input name="exact_name" maxlength="200" required></label>'
            '<button type="submit">Find observed locations</button></form>'
        )

    def page(self, request: Request) -> HTMLResponse:
        operation, owner, current = self._owner(request)
        if request.method != "GET":
            raise ValueError("GET required")
        content = "<h1>Caz AI context lookup</h1><p>One dated navigation observation. No messages, meeting transcripts or current status are inferred.</p>"
        if self._mode == "CAPTURE" and self._phase == "NEW":
            p = self._preparation
            assert p is not None and self._expires is not None
            scope = p.companion.scope
            content += (
                f"<h2>Save the reviewed navigation observation</h2><p>BRAINSTORM / HIGHLY_RESTRICTED.</p>"
                f"<p>Inspected: {escape(scope.inspected_at.isoformat())}. Reported acquired: {escape(str(scope.reported_acquired_at))}.</p>"
                f"<p>Selection: {escape(scope.declared_navigation_selection)}</p>"
                f"<p>Coverage: {escape(scope.coverage_notes)}. Pagination: {escape(scope.reported_pagination)}. Representation: {escape(scope.representation)}.</p>"
                f"<p>Raw SHA256: {p.artifacts[0].content_hash}<br>Companion SHA256: {p.artifacts[1].content_hash}</p>"
                "<p>This action saves these two files and an owner decision, then verifies encrypted recovery of the whole BRAINSTORM artifact, State and journal boundary. It does not approve AI processing or any communication.</p>"
                f"<p>One-attempt deadline: {escape(self._expires.isoformat())}. Durable claim directory: {escape(str(catalog_claim_root(self._protector._cache)))}</p>"
            )
            if self._inputs.clock() < self._expires:
                content += (
                    '<form method="post" action="/capture-managed-catalog">'
                    '<input type="hidden" name="action" value="capture">'
                    f'<input type="hidden" name="csrf" value="{escape(current.csrf, quote=True)}">'
                    f'<input type="hidden" name="request_id" value="{self._request_id}">'
                    f'<input type="hidden" name="selection_digest" value="{self._digest}">'
                    '<button type="submit">Save and verify this context once</button></form>'
                )
            else:
                content += "<p>This original capture window has expired. Do not retry it.</p>"
        elif self._decision_reference is not None and self._phase in ("COMPLETE", "READ_EXISTING"):
            content += (
                "<p>Read-existing mode. Every lookup freshly verifies this saved observation and current access. No new capture is authorized.</p>"
                + self._lookup_form(current.csrf)
            )
        else:
            content += (
                "<p>Capture is held or in progress. Reconcile it before doing anything else.</p>"
            )
        response = _document(content)
        if operation.recheck(owner.binding_digest) != owner:
            raise ValueError("owner changed during review")
        self._configuration()
        if not self._inputs.clock() < owner.effective_expires_at:
            raise ValueError("owner review session expired")
        return response

    def capture(self, request: Request, body: bytes) -> HTMLResponse:
        if not self._lock.acquire(blocking=False):
            raise ManagedCatalogWebError("managed catalog capture unavailable")
        try:
            operation, _, _ = self._form(
                request, body, frozenset({"action", "csrf", "request_id", "selection_digest"})
            )
            if self._mode != "CAPTURE" or self._phase != "NEW":
                raise ValueError("original capture only")
            assert (
                self._request_id is not None
                and self._preparation is not None
                and self._expires is not None
            )
            decision = observe_managed_catalog_post(
                request,
                body=body,
                operation=operation,
                request_id=self._request_id,
                preparation=self._preparation,
                expires_at=self._expires,
            )
            # All malformed/unauthenticated requests above leave NEW untouched.
            self._phase = "ENTERED"
            try:
                core = CanonicalManagedCatalogCapture(
                    protector=self._protector,
                    operation=operation,
                    expected_identity=self._identity,
                    request_id=self._request_id,
                    preparation=self._preparation,
                    expires_at=self._expires,
                )
                checkpoint = core.capture(decision)
                self._decision_reference = self._reference_pin = checkpoint.references[2]
                self._phase = "COMPLETE"
            except BaseException:
                self._phase = "HELD"
                raise
            response = _document(
                '<h1>Context saved and recovery checked</h1><p>No AI processing or communication was authorized.</p><a href="/managed-catalog">Look up an observed location</a>'
            )
            self._configuration()
            if not self._inputs.clock() < min(self._expires, decision.owner.effective_expires_at):
                self._phase = "HELD"
                raise ValueError("original capture expired before response")
            return response
        finally:
            self._lock.release()

    def lookup(self, request: Request, body: bytes) -> HTMLResponse:
        if not self._lock.acquire(blocking=False):
            raise ManagedCatalogWebError("managed catalog operation already running")
        try:
            return self._lookup(request, body)
        finally:
            self._lock.release()

    def _lookup(self, request: Request, body: bytes) -> HTMLResponse:
        operation, owner, values = self._form(
            request, body, frozenset({"action", "csrf", "exact_name"})
        )
        name = values["exact_name"]
        if (
            values["action"] != "lookup"
            or self._decision_reference is None
            or self._phase not in ("COMPLETE", "READ_EXISTING")
            or not 0 < len(name) <= 200
            or name != name.strip()
            or len(name.encode("utf-8")) > 800
            or any(ord(c) < 32 or ord(c) == 127 for c in name)
        ):
            raise ValueError("explicit saved observation and exact name required")
        reference = self._decision_reference
        gate = CanonicalManagedCatalogRecovery(
            protector=self._protector, operation=operation, expected_identity=self._identity
        )
        reopened = gate.reopen(decision_reference=reference)
        result = lookup_catalog_navigation(reopened=reopened, exact_name=values["exact_name"])
        scope = result.observation
        content = (
            f"<h1>Observed navigation matches</h1><p>{escape(result.status)}</p>"
            f"<p>Inspected: {escape(scope.inspected_at.isoformat())}. Reported acquired: {escape(str(scope.reported_acquired_at))}. Access/recovery checked: {escape(result.checked_at.isoformat())}.</p>"
            f"<p>Coverage: {escape(scope.coverage_notes)}. Pagination: {escape(scope.reported_pagination)}. Representation: {escape(scope.representation)}.</p>"
            "<p>Names, IDs and URL text below are untrusted navigation hints, not verified current accounts, project status, messages or meeting content. No exact match means only not found in this bounded dated observation.</p>"
        )
        for candidate in result.candidates:
            content += (
                f"<section><h2>{escape(candidate.object_pointer or '(root object)')}</h2><dl>"
            )
            for key, value in candidate.observed_scalar_hints:
                content += f"<dt>{escape(key)}</dt><dd>{escape(value)}</dd>"
            content += "</dl></section>"
        content += (
            "<p>Source references: "
            + ", ".join(escape(str(r.source_id) + ":" + r.content_hash) for r in result.references)
            + "</p>"
        )
        response = _document(content)
        self._configuration()
        if self._decision_reference != reference:
            raise ValueError("configured decision reference changed")
        release_at = gate.recheck_reopened(reopened=reopened, original_binding=owner.binding_digest)
        self._configuration()  # pure graph/reference check, no owner or source callbacks
        if not release_at <= self._inputs.clock() < owner.effective_expires_at:
            raise ValueError("original lookup session expired during final graph check")
        return response


def install_managed_catalog_routes(app: FastAPI, controller: ManagedCatalogWeb) -> None:
    """Trusted pre-serve mount only; never start a listener or replace auth routes."""
    if (
        type(app) is not FastAPI
        or type(controller) is not ManagedCatalogWeb
        or controller._mounted
        or any(getattr(route, "path", None) in _PATHS for route in app.routes)
    ):
        raise ManagedCatalogWebError("managed catalog mount unavailable")
    controller._configuration()
    controller._mounted = True

    async def body(request: Request, limit: int) -> bytes:
        raw = bytearray()
        async for chunk in request.stream():
            if len(raw) + len(chunk) > limit:
                raise ValueError("bounded form required")
            raw.extend(chunk)
        return bytes(raw)

    @app.get("/managed-catalog")
    def review(request: Request) -> Response:
        try:
            return controller.page(request)
        except Exception:  # noqa: BLE001
            return Response("Catalog review unavailable", status_code=403)

    @app.post("/capture-managed-catalog")
    async def capture(request: Request) -> Response:
        try:
            return await run_sync(
                controller.capture, request, await body(request, 2048), abandon_on_cancel=False
            )
        except Exception:  # noqa: BLE001
            return Response("Catalog capture held. Reconcile before retrying.", status_code=403)

    @app.post("/lookup-managed-catalog")
    async def lookup(request: Request) -> Response:
        try:
            return await run_sync(
                controller.lookup, request, await body(request, 4096), abandon_on_cancel=False
            )
        except Exception:  # noqa: BLE001
            return Response("Catalog lookup unavailable", status_code=403)
