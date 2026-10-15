"""Thin same-cookie/CSRF issuance for one configured catalog capture decision.

No route is mounted, source is captured or backup/model invoked here. Shared
capture/recovery logic lives in managed_catalog_custody, independent of HTTP.
"""

from __future__ import annotations

import json
import secrets
from datetime import datetime, timedelta
from urllib.parse import parse_qs, urlsplit
from uuid import UUID

from starlette.requests import Request

from zacai.ingestion.managed_app_catalog_observation import (
    ManagedAppCatalogObservationPreparationV1,
)
from zacai.interfaces.named_session_binding import NamedSessionOperation
from zacai.interfaces.private_web import _USER, _cookie
from zacai.managed_catalog_custody import (
    _DECISION_KEY,
    _ManagedCatalogOwnerDecision,
    catalog_capture_review_digest,
)
from zacai.owner_authority import BoundaryScope
from zacai.policy import TrustBoundary as B


class ManagedCatalogPostError(ValueError):
    """Fixed failure without identity, cookie or submitted content."""


def observe_managed_catalog_post(
    request: Request,
    *,
    body: bytes,
    operation: NamedSessionOperation,
    request_id: UUID,
    preparation: ManagedAppCatalogObservationPreparationV1,
    expires_at: datetime,
) -> _ManagedCatalogOwnerDecision:
    """Bind an actual owner action to the exact server-held pair and window.

    The request handler must limit the stream before calling this observer.
    A private witness is meaningful only through unchanged actual owner checks;
    it is not a sandbox against trusted Python callers constructing private data.
    """
    result = None
    try:
        if (
            type(request) is not Request
            or type(operation) is not NamedSessionOperation
            or type(body) is not bytes
            or not 0 < len(body) <= 2048
            or request.url.scheme != "https"
            or request.method != "POST"
            or request.url.path != "/capture-managed-catalog"
            or request.scope.get("query_string", b"")
            or request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]
        ):
            raise ValueError("closed owner catalog POST required")
        digest = catalog_capture_review_digest(request_id, preparation, expires_at)
        continuity = operation._source
        origin = json.loads(continuity._context)["origin"]
        if request.headers.getlist("host") != [urlsplit(origin).netloc] or request.headers.getlist(
            "origin"
        ) != [origin]:
            raise ValueError("same-origin owner action required")
        cookie = _cookie(request, _USER)
        first = operation.establish()
        observed = continuity.for_cookie(cookie).establish()
        if observed != first:
            raise ValueError("actual original cookie required")
        now = operation.host_clock()
        current = continuity._sessions.peek_user(cookie, now)
        values = parse_qs(
            body.decode("ascii", errors="strict"),
            keep_blank_values=True,
            strict_parsing=True,
            encoding="utf-8",
            errors="strict",
        )
        if (
            current is None
            or set(values) != {"action", "csrf", "request_id", "selection_digest"}
            or any(len(v) != 1 for v in values.values())
            or values["action"] != ["capture"]
            or values["request_id"] != [str(request_id)]
            or values["selection_digest"] != [digest]
            or not secrets.compare_digest(values["csrf"][0], current.csrf)
            or current.identity != first.principal.identity
            or preparation.companion.scope.inspected_at > now
            or not now < expires_at <= first.effective_expires_at
            or expires_at - now > timedelta(minutes=15)
        ):
            raise ValueError("exact reviewed capture action required")
        final = operation.recheck(first.binding_digest)
        final_time = operation.host_clock()
        if (
            final != first
            or not now <= final_time < expires_at
            or final.principal.scopes
            != (
                BoundaryScope(
                    B.BRAINSTORM, frozenset({preparation.companion.scope.classification})
                ),
            )
        ):
            raise ValueError("current exact catalog owner scope required")
        result = _ManagedCatalogOwnerDecision(
            request_id, digest, expires_at, now, final, operation, _DECISION_KEY
        )
    except Exception:  # noqa: BLE001,S110 - no private request/config diagnostics
        pass
    if result is None:
        raise ManagedCatalogPostError("managed catalog capture action not acknowledged")
    return result
