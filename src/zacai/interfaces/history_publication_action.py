"""Complete-family actual POST observation; not a supplied approval or runtime gate."""

from __future__ import annotations

import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal
from urllib.parse import parse_qs

from starlette.requests import Request

from zacai.claude_local_custody import _SCOPE
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.history_generation_review_declaration import (
    HistoryGenerationReviewDeclarationV1,
    history_generation_review_declaration_digest,
)
from zacai.intelligence.history_review_retention import _parts, history_declaration_owner
from zacai.interfaces.named_session_binding import (
    NamedSessionContinuity,
    NamedSessionOperation,
    VerifiedNamedSession,
)
from zacai.interfaces.private_web import _USER, _cookie
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")
_ACTION_SEAL = object()
_ACTIONS: dict[str, Literal["APPROVE", "WITHDRAW"]] = {
    "approve_history_generation_and_review": "APPROVE",
    "withdraw_history_generation_and_review": "WITHDRAW",
}


class HistoryPublicationWebError(ValueError):
    """Fixed browser observation hold; no privacy traceback chain."""


@dataclass(frozen=True, repr=False)
class _HistoryPostObservation:
    purpose: Literal["APPROVE", "WITHDRAW"]
    publication: HistoryGenerationReviewDeclarationV1 = field(repr=False)
    reference: EvidenceReference
    operation: NamedSessionOperation = field(repr=False)
    current_session: VerifiedNamedSession = field(repr=False)
    observed_at: datetime


class _PostedHistoryAction:
    """One-use internal HTTP observation, neither constructor nor JSON approval.

    There is no public constructor or supplied approval bool. Only the validated
    concrete HTTP observation function below mints the instance. Trusted Python
    with access to private implementation state is outside this boundary.
    """

    _seal: object
    _used: bool
    _observation: _HistoryPostObservation

    def __init__(self) -> None:
        raise HistoryPublicationWebError("validated browser action required")


def _same_current(a: VerifiedNamedSession, b: VerifiedNamedSession) -> bool:
    return (
        a.principal == b.principal
        and a.binding_digest == b.binding_digest
        and a.issued_at == b.issued_at
        and a.expires_at == b.expires_at
        and a.effective_expires_at == b.effective_expires_at
    )


def _observe_history_http_post(
    *,
    request: Request,
    body: bytes,
    continuity: NamedSessionContinuity,
    publication: HistoryGenerationReviewDeclarationV1,
    reference: EvidenceReference,
    operation: NamedSessionOperation,
) -> _PostedHistoryAction:
    """Actual handler seam after bounded streaming; independently checks HTTP.

    Caller must pass the actual ASGI request and its exact body, never fabricated
    client declarations or a replaced pre-parsed action. Runtime/input readiness
    and canonical target checks remain necessary in the consuming controller.
    """
    result = None
    try:
        if (
            type(request) is not Request
            or type(reference) is not EvidenceReference
            or reference.source_id.int == 0
            or reference.trust_boundary is not B.PERSONAL
            or reference.effective_classification is not C.HIGHLY_RESTRICTED
            or type(continuity) is not NamedSessionContinuity
            or type(body) is not bytes
            or not 0 < len(body) <= 2048
            or request.method != "POST"
            or request.url.path != "/ask-caz-locally"
            or request.scope.get("query_string", b"")
            or request.headers.getlist("content-type") != ["application/x-www-form-urlencoded"]
        ):
            raise ValueError("closed original POST required")
        import json

        origin = json.loads(continuity._context)["origin"]
        from urllib.parse import urlsplit

        if request.headers.getlist("host") != [urlsplit(origin).netloc] or request.headers.getlist(
            "origin"
        ) != [origin]:
            raise ValueError("original host/origin required")
        raw_cookie = _cookie(request, _USER)
        if type(operation) is not NamedSessionOperation or operation._source is not continuity:
            raise ValueError("original host operation required")
        before = operation.establish()
        observed_cookie = continuity.for_cookie(raw_cookie).establish()
        if not _same_current(before, observed_cookie):
            raise ValueError("actual original cookie differs")
        current = continuity._sessions.peek_user(raw_cookie, continuity._clock())
        if current is None or current.identity != before.principal.identity:
            raise ValueError("current actual browser session required")
        fields = parse_qs(
            body.decode("ascii", errors="strict"), keep_blank_values=True, strict_parsing=True
        )
        if set(fields) != {"action", "csrf", "publication_digest", "source_id"} or any(
            len(v) != 1 for v in fields.values()
        ):
            raise ValueError("closed exact action fields required")
        purpose = _ACTIONS.get(fields["action"][0])
        if (
            purpose is None
            or _TOKEN.fullmatch(fields["csrf"][0]) is None
            or not secrets.compare_digest(fields["csrf"][0], current.csrf)
            or fields["publication_digest"][0]
            != history_generation_review_declaration_digest(publication)
            or fields["source_id"][0] != str(reference.source_id)
        ):
            raise ValueError("exact published target/CSRF required")
        raw, g, _ = _parts(publication)
        from zacai.ingestion.artifact_store import content_hash_of

        if reference.content_hash != content_hash_of(raw):
            raise ValueError("exact immutable target required")
        continuity._clock()
        actual = operation.recheck(before.binding_digest)
        with continuity._clock._lock:
            observed_at = continuity._clock._last
        if observed_at is None:
            raise ValueError("actual owner clock observation required")
        if (
            not _same_current(before, actual)
            or actual.principal.scopes != _SCOPE
            or (actual.principal.identity.issuer, actual.principal.identity.subject)
            != (g.owner_issuer, g.owner_subject)
            or not actual.issued_at <= observed_at < actual.effective_expires_at
        ):
            raise ValueError("current exact owner required")
        if purpose == "APPROVE" and (
            actual.binding_digest != g.original_session_binding
            or actual.issued_at != g.original_session_issued_at
            or actual.effective_expires_at != g.original_session_expires_at
            or not g.approved_at <= observed_at < g.expires_at
        ):
            raise ValueError("original publication session/window required")
        observation = _HistoryPostObservation(
            purpose, publication, reference, operation, actual, observed_at
        )
        result = object.__new__(_PostedHistoryAction)
        result._seal = _ACTION_SEAL
        result._used = False
        result._observation = observation
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryPublicationWebError("validated browser publication action unavailable")
    return result


def _consume_history_post(
    action: _PostedHistoryAction, *, purpose: Literal["APPROVE", "WITHDRAW"]
) -> _HistoryPostObservation:
    """Consume once before callbacks; wrong purpose cannot consume another action.

    A WITHDRAW observation may use a fresh current same-owner cookie after the
    original processing window. It never replaces or renews original processing.
    The withdrawal writer must separately prove its historical canonical target.
    """
    result = None
    try:
        if (
            type(action) is not _PostedHistoryAction
            or action._seal is not _ACTION_SEAL
            or action._used is not False
            or type(action._observation) is not _HistoryPostObservation
            or action._observation.purpose != purpose
        ):
            raise ValueError("exact one-use HTTP observation required")
        action._used = True
        observation = action._observation
        _, g, _ = _parts(observation.publication)
        observation.operation.host_clock()
        actual = observation.operation.recheck(observation.current_session.binding_digest)
        with observation.operation.host_clock._lock:
            now = observation.operation.host_clock._last
        if now is None:
            raise ValueError("current exact action time required")
        if (
            not _same_current(actual, observation.current_session)
            or actual.principal.scopes != _SCOPE
            or (actual.principal.identity.issuer, actual.principal.identity.subject)
            != (g.owner_issuer, g.owner_subject)
            or not actual.issued_at <= now < actual.effective_expires_at
        ):
            raise ValueError("current exact action owner required")
        if purpose == "APPROVE":
            history_declaration_owner(observation.operation, observation.operation.host_clock, g)
        result = observation
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise HistoryPublicationWebError("validated browser publication action unavailable")
    return result
