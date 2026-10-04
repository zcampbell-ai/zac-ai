"""Explicit trusted BRAINSTORM shadow wiring; no issuer, credentials or service.

Constructing this operator grants no approval. Actual use requires an already
committed human consent, protected checkpoint and exact trusted tokenizer/model.
The returned draft stays local and unevaluated; this module never publishes it.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from zacai.backup_artifacts import BackupObjectStore
from zacai.ingestion.artifact_store import ArtifactStore
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.eligibility import ApprovedRoute, ApprovedRouteRegistry
from zacai.intelligence.local_review_runtime import LocalPromptTokenCounter, LocalReviewRuntime
from zacai.intelligence.review_host import (
    ReviewSelection,
    ShadowReviewResult,
    execute_review_shadow,
)
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B
from zacai.review_authorization import CanonicalReviewAuthorization
from zacai.review_protection import BrainstormReviewProtector, DisposableStateRestoreVerifier
from zacai.review_recovery import BrainstormReviewRecoveryGate, ReviewRecoveryCheckpoint

_BOUNDARIES = frozenset({B.BRAINSTORM})
_LABELS = frozenset({C.CONFIDENTIAL})


class ReviewOperatorError(RuntimeError):
    """Fixed operator diagnostics; no private configuration/backend text."""


class BrainstormReviewOperator:
    """Wire the existing concrete adapters, preserving every host gate.

    The trusted host alone selects configuration and already committed authority.
    Authorization, recovery and protection use concrete implementations.
    Configuration objects remain trusted Python; this is not a sandbox against
    a caller replacing methods or supplying malicious subclasses.
    One successfully constructed instance owns one attempt, including target failure.
    New instances still cannot replay the canonical consent's durable claim.
    Construction performs no database, credential, artifact or model I/O.
    """

    def __init__(
        self,
        *,
        factory: sessionmaker[Session],
        engine: Engine,
        artifacts: ArtifactStore,
        objects: BackupObjectStore,
        verification_objects: BackupObjectStore,
        recipient: str,
        identity_path: Path,
        recovered_key_receipt: Path,
        checkpoint: ReviewRecoveryCheckpoint,
        manifest_cache: Path,
        approval_id: UUID,
        route: ModelRoute,
        model_digest: str,
        token_counter: LocalPromptTokenCounter,
        restoration: DisposableStateRestoreVerifier,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        try:
            url = engine.url
            if (
                url.drivername != "postgresql+psycopg"
                or url.host != "127.0.0.1"
                or url.port != 5432
                or url.database not in ("zacai_dev", "zacai_test")
                or url.password
                or url.query
                or factory.kw.get("bind") is not engine
                or objects is verification_objects
                or not isinstance(restoration, DisposableStateRestoreVerifier)
            ):
                raise ValueError("invalid controlled operator configuration")
            route = ModelRoute.model_validate(route)
            if route.destination != Destination.LOCAL or token_counter.model_digest != model_digest:
                raise ValueError("invalid local route/tokenizer binding")
            self._recovery = BrainstormReviewRecoveryGate(
                factory=factory,
                engine=engine,
                verification_objects=verification_objects,
                recipient=recipient,
                identity_path=identity_path,
                recovered_key_receipt=recovered_key_receipt,
                checkpoint=checkpoint,
                restoration=restoration,
            )
            self._authorization = CanonicalReviewAuthorization(
                factory=factory,
                store=artifacts,
                approval_id=approval_id,
                recovery=self._recovery,
                clock=clock,
            )
            self._runtime = LocalReviewRuntime(
                route=route,
                model_digest=model_digest,
                token_counter=token_counter,
            )
            self._protection = BrainstormReviewProtector(
                factory=factory,
                engine=engine,
                artifacts=artifacts,
                objects=objects,
                verification_objects=verification_objects,
                recipient=recipient,
                identity_path=identity_path,
                manifest_cache=manifest_cache,
                approval_id=approval_id,
                restoration=restoration,
            )
            self._registry = ApprovedRouteRegistry((ApprovedRoute(route, _BOUNDARIES, _LABELS),))
            self._factory, self._engine, self._artifacts, self._clock = (
                factory,
                engine,
                artifacts,
                clock,
            )
            self._attempted = False
            self._attempt_lock = Lock()
        except Exception:  # noqa: BLE001 - private operator configuration diagnostics
            raise ReviewOperatorError("review operator configuration rejected") from None

    def execute(self, selection: ReviewSelection) -> ShadowReviewResult:
        """One already-approved local shadow attempt; never issues consent.

        Target validation is read-only and precedes host/artifact/model actions.
        Other failures use the host's canonical audit and fail-closed behavior.
        A result does not establish semantic/style quality or permission to send.
        """
        with self._attempt_lock:
            if self._attempted:
                raise ReviewOperatorError("review operator attempt already consumed")
            self._attempted = True
        try:
            with self._engine.connect() as conn:
                conn.execute(text("SET TRANSACTION READ ONLY"))
                actual = conn.execute(
                    text(
                        "SELECT pg_catalog.current_database(), pg_catalog.inet_server_port(), "
                        "pg_catalog.host(pg_catalog.inet_server_addr())"
                    )
                ).one()
                if tuple(actual) != (self._engine.url.database, 5432, "127.0.0.1"):
                    raise ValueError("connected operator target differs")
                if conn.execute(
                    text("SELECT version_num FROM public.alembic_version")
                ).scalars().all() != ["0005"]:
                    raise ValueError("review operator requires protected schema 0005")
        except Exception:  # noqa: BLE001 - database diagnostics must stay private
            raise ReviewOperatorError("review operator target rejected; no host attempt") from None
        return execute_review_shadow(
            self._factory,
            artifacts=self._artifacts,
            selection=selection,
            authorized_boundaries=_BOUNDARIES,
            allowed_classifications=_LABELS,
            registry=self._registry,
            runtime=self._runtime,
            authorization=self._authorization,
            protection=self._protection,
            clock=self._clock,
        )
