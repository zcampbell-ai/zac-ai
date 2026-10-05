"""Explicit trusted BRAINSTORM shadow wiring; no issuer, credentials or service.

Constructing this operator grants no approval. Actual use requires an already
committed human consent, protected checkpoint and exact trusted tokenizer/model.
The returned draft stays local and unevaluated; this module never publishes it.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from zacai.backup_artifacts import BackupObjectStore
from zacai.contextual_attempt import AttemptRecoveryReceipt, protect_failed_attempt
from zacai.contextual_authorization import (
    BrainstormContextualRecoveryGate,
    CanonicalContextualAuthorization,
)
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.contextual_recovery_record import ContextualRecoveryReceipt
from zacai.ingestion.artifact_store import ArtifactStore
from zacai.intelligence.contextual_host import (
    ContextualHostFailure,
    ContextualHostResult,
    execute_contextual_shadow,
)
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.eligibility import ApprovedRoute, ApprovedRouteRegistry
from zacai.intelligence.local_contextual_runtime import LocalContextualRuntime
from zacai.intelligence.local_review_runtime import LocalPromptTokenCounter
from zacai.intelligence.research_context import ResearchReviewSelection
from zacai.intelligence.review_host import ReviewSelection
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.review_recovery import BrainstormReviewRecoveryGate, ReviewRecoveryCheckpoint

_BOUNDARIES = frozenset({B.BRAINSTORM})
_LABELS = frozenset({C.CONFIDENTIAL})


class ContextualOperatorError(RuntimeError):
    """Fixed operator diagnostics; no private configuration/backend text."""


class BrainstormContextualOperator:
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
        builder_id: UUID,
        route: ModelRoute,
        model_digest: str,
        token_counter: LocalPromptTokenCounter,
        restoration: DisposableStateRestoreVerifier,
        max_output_tokens: int = 1600,
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
            if type(max_output_tokens) is not int or max_output_tokens not in {1600, 3200} or max_output_tokens > route.max_output_tokens:
                raise ValueError("invalid approved contextual budget")
            self._max_output_tokens = max_output_tokens
            if (
                route.destination != Destination.LOCAL
                or token_counter.model_digest != model_digest
                or "contextual_meeting_review" not in route.capabilities
                or "compact_meeting_review" in route.capabilities
                or not isinstance(builder_id, UUID)
            ):
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
            self._authorization = CanonicalContextualAuthorization(
                factory=factory,
                store=artifacts,
                approval_id=approval_id,
                recovery=BrainstormContextualRecoveryGate(self._recovery),
                clock=clock,
            )
            self._runtime = LocalContextualRuntime(
                route=route,
                model_digest=model_digest,
                token_counter=token_counter,
            )
            self._protection = BrainstormContextualProtector(
                factory=factory,
                engine=engine,
                artifacts=artifacts,
                objects=objects,
                verification_objects=verification_objects,
                recipient=recipient,
                identity_path=identity_path,
                manifest_cache=manifest_cache,
                restoration=restoration,
                approval_id=approval_id,
            )
            self._registry = ApprovedRouteRegistry((ApprovedRoute(route, _BOUNDARIES, _LABELS),))
            self._factory, self._engine, self._artifacts, self._clock = (
                factory,
                engine,
                artifacts,
                clock,
            )
            self._approval_id, self._builder_id = approval_id, builder_id
            self._failure_receipt: AttemptRecoveryReceipt | None = None
            self._recovery_receipt: ContextualRecoveryReceipt | None = None
            self._attempted = False
            self._attempt_lock = Lock()
            return
        except Exception:  # noqa: BLE001, S110
            pass
        raise ContextualOperatorError("contextual operator configuration rejected")

    @property
    def recovery_receipt(self) -> ContextualRecoveryReceipt | None:
        """Recovery metadata retained even if lease cleanup withholds the packet."""
        return self._recovery_receipt

    @property
    def failed_recovery_receipt(self) -> AttemptRecoveryReceipt | None:
        """Failure evidence only; no approval, retry or captured-packet release."""
        return self._failure_receipt

    def execute(self, selection: ReviewSelection | ResearchReviewSelection) -> ContextualHostResult:
        """One committed approval, with complete failed-attempt recovery if possible.

        A cross-process operator lease prevents concurrent backup/manifest work
        by this operator. It does not coordinate unrelated backup programs/admins;
        use an exclusive operator recovery window. No service is enabled here.
        """
        with self._attempt_lock:
            if self._attempted:
                raise ContextualOperatorError("contextual operator attempt already consumed")
            self._attempted = True
        failure: ContextualHostFailure | None = None
        result: ContextualHostResult | None = None
        interruption: type[BaseException] | None = None
        host_entered = False
        recovery_failed = False
        lease_failed = False
        exit_code = 1

        def remember(error: BaseException) -> None:
            nonlocal interruption, exit_code
            if isinstance(error, (KeyboardInterrupt, SystemExit, asyncio.CancelledError)):
                if interruption is None or not issubclass(
                    interruption, (KeyboardInterrupt, SystemExit, asyncio.CancelledError)
                ):
                    interruption = type(error)
                    if isinstance(error, SystemExit):
                        exit_code = error.code if type(error.code) is int and error.code != 0 else 1
            elif interruption is None:
                interruption = type(error)

        def observe(value: ContextualHostFailure) -> None:
            nonlocal failure
            failure = value

        try:
            with self._engine.connect() as lease:
                lease.execute(text("SET TRANSACTION READ ONLY"))
                actual = lease.execute(
                    text(
                        "SELECT pg_catalog.current_database(), pg_catalog.inet_server_port(), "
                        "pg_catalog.host(pg_catalog.inet_server_addr()), current_schema()"
                    )
                ).one()
                if tuple(actual) != (self._engine.url.database, 5432, "127.0.0.1", "public"):
                    raise ValueError("connected operator target differs")
                if lease.execute(
                    text("SELECT version_num FROM public.alembic_version")
                ).scalars().all() != ["0005"]:
                    raise ValueError("protected schema required")
                lease.execute(text("SET LOCAL idle_in_transaction_session_timeout = 0"))
                if (
                    lease.scalar(text("SELECT current_setting('server_version_num')::integer"))
                    >= 170000
                ):
                    lease.execute(text("SET LOCAL transaction_timeout = 0"))
                # Transaction-scoped lease releases even when rollback/connection cleanup fails.
                if not lease.scalar(text("SELECT pg_try_advisory_xact_lock(73403416)")):
                    raise ValueError("another contextual operator active")

                def require_lease() -> None:
                    if not lease.scalar(
                        text(
                            "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' "
                            "AND pid=pg_backend_pid() AND classid=0 AND objid=73403416 "
                            "AND objsubid=1 AND granted)"
                        )
                    ):
                        raise ValueError("operator lease lost")

                self._protection._lease_guard = require_lease
                try:
                    host_entered = True
                    result = execute_contextual_shadow(
                        self._factory,
                        artifacts=self._artifacts,
                        selection=selection,
                        builder_id=self._builder_id,
                        authorized_boundaries=_BOUNDARIES,
                        allowed_classifications=_LABELS,
                        registry=self._registry,
                        runtime=self._runtime,
                        authorization=self._authorization,
                        protection=self._protection,
                        clock=self._clock,
                        failure_observer=observe,
                        max_output_tokens=self._max_output_tokens,
                    )
                    self._recovery_receipt = result.recovery_receipt
                    require_lease()
                except BaseException as error:  # noqa: BLE001 - discard private host diagnostics
                    remember(error)
                    if result is not None:
                        lease_failed = True
                if result is None:
                    if failure is None:
                        recovery_failed = True
                    else:
                        try:
                            require_lease()
                            self._failure_receipt = protect_failed_attempt(
                                self._protection,
                                failure=failure,
                                approval_id=self._approval_id,
                                builder_id=self._builder_id,
                                clock=self._clock,
                            )
                            require_lease()
                        except BaseException as error:  # noqa: BLE001 - preserve cancellation
                            remember(error)
                            recovery_failed = self._failure_receipt is None
                            if self._failure_receipt is not None:
                                lease_failed = True
        except BaseException as error:  # noqa: BLE001 - safe cleanup/target errors
            remember(error)
            lease_failed = True
        finally:
            self._protection._lease_guard = None
        if interruption is not None:
            if issubclass(interruption, KeyboardInterrupt):
                raise KeyboardInterrupt
            if issubclass(interruption, SystemExit):
                raise SystemExit(exit_code)
            if issubclass(interruption, asyncio.CancelledError):
                raise asyncio.CancelledError
        if result is not None:
            if lease_failed:
                raise ContextualOperatorError(
                    "operator lease release unverified; packet recovery verified; no output released"
                )
            return result
        if not host_entered:
            raise ContextualOperatorError(
                "contextual operator target or lease rejected; no host attempt"
            )
        if recovery_failed:
            raise ContextualOperatorError(
                "contextual attempt failed; recovery unavailable; no output released"
            )
        if lease_failed:
            raise ContextualOperatorError(
                "contextual attempt failed; failure recovery verified; lease release unverified; no output released"
            )
        raise ContextualOperatorError(
            "contextual attempt failed; failure recovery verified; no output released"
        )
