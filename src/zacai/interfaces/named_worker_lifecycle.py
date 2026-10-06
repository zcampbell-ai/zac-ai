"""Operational real-thread lifecycle; no independent mode lease or authority.

Compose only inside the existing dedicated PrivateOperatorWindow.serve lifetime.
Its retained flock/log suppression/final thread drain remains authoritative.
This module neither starts a service nor grants session/source/model permission.
Actual canonical one-shot claim remains mandatory; restart loses this registry
and must reconcile pending operational/canonical records, never retry inference.
"""
from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime
from functools import partial
from threading import RLock, Thread
from typing import TYPE_CHECKING, Literal, TypeVar, cast
from uuid import UUID

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_admission_store import NamedAdmissionRecord, SqliteNamedAdmissionStore

if TYPE_CHECKING:
    from fastapi import FastAPI

    from zacai.interfaces.named_followup_web import NamedAskPipeline
    from zacai.interfaces.named_session_binding import NamedSessionOperation
    from zacai.interfaces.text_reply_capture import SavedTextReply

_T = TypeVar('_T')


class NamedWorkerLifecycleError(ValueError):
    """Fixed error only: worker exceptions/raw closure data are never chained."""


@dataclass(frozen=True)
class NamedWorkerRequest:
    request_id: UUID = field(repr=False)
    binding_digest: str = field(repr=False)
    admitted_at: datetime = field(repr=False)
    expires_at: datetime = field(repr=False)

    @classmethod
    def from_admission(cls, record: NamedAdmissionRecord) -> NamedWorkerRequest:
        if type(record) is not NamedAdmissionRecord:
            raise NamedWorkerLifecycleError('exact admitted worker scope required')
        record = NamedAdmissionRecord.model_validate(record)
        if record.phase != 'ADMITTED' or record.admitted_at is None or record.processing_expires_at is None:
            raise NamedWorkerLifecycleError('original admitted worker scope required')
        digest = content_hash_of(b'zac-named-worker-scope-v1\x00' + canonical_bytes({
            'manifest': record.manifest.model_dump(mode='json'), 'session_binding': record.session_binding,
            'question_digest': record.question_digest, 'question_bytes': record.question_bytes,
            'admitted_at': record.admitted_at.isoformat(),
            'expires_at': record.processing_expires_at.isoformat(),
        }))
        return cls(record.manifest.request_id, digest, record.admitted_at, record.processing_expires_at)


@dataclass(frozen=True)
class NamedWorkerDrain:
    request_id: UUID = field(repr=False)
    binding_digest: str = field(repr=False)

    @property
    def processing_authorized(self) -> Literal[False]: return False

    @property
    def execution_authorized(self) -> Literal[False]: return False


@dataclass(repr=False)
class _Job:
    lock: RLock = field(default_factory=RLock)
    thread: Thread | None = None
    result: object = None
    failed: bool = True
    consumed: bool = False
    started: bool = False


@dataclass(repr=False)
class _Worker:
    request: NamedWorkerRequest
    lock: RLock = field(default_factory=RLock)
    job: _Job | None = None
    retiring: bool = False
    reserved: bool = False


@dataclass(frozen=True, repr=False)
class _AdmissionReservation:
    issued: NamedAdmissionRecord
    handle: str
    question_digest: str
    question_bytes: int


class NamedWorkerRegistry:
    def __init__(self, *, clock: HostObservedClock, capacity: int = 128) -> None:
        if type(clock) is not HostObservedClock or type(capacity) is not int or not 1 <= capacity <= 128:
            raise NamedWorkerLifecycleError('named worker host unavailable')
        self._clock, self._capacity, self._lock = clock, capacity, RLock()
        self._entries: dict[UUID, _Worker] = {}
        self._reservations: dict[UUID, _AdmissionReservation] = {}
        self._closed = False

    @property
    def host_clock(self) -> HostObservedClock: return self._clock

    def _active(self, request: NamedWorkerRequest) -> None:
        if (type(request) is not NamedWorkerRequest or type(request.request_id) is not UUID
            or type(request.binding_digest) is not str or len(request.binding_digest) != 64
            or type(request.admitted_at) is not datetime or type(request.expires_at) is not datetime
            or request.admitted_at.utcoffset() is None or request.expires_at.utcoffset() is None
            or not request.admitted_at <= self._clock() < request.expires_at):
            raise NamedWorkerLifecycleError('original named worker window unavailable')

    def _start(self, request: NamedWorkerRequest, work: Callable[[], _T], *, check_only: bool, reserved_only: bool = False) -> _Job:
        if not callable(work): raise NamedWorkerLifecycleError('named worker callback unavailable')
        with self._lock:
            self._active(request)  # Time and registration checked under the same lifecycle guard.
            if self._closed: raise NamedWorkerLifecycleError('named workers closing')
            worker = self._entries.get(request.request_id)
            if check_only:
                if worker is None or worker.request != request or worker.reserved or worker.job is None:
                    raise NamedWorkerLifecycleError('original named worker missing')
            else:
                if worker is not None:
                    if not reserved_only:
                        raise NamedWorkerLifecycleError('original reserved worker binding unavailable')
                    if not worker.reserved or worker.job is not None or worker.request != request:
                        raise NamedWorkerLifecycleError('named dispatch already registered')
                    worker.reserved = False  # Transfer is consumed exactly once.
                else:
                    if reserved_only:
                        raise NamedWorkerLifecycleError('original reserved worker missing')
                    if request.request_id in self._reservations or len(self._entries)+len(self._reservations) >= self._capacity:
                        raise NamedWorkerLifecycleError('named worker capacity unavailable')
                    worker = _Worker(request)
                    self._entries[request.request_id] = worker
            with worker.lock:
                prior = worker.job
                if worker.retiring or (prior is not None and (
                    not prior.started or not prior.consumed or prior.thread is None or prior.thread.is_alive())):
                    raise NamedWorkerLifecycleError('named worker still active')
                job = _Job()
                worker.job = job
                def run() -> None:
                    result: object = None
                    failed = True
                    try:
                        result = work()
                        failed = False
                    except BaseException:  # noqa: BLE001,S110 - private diagnostics stay inside worker
                        pass
                    finally:
                        with job.lock:
                            job.result, job.failed = result, failed
                job.thread = Thread(target=run, name='caz-named-worker', daemon=False)
                start_failed = False
                try:
                    job.thread.start()
                    job.started = True
                except BaseException:  # noqa: BLE001
                    start_failed = True
                if start_failed:
                    # Retain ambiguous registration; no automatic second dispatch.
                    raise NamedWorkerLifecycleError('named worker start unavailable')
                return job

    def _join_result(self, job: _Job) -> object:
        thread = job.thread
        if thread is None or not job.started:
            raise NamedWorkerLifecycleError('named worker unavailable')
        thread.join()
        with job.lock:
            if thread.is_alive() or job.consumed:
                raise NamedWorkerLifecycleError('named worker not acknowledged')
            result, job.result = job.result, None
            job.consumed = True
            if job.failed: raise NamedWorkerLifecycleError('named worker not acknowledged')
            return result

    def run(self, request: NamedWorkerRequest, work: Callable[[], _T]) -> _T:
        return cast(_T, self._join_result(self._start(request, work, check_only=False)))

    def run_reserved(self, request: NamedWorkerRequest, work: Callable[[], _T]) -> _T:
        """Transfer only an existing exact placeholder; never allocate a new job."""
        return cast(_T, self._join_result(self._start(request, work, check_only=False, reserved_only=True)))

    def recheck(self, request: NamedWorkerRequest, read: Callable[[], _T]) -> _T:
        """Trusted canonical read continuation only, never another dispatch."""
        return cast(_T, self._join_result(self._start(request, read, check_only=True)))

    async def run_shielded(self, request: NamedWorkerRequest, work: Callable[[], _T]) -> _T:
        job = self._start(request, work, check_only=False)
        waiter = asyncio.create_task(asyncio.to_thread(self._join_result, job))
        cancelled = False
        result: object = None
        while True:
            try:
                result = await asyncio.shield(waiter)
                break
            except asyncio.CancelledError:
                cancelled = True
                # Client cancellation cannot mark the actual job drained or
                # release registration. Wait for native termination first.
                if waiter.cancelled():
                    # Loop-wide shutdown may cancel the waiter too. Physical
                    # foreground runner still joins every new native thread.
                    assert job.thread is not None
                    job.thread.join()
                    raise asyncio.CancelledError from None
            except NamedWorkerLifecycleError:
                if cancelled: raise asyncio.CancelledError from None
                raise
        if cancelled: raise asyncio.CancelledError from None
        return cast(_T, result)

    def retire_after_drain(self, request: NamedWorkerRequest, cleanup: Callable[[], object]) -> NamedWorkerDrain:
        """Caller supplies exact authenticated expiry writer, never a drain bool.

        Runs only for this registry's actual terminated job while its lifecycle
        guard is retained. Unknown/restarted jobs require explicit reconciliation.
        """
        with self._lock:
            worker = self._entries.get(request.request_id)
            if worker is None or worker.request != request or not callable(cleanup):
                raise NamedWorkerLifecycleError('known named worker required for retirement')
            with worker.lock:
                job = worker.job
                unused_placeholder = worker.reserved and job is None
                terminated = (job is not None and job.started and job.thread is not None
                              and not job.thread.is_alive())
                if (not (unused_placeholder or terminated) or self._clock() < request.expires_at):
                    raise NamedWorkerLifecycleError('named worker not terminal')
                if job is not None and job.thread is not None:
                    job.thread.join()
                worker.retiring = True
                cleanup_failed = False
                try:
                    if cleanup() is not None:
                        raise ValueError('terminal cleanup acknowledgement invalid')
                except Exception:  # noqa: BLE001
                    cleanup_failed = True
                if cleanup_failed:
                    worker.retiring = False
                    raise NamedWorkerLifecycleError('named worker retirement unavailable')
                del self._entries[request.request_id]
                return NamedWorkerDrain(request.request_id, request.binding_digest)

    def close_and_drain(self) -> None:
        with self._lock:
            self._closed = True
            jobs = [worker.job for worker in self._entries.values() if worker.job is not None]
            ambiguous = (bool(self._reservations) or any(worker.job is None for worker in self._entries.values())
                         or any(not job.started for job in jobs))
            threads = [job.thread for job in jobs if job.thread is not None
                       and (job.started or job.thread.ident is not None)]
        for thread in threads:
            thread.join()
        if ambiguous or any(thread.is_alive() for thread in threads):
            raise NamedWorkerLifecycleError('named worker shutdown held')


def install_named_worker_drain(app: FastAPI, workers: NamedWorkerRegistry,
                               *, pipeline: ThreadBoundNamedAskPipeline | None = None) -> None:
    """Compose before actual foreground serve; no listener or lease acquired here.

    Lifespan drain finishes before ASGI serve returns. Existing operator finally
    also joins all new threads before restoring logging/signals/releasing flock.
    """
    if pipeline is not None and (type(pipeline) is not ThreadBoundNamedAskPipeline
                                 or pipeline._workers is not workers or pipeline._store is None):
        raise NamedWorkerLifecycleError('paired worker shutdown unavailable')
    drain = workers.close_and_drain if pipeline is None else pipeline.close_and_retire
    previous = app.router.lifespan_context
    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[object]:
        async with previous(application) as state:
            try:
                yield state
            finally:
                import anyio
                with anyio.CancelScope(shield=True):
                    await anyio.to_thread.run_sync(drain, abandon_on_cancel=False)
    app.router.lifespan_context = lifespan  # type: ignore[assignment]


@dataclass(frozen=True, repr=False)
class _RetainedWorkerAdmission:
    request: NamedWorkerRequest
    handle: str
    session_binding: str


class ThreadBoundNamedAskPipeline:
    """Trusted pipeline wrapper, not a canonical pipeline or a permission grant.

    Methods intentionally preserve the existing native pipeline signatures.
    Underlying submit must be the reviewed one-shot canonical pipeline; recheck
    must be its read-only release path. The registry cannot inspect Python side
    effects or turn an arbitrary callback into canonical authority.
    """
    def __init__(self, *, workers: NamedWorkerRegistry, pipeline: NamedAskPipeline,
                 store: SqliteNamedAdmissionStore | None = None) -> None:
        if (type(workers) is not NamedWorkerRegistry or
            (store is not None and (type(store) is not SqliteNamedAdmissionStore
             or store._clock is not workers.host_clock))):
            raise NamedWorkerLifecycleError('named worker host unavailable')
        self._workers, self._pipeline, self._store = workers, pipeline, store
        self._retained: dict[UUID, _RetainedWorkerAdmission] = {}
        self._retention_lock = RLock()

    def _retire_completed(self) -> None:
        # Called with wrapper's metadata guard. No model/recovery callback under
        # it; only actual completed-job retirement and short operational writes.
        if self._store is None:
            return  # Legacy bounded wrapper, no invented cleanup acknowledgement.
        now = self._workers.host_clock()
        for request_id, retained in tuple(self._retained.items()):
            if now < retained.request.expires_at:
                continue
            with self._workers._lock:
                worker = self._workers._entries.get(request_id)
                if worker is None or worker.request != retained.request:
                    raise NamedWorkerLifecycleError('retained named worker reconciliation required')
                with worker.lock:
                    job = worker.job
                    eligible = (not worker.retiring and ((worker.reserved and job is None)
                                or (job is not None and job.started
                                    and job.thread is not None and not job.thread.is_alive())))
            if not eligible:
                continue  # Unknown start/active waiter remains held, never pruned.
            store = self._store
            try:
                self._workers.retire_after_drain(retained.request, partial(store.retire_expired,
                    handle=retained.handle, session_binding=retained.session_binding))
            except NamedWorkerLifecycleError:
                # Keep this exact known slot; failure does not consume other free
                # capacity or erase its pending record. No private error logging.
                continue
            del self._retained[request_id]

    def close_and_retire(self) -> None:
        """Actual thread drain then known-expired sweep, not startup reconciliation.

        Physical serving/operator leases remain owned by the enclosing host.
        Unknown or uncertain starts cannot become known unused reservations.
        """
        try:
            self._workers.close_and_drain()
        except NamedWorkerLifecycleError:
            # close_and_drain already joined actual started threads before its
            # ambiguity hold. Only exact known expired placeholders may resolve.
            pass
        with self._retention_lock:
            self._retire_completed()
        self._workers.close_and_drain()  # Final actual joins/unknown-outcome hold.

    def admit_reserved(self, *, issued_record: NamedAdmissionRecord,
                       admission_handle: str, original_utf8: bytes) -> NamedAdmissionRecord:
        """Concrete native host admission: secure capacity BEFORE consumption.

        No processing authority is granted by reservation. Raw handle stays only
        in repr-hidden transient memory. Any uncertain post-write outcome holds.
        No model/recovery/owner/session callback executes under registry locks.
        """
        if self._store is None or type(issued_record) is not NamedAdmissionRecord:
            raise NamedWorkerLifecycleError('concrete worker admission unavailable')
        record = NamedAdmissionRecord.model_validate(issued_record)
        if (record.phase != 'ISSUED' or type(original_utf8) is not bytes
            or not 0 < len(original_utf8) <= 8000):
            raise NamedWorkerLifecycleError('original issued worker scope required')
        text: str | None = None
        try:
            text = original_utf8.decode('utf-8', errors='strict')
        except UnicodeError:  # Private bytes must not escape in decoder diagnostics.
            pass
        if text is None or not text.strip() or len(text)>2000:
            raise NamedWorkerLifecycleError('bounded original worker question required')
        store, workers = self._store, self._workers
        reservation = _AdmissionReservation(record, admission_handle, content_hash_of(original_utf8),len(original_utf8))
        request_id = record.manifest.request_id
        with self._retention_lock:
            self._retire_completed()  # Real SQLite cleanup; registry lease is separate.
            if store.get(handle=admission_handle,session_binding=record.session_binding) != record:
                raise NamedWorkerLifecycleError('actual issued worker admission changed')
            now=workers.host_clock()
            if now >= record.manifest.admission_expires_at:
                raise NamedWorkerLifecycleError('original worker admission expired')
            with workers._lock:
                if (workers._closed or request_id in workers._entries or request_id in workers._reservations
                    or len(workers._entries)+len(workers._reservations)>=workers._capacity):
                    raise NamedWorkerLifecycleError('named worker capacity unavailable')
                workers._reservations[request_id]=reservation
        admitted: NamedAdmissionRecord | None = None
        failed=False
        try:
            admitted=store.admit_reserved_outcome(expected_issued=record,handle=admission_handle,session_binding=record.session_binding,
                question_digest=reservation.question_digest,question_bytes=reservation.question_bytes)
        except Exception:  # noqa: BLE001 - fixed diagnostics outside private exception context
            failed=True
        if failed:
            unchanged=False
            try:
                unchanged=store.status(handle=admission_handle,session_binding=record.session_binding)==record
            except Exception:  # noqa: BLE001,S110 - unknown outcome retains capacity
                pass
            if unchanged:
                with workers._lock:
                    if workers._reservations.get(request_id) is reservation:
                        del workers._reservations[request_id]
            raise NamedWorkerLifecycleError('named admission not acknowledged; reconcile pending outcome')
        if admitted == record:
            # Authenticated expired unchanged ISSUED was observed atomically in
            # the admission transaction. No later status read/purge can erase
            # that known no-write outcome. Missing/corrupt outcomes never reach it.
            with workers._lock:
                if workers._reservations.get(request_id) is reservation:
                    del workers._reservations[request_id]
            raise NamedWorkerLifecycleError('original worker admission expired')
        if (admitted is None or admitted.phase!='ADMITTED' or admitted.manifest!=record.manifest
            or admitted.session_binding!=record.session_binding or admitted.question_digest!=reservation.question_digest
            or admitted.question_bytes!=reservation.question_bytes):
            raise NamedWorkerLifecycleError('admitted worker scope changed; reconcile pending outcome')
        request=NamedWorkerRequest.from_admission(admitted)  # Actual original admitted_at/expiry only.
        with self._retention_lock, workers._lock:
            if workers._reservations.get(request_id) is not reservation:
                raise NamedWorkerLifecycleError('original worker reservation unavailable')
            del workers._reservations[request_id]
            workers._entries[request_id]=_Worker(request,reserved=True)
            self._retained[request_id]=_RetainedWorkerAdmission(request,admission_handle,record.session_binding)
        # Shutdown between reservation/admit still leaves the real admitted
        # placeholder held; _start rejects closed, never refunds or dispatches.
        return admitted

    def submit(self, *, operation: NamedSessionOperation, admission_handle: str,
               admitted_record: NamedAdmissionRecord, original_utf8: bytes) -> SavedTextReply:
        request = NamedWorkerRequest.from_admission(admitted_record)
        reserved = False
        if self._store is not None:
            with self._retention_lock:
                retained=self._retained.get(request.request_id)
                with self._workers._lock:
                    worker=self._workers._entries.get(request.request_id)
                    reserved=(retained is not None and worker is not None and worker.reserved
                              and worker.job is None and worker.request==request
                              and retained==_RetainedWorkerAdmission(request,admission_handle,admitted_record.session_binding))
                    placeholder = worker is not None and worker.reserved and worker.job is None
                if placeholder and not reserved:
                    raise NamedWorkerLifecycleError('original reserved worker binding unavailable')
                if not reserved:
                    # Capacity retirement belongs before new admission/allocation,
                    # not after a successfully reserved action was consumed.
                    self._retire_completed()
                if ((retained is not None and not reserved) or self._store.get(
                    handle=admission_handle, session_binding=admitted_record.session_binding) != admitted_record
                    or content_hash_of(original_utf8)!=admitted_record.question_digest
                    or len(original_utf8)!=admitted_record.question_bytes):
                    raise NamedWorkerLifecycleError('original worker admission unavailable')
                if not reserved:
                    # Direct trusted fixture/legacy use remains bounded but does
                    # not guarantee pre-admission capacity. Native host must use
                    # admit_reserved; it never enters this allocation branch.
                    with self._workers._lock:
                        if (self._workers._closed or request.request_id in self._workers._entries
                            or request.request_id in self._workers._reservations
                            or len(self._workers._entries)+len(self._workers._reservations)>=self._workers._capacity):
                            raise NamedWorkerLifecycleError('named worker capacity unavailable')
                        # Bind the placeholder and retention together before any
                        # concurrent wrapper/direct call can take the same slot.
                        self._workers._entries[request.request_id] = _Worker(request, reserved=True)
                        self._retained[request.request_id] = _RetainedWorkerAdmission(
                            request, admission_handle, admitted_record.session_binding)
                        reserved = True
        try:
            run = self._workers.run_reserved if reserved else self._workers.run
            return run(request, lambda: self._pipeline.submit(
                operation=operation, admission_handle=admission_handle,
                admitted_record=admitted_record, original_utf8=original_utf8))
        finally:
            # Only unregistered admission metadata may be removed here. Actual
            # attempted/ambiguous jobs persist until known termination + expiry.
            if self._store is not None:
                with self._retention_lock, self._workers._lock:
                    if request.request_id not in self._workers._entries:
                        self._retained.pop(request.request_id, None)

    def recheck(self, *, operation: NamedSessionOperation, admission_handle: str,
                admitted_record: NamedAdmissionRecord, original_utf8: bytes,
                saved: SavedTextReply) -> SavedTextReply:
        request = NamedWorkerRequest.from_admission(admitted_record)
        if self._store is not None:
            with self._retention_lock:
                current = self._store.get(handle=admission_handle,
                    session_binding=admitted_record.session_binding)
                # Authenticated attachments may advance phase after the original
                # one-shot admission. Preserve every original worker-scope field;
                # attachments are validated by the underlying canonical recheck.
                if (self._retained.get(request.request_id) != _RetainedWorkerAdmission(
                    request, admission_handle, admitted_record.session_binding)
                    or current.phase == 'ISSUED'
                    or current.manifest != admitted_record.manifest
                    or current.session_binding != admitted_record.session_binding
                    or current.admitted_at != admitted_record.admitted_at
                    or current.processing_expires_at != admitted_record.processing_expires_at
                    or current.question_digest != admitted_record.question_digest
                    or current.question_bytes != admitted_record.question_bytes
                    or type(original_utf8) is not bytes
                    or content_hash_of(original_utf8) != admitted_record.question_digest
                    or len(original_utf8) != admitted_record.question_bytes):
                    raise NamedWorkerLifecycleError('original retained worker binding unavailable')
        return self._workers.recheck(request, lambda: self._pipeline.recheck(
            operation=operation, admission_handle=admission_handle,
            admitted_record=admitted_record, original_utf8=original_utf8, saved=saved))
