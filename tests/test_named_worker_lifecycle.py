"""Real native-thread lifecycle, invented scope only; no SQL/source/model/proof."""
import asyncio
from datetime import UTC, datetime, timedelta
from threading import Event, Thread
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import FastAPI

from zacai.interfaces import named_worker_lifecycle as m
from zacai.interfaces.host_clock import HostObservedClock


@pytest.fixture
def s():
    state = SimpleNamespace(now=datetime(2026, 10, 5, tzinfo=UTC))
    state.clock = HostObservedClock(lambda: state.now)
    state.registry = m.NamedWorkerRegistry(clock=state.clock)
    state.request = m.NamedWorkerRequest(uuid4(), 'a'*64, state.now, state.now+timedelta(minutes=2))
    return state


def test_actual_thread_terminal_and_duplicate_denial(s):
    entered, release, ended = Event(), Event(), Event()
    result = []
    def work():
        entered.set()
        try: assert release.wait(5)
        finally: ended.set()
        return 'invented'
    caller = Thread(target=lambda: result.append(s.registry.run(s.request, work)))
    caller.start()
    assert entered.wait(5)
    try:
        with pytest.raises(m.NamedWorkerLifecycleError): s.registry.run(s.request, lambda: pytest.fail('duplicate'))
        s.now = s.request.expires_at
        with pytest.raises(m.NamedWorkerLifecycleError): s.registry.retire_after_drain(s.request, lambda: pytest.fail('alive cleanup'))
    finally:
        release.set(); caller.join(5)
    assert ended.is_set() and not caller.is_alive() and result == ['invented']
    cleanup = []
    proof = s.registry.retire_after_drain(s.request, lambda: cleanup.append('cleanup'))
    assert cleanup == ['cleanup'] and not proof.processing_authorized and not proof.execution_authorized
    with pytest.raises(m.NamedWorkerLifecycleError): s.registry.run(s.request, lambda: pytest.fail('renew'))


def test_failed_work_sanitized_no_retry(s):
    def work(): raise ValueError('private question secret')
    with pytest.raises(m.NamedWorkerLifecycleError) as caught: s.registry.run(s.request, work)
    assert caught.value.__context__ is None and 'private' not in str(caught.value)
    with pytest.raises(m.NamedWorkerLifecycleError): s.registry.run(s.request, lambda: pytest.fail('retry'))
    s.now = s.request.expires_at
    s.registry.retire_after_drain(s.request, lambda: None)


def test_read_continuation_is_registered_until_termination(s):
    assert s.registry.run(s.request, lambda: 1) == 1
    entered, release = Event(), Event()
    result = []
    def read():
        entered.set(); assert release.wait(5); return 2
    caller = Thread(target=lambda: result.append(s.registry.recheck(s.request, read)))
    caller.start(); assert entered.wait(5)
    try:
        with pytest.raises(m.NamedWorkerLifecycleError): s.registry.recheck(s.request, lambda: pytest.fail('parallel read'))
        s.now = s.request.expires_at
        with pytest.raises(m.NamedWorkerLifecycleError): s.registry.retire_after_drain(s.request, lambda: pytest.fail('active'))
    finally: release.set(); caller.join(5)
    assert result == [2]
    s.registry.retire_after_drain(s.request, lambda: None)


def test_repeated_cancellation_waits_real_finally(s):
    entered, release, ended = Event(), Event(), Event()
    def work():
        entered.set()
        try: assert release.wait(5)
        finally: ended.set()
        return 'private result'
    async def scenario():
        task = asyncio.create_task(s.registry.run_shielded(s.request, work))
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel(); await asyncio.sleep(0)
        task.cancel(); await asyncio.sleep(0)
        assert not task.done() and not ended.is_set()
        release.set()
        with pytest.raises(asyncio.CancelledError): await task
        assert ended.is_set()
        job = s.registry._entries[s.request.request_id].job
        assert job.thread is not None and not job.thread.is_alive()
    try: asyncio.run(scenario())
    finally: release.set(); s.registry.close_and_drain()


def test_close_drain_blocks_until_native_worker_finishes(s):
    entered, release, drained = Event(), Event(), Event()
    caller = Thread(target=lambda: s.registry.run(s.request, lambda: (entered.set(), release.wait(5))))
    caller.start(); assert entered.wait(5)
    closer = Thread(target=lambda: (s.registry.close_and_drain(), drained.set()))
    closer.start()
    try:
        assert not drained.wait(.03)
        with pytest.raises(m.NamedWorkerLifecycleError): s.registry.run(s.request, lambda: None)
    finally: release.set(); caller.join(5); closer.join(5)
    assert drained.is_set() and not caller.is_alive() and not closer.is_alive()


def test_lifespan_drains_before_foreground_lease_cleanup(s):
    app = FastAPI()
    m.install_named_worker_drain(app, s.registry)
    entered, release, exiting, returned = Event(), Event(), Event(), Event()
    order = []
    def work():
        entered.set()
        try: assert release.wait(5)
        finally: order.append('worker finally')
    caller = Thread(target=lambda: s.registry.run(s.request, work))
    def release_after_observing_exit_hold():
        assert exiting.wait(5)
        assert not returned.wait(.03)
        release.set()
    helper = Thread(target=release_after_observing_exit_hold)
    async def serve():
        async with app.router.lifespan_context(app):
            caller.start(); assert await asyncio.to_thread(entered.wait, 5)
            helper.start(); exiting.set()
        order.append('serve returned'); returned.set()
    try:
        asyncio.run(serve())
    finally:
        release.set(); caller.join(5); helper.join(5)
        order.append('foreground lease/log finally')
    assert order == ['worker finally','serve returned','foreground lease/log finally']
    assert not caller.is_alive() and not helper.is_alive()


def test_cleanup_failure_hidden_and_registration_retained(s):
    s.registry.run(s.request, lambda: None); s.now=s.request.expires_at
    def cleanup(): raise ValueError('private nonce')
    with pytest.raises(m.NamedWorkerLifecycleError) as caught: s.registry.retire_after_drain(s.request, cleanup)
    assert caught.value.__context__ is None and 'nonce' not in str(caught.value)
    assert s.request.request_id in s.registry._entries
    s.registry.retire_after_drain(s.request, lambda: None)


def test_unknown_restart_and_active_cleanup_hold(s):
    with pytest.raises(m.NamedWorkerLifecycleError): s.registry.retire_after_drain(s.request, lambda: None)
    s.registry.run(s.request, lambda: None)
    with pytest.raises(m.NamedWorkerLifecycleError): s.registry.retire_after_drain(s.request, lambda: None)
    assert str(s.request.request_id) not in repr(s.request)
    entry_repr = repr(s.registry._entries[s.request.request_id])
    assert str(s.request.request_id) not in entry_repr
    assert s.request.binding_digest not in entry_repr


@pytest.fixture
def admission_workers(tmp_path,monkeypatch):
    # Actual invented encrypted operational SQLite; no canonical SQL/model.
    from tests.test_named_admission_store import fixture as store_fixture
    from zacai.interfaces.named_admission_store import named_admission_nonce_digest
    state=store_fixture.__wrapped__(tmp_path,monkeypatch)
    state.registry=m.NamedWorkerRegistry(clock=state.clock,capacity=1)
    state.calls=0
    state.entered,state.release=Event(),Event()
    state.block=False
    class Pipeline:
        def submit(self,**kwargs):
            state.calls+=1
            assert named_admission_nonce_digest(kwargs['admission_handle'])==kwargs['admitted_record'].manifest.nonce_digest
            if state.block:
                state.entered.set(); assert state.release.wait(5)
        def recheck(self,**kwargs):return None
    state.wrapper=m.ThreadBoundNamedAskPipeline(workers=state.registry,pipeline=Pipeline(),store=state.store)
    def new():
        issued=state.issue()
        record=state.store.admit(handle=issued.handle,session_binding=state.session,
            question_digest=m.content_hash_of(b'inventeddata'),question_bytes=12)
        return issued,record
    state.new=new
    state.submit=lambda issued,record:state.wrapper.submit(operation=None,admission_handle=issued.handle,
        admitted_record=record,original_utf8=b'inventeddata')
    return state


def test_actual_expired_completed_retirement_reuses_capacity_repeatedly(admission_workers):
    import sqlite3
    s=admission_workers
    originals=[]
    for _ in range(5):
        issued,record=s.new(); originals.append(issued.handle)
        s.submit(issued,record)
        assert len(s.registry._entries)==len(s.wrapper._retained)==1
        s.now=record.processing_expires_at
    assert s.calls==5
    with sqlite3.connect(s.store._path) as conn:
        assert conn.execute('SELECT COUNT(*) FROM admissions').fetchone()[0]==1
    assert all(item.handle not in repr(item) and item.session_binding not in repr(item)
               for item in s.wrapper._retained.values())


def test_actual_cleanup_failure_holds_capacity_and_original_record(admission_workers,monkeypatch):
    s=admission_workers
    first,record=s.new(); s.submit(first,record); s.now=record.processing_expires_at
    original=s.store.retire_expired
    def failed(**kwargs):raise ValueError('invented operational failure')
    monkeypatch.setattr(s.store,'retire_expired',failed)
    second,newrecord=s.new()
    with pytest.raises(m.NamedWorkerLifecycleError):s.submit(second,newrecord)
    assert s.calls==1 and record.manifest.request_id in s.registry._entries
    assert record.manifest.request_id in s.wrapper._retained
    monkeypatch.setattr(s.store,'retire_expired',original)
    s.submit(second,newrecord)
    assert s.calls==2 and record.manifest.request_id not in s.registry._entries


def test_active_or_unexpired_completed_worker_never_retired(admission_workers):
    s=admission_workers
    first,record=s.new(); s.submit(first,record)
    second,newrecord=s.new()
    with pytest.raises(m.NamedWorkerLifecycleError):s.submit(second,newrecord)
    assert s.calls==1 and len(s.registry._entries)==1
    s.now=record.processing_expires_at
    # A genuinely new active request triggers retirement; the other consumed
    # admission remains outside registry knowledge, never deleted/resumed.
    third,thirdrecord=s.new()
    s.submit(third,thirdrecord)
    assert s.calls==2
    import sqlite3
    with sqlite3.connect(s.store._path) as conn:
        assert conn.execute('SELECT COUNT(*) FROM admissions').fetchone()[0]==2


def test_expired_running_thread_is_not_cleanup_witness(admission_workers):
    s=admission_workers
    first,record=s.new();s.block=True
    failures=[]
    def call():
        try:s.submit(first,record)
        except m.NamedWorkerLifecycleError as exc:failures.append(type(exc))
    caller=Thread(target=call);caller.start();assert s.entered.wait(5)
    s.now=record.processing_expires_at
    second,newrecord=s.new()
    try:
        with pytest.raises(m.NamedWorkerLifecycleError):s.submit(second,newrecord)
        assert record.manifest.request_id in s.registry._entries
        assert s.calls==1
    finally:s.release.set();caller.join(5)
    assert not caller.is_alive() and not failures
    s.block=False;s.submit(second,newrecord)
    assert s.calls==2


def test_store_clock_identity_mismatch_denied(admission_workers):
    s=admission_workers
    other=m.NamedWorkerRegistry(clock=HostObservedClock(lambda:s.now))
    with pytest.raises(m.NamedWorkerLifecycleError):
        m.ThreadBoundNamedAskPipeline(workers=other,pipeline=s.wrapper._pipeline,store=s.store)


def test_reservation_counts_before_actual_admission_and_transfers_once(admission_workers):
    s=admission_workers
    one=s.issue();two=s.issue()
    admitted=s.wrapper.admit_reserved(issued_record=one.record,admission_handle=one.handle,original_utf8=b'inventeddata')
    assert not s.registry._reservations and s.registry._entries[one.record.manifest.request_id].reserved
    with pytest.raises(m.NamedWorkerLifecycleError):
        s.wrapper.admit_reserved(issued_record=two.record,admission_handle=two.handle,original_utf8=b'inventeddata')
    assert s.store.get(handle=two.handle,session_binding=s.session).phase=='ISSUED'
    s.submit(one,admitted)
    assert s.calls==1 and not s.registry._entries[one.record.manifest.request_id].reserved
    with pytest.raises(m.NamedWorkerLifecycleError):s.submit(one,admitted)


def test_unused_reservation_released_only_after_actual_unchanged_issued_read(admission_workers,monkeypatch):
    s=admission_workers;one=s.issue()
    actual=s.store.admit_reserved_outcome
    def fail_before_write(**kwargs):raise ValueError('invented store failure')
    monkeypatch.setattr(s.store,'admit_reserved_outcome',fail_before_write)
    with pytest.raises(m.NamedWorkerLifecycleError):
        s.wrapper.admit_reserved(issued_record=one.record,admission_handle=one.handle,original_utf8=b'inventeddata')
    assert not s.registry._reservations and not s.registry._entries
    assert s.store.get(handle=one.handle,session_binding=s.session).phase=='ISSUED'
    monkeypatch.setattr(s.store,'admit_reserved_outcome',actual)
    admitted=s.wrapper.admit_reserved(issued_record=one.record,admission_handle=one.handle,original_utf8=b'inventeddata')
    s.submit(one,admitted);assert s.calls==1


def test_unknown_postcommit_store_error_keeps_capacity_and_never_retries(admission_workers,monkeypatch):
    s=admission_workers;one=s.issue();two=s.issue();actual=s.store.admit_reserved_outcome
    def commit_then_fail(**kwargs):
        actual(**kwargs);raise ValueError('invented ambiguous acknowledgement')
    monkeypatch.setattr(s.store,'admit_reserved_outcome',commit_then_fail)
    with pytest.raises(m.NamedWorkerLifecycleError):
        s.wrapper.admit_reserved(issued_record=one.record,admission_handle=one.handle,original_utf8=b'inventeddata')
    assert s.store.get(handle=one.handle,session_binding=s.session).phase=='ADMITTED'
    assert len(s.registry._reservations)==1 and not s.registry._entries and s.calls==0
    with pytest.raises(m.NamedWorkerLifecycleError):
        s.wrapper.admit_reserved(issued_record=two.record,admission_handle=two.handle,original_utf8=b'inventeddata')
    assert s.store.get(handle=two.handle,session_binding=s.session).phase=='ISSUED'
    with pytest.raises(m.NamedWorkerLifecycleError):s.registry.close_and_drain()


def test_two_concurrent_original_actions_compete_before_consumption(admission_workers):
    import sqlite3
    from concurrent.futures import ThreadPoolExecutor
    s=admission_workers;one=s.issue();two=s.issue()
    def admit(issued):
        try:
            return s.wrapper.admit_reserved(issued_record=issued.record,admission_handle=issued.handle,original_utf8=b'inventeddata')
        except m.NamedWorkerLifecycleError:return None
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(admit,(one,two)))
    assert sum(r is not None for r in results)==1
    assert len(s.registry._entries)==1 and not s.registry._reservations and s.calls==0
    with sqlite3.connect(s.store._path) as conn:
        assert sorted(row[0] for row in conn.execute('SELECT phase FROM admissions'))==['ADMITTED','ISSUED']


def test_shutdown_between_reserved_admission_and_start_is_consumed_hold(admission_workers):
    s=admission_workers;one=s.issue()
    admitted=s.wrapper.admit_reserved(issued_record=one.record,admission_handle=one.handle,original_utf8=b'inventeddata')
    with pytest.raises(m.NamedWorkerLifecycleError):s.registry.close_and_drain()
    with pytest.raises(m.NamedWorkerLifecycleError):s.submit(one,admitted)
    assert s.store.get(handle=one.handle,session_binding=s.session).phase=='ADMITTED'
    assert one.record.manifest.request_id in s.registry._entries and s.calls==0


def test_close_joins_started_thread_before_reporting_other_start_ambiguity(s,monkeypatch):
    entered,release,closed=Event(),Event(),Event()
    caller=Thread(target=lambda:s.registry.run(s.request,lambda:(entered.set(),release.wait(5))))
    caller.start();assert entered.wait(5)
    actual_start=Thread.start
    def fail_named_start(thread):
        if thread.name=='caz-named-worker':raise RuntimeError('invented start failure')
        return actual_start(thread)
    monkeypatch.setattr(Thread,'start',fail_named_start)
    other=m.NamedWorkerRequest(uuid4(),'b'*64,s.request.admitted_at,s.request.expires_at)
    with pytest.raises(m.NamedWorkerLifecycleError):s.registry.run(other,lambda:None)
    failures=[]
    def close():
        try:s.registry.close_and_drain()
        except m.NamedWorkerLifecycleError:failures.append('held')
        finally:closed.set()
    closer=Thread(target=close);closer.start()
    try:assert not closed.wait(.03)
    finally:release.set();caller.join(5);closer.join(5)
    assert closed.is_set() and failures==['held'] and not caller.is_alive()


def test_reservation_bad_utf8_denies_with_fixed_private_safe_error(admission_workers):
    s=admission_workers;one=s.issue()
    with pytest.raises(m.NamedWorkerLifecycleError) as caught:
        s.wrapper.admit_reserved(issued_record=one.record,admission_handle=one.handle,original_utf8=b'private\xff')
    assert caught.value.__context__ is None and 'private' not in str(caught.value)
    assert not s.registry._reservations and not s.registry._entries
    assert s.store.get(handle=one.handle,session_binding=s.session).phase=='ISSUED'


def test_reserved_submit_ignores_unrelated_newly_expired_cleanup_failure(admission_workers,monkeypatch):
    s=admission_workers
    s.registry=m.NamedWorkerRegistry(clock=s.clock,capacity=2)
    s.wrapper=m.ThreadBoundNamedAskPipeline(workers=s.registry,pipeline=s.wrapper._pipeline,store=s.store)
    one,first=s.new();s.submit(one,first)
    s.now=first.processing_expires_at-timedelta(seconds=1)
    two=s.issue()
    second=s.wrapper.admit_reserved(issued_record=two.record,admission_handle=two.handle,original_utf8=b'inventeddata')
    s.now=first.processing_expires_at
    attempted=[]
    def failed(**kwargs):
        attempted.append(kwargs['handle']);raise ValueError('invented unrelated cleanup hold')
    monkeypatch.setattr(s.store,'retire_expired',failed)
    s.submit(two,second)
    assert s.calls==2 and not attempted
    assert one.record.manifest.request_id in s.registry._entries
    assert s.registry._entries[two.record.manifest.request_id].job.consumed


def test_reserved_placeholder_cannot_be_started_by_other_wrapper_with_no_retained_binding(admission_workers):
    s=admission_workers;one=s.issue()
    admitted=s.wrapper.admit_reserved(issued_record=one.record,admission_handle=one.handle,original_utf8=b'inventeddata')
    other=m.ThreadBoundNamedAskPipeline(workers=s.registry,pipeline=s.wrapper._pipeline,store=s.store)
    with pytest.raises(m.NamedWorkerLifecycleError):
        other.submit(operation=None,admission_handle=one.handle,admitted_record=admitted,original_utf8=b'inventeddata')
    worker=s.registry._entries[one.record.manifest.request_id]
    assert worker.reserved and worker.job is None and s.calls==0 and not other._retained
    s.submit(one,admitted);assert s.calls==1


def test_known_unused_reserved_placeholder_retires_only_after_original_expiry(admission_workers):
    s=admission_workers;one=s.issue()
    admitted=s.wrapper.admit_reserved(issued_record=one.record,admission_handle=one.handle,original_utf8=b'inventeddata')
    with pytest.raises(m.NamedWorkerLifecycleError):s.wrapper.close_and_retire()
    assert s.registry._entries[one.record.manifest.request_id].job is None and s.calls==0
    s.now=admitted.processing_expires_at
    s.wrapper.close_and_retire()
    assert not s.registry._entries and not s.wrapper._retained and s.calls==0
    from zacai.interfaces.named_admission_store import NamedAdmissionStoreError
    with pytest.raises(NamedAdmissionStoreError):s.store.status(handle=one.handle,session_binding=s.session)


def test_actual_expiry_before_store_admit_refunds_proven_unused_reservation(admission_workers,monkeypatch):
    s=admission_workers;one=s.issue();actual=s.store.admit_reserved_outcome
    def expires_before_actual_transaction(**kwargs):
        s.now=one.record.manifest.admission_expires_at
        return actual(**kwargs)
    monkeypatch.setattr(s.store,'admit_reserved_outcome',expires_before_actual_transaction)
    with pytest.raises(m.NamedWorkerLifecycleError):
        s.wrapper.admit_reserved(issued_record=one.record,admission_handle=one.handle,original_utf8=b'inventeddata')
    assert not s.registry._reservations and not s.registry._entries and s.calls==0
    assert s.store.status(handle=one.handle,session_binding=s.session)==one.record
    from zacai.interfaces.named_admission_store import NamedAdmissionStoreError
    with pytest.raises(NamedAdmissionStoreError):s.store.get(handle=one.handle,session_binding=s.session)


@pytest.mark.parametrize('unknown',['missing','corrupt'])
def test_unprovable_admission_failure_does_not_refund_reserved_capacity(admission_workers,monkeypatch,unknown):
    import sqlite3
    s=admission_workers;one=s.issue()
    def fail_unknown(**kwargs):
        with sqlite3.connect(s.store._path) as conn:
            if unknown=='missing':conn.execute('DELETE FROM admissions')
            else:conn.execute('UPDATE admissions SET sealed=?',(b'x'*50,))
        raise ValueError('invented uncertain operational write')
    monkeypatch.setattr(s.store,'admit_reserved_outcome',fail_unknown)
    with pytest.raises(m.NamedWorkerLifecycleError):
        s.wrapper.admit_reserved(issued_record=one.record,admission_handle=one.handle,original_utf8=b'inventeddata')
    assert len(s.registry._reservations)==1 and not s.registry._entries and s.calls==0
    with pytest.raises(m.NamedWorkerLifecycleError):s.wrapper.close_and_retire()


def test_failed_known_cleanup_does_not_consume_other_available_slot(admission_workers,monkeypatch):
    s=admission_workers
    s.registry=m.NamedWorkerRegistry(clock=s.clock,capacity=2)
    s.wrapper=m.ThreadBoundNamedAskPipeline(workers=s.registry,pipeline=s.wrapper._pipeline,store=s.store)
    one,first=s.new();s.submit(one,first);s.now=first.processing_expires_at
    two=s.issue();actual=s.store.retire_expired
    def fail_old_only(**kwargs):
        if kwargs['handle']==one.handle:raise ValueError('invented old cleanup hold')
        return actual(**kwargs)
    monkeypatch.setattr(s.store,'retire_expired',fail_old_only)
    second=s.wrapper.admit_reserved(issued_record=two.record,admission_handle=two.handle,original_utf8=b'inventeddata')
    s.submit(two,second)
    assert s.calls==2 and len(s.registry._entries)==2
    assert one.record.manifest.request_id in s.wrapper._retained
    with pytest.raises(m.NamedWorkerLifecycleError):s.submit(two,second)


def test_expired_uncertain_thread_start_never_becomes_unused_placeholder(admission_workers,monkeypatch):
    s=admission_workers;one=s.issue()
    admitted=s.wrapper.admit_reserved(issued_record=one.record,admission_handle=one.handle,original_utf8=b'inventeddata')
    actual_start=Thread.start
    def fail_named_start(thread):
        if thread.name=='caz-named-worker':raise RuntimeError('invented unknown native start')
        return actual_start(thread)
    monkeypatch.setattr(Thread,'start',fail_named_start)
    with pytest.raises(m.NamedWorkerLifecycleError):s.submit(one,admitted)
    s.now=admitted.processing_expires_at
    with pytest.raises(m.NamedWorkerLifecycleError):s.wrapper.close_and_retire()
    assert one.record.manifest.request_id in s.registry._entries and s.calls==0
    assert s.store.status(handle=one.handle,session_binding=s.session).phase=='ADMITTED'


def test_wrapper_graceful_sweep_waits_for_actual_thread_termination(admission_workers):
    s=admission_workers;one=s.issue()
    admitted=s.wrapper.admit_reserved(issued_record=one.record,admission_handle=one.handle,original_utf8=b'inventeddata')
    s.block=True
    caller=Thread(target=lambda:s.submit(one,admitted))
    caller.start();assert s.entered.wait(5)
    s.now=admitted.processing_expires_at
    drained=Event()
    closer=Thread(target=lambda:(s.wrapper.close_and_retire(),drained.set()))
    closer.start()
    try:
        assert not drained.wait(.03)
        assert s.store.status(handle=one.handle,session_binding=s.session).phase=='ADMITTED'
    finally:s.release.set();caller.join(5);closer.join(5)
    assert drained.is_set() and not caller.is_alive() and not closer.is_alive()
    # Actual terminated/joined thread is sufficient, even if its waiter has
    # not yet consumed a result when the first sweep inspects it.
    s.wrapper.close_and_retire()
    assert not s.registry._entries and not s.wrapper._retained


def test_reserved_start_waits_for_registration_guard_before_clock_and_cannot_reallocate(s, monkeypatch):
    # Actual bounded caller thread waits on the lifecycle guard while the known
    # expired never-started placeholder is retired. No synthetic clock rollback.
    from threading import current_thread
    attempted, observed, ended = Event(), Event(), Event()
    original_active = s.registry._active
    def active(request):
        if current_thread().name == 'reserved-caller': observed.set()
        return original_active(request)
    monkeypatch.setattr(s.registry, '_active', active)
    s.registry._entries[s.request.request_id] = m._Worker(s.request, reserved=True)
    failures = []
    def caller():
        attempted.set()
        try: s.registry.run_reserved(s.request, lambda: pytest.fail('retired action dispatched'))
        except m.NamedWorkerLifecycleError: failures.append('held')
        finally: ended.set()
    with s.registry._lock:
        thread = Thread(target=caller, name='reserved-caller')
        thread.start(); assert attempted.wait(5)
        assert not observed.wait(.03)  # Active check cannot race outside the lock.
        s.now = s.request.expires_at
        s.registry.retire_after_drain(s.request, lambda: None)
    thread.join(5)
    assert ended.is_set() and failures == ['held'] and not s.registry._entries


def test_reserved_only_start_missing_placeholder_never_legacy_allocates(s):
    with pytest.raises(m.NamedWorkerLifecycleError):
        s.registry.run_reserved(s.request, lambda: pytest.fail('missing placeholder dispatched'))
    assert not s.registry._entries


def test_reserved_placeholder_cannot_recheck_as_if_it_ran(s):
    s.registry._entries[s.request.request_id] = m._Worker(s.request, reserved=True)
    with pytest.raises(m.NamedWorkerLifecycleError):
        s.registry.recheck(s.request, lambda: pytest.fail('unstarted read continuation'))
    assert s.registry._entries[s.request.request_id].job is None


def test_recheck_requires_exact_wrapper_retention_even_for_actual_completed_job(admission_workers):
    s = admission_workers; one = s.issue()
    admitted = s.wrapper.admit_reserved(issued_record=one.record, admission_handle=one.handle,
                                       original_utf8=b'inventeddata')
    s.submit(one, admitted)
    foreign = m.ThreadBoundNamedAskPipeline(workers=s.registry, pipeline=s.wrapper._pipeline, store=s.store)
    with pytest.raises(m.NamedWorkerLifecycleError):
        foreign.recheck(operation=None, admission_handle=one.handle, admitted_record=admitted,
                        original_utf8=b'inventeddata', saved=None)
    with pytest.raises(m.NamedWorkerLifecycleError):
        s.wrapper.recheck(operation=None, admission_handle=one.handle, admitted_record=admitted,
                          original_utf8=b'changed data', saved=None)
    assert s.wrapper.recheck(operation=None, admission_handle=one.handle, admitted_record=admitted,
                             original_utf8=b'inventeddata', saved=None) is None


def test_actual_terminated_thread_can_retire_without_waiter_consumption(s):
    ended = Event()
    job = s.registry._start(s.request, lambda: ended.set(), check_only=False)
    assert ended.wait(5) and job.thread is not None
    job.thread.join(5)
    assert not job.consumed and not job.thread.is_alive()
    # While active, a missing waiter acknowledgement still forbids replay/read.
    with pytest.raises(m.NamedWorkerLifecycleError): s.registry.recheck(s.request, lambda: None)
    s.now = s.request.expires_at
    s.registry.retire_after_drain(s.request, lambda: None)
    assert not s.registry._entries


def test_atomic_expired_issued_outcome_refunds_even_if_peer_purges_after_return(admission_workers, monkeypatch):
    s = admission_workers; one = s.issue(); actual = s.store.admit_reserved_outcome
    def expired_then_peer_issue(**kwargs):
        s.now = one.record.manifest.admission_expires_at
        result = actual(**kwargs)  # Real authenticated no-write transaction.
        s.issue()  # Actual peer issuance purges expired ISSUED before caller handles result.
        return result
    monkeypatch.setattr(s.store, 'admit_reserved_outcome', expired_then_peer_issue)
    with pytest.raises(m.NamedWorkerLifecycleError):
        s.wrapper.admit_reserved(issued_record=one.record, admission_handle=one.handle,
                                original_utf8=b'inventeddata')
    assert not s.registry._reservations and not s.registry._entries and s.calls == 0


def test_missing_before_actual_admission_cannot_refund(admission_workers, monkeypatch):
    s = admission_workers; one = s.issue(); actual = s.store.admit_reserved_outcome
    def peer_issue_before_admission(**kwargs):
        s.now = one.record.manifest.admission_expires_at
        s.issue()  # No authentic original row remains inside actual admission.
        return actual(**kwargs)
    monkeypatch.setattr(s.store, 'admit_reserved_outcome', peer_issue_before_admission)
    with pytest.raises(m.NamedWorkerLifecycleError):
        s.wrapper.admit_reserved(issued_record=one.record, admission_handle=one.handle,
                                original_utf8=b'inventeddata')
    assert len(s.registry._reservations) == 1 and not s.registry._entries and s.calls == 0


@pytest.mark.parametrize('phase', ['QUESTION_BOUND', 'DECISION_BOUND'])
def test_real_attachment_phase_preserves_original_retained_recheck(admission_workers, phase):
    from tests.test_named_admission_store import ref
    s = admission_workers; one = s.issue()
    admitted = s.wrapper.admit_reserved(issued_record=one.record, admission_handle=one.handle,
                                       original_utf8=b'inventeddata')
    s.submit(one, admitted)
    s.store.attach_question(handle=one.handle, session_binding=s.session,
                            reference=ref(), recovery_digest='d'*64)
    if phase == 'DECISION_BOUND':
        s.store.attach_decision(handle=one.handle, session_binding=s.session,
                                reference=ref(), recovery_digest='e'*64)
    assert s.store.get(handle=one.handle, session_binding=s.session).phase == phase
    assert s.wrapper.recheck(operation=None, admission_handle=one.handle, admitted_record=admitted,
                             original_utf8=b'inventeddata', saved=None) is None


def test_foreign_completed_submit_cannot_retain_or_retire_original(admission_workers):
    s=admission_workers; one=s.issue()
    admitted=s.wrapper.admit_reserved(issued_record=one.record,admission_handle=one.handle,original_utf8=b'inventeddata')
    s.submit(one,admitted)
    other=m.ThreadBoundNamedAskPipeline(workers=s.registry,pipeline=s.wrapper._pipeline,store=s.store)
    with pytest.raises(m.NamedWorkerLifecycleError):
        other.submit(operation=None,admission_handle=one.handle,admitted_record=admitted,original_utf8=b'inventeddata')
    assert not other._retained
    s.now=admitted.processing_expires_at
    s.wrapper._retire_completed()
    other._retire_completed()
    two=s.issue()
    fresh=s.wrapper.admit_reserved(issued_record=two.record,admission_handle=two.handle,original_utf8=b'inventeddata')
    s.submit(two,fresh)


def test_direct_run_cannot_consume_reserved_placeholder(s):
    s.registry._entries[s.request.request_id]=m._Worker(s.request,reserved=True)
    called=[]
    with pytest.raises(m.NamedWorkerLifecycleError):
        s.registry.run(s.request,lambda: called.append(True))
    assert not called and s.registry._entries[s.request.request_id].reserved
    assert s.registry.run_reserved(s.request,lambda: 'original')=='original'


def test_direct_shielded_run_cannot_consume_reserved_placeholder(s):
    s.registry._entries[s.request.request_id]=m._Worker(s.request,reserved=True)
    called=[]
    with pytest.raises(m.NamedWorkerLifecycleError):
        asyncio.run(s.registry.run_shielded(s.request,lambda: called.append(True)))
    assert not called and s.registry._entries[s.request.request_id].reserved
    assert s.registry.run_reserved(s.request,lambda: 'original')=='original'


def test_concurrent_legacy_wrappers_atomically_bind_only_one_retention(admission_workers, monkeypatch):
    from concurrent.futures import ThreadPoolExecutor
    from threading import Barrier
    s=admission_workers;one,admitted=s.new()
    other=m.ThreadBoundNamedAskPipeline(workers=s.registry,pipeline=s.wrapper._pipeline,store=s.store)
    actual=s.store.get; barrier=Barrier(2)
    def get(**kwargs):
        value=actual(**kwargs)
        barrier.wait(timeout=5)
        return value
    monkeypatch.setattr(s.store,'get',get)
    def submit(wrapper):
        try:
            wrapper.submit(operation=None,admission_handle=one.handle,admitted_record=admitted,original_utf8=b'inventeddata')
            return True
        except m.NamedWorkerLifecycleError:
            return False
    with ThreadPoolExecutor(max_workers=2) as pool:
        results=list(pool.map(submit,(s.wrapper,other)))
    assert sum(results)==1 and s.calls==1
    assert sum(len(w._retained) for w in (s.wrapper,other))==1
