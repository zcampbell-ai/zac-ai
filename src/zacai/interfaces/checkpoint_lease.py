"""Existing audited operator/restore-target lease, shared by fixed host adapters.

No backup receipt, Source authority, credential selection or service is created.
This is a trusted-host primitive, not a browser/agent-provided proof. Exact
namespace/envelope/recovery checks remain the owning adapter's obligations.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from threading import Lock, RLock

from sqlalchemy import text

from zacai import backup
from zacai.contextual_protection import BrainstormContextualProtector

_OPERATOR_LOCK = 73403416


@contextmanager
def checkpoint_lease(
    p: BrainstormContextualProtector, lock: Lock | RLock
) -> Iterator[Callable[[], None]]:
    with lock, p._engine.connect() as lease:
        p._assert_target()
        lease.execute(text("SET TRANSACTION READ ONLY"))
        lease.execute(text("SET LOCAL idle_in_transaction_session_timeout = 0"))
        if lease.scalar(text("SELECT current_setting('server_version_num')::integer")) >= 170000:
            lease.execute(text("SET LOCAL transaction_timeout = 0"))
        if not lease.scalar(text(f"SELECT pg_try_advisory_xact_lock({_OPERATOR_LOCK})")):
            raise ValueError("operator recovery lease unavailable")

        def require() -> None:
            if not lease.scalar(
                text(
                    "SELECT EXISTS (SELECT 1 FROM pg_locks WHERE locktype='advisory' "
                    "AND pid=pg_backend_pid() AND classid=0 AND objid=73403416 "
                    "AND objsubid=1 AND granted)"
                )
            ):
                raise ValueError("operator recovery lease lost")

        if p._lease_guard is not None:
            raise ValueError("protector already in use")
        p._lease_guard = require
        try:
            with backup._admin_connection():
                require()
                yield require
                require()
        finally:
            p._lease_guard = None
