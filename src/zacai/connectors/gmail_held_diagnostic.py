"""Authenticated read-only aggregate observations, never OAuth recovery authority.

The foreground host supplies the original reconciler and retains its actual
operator lease. Paired existing namespaces must be preflighted before authority
construction; this component does not attest that host prerequisite. Expired rows
are counted without resuming them. Loaded means entry to the secret-load phase,
not provider success, native material, original actor or source identity proof.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from functools import wraps
from typing import Literal

from zacai.connectors.gmail_held_reconciliation import HeldGmailReconciliation


class GmailHeldDiagnosticError(RuntimeError):
    """Fixed private-safe diagnostic denial."""


class GmailHeldDiagnosticCancelled(BaseException):
    """Fixed private-safe interruption; no automatic retry."""


def _closed[**P, R](method: Callable[P, R]) -> Callable[P, R]:
    @wraps(method)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        failure: type[BaseException]
        try:
            return method(*args, **kwargs)
        except Exception:  # noqa: BLE001 - drop private cookie and decrypted ledger frames
            failure = GmailHeldDiagnosticError
        except BaseException:  # noqa: BLE001 - interruption conveys no private diagnostics
            failure = GmailHeldDiagnosticCancelled
        del args, kwargs
        raise failure("Gmail held diagnostic unavailable; host review required")

    return call


@dataclass(frozen=True, init=False, repr=False)
class GmailHeldDiagnosticReceipt:
    """Private aggregate metadata; no row identifiers or installation proof."""

    pending: int
    exchange_pending: int
    exchange_started: int
    denied: int
    held: int
    loaded: int
    installed: Literal[False] = field(default=False, init=False)
    original_actor_verified: Literal[False] = field(default=False, init=False)
    source_subject_verified: Literal[False] = field(default=False, init=False)
    native_material_verified: Literal[False] = field(default=False, init=False)
    live_access_proven: Literal[False] = field(default=False, init=False)
    credential_authority: Literal[False] = field(default=False, init=False)
    processing_authorized: Literal[False] = field(default=False, init=False)
    execution_authorized: Literal[False] = field(default=False, init=False)

    def __init__(self) -> None:
        raise GmailHeldDiagnosticError("Gmail held diagnostic receipt unavailable")

    def __repr__(self) -> str:
        return "GmailHeldDiagnosticReceipt(installed=False)"

    @property
    def total(self) -> int:
        return (
            self.pending + self.exchange_pending + self.exchange_started + self.denied + self.held
        )


class HeldGmailDiagnostic:
    """Inert counts inspector pinned to an exact original concrete reconciler."""

    @_closed
    def __init__(self, *, reconciliation: HeldGmailReconciliation) -> None:
        if type(reconciliation) is not HeldGmailReconciliation:
            raise ValueError("actual reconciliation required")
        self._reconciliation = reconciliation
        self._original = reconciliation
        # The accepted reconciler retains and checks its original dependencies.
        # No callbacks, storage reads or credential I/O occur in this constructor.

    def _current(self) -> HeldGmailReconciliation:
        if self._reconciliation is not self._original:
            raise ValueError("original reconciliation required")
        self._original._current()
        return self._original

    @_closed
    def inspect(self, *, cookie: str) -> GmailHeldDiagnosticReceipt:
        reconciliation = self._current()
        witness = reconciliation._files()  # existing files before any lock callback
        authority = reconciliation._authority
        operation = authority._continuity.for_cookie(cookie)
        verified = operation.establish()

        def check() -> None:
            self._current()
            if reconciliation._files() != witness:
                raise ValueError("operational storage changed")
            authority._scope(operation, verified.binding_digest)
            current = operation.recheck(verified.binding_digest)
            if current.principal != verified.principal:
                raise ValueError("current enrolled owner changed")
            self._current()  # pure audit after trusted owner/session/clock callbacks
            if reconciliation._files() != witness:
                raise ValueError("operational storage changed")

        check()
        with authority._locked():
            check()  # current owner after lock admission, before decrypted metadata
            ledger = authority._read()
            check()
            counts = dict.fromkeys(
                ("pending", "exchange_pending", "exchange_started", "denied", "held"), 0
            )
            loaded = 0
            for row in ledger["rows"].values():
                if row["account"] != reconciliation._account:
                    continue
                if row["configuration"] != reconciliation._digest or row["rotation"] is not None:
                    raise ValueError("conflicting selected account configuration")
                counts[row["state"]] += 1
                loaded += int(row["loaded"])
            check()
            observed = authority._continuity._clock()
            check()
            if observed < authority._time(ledger["watermark"]):
                raise ValueError("observed host clock rollback")
            receipt = object.__new__(GmailHeldDiagnosticReceipt)
            for name, count in counts.items():
                object.__setattr__(receipt, name, count)
            object.__setattr__(receipt, "loaded", loaded)
        check()  # cleanup callbacks must not change owner, composition or storage
        return receipt
