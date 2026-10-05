"""Explicit foreground trial glue; construction never starts a listener.

The host selects one already protected BRAINSTORM/CONFIDENTIAL packet. Receipt
shape/hash cannot establish retained verified origin: the host must independently
establish that before construction. No browser receipt/path/selection is accepted.
No choices, conversation, model calls, connector intake or execution are mounted.

Run the enrollment-only entry with ``python -m zacai.interfaces.private_trial``
after exact client/origin, escrow and PRIVATE TLS approvals. Owner mode requires
host-reviewed canonical factory/artifacts/selection via run_owner_trial; it has no
arbitrary path/credential CLI. These callables start serving only when explicitly
invoked by the trusted local operator. No runtime readiness is asserted here.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from sqlalchemy.orm import Session, sessionmaker
from starlette.concurrency import run_in_threadpool

from zacai.contextual_recovery_record import ContextualRecoveryReceipt, encode_recovery_receipt
from zacai.ingestion.artifact_store import ArtifactStore, content_hash_of
from zacai.intelligence.briefing_delivery import render_retained_decision_cards
from zacai.interfaces.build_progress import BuildProgressSnapshot, render_build_progress
from zacai.interfaces.owner_enrollment import PendingOwner
from zacai.interfaces.private_operator import PrivateOperatorMode, open_private_operator
from zacai.interfaces.private_web import InterfacePrincipal, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.review_authorization import _assert_ledger_isolation


class PrivateTrialError(RuntimeError):
    """Fixed diagnostics: no private source, identity or credential error chains."""


@dataclass(frozen=True, repr=False)
class RetainedCardSelection:
    receipt: ContextualRecoveryReceipt = field(repr=False)
    receipt_digest: str = field(repr=False)
    selected_item: int = 0

    def __post_init__(self) -> None:
        if (
            type(self.receipt) is not ContextualRecoveryReceipt
            or type(self.receipt_digest) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.receipt_digest) is None
            or content_hash_of(encode_recovery_receipt(self.receipt)) != self.receipt_digest
            or type(self.selected_item) is not int
            or not 0 <= self.selected_item < 32
        ):
            raise PrivateTrialError("private trial selection unavailable")


class SelectedPacketView:
    """Read-only fixed host selection; each render uses its own worker session.

    Current source ACLs/recovery binding are checked by the canonical renderer.
    Historical protection is not current business status or a complete briefing.
    The outer private_web route must reauthenticate after awaiting this callback.
    Trusted SQL factory/storage ancestry/receipt origin remain host obligations.
    """

    def __init__(
        self, *, factory: sessionmaker[Session], artifacts: ArtifactStore,
        selection: RetainedCardSelection, clock: Callable[[], datetime],
        progress: BuildProgressSnapshot | None = None,
    ) -> None:
        if type(selection) is not RetainedCardSelection or not callable(factory) or not callable(clock):
            raise PrivateTrialError("private trial view unavailable")
        if progress is not None and type(progress) is not BuildProgressSnapshot:
            raise PrivateTrialError("private trial progress unavailable")
        self._progress = progress
        self._factory, self._artifacts, self._selection, self._clock = (
            factory, artifacts, selection, clock
        )

    def __repr__(self) -> str:
        return "SelectedPacketView()"

    async def __call__(self, principal: InterfacePrincipal) -> str:
        result: str | None = None
        try:
            if type(principal) is not InterfacePrincipal:
                raise ValueError("invalid principal")

            def render() -> str:
                now = self._clock()
                if type(now) is not datetime or now.utcoffset() is None:
                    raise ValueError("invalid host clock")
                with self._factory() as session:
                    _assert_ledger_isolation(session)
                    html = render_retained_decision_cards(
                        session, artifacts=self._artifacts,
                        retained_receipt=self._selection.receipt,
                        expected_receipt_digest=self._selection.receipt_digest,
                        principal=principal, as_of=now,
                        selected_item=self._selection.selected_item,
                    )
                    if self._progress is not None:
                        if html.count("</main>") != 1:
                            raise ValueError("protected document composition unavailable")
                        fragment = render_build_progress(self._progress)
                        html = html.replace("</main>", fragment + "</main>")
                    return html

            result = await run_in_threadpool(render)
        except Exception:  # noqa: BLE001,S110 - no source/storage/SQL diagnostics
            pass
        if result is None:
            raise PrivateTrialError("private trial view unavailable")
        return result


@dataclass(frozen=True, repr=False)
class LocalOwnerConfirmation:
    expected_identity: Identity = field(repr=False)
    pairing_code: str = field(repr=False)
    confirmation: str = field(repr=False)


def run_enrollment_trial(
    *, client_id: str, origin: str, directory: Path,
    escrow_confirmed_by_operator: bool,
    local_confirm: Callable[[PendingOwner], LocalOwnerConfirmation],
) -> OwnerGrant:
    """Serve once, stop, then require separate explicit LOCAL confirmation.

    No default confirmer, browser claim or grant is supplied. A five-minute
    enrollment window starts at host construction; finish and confirm promptly.
    Returned grant is not source ingestion/model/execution authorization.
    """
    result: OwnerGrant | None = None
    try:
        if not callable(local_confirm):
            raise TypeError("local confirmation required")
        with open_private_operator(
            mode=PrivateOperatorMode.ENROLLMENT, client_id=client_id, origin=origin,
            directory=directory, escrow_confirmed_by_operator=escrow_confirmed_by_operator,
        ) as window:
            window.serve()
            answer = local_confirm(window.pending_owner())
            if type(answer) is not LocalOwnerConfirmation:
                raise ValueError("invalid local confirmation")
            result = window.confirm_owner(
                expected_identity=answer.expected_identity,
                pairing_code=answer.pairing_code, confirmation=answer.confirmation,
            )
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise PrivateTrialError("private trial enrollment unavailable; stop and reconcile")
    return result


def run_owner_trial(
    *, client_id: str, origin: str, directory: Path,
    escrow_confirmed_by_operator: bool, view: SelectedPacketView,
) -> None:
    """Explicit foreground read-only serving; no work-choice/chat/model routes."""
    okay = False
    try:
        if type(view) is not SelectedPacketView:
            raise ValueError("invalid protected view")
        with open_private_operator(
            mode=PrivateOperatorMode.OWNER, client_id=client_id, origin=origin,
            directory=directory, escrow_confirmed_by_operator=escrow_confirmed_by_operator,
            view=view,
            clock=view._clock,
        ) as window:
            window.serve()
        okay = True
    except Exception:  # noqa: BLE001,S110
        pass
    if not okay:
        raise PrivateTrialError("private trial serving unavailable; stop and reconcile")


def _terminal_confirmation(pending: PendingOwner) -> LocalOwnerConfirmation:
    # Deliberate local inspection, not logging. Never run with redirected streams.
    if not sys.stdin.isatty() or not sys.stdout.isatty() or not sys.stderr.isatty():
        raise PrivateTrialError("private local terminal required")
    print("Verified sign-in issuer:", pending.identity.issuer)
    print("Verified sign-in subject:", pending.identity.subject)
    print("Mac pairing code:", pending.pairing_code)
    print("Confirm this matches the intended browser sign-in. No PERSONAL access.")
    issuer = input("Enter the verified issuer: ")
    subject = input("Enter the verified subject: ")
    code = input("Enter the matching code from the browser: ")
    confirmation = input("Type CONFIRM BRAINSTORM / CONFIDENTIAL to grant this scope: ")
    return LocalOwnerConfirmation(Identity(issuer, subject), code, confirmation)


def main() -> None:
    """Enrollment only; nonsecret arguments, explicit operator gates, no fallback."""
    parser = argparse.ArgumentParser(description="Explicit private Caz AI owner enrollment")
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--origin", required=True)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--escrow-confirmed-by-operator", action="store_true", required=True)
    args = parser.parse_args()
    # Check terminal BEFORE credential loading/listening, not only at confirmation.
    if not all(stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr)):
        parser.exit(1, "Private local terminal required.\n")
    print("Open " + args.origin + "/enroll after serving starts.")
    print("After browser pairing appears, press Ctrl-C once here; then confirm locally.")
    try:
        run_enrollment_trial(
            client_id=args.client_id, origin=args.origin, directory=args.directory,
            escrow_confirmed_by_operator=args.escrow_confirmed_by_operator,
            local_confirm=_terminal_confirmation,
        )
    except BaseException:  # noqa: BLE001 - CLI must never emit backend traceback/local values.
        parser.exit(1, "Private enrollment not acknowledged; stop and reconcile.\n")
    print("Owner enrollment saved. Close setup before separately starting the reviewed owner host.")


if __name__ == "__main__":
    main()
