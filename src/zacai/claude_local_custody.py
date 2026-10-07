"""Explicit LOCAL owner-operated custody, not import/recovery/model permission.

Trusted host supplies reviewed actual configuration, independently expected owner,
closed file locators/hashes and canonical Session factory. Import runs nothing.
The foreground TTY action reviews the EXACT canonical proposal; no --yes, caller
approval boolean, injected approval callback or self-hash grants capture. TTY
participation is an operator procedure, not cryptographic proof a human attended.

Existing operator foreground lifecycle wraps a local callback with NO listener.
Parents/storage/configuration remain trusted, cross-host operation serialized by
operator, and external traceback-local capture/telemetry disabled. Fixed errors
hide message values, not Python traceback locals or inherited caller context.
Capture failure can leave orphan artifacts or an uncertain completed outer commit;
stop and reconcile, never auto-retry. A successful reopened pair is still recovery
pending, never source completeness, current facts, processing or protection proof.
"""

from __future__ import annotations

import json
import os
import re
import stat
from dataclasses import dataclass, field
from datetime import datetime
from os import close as _tty_close
from os import open as _tty_open
from os import read as _tty_read
from os import write as _tty_write
from pathlib import Path
from termios import TCIFLUSH
from termios import tcflush as _tty_flush
from typing import Literal

from sqlalchemy.orm import Session, sessionmaker

from zacai.claude_original_capture import (
    ClaudeArtifactRootIdentity,
    ClaudeCustodyProposal,
    prepare_claude_custody_proposal,
    record_claude_original,
)
from zacai.claude_original_read import ReadClaudeCustody, load_claude_original
from zacai.history_manifest import MAX_MANIFEST_BYTES
from zacai.ingestion.artifact_store import (
    LocalFilesystemArtifactStore,
    canonical_bytes,
    content_hash_of,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.interfaces.owner_store import OwnerGrantStore
from zacai.interfaces.private_host import PreparedOwnerHost
from zacai.interfaces.private_operator import PrivateOperatorMode, open_private_operator
from zacai.interfaces.private_startup import OwnerStartupConfiguration
from zacai.interfaces.private_web import BoundaryScope, OwnerGrant
from zacai.interfaces.session_store import Identity
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

_MAX_ORIGINAL = 100_000_000
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_SCOPE = (BoundaryScope(B.PERSONAL, frozenset({C.HIGHLY_RESTRICTED})),)


class LocalClaudeCustodyError(ValueError):
    """Fixed diagnostics; no path/identity/proposal/backend values."""


@dataclass(frozen=True, repr=False)
class LocalClaudeCustodyResult:
    original_reference: EvidenceReference
    companion_reference: EvidenceReference
    proposal_hash: str
    original_captured_at: datetime
    status: Literal["COMMITTED_REOPENED_RECOVERY_PENDING"] = field(
        default="COMMITTED_REOPENED_RECOVERY_PENDING", init=False
    )
    recovery_verified: Literal[False] = field(default=False, init=False)
    processing_authorized: Literal[False] = field(default=False, init=False)
    current_facts_verified: Literal[False] = field(default=False, init=False)


def _read_file(path: Path, maximum: int, expected_hash: str) -> bytes:
    if not isinstance(path, Path) or not path.is_absolute() or path.resolve(strict=True) != path:
        raise ValueError("closed original locator required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise ValueError("private bounded original required")
        with os.fdopen(fd, "rb") as file:
            fd = -1
            raw = file.read(before.st_size + 1)
            after = os.fstat(file.fileno())
        current = path.lstat()
        keys = (
            "st_dev",
            "st_ino",
            "st_size",
            "st_mtime_ns",
            "st_ctime_ns",
            "st_mode",
            "st_uid",
            "st_nlink",
        )
        if (
            any(getattr(before, k) != getattr(after, k) for k in keys)
            or any(getattr(after, k) != getattr(current, k) for k in keys)
            or len(raw) != before.st_size
            or content_hash_of(raw) != expected_hash
        ):
            raise ValueError("original observation changed")
        return raw
    finally:
        if fd >= 0:
            os.close(fd)


def _approve_on_tty(
    proposal: ClaudeCustodyProposal, original_path: Path, *, expected_proposal_hash: str
) -> None:
    digest = content_hash_of(canonical_bytes(proposal.model_dump(mode="json")))
    if digest != expected_proposal_hash:
        raise ValueError("affirmed proposal digest differs")
    review = {
        "action": "LOCAL canonical custody only; recovery pending; NO model processing",
        "original_path": str(original_path),
        "original_sha256": proposal.original_hash,
        "original_bytes": proposal.original_bytes,
        "proposal_sha256": digest,
        "custody_id": str(proposal.custody_id),
        "boundary": proposal.boundary.value,
        "classification": proposal.classification.value,
        "reported_account": proposal.account_ref,
        "reported_exported_at": proposal.exported_at.isoformat() if proposal.exported_at else None,
        "declared_acquired_at": proposal.acquired_at.isoformat(),
        "declared_captured_at": proposal.captured_at.isoformat(),
        "coverage": "SELECTED_RECORDS_ONLY; ancestry/role/date are historical claims",
        "selected_record_metadata": [s.model_dump(mode="json") for s in proposal.selections],
    }
    phrase = "CAPTURE PERSONAL / HIGHLY_RESTRICTED " + digest
    prompt = (
        json.dumps(review, ensure_ascii=True, indent=2)
        + "\nType exactly:\n"
        + phrase
        + "\nAny other response holds.\n"
    )
    fd = _tty_open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    try:
        if not os.isatty(fd) or os.tcgetpgrp(fd) != os.getpgrp():
            raise ValueError("foreground owner TTY required")
        output = prompt.encode("utf-8")
        written = 0
        while written < len(output):
            amount = _tty_write(fd, output[written:])
            if amount <= 0:
                raise ValueError("owner TTY output unavailable")
            written += amount
        # Affirmation must follow the completed review, never queued type-ahead.
        _tty_flush(fd, TCIFLUSH)
        answer = bytearray()
        while len(answer) < 128:
            character = _tty_read(fd, 1)
            if not character:
                raise ValueError("owner TTY affirmation absent")
            answer.extend(character)
            if character == b"\n":
                break
        if bytes(answer) != (phrase + "\n").encode("ascii"):
            raise ValueError("exact owner proposal affirmation required")
    finally:
        try:
            _tty_flush(fd, TCIFLUSH)
        finally:
            _tty_close(fd)


def run_local_claude_custody(
    *,
    configuration: OwnerStartupConfiguration,
    owner_directory: Path,
    expected_identity: Identity,
    escrow_confirmed_by_operator: bool,
    original_path: Path,
    expected_original_hash: str,
    proposal_path: Path,
    expected_proposal_hash: str,
    session_factory: sessionmaker[Session],
    artifacts: LocalFilesystemArtifactStore,
    expected_root: ClaudeArtifactRootIdentity,
) -> LocalClaudeCustodyResult:
    """Explicit host action; actual authenticated owner and TTY before DB writes.

    Supplied hashes identify approved host-selected files, not owner permission.
    Human exact-proposal affirmation occurs independently through foreground TTY.
    No listener, source search, credentials fallback, approval registry or recovery
    operation is performed. Root must verify actual PERSONAL off-device protection
    separately before any useful private task processing.
    """
    result = None
    baseline: OwnerGrant | None = None
    try:
        if (
            type(configuration) is not OwnerStartupConfiguration
            or type(expected_identity) is not Identity
            or type(escrow_confirmed_by_operator) is not bool
            or not escrow_confirmed_by_operator
            or type(artifacts) is not LocalFilesystemArtifactStore
            or type(expected_root) is not ClaudeArtifactRootIdentity
            or not isinstance(session_factory, sessionmaker)
            or type(expected_original_hash) is not str
            or _DIGEST.fullmatch(expected_original_hash) is None
            or type(expected_proposal_hash) is not str
            or _DIGEST.fullmatch(expected_proposal_hash) is None
        ):
            raise ValueError("reviewed host inputs required")

        async def unavailable_view(principal: object) -> str:
            raise ValueError("LOCAL custody exposes no HTTP view")

        with open_private_operator(
            mode=PrivateOperatorMode.OWNER,
            client_id=configuration.client_id,
            origin=configuration.origin,
            directory=owner_directory,
            escrow_confirmed_by_operator=escrow_confirmed_by_operator,
            view=unavailable_view,
            startup_loader=lambda **kwargs: configuration,
        ) as window:
            prepared = window._prepared
            if type(prepared) is not PreparedOwnerHost or prepared.named is not None:
                raise ValueError("LOCAL owner host required")
            owners = prepared.owners
            if (
                type(owners) is not OwnerGrantStore
                or owners._origin != configuration.origin
                or owners._client_id != configuration.client_id
                or owners._directory != owner_directory / "owner"
            ):
                raise ValueError("owner store context differs")

            def current_owner() -> OwnerGrant:
                grant = owners.load()
                if grant.identity != expected_identity or grant.scopes != _SCOPE:
                    raise ValueError("current exact PERSONAL owner required")
                return grant

            def local_action() -> None:
                nonlocal result, baseline
                baseline = current_owner()
                original = _read_file(original_path, _MAX_ORIGINAL, expected_original_hash)
                current_owner()
                raw = _read_file(proposal_path, MAX_MANIFEST_BYTES, expected_proposal_hash)
                proposal = ClaudeCustodyProposal.model_validate_json(raw)
                recomposed = prepare_claude_custody_proposal(
                    custody_id=proposal.custody_id,
                    original_raw=original,
                    account_ref=proposal.account_ref,
                    exported_at=proposal.exported_at,
                    acquired_at=proposal.acquired_at,
                    captured_at=proposal.captured_at,
                    boundary=proposal.boundary,
                    classification=proposal.classification,
                    selections=proposal.selections,
                )
                if (
                    raw != recomposed
                    or proposal.original_hash != expected_original_hash
                    or proposal.boundary != B.PERSONAL
                    or proposal.classification != C.HIGHLY_RESTRICTED
                    or current_owner() != baseline
                ):
                    raise ValueError("exact approved custody scope required")
                _approve_on_tty(
                    proposal, original_path, expected_proposal_hash=expected_proposal_hash
                )
                if current_owner() != baseline:
                    raise ValueError("owner changed during affirmation")
                with session_factory() as session, session.begin():
                    captured = record_claude_original(
                        session,
                        artifacts=artifacts,
                        expected_root=expected_root,
                        proposal_raw=raw,
                        original_raw=original,
                        approved_proposal_hash=expected_proposal_hash,
                        requestor_boundaries=frozenset({B.PERSONAL}),
                        allowed_classifications=frozenset({C.HIGHLY_RESTRICTED}),
                    )
                    if current_owner() != baseline:
                        raise ValueError("owner changed before commit")
                # Assign no result until successful outer exit AND a fresh actual
                # read-only pair observation. Unknown commit failures stay held.
                with session_factory() as session, session.begin():
                    current_owner()
                    read = load_claude_original(
                        session,
                        artifacts=artifacts,
                        expected_root=expected_root,
                        original_reference=captured.original_reference,
                        companion_reference=captured.companion_reference,
                        expected_account_ref=proposal.account_ref,
                        expected_exported_at=proposal.exported_at,
                        requestor_boundaries=frozenset({B.PERSONAL}),
                        allowed_classifications=frozenset({C.HIGHLY_RESTRICTED}),
                    )
                    if (
                        type(read) is not ReadClaudeCustody
                        or read.proposal_hash != expected_proposal_hash
                        or read.proposal != proposal
                        or read.original_raw != original
                        or read.original_reference != captured.original_reference
                        or read.companion_reference != captured.companion_reference
                        or read.captured_at != captured.original_captured_at
                        or read.captured_at != proposal.captured_at
                        or current_owner() != baseline
                    ):
                        raise ValueError("committed custody observation differs")
                result = LocalClaudeCustodyResult(
                    read.original_reference,
                    read.companion_reference,
                    read.proposal_hash,
                    read.captured_at,
                )

            # Reuse existing actual foreground signal/log/thread-drain lifecycle;
            # supported action is LOCAL only and binds NO listener.
            window.run_local(action=local_action)
            if result is None or baseline is None or current_owner() != baseline:
                raise ValueError("owner changed during foreground cleanup")
        # Actual context shutdown completes before this final signed-store read.
        if current_owner() != baseline:
            raise ValueError("owner changed during operator shutdown")
    except BaseException:  # noqa: BLE001 - interrupted cleanup holds; commit may be uncertain.
        result = None
    if result is None:
        raise LocalClaudeCustodyError("LOCAL Claude custody held; stop and reconcile")
    return result
