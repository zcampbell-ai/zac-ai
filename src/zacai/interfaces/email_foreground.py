"""Proposal-first foreground OWNER initializer, never an agent execution grant.

CLI proposal prints public declarations only and reads no files or metadata.
Actual window requires separately configured
concrete recovery/runtime objects and future explicit owner operator action.
Credentials remain in existing startup/gateway host memory, never argv/env.
"""

from __future__ import annotations

import argparse
import json
import os
import stat
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import AwareDatetime, Field

from zacai.backup_artifacts_s3 import S3CompatibleBackupObjectStore
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
from zacai.ingestion.gmail_app_observation import (
    MAX_OBSERVATION_BYTES,
    GmailAppObservationPreparationV1,
    GmailAppObservationScopeV1,
    prepare_gmail_app_observation,
)
from zacai.intelligence.email_draft import EmailContract, EmailRecipientComparisonV1
from zacai.intelligence.email_processing_runtime import FixedLocalEmailRuntimeV1
from zacai.intelligence.local_followup_runtime import _raise_interruption
from zacai.intelligence.local_review_runtime import _json
from zacai.interfaces.email_workflow_web import EmailWorkflowWeb
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.interfaces.private_operator import (
    PrivateOperatorMode,
    PrivateOperatorWindow,
    open_private_operator,
)
from zacai.interfaces.private_startup import _configuration
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B


class EmailForegroundError(ValueError):
    """Fixed diagnostics; no private paths, message fields or nested exceptions."""


class EmailFolderMessageV1(EmailContract):
    filename: Literal["message-1.json", "message-2.json"]
    reported_tool_name: str = Field(
        strict=True, min_length=1, max_length=100, pattern=r"^[A-Za-z0-9_.:/-]+$"
    )
    declared_account_label: str = Field(strict=True, min_length=1, max_length=200, repr=False)
    expected_message_id: str = Field(
        strict=True, min_length=1, max_length=200, pattern=r"^[A-Za-z0-9_-]+$"
    )
    expected_thread_id: str | None = Field(strict=True, max_length=200, pattern=r"^[A-Za-z0-9_-]+$")
    selected_part_path: tuple[int, ...] = Field(max_length=8)
    selected_body_field: Literal["content", "base64_url_content"]
    reported_acquired_at: AwareDatetime | None


class EmailFolderSelectionV1(EmailContract):
    format: Literal["zac-owner-email-app-folder-v1"]
    messages: tuple[EmailFolderMessageV1, ...] = Field(min_length=1, max_length=2, repr=False)
    recipient: EmailRecipientComparisonV1 | None = Field(repr=False)


def _folder(folder: Path) -> tuple[int, int, int, int, int]:
    if (
        not isinstance(folder, Path)
        or not folder.is_absolute()
        or folder.resolve(strict=True) != folder
    ):
        raise ValueError("canonical owned folder required")
    s = folder.lstat()
    if not stat.S_ISDIR(s.st_mode) or s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
        raise ValueError("private owned folder required")
    return s.st_dev, s.st_ino, s.st_uid, s.st_mode, s.st_mtime_ns


def _bounded(fd: int, name: str, limit: int) -> bytes:
    opened = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
    try:
        before = os.fstat(opened)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
            or not 0 < before.st_size <= limit
        ):
            raise ValueError("owned finite private input required")
        with os.fdopen(opened, "rb", closefd=False) as source:
            value = source.read(limit + 1)
        after = os.fstat(opened)
        current = os.stat(name, dir_fd=fd, follow_symlinks=False)

        def fields(s: os.stat_result) -> tuple[int, ...]:
            return (
                s.st_dev,
                s.st_ino,
                s.st_size,
                s.st_mtime_ns,
                s.st_ctime_ns,
                s.st_mode,
                s.st_uid,
                s.st_nlink,
            )

        if (
            fields(before) != fields(after)
            or fields(after) != fields(current)
            or len(value) != before.st_size
        ):
            raise ValueError("input changed during bounded read")
        return value
    finally:
        os.close(opened)


def load_selected_app_folder(
    folder: Path, clock: HostObservedClock
) -> tuple[tuple[GmailAppObservationPreparationV1, ...], EmailRecipientComparisonV1 | None]:
    """Future host-only exact selected serialization read, not Gmail acquisition.

    No discovery/recursive import. Two fixed filenames maximum. Every original
    field/byte is retained; neither tool status text nor MIME is manufactured.
    Existing source preparation owns reported date/role/attachment limitations.
    """
    result = None
    interruption: type[BaseException] | None = None
    code: int | None = 1
    try:
        if type(clock) is not HostObservedClock:
            raise ValueError("actual host clock required")
        pin = _folder(folder)
        fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (pin[0], pin[1]):
                raise ValueError("folder identity changed")
            config = EmailFolderSelectionV1.model_validate(
                _json(_bounded(fd, "selection.json", 12000))
            )
            if len({m.filename for m in config.messages}) != len(config.messages):
                raise ValueError("distinct selected files required")
            selected = tuple(
                (m, _bounded(fd, m.filename, MAX_OBSERVATION_BYTES)) for m in config.messages
            )
            inspected = clock()  # actual completed host inspection, never historical message time
            plans = tuple(
                prepare_gmail_app_observation(
                    raw=raw,
                    scope=GmailAppObservationScopeV1(
                        **{k: v for k, v in m.model_dump(mode="python").items() if k != "filename"},
                        inspected_at=inspected,
                    ),
                    requestor_boundaries=frozenset({B.BRAINSTORM}),
                    allowed_classifications=frozenset({C.CONFIDENTIAL}),
                )
                for m, raw in selected
            )
            if _folder(folder) != pin:
                raise ValueError("folder changed after exact read")
            result = (plans, config.recipient)
        finally:
            os.close(fd)
    except BaseException as error:  # noqa: BLE001 - no message/file/cancellation diagnostics escape
        interruption = type(error)
        if isinstance(error, SystemExit):
            code = error.code if error.code is None or type(error.code) is int else 1
    _raise_interruption(interruption, code)
    if result is None:
        raise EmailForegroundError("selected email app inputs unavailable")
    return result


class _EmailForegroundFactory:
    def __init__(
        self,
        folder: Path,
        protector: BrainstormContextualProtector,
        runtime: FixedLocalEmailRuntimeV1,
    ) -> None:
        if (
            type(protector) is not BrainstormContextualProtector
            or type(runtime) is not FixedLocalEmailRuntimeV1
            or type(protector._artifacts) is not LocalFilesystemArtifactStore
            or type(protector._objects) is not S3CompatibleBackupObjectStore
            or type(protector._reader) is not S3CompatibleBackupObjectStore
            or protector._objects is protector._reader
            or protector._objects._client is protector._reader._client
            or protector._objects._bucket != protector._reader._bucket
            or protector._engine.url.database != "zacai_dev"
            or protector._approval_id is not None
        ):
            raise EmailForegroundError("concrete business recovery and local runtime required")
        # Distinct concrete clients are not proof of independent credentials,
        # geography or recovered age custody. Those remain existing host gates.
        self._folder, self._protector, self._runtime = folder, protector, runtime

    def __call__(self, inputs: NamedOwnerHostInputs) -> EmailWorkflowWeb:
        result = None
        interruption: type[BaseException] | None = None
        code: int | None = 1
        try:
            if type(inputs) is not NamedOwnerHostInputs:
                raise ValueError("actual operator inputs required")
            self._runtime.pins()  # offline exact manifest/tokenizer/template/implementation count pins, no HTTP
            preparations, recipient = load_selected_app_folder(self._folder, inputs.clock)
            continuity = NamedSessionContinuity(
                sessions=inputs.sessions,
                owner=inputs.owner,
                clock=inputs.clock,
                key=inputs.session_key,
                origin=inputs.origin,
                client_id=inputs.client_id,
            )
            result = EmailWorkflowWeb(
                continuity=continuity,
                protector=self._protector,
                runtime=self._runtime,
                preparations=preparations,
                recipient=recipient,
            )
        except BaseException as error:  # noqa: BLE001 - no source/key/backend details escape
            interruption = type(error)
            if isinstance(error, SystemExit):
                code = error.code if error.code is None or type(error.code) is int else 1
        _raise_interruption(interruption, code)
        if result is None:
            raise EmailForegroundError("foreground email assembly unavailable")
        return result


@contextmanager
def foreground_email_window(
    *,
    client_id: str,
    origin: str,
    owner_directory: Path,
    input_folder: Path,
    protector: BrainstormContextualProtector,
    runtime: FixedLocalEmailRuntimeV1,
    escrow_confirmed_by_operator: bool,
) -> Iterator[PrivateOperatorWindow]:
    """Future explicit owner operator only; retains existing mode lease/drain.

    Does not serve. Caller may separately choose window.serve() after review and
    authorization. No private credential file/Keychain/model/source is read by
    the default proposal CLI. Recovery objects are actual host configuration,
    never supplied by HTTP fields, identity claims or secret argv/environment.
    """
    failed = False
    interruption: type[BaseException] | None = None
    code: int | None = 1
    try:
        _configuration(client_id, origin)
        factory = _EmailForegroundFactory(input_folder, protector, runtime)

        async def view(principal: object) -> str:
            return '<a href="/prepare-caz-email">Prepare email follow-up</a>'

        with open_private_operator(
            mode=PrivateOperatorMode.OWNER,
            client_id=client_id,
            origin=origin,
            directory=owner_directory,
            escrow_confirmed_by_operator=escrow_confirmed_by_operator,
            view=view,
            email_factory=factory,
            clock=HostObservedClock(lambda: datetime.now(UTC)),
        ) as window:
            yield window
    except BaseException as error:  # noqa: BLE001 - mode lease/drain closes before sanitized error
        failed = True
        interruption = type(error)
        if isinstance(error, SystemExit):
            code = error.code if error.code is None or type(error.code) is int else 1
    _raise_interruption(interruption, code)
    if failed:
        raise EmailForegroundError("foreground email window unavailable")


def proposal(
    *,
    client_id: str | None,
    origin: str | None,
    owner_directory: Path | None,
    input_folder: Path | None,
) -> dict[str, object]:
    """Public declarations only: never read input/config/secret/model files."""
    valid = False
    try:
        if (client_id is None) != (origin is None):
            raise ValueError("paired public configuration required")
        if client_id is not None and origin is not None:
            _configuration(client_id, origin)
        valid = True
    except Exception:  # noqa: BLE001,S110 - no invalid public argument values in errors
        pass
    if not valid:
        raise EmailForegroundError("public foreground proposal configuration unavailable")
    return {
        "mode": "PROPOSAL_ONLY",
        "execution_enabled": False,
        "historical_owner_sign_in": {
            "client_id": "744416556882-0skde0finhnbrg2i937ak7k6mtl03ml8.apps.googleusercontent.com",
            "origin": "https://zacharys-mac-studio.taila3938c.ts.net",
            "source": "work/gmail-slack-account-connection-handoff-2026-10-06.md:235/304",
            "status": "HISTORICAL; current registered callback/credential escrow require owner confirmation; no callback URL or code printed",
        },
        "owner_directory": str(owner_directory)
        if owner_directory is not None
        else "/Users/brainstormzac/Library/Application Support/Caz AI/private-interface",
        "known_location_metadata": {
            "basis": "Metadata observed by root on2026-10-13; this CLI performs no inspection",
            "owner_directory": "existing0700, non-symlink",
            "artifact_root": "/Users/brainstormzac/zac-ai/var/artifacts; existing0700, non-symlink",
            "age_identity": "/Users/brainstormzac/.config/zacai/backup-keys/brainstorm.agekey; existing0600, non-symlink; contents not read",
            "model_root": "/Users/brainstormzac/.ollama/models; exists; no manifest/weights read by proposal",
            "manifest_cache": "OWNER_REQUIRED; exact existing private location not established",
            "canonical_dev_engine": "postgresql+psycopg://127.0.0.1:5432/zacai_dev; lazy READ COMMITTED, brainstormzac, passfile /dev/null; reject PG credential/service environment names before connect",
        },
        "known_backup_gateway": {
            "source": "scripts/protected_schema_rollout.py:30-45; independent reader RECOVERY.md:314-320",
            "writer_services": [
                "zacai-brainstorm-b2-backup-key-id",
                "zacai-brainstorm-b2-backup-application-key",
            ],
            "reader_services": [
                "zacai-brainstorm-b2-verifier-key-id",
                "zacai-brainstorm-b2-verifier-application-key",
            ],
            "account": "brainstormzac",
            "bucket": "zac-ai-brainstorm-backup",
            "endpoint": "https://s3.us-east-005.backblazeb2.com",
            "region": "us-east-005",
            "recipient": "age1c84dtx3xxed5lacj3pn48v6p7xjvmvalr8umgnvs97fd02pg6yss34hvfr",
            "status": "Public installed references only. No credential, key or cloud invocation. Never duplicate writer as reader.",
        },
        "input_folder": str(input_folder) if input_folder is not None else "OWNER_REQUIRED",
        "registered_callback_rule": "Configured private origin must have its exact /auth/callback registered. No callback URL/code is printed.",
        "owner_keychain_services": [
            "zacai-shared-owner-google-client-secret",
            "zacai-shared-owner-session-key",
        ],
        "owner_keychain_account": "zac-owner-sign-in",
        "owner_keychain_presence": "NOT_INSPECTED",
        "recovery_required": [
            "existing encrypted enrolled BRAINSTORM owner directory",
            "local canonical zacai_dev engine and LocalFilesystemArtifactStore",
            "independently authorized B2 writer and reader services for the same reviewed bucket/endpoint",
            "proven BRAINSTORM age recipient/identity and private manifest cache",
            "actual offline qwen3.8:27b-mlx email runtime pins",
        ],
        "selection_files": ["selection.json", "message-1.json", "optional message-2.json"],
        "source_family": "Exact serialization of returned structured app messages. Not original MCP wire, provider RAW/MIME or authenticated mailbox/sender.",
        "remaining_handoff": "Owner supplies actual public client/origin, existing owner directory and input folder, plus existing credential-gateway-backed concrete protector/runtime. Known public references do not prove current callback, credential custody or reader permission. Actual constructor assembly remains owner-gated.",
        "ui_actions": [
            "actual owner sign-in and first GET binding",
            "separate capture POST",
            "separate one-attempt LOCAL generation POST",
            "semantic ACCEPT/DECLINE/DEFER",
            "separate checked manual-use release; no send",
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Print a non-executing foreground email initializer proposal."
    )
    parser.add_argument("--client-id")
    parser.add_argument("--origin")
    parser.add_argument("--owner-directory", type=Path)
    parser.add_argument("--input-folder", type=Path)
    args = parser.parse_args(argv)
    print(
        json.dumps(
            proposal(
                client_id=args.client_id,
                origin=args.origin,
                owner_directory=args.owner_directory,
                input_folder=args.input_folder,
            ),
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
