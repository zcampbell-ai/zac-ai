"""Attended concrete foreground email command; default is no-effect proposal.

Execute is a local operator startup action, never source/model/send consent.
Fixed known recovery/model constructors run under operator lease and startup
log/signal/drain protection. Original sign-in and separate UI POSTs remain required.
"""

from __future__ import annotations

import argparse
import logging
import os
import signal
import stat
import subprocess
import sys
import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import TextIO

from sqlalchemy import create_engine
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from zacai.backup_artifacts_s3 import S3CompatibleBackupObjectStore
from zacai.config import get_secret
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
from zacai.intelligence.contracts import ModelRoute
from zacai.intelligence.email_local_wire import LARGE_CONTEXT_TOKENS, LARGE_RUNTIME
from zacai.intelligence.email_processing_runtime import FixedLocalEmailRuntimeV1
from zacai.intelligence.local_followup_runtime import _raise_interruption
from zacai.intelligence.ollama_token_counter import OllamaQwenEmailTokenCounter
from zacai.interfaces.email_foreground import _EmailForegroundFactory, proposal
from zacai.interfaces.email_workflow_web import EmailWorkflowWeb
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.interfaces.private_operator import (
    PrivateOperatorMode,
    _drain_threads,
    open_private_operator,
)
from zacai.interfaces.private_startup import _configuration, load_attended_owner_startup
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier

_OWNER = Path("/Users/brainstormzac/Library/Application Support/Caz AI/private-interface")
_ARTIFACTS = Path("/Users/brainstormzac/zac-ai/var/artifacts")
_IDENTITY = Path("/Users/brainstormzac/.config/zacai/backup-keys/brainstorm.agekey")
_CACHE = Path("/Users/brainstormzac/zac-ai/private-data/context-backup-manifest.cache")
_MODELS = Path("/Users/brainstormzac/.ollama/models")
_RECIPIENT = "age1c84dtx3xxed5lacj3pn48v6p7xjvmvalr8umgnvs97fd02pg6yss34hvfr"
_DIGEST = "5642e97495e1a088883805981563dcdc4a040c2f53388b7a41d1f24d3622cf7e"
_CALLBACK = "CONFIRM CURRENT OWNER CALLBACK AND CREDENTIAL ESCROW"
_ATTEMPT = "OPEN REVIEWED ATTENDED BRAINSTORM EMAIL ATTEMPT"
_SERVICES = {
    "BRAINSTORM_B2_BACKUP_KEY_ID": "zacai-brainstorm-b2-backup-key-id",
    "BRAINSTORM_B2_BACKUP_APPLICATION_KEY": "zacai-brainstorm-b2-backup-application-key",
    "BRAINSTORM_B2_VERIFIER_KEY_ID": "zacai-brainstorm-b2-verifier-key-id",
    "BRAINSTORM_B2_VERIFIER_APPLICATION_KEY": "zacai-brainstorm-b2-verifier-application-key",
}


class EmailLaunchError(ValueError):
    """Fixed local diagnostic; no secret values, backend trace or private paths."""


def _backup_credential(name: str) -> str:
    result = None
    try:
        found = subprocess.run(
            [
                "/usr/bin/security",
                "find-generic-password",
                "-w",
                "-s",
                _SERVICES[name],
                "-a",
                "brainstormzac",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=30,
            env={},
        )
        if found.returncode != 0 or type(found.stdout) is not bytes:
            raise ValueError("fixed credential unavailable")
        raw = found.stdout[:-1] if found.stdout.endswith(b"\n") else found.stdout
        if not 1 <= len(raw) <= 4096:
            raise ValueError("bounded credential required")
        value = raw.decode("ascii")
        if any(not 33 <= ord(c) <= 126 for c in value):
            raise ValueError("exact credential characters required")
        result = get_secret(name, B.BRAINSTORM, env={name: value})
    except Exception:  # noqa: BLE001,S110 - no captured credential/process details escape
        pass
    if type(result) is not str or not result:
        raise EmailLaunchError("business backup credential unavailable")
    return result


def _reject_pg_environment() -> None:
    # Names only, never retrieve/print potential password or service values.
    if any(name.startswith("PG") for name in os.environ):
        raise EmailLaunchError("PostgreSQL environment overrides must be absent")


def _known_path(path: Path, *, directory: bool) -> None:
    info = path.lstat()
    if (
        path.resolve(strict=True) != path
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != (0o700 if directory else 0o600)
        or not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        or not directory
        and info.st_nlink != 1
    ):
        raise ValueError("existing owned recovery location required")


class _ConfiguredEmailFactory:
    """One actual fixed constructor scope. No configurable permission levels."""

    def __init__(self, folder: Path) -> None:
        self._folder = folder
        self._engine: Engine | None = None
        self._stores: list[S3CompatibleBackupObjectStore] = []
        self._used = False

    def close(self) -> None:
        failed = False
        for store in reversed(self._stores):
            try:
                store._client.close()
            except BaseException:  # noqa: BLE001 - attempt every close, hide private interruptions
                failed = True
        self._stores = []
        if self._engine is not None:
            try:
                self._engine.dispose()
            except BaseException:  # noqa: BLE001 - attempt every close, hide private interruptions
                failed = True
            self._engine = None
        if failed:
            raise EmailLaunchError("foreground dependency cleanup held")

    def __call__(self, inputs: NamedOwnerHostInputs) -> EmailWorkflowWeb:
        interruption: type[BaseException] | None = None
        code: int | None = 1
        result = None
        try:
            if self._used or type(inputs) is not NamedOwnerHostInputs:
                raise ValueError("one original host assembly required")
            self._used = True
            _reject_pg_environment()
            _known_path(_ARTIFACTS, directory=True)
            _known_path(_IDENTITY, directory=False)
            _known_path(_CACHE, directory=False)
            counter = OllamaQwenEmailTokenCounter(models_root=_MODELS, model_digest=_DIGEST)
            route = ModelRoute(
                identity={
                    "provider_id": "ollama",
                    "model_id": "qwen3.8:27b-mlx",
                    "runtime_id": LARGE_RUNTIME,
                },
                destination="LOCAL",
                capabilities=frozenset({"email_draft"}),
                available=True,
                max_input_characters=64000,
                max_output_tokens=2048,
                estimated_latency_ms=0.0,
                estimated_cost_usd=0.0,
            )
            runtime = FixedLocalEmailRuntimeV1(route=route, model_digest=_DIGEST, counter=counter)
            runtime.pins()  # actual offline blobs/implementation before private folder/backup credentials
            credentials = {name: _backup_credential(name) for name in _SERVICES}
            if (
                credentials["BRAINSTORM_B2_BACKUP_KEY_ID"]
                == credentials["BRAINSTORM_B2_VERIFIER_KEY_ID"]
            ):
                raise ValueError("independent reader identity required")
            for role in ("BACKUP", "VERIFIER"):
                store = S3CompatibleBackupObjectStore(
                    bucket="zac-ai-brainstorm-backup",
                    endpoint_url="https://s3.us-east-005.backblazeb2.com",
                    region="us-east-005",
                    max_attempts=0,
                    access_key_id=credentials["BRAINSTORM_B2_" + role + "_KEY_ID"],
                    secret_access_key=credentials["BRAINSTORM_B2_" + role + "_APPLICATION_KEY"],
                )
                self._stores.append(store)
            del credentials
            self._engine = create_engine(
                "postgresql+psycopg://127.0.0.1:5432/zacai_dev",
                isolation_level="READ COMMITTED",
                connect_args={"user": "brainstormzac", "passfile": "/dev/null"},
            )
            protector = BrainstormContextualProtector(
                factory=sessionmaker(bind=self._engine),
                engine=self._engine,
                artifacts=LocalFilesystemArtifactStore(_ARTIFACTS),
                objects=self._stores[0],
                verification_objects=self._stores[1],
                recipient=_RECIPIENT,
                identity_path=_IDENTITY,
                manifest_cache=_CACHE,
                restoration=DisposableStateRestoreVerifier(),
                approval_id=None,
            )
            result = _EmailForegroundFactory(self._folder, protector, runtime)(inputs)
        except BaseException as error:  # noqa: BLE001 - private construction failure remains closed
            interruption = type(error)
            if isinstance(error, SystemExit):
                code = error.code if error.code is None or type(error.code) is int else 1
            try:
                with _cleanup_signals():
                    self.close()
            except BaseException:  # noqa: BLE001,S110 - preserve the already closed constructor failure
                pass
        _raise_interruption(interruption, code)
        if result is None:
            raise EmailLaunchError("foreground email constructor unavailable")
        return result


def _startup_interruption(signum: int, frame: object) -> None:
    # Empty arguments prevent handler context from becoming public output.
    raise KeyboardInterrupt()


@contextmanager
def _cleanup_signals() -> Iterator[None]:
    # Only resource close/drain sections suppress interruption. No startup,
    # credential acquisition or serving work belongs inside this section.
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    try:
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        yield
    finally:
        for sig in reversed(handlers):
            signal.signal(sig, handlers[sig])


@contextmanager
def _startup_controls() -> Iterator[None]:
    # Extend the existing operator's controls over constructor/startup work, not
    # a new service/authority. The nested mode lease still governs the operator.
    if threading.current_thread() is not threading.main_thread() or set(threading.enumerate()) != {
        threading.main_thread()
    }:
        raise EmailLaunchError("dedicated foreground process required")
    disabled = logging.root.manager.disable
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    if any(h is None for h in handlers.values()):
        raise EmailLaunchError("known foreground signal handlers required")
    try:
        logging.disable(sys.maxsize)
        for sig in handlers:
            signal.signal(sig, _startup_interruption)
        yield
    finally:
        with _cleanup_signals():
            _drain_threads({threading.main_thread()})
        try:
            logging.disable(disabled)
        finally:
            for sig in reversed(handlers):
                signal.signal(sig, handlers[sig])


def _attest(stdin: TextIO, stdout: TextIO, phrase: str) -> None:
    stdout.write(phrase + "\nType the exact line above to continue: ")
    stdout.flush()
    if stdin.readline(160) != phrase + "\n":
        raise ValueError("exact attended attestation required")


def run_attended(
    *, client_id: str, origin: str, input_folder: Path, stdin: TextIO, stdout: TextIO
) -> None:
    interruption: type[BaseException] | None = None
    code: int | None = 1
    failed = False
    try:
        if not stdin.isatty() or not stdout.isatty():
            raise ValueError("foreground terminal required")
        _configuration(client_id, origin)
        if not input_folder.is_absolute():
            raise ValueError("owned selected folder required")
        _reject_pg_environment()
        _attest(stdin, stdout, _CALLBACK)
        _attest(stdin, stdout, _ATTEMPT)
        with _startup_controls():
            factory = _ConfiguredEmailFactory(input_folder)

            async def view(principal: object) -> str:
                return '<a href="/prepare-caz-email">Prepare email follow-up</a>'

            try:
                with open_private_operator(
                    mode=PrivateOperatorMode.OWNER,
                    client_id=client_id,
                    origin=origin,
                    directory=_OWNER,
                    escrow_confirmed_by_operator=True,
                    view=view,
                    startup_loader=load_attended_owner_startup,
                    email_factory=factory,
                    email_startup_failure_cleanup=factory.close,
                    clock=HostObservedClock(lambda: datetime.now(UTC)),
                ) as window:
                    try:
                        window.serve()
                    finally:
                        with _cleanup_signals():
                            _drain_threads({threading.main_thread()})
                            try:
                                factory.close()
                            finally:
                                _drain_threads({threading.main_thread()})
            finally:
                # Idempotent fallback only. The operator's startup-failure hook
                # closes before its drain/lease release on a pre-yield failure.
                with _cleanup_signals():
                    factory.close()
    except BaseException as error:  # noqa: BLE001 - all nested leases/drains complete first
        failed = True
        interruption = type(error)
        if isinstance(error, SystemExit):
            code = error.code if error.code is None or type(error.code) is int else 1
    _raise_interruption(interruption, code)
    if failed:
        raise EmailLaunchError("attended foreground email attempt unavailable")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Proposal by default; execute requires an attended reviewed owner attempt."
    )
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--client-id")
    parser.add_argument("--origin")
    parser.add_argument("--input-folder", type=Path)
    args = parser.parse_args(argv)
    if not args.execute:
        import json

        public = proposal(
            client_id=args.client_id,
            origin=args.origin,
            owner_directory=_OWNER,
            input_folder=args.input_folder,
        )
        locations = public["known_location_metadata"]
        if type(locations) is not dict:
            raise EmailLaunchError("public proposal metadata unavailable")
        locations["manifest_cache"] = (
            str(_CACHE)
            + "; root metadata observation: owned0600 regular non-symlink; proposal reads no files"
        )
        public["manifest_cache_provenance"] = {
            "observation": "Root metadata-only inspection during this launch review; not backup authority",
            "reported_boundary": "BRAINSTORM",
            "reported_top_keys": ["boundary", "entries", "generated_at", "manifest_version"],
            "supersedes": "Precursor OWNER_REQUIRED cache-location handoff only",
            "proposal_inspects_files": False,
        }
        public["startup_construction"] = (
            "Actual prepare_owner_host calls the cold factory on the main startup thread before serve; original owner sign-in and first authenticated GET bind later"
        )
        public["owner_credential_wait_seconds"] = 60
        public["model_digest"] = _DIGEST
        public["runtime_id"] = LARGE_RUNTIME
        public["model_context_tokens"] = LARGE_CONTEXT_TOKENS
        public["execute_command_capable"] = True
        public["execute_requirements"] = (
            "Current callback/escrow confirmation and exact attended terminal attestation; startup is not capture/inference/send consent."
        )
        print(json.dumps(public, indent=2))
        return 0
    if args.client_id is None or args.origin is None or args.input_folder is None:
        raise EmailLaunchError("current public configuration and selected folder required")
    run_attended(
        client_id=args.client_id,
        origin=args.origin,
        input_folder=args.input_folder,
        stdin=sys.stdin,
        stdout=sys.stdout,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
