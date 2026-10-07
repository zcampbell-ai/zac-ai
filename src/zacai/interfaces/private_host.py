"""Trusted host assembly for explicit enrollment OR an enrolled private view.

These factories construct ASGI apps but do not bind a listener, configure TLS,
read Keychain, discover sources, or start model/tool execution. The host supplies
reviewed startup configuration, a private operational directory, a trusted clock
and (only in owner mode) a protected view callback. Never call from agents or use
request fields for these inputs. No automatic enrollment fallback exists.

The owner record and encrypted sessions are operational authentication state,
not a second canonical memory store. The injected key is shared only inside this
host assembly; OwnerGrantStore domain-separates its authentication key with HKDF.
Same-UID malicious access and filesystem rollback still require host isolation.
The root and its ancestors must be trusted host locations. Actual credential
escrow, local confirmation, serving and mobile validation remain release gates.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import FastAPI

from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.oidc_identity import AuthlibGoogleIdentity, IdentityProvider
from zacai.interfaces.owner_enrollment import OwnerEnrollment, create_owner_enrollment
from zacai.interfaces.owner_store import OwnerGrantStore
from zacai.interfaces.private_startup import OwnerStartupConfiguration, _configuration
from zacai.interfaces.private_web import InterfacePrincipal, OwnerGrant, create_private_web
from zacai.interfaces.sqlite_sessions import SqliteSessionStore

if TYPE_CHECKING:
    from zacai.interfaces.gmail_connection_web import GmailConnectionWeb
    from zacai.interfaces.named_followup_web import NamedFollowupWeb
    from zacai.interfaces.named_worker_lifecycle import NamedWorkerRegistry
    from zacai.interfaces.work_choice_web import WorkChoiceWeb


class PrivateHostError(ValueError):
    """Closed host assembly diagnostic; no private credentials, paths or inputs."""


@dataclass(frozen=True, repr=False)
class NamedOwnerHostInputs:
    """Trusted assembly inputs only; typed shape grants no data/model authority.

    No OAuth client secret is shared with the named factory. The in-memory host
    seal key must never enter argv, request fields, logs or agent construction.
    """

    origin: str
    client_id: str
    session_key: bytes = field(repr=False)
    directory: Path = field(repr=False)
    owners: OwnerGrantStore = field(repr=False)
    owner: Callable[[], OwnerGrant] = field(repr=False)
    sessions: SqliteSessionStore = field(repr=False)
    clock: HostObservedClock = field(repr=False)


@dataclass(frozen=True, repr=False)
class PreparedNamedOwnerHost:
    """Exact controller/lifecycle pair, not proof its canonical gates are real."""

    controller: NamedFollowupWeb = field(repr=False)
    workers: NamedWorkerRegistry = field(repr=False)


NamedOwnerHostFactory = Callable[[NamedOwnerHostInputs], PreparedNamedOwnerHost]
GmailOwnerHostFactory = Callable[[NamedOwnerHostInputs], "GmailConnectionWeb"]


def _named_owner_pair(inputs: NamedOwnerHostInputs, result: object) -> PreparedNamedOwnerHost:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    from zacai.interfaces.named_admission_store import SqliteNamedAdmissionStore
    from zacai.interfaces.named_browser_pointer import NamedBrowserPointerCodec
    from zacai.interfaces.named_followup_web import NamedFollowupWeb
    from zacai.interfaces.named_published_display import CanonicalNamedPublishedDisplayGate
    from zacai.interfaces.named_session_binding import NamedSessionContinuity
    from zacai.interfaces.named_worker_lifecycle import (
        NamedWorkerRegistry,
        ThreadBoundNamedAskPipeline,
    )

    if type(result) is not PreparedNamedOwnerHost:
        raise ValueError("exact named host assembly required")
    controller, workers = result.controller, result.workers
    if (
        type(controller) is not NamedFollowupWeb
        or type(workers) is not NamedWorkerRegistry
        or controller.host_clock is not inputs.clock
        or type(controller._display) is not CanonicalNamedPublishedDisplayGate
        or controller._display.host_clock is not inputs.clock
        or workers.host_clock is not inputs.clock
        or type(controller._continuity) is not NamedSessionContinuity
        or controller._continuity._clock is not inputs.clock
        or controller._coordinator._clock is not inputs.clock
        or controller._continuity._sessions is not inputs.sessions
        or controller._continuity._owner is not inputs.owner
        or getattr(controller._continuity._owner, "__self__", None) is not inputs.owners
        or getattr(controller._continuity._owner, "__func__", None) is not OwnerGrantStore.load
    ):
        raise ValueError("actual owner/session/lifecycle assembly differs")
    # Derivation opens nothing. Compare the actual HMAC origin/client/key binding
    # without reading or displaying cookies or decrypting another operational DB.
    expected = NamedSessionContinuity(
        sessions=inputs.sessions,
        owner=inputs.owner,
        clock=inputs.clock,
        key=inputs.session_key,
        origin=inputs.origin,
        client_id=inputs.client_id,
    )
    if (
        controller._continuity._context != expected._context
        or controller._continuity._key != expected._key
    ):
        raise ValueError("actual host session binding differs")
    store, codec = controller._store, controller._coordinator._codec
    if (
        type(store) is not SqliteNamedAdmissionStore
        or controller._coordinator._store is not store
        or store._clock is not inputs.clock
        or store._context != expected._context
        or type(codec) is not NamedBrowserPointerCodec
        or codec.host_clock is not inputs.clock
        or not store._directory.is_absolute()
        or store._directory == inputs.directory
        or not store._directory.is_relative_to(inputs.directory)
        or store._directory.resolve(strict=True) != store._directory
        or inputs.directory.resolve(strict=True) != inputs.directory
        or store._path != store._directory / "admissions.sqlite"
    ):
        raise ValueError("actual named store/pointer host configuration differs")
    # Derive from actual host inputs without creating a comparison database.
    # A private transient challenge checks cipher binding without exposing keys
    # or reading/decrypting an operational record; it establishes no permission.
    store_key = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"zac-named-admission-key-v1",
        info=b"zac-named-admission-store-v1\x00" + expected._context,
    ).derive(inputs.session_key)
    nonce, challenge = os.urandom(12), b"zac-named-host-binding-check-v1"
    sealed = AESGCM(store_key).encrypt(nonce, challenge, expected._context)
    if store._cipher.decrypt(nonce, sealed, expected._context) != challenge:
        raise ValueError("actual named store key differs")
    expected_codec = NamedBrowserPointerCodec(
        key=inputs.session_key, origin=inputs.origin, client_id=inputs.client_id,
        clock=inputs.clock,
    )
    if codec._aad != expected_codec._aad:
        raise ValueError("actual named pointer context differs")
    nonce = os.urandom(12)
    sealed = expected_codec._cipher.encrypt(nonce, challenge, expected_codec._aad)
    if codec._cipher.decrypt(nonce, sealed, expected_codec._aad) != challenge:
        raise ValueError("actual named pointer key differs")
    if controller._pipeline is not None and (
        type(controller._pipeline) is not ThreadBoundNamedAskPipeline
        or controller._pipeline._workers is not workers
        or controller._pipeline._store is not controller._store
    ):
        raise ValueError("actual named worker wrapper required")
    return result


def _gmail_owner_controller(inputs: NamedOwnerHostInputs, result: object) -> GmailConnectionWeb:
    """Verify actual host owner/session/key/clock and isolated transaction ledger."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
    from zacai.interfaces.gmail_connection_web import GmailConnectionWeb
    from zacai.interfaces.named_session_binding import NamedSessionContinuity

    if type(result) is not GmailConnectionWeb or type(result._authority) is not OAuthTransactionAuthority:
        raise ValueError("exact Gmail host controller required")
    authority = result._authority
    continuity = authority._continuity
    if (
        type(continuity) is not NamedSessionContinuity
        or continuity._sessions is not inputs.sessions
        or continuity._owner is not inputs.owner
        or continuity._clock is not inputs.clock
        or getattr(continuity._owner, "__self__", None) is not inputs.owners
        or getattr(continuity._owner, "__func__", None) is not OwnerGrantStore.load
        or result._configuration.private_origin != inputs.origin
        or not authority._directory.is_absolute()
        or authority._directory == inputs.directory
        or not authority._directory.is_relative_to(inputs.directory)
        or authority._directory.resolve(strict=True) != authority._directory
        or inputs.directory.resolve(strict=True) != inputs.directory
        or authority._path != authority._directory / "provider-oauth-transactions.bin"
        or authority._lock_path != authority._directory / "provider-oauth-transactions.lock"
    ):
        raise ValueError("actual Gmail owner/session/ledger differs")
    expected = NamedSessionContinuity(
        sessions=inputs.sessions, owner=inputs.owner, clock=inputs.clock,
        key=inputs.session_key, origin=inputs.origin, client_id=inputs.client_id,
    )
    expected_context = b"zac-provider-oauth-transactions-v1\x00" + expected._context
    if (
        continuity._context != expected._context
        or continuity._key != expected._key
        or authority._context != expected_context
        or authority._origin != inputs.origin
    ):
        raise ValueError("actual Gmail session binding differs")
    key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b"zac-provider-oauth-transactions-v1", info=expected_context,
    ).derive(inputs.session_key)
    nonce, challenge = os.urandom(12), b"zac-gmail-host-binding-check-v1"
    sealed = AESGCM(key).encrypt(nonce, challenge, expected_context)
    if authority._cipher.decrypt(nonce, sealed, expected_context) != challenge:
        raise ValueError("actual Gmail ledger key differs")
    # This guard must already have been initialized/reconciled by trusted host
    # operations. Factory validation never creates a ready marker or clears holds.
    result._ready()
    return result


@dataclass(frozen=True)
class PreparedOwnerHost:
    app: FastAPI = field(repr=False)
    owners: OwnerGrantStore = field(repr=False)
    sessions: SqliteSessionStore = field(repr=False)
    named: PreparedNamedOwnerHost | None = field(default=None, repr=False)

    def revoke_owner(self) -> None:
        """Trusted local revocation: deny owner and invalidate all old cookies.

        Always attempt session invalidation even if the owner write fails. A
        partial failure is not acknowledged; the host must stop serving and
        reconcile storage before retrying. Direct store methods do not implement
        the composed lifecycle and must not replace this operational entrypoint.
        """
        okay = False
        try:
            try:
                self.owners.revoke()
            finally:
                self.sessions.revoke_all()
            okay = True
        except Exception:  # noqa: BLE001, S110 - closed operational diagnostics
            pass
        if not okay:
            raise PrivateHostError("private owner revocation unavailable")


@dataclass(frozen=True)
class PreparedEnrollmentHost:
    app: FastAPI = field(repr=False)
    owners: OwnerGrantStore = field(repr=False)
    sessions: SqliteSessionStore = field(repr=False)
    enrollment: OwnerEnrollment = field(repr=False)


def _validate(configuration: OwnerStartupConfiguration, directory: Path) -> None:
    if type(configuration) is not OwnerStartupConfiguration:
        raise ValueError("invalid host configuration")
    _configuration(configuration.client_id, configuration.origin)
    if (
        type(configuration.client_secret) is not str
        or not 1 <= len(configuration.client_secret) <= 4096
        or any(not 33 <= ord(c) <= 126 for c in configuration.client_secret)
        or type(configuration.session_key) is not bytes
        or len(configuration.session_key) != 32
        or not isinstance(directory, Path)
        or not directory.is_absolute()
    ):
        raise ValueError("invalid host configuration")


def _directory(directory: Path) -> None:
    directory.mkdir(mode=0o700, exist_ok=True)
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_IMODE(info.st_mode) != 0o700
        or info.st_uid != os.getuid()
    ):
        raise ValueError("invalid host directory")


def prepare_owner_host(
    *,
    configuration: OwnerStartupConfiguration,
    directory: Path,
    view: Callable[[InterfacePrincipal], Awaitable[str]],
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    identities: IdentityProvider | None = None,
    work_choices: WorkChoiceWeb | None = None,
    named_factory: NamedOwnerHostFactory | None = None,
    gmail_factory: GmailOwnerHostFactory | None = None,
) -> PreparedOwnerHost:
    """Compose durable enrolled access; missing/tampered/revoked owner denies.

    No enrollment route is mounted here. Owner validity is checked before a
    session database or provider client is constructed and refreshed per request.
    The host-owned view must independently refresh canonical source ACLs and
    retained recovery evidence. Injected identities are for trusted assembly and
    isolated tests, never selected by a browser or used as authentication claims.
    """
    result: PreparedOwnerHost | None = None
    try:
        _validate(configuration, directory)
        if named_factory is not None and (
            not callable(named_factory) or type(clock) is not HostObservedClock
        ):
            raise ValueError("actual named host factory/shared clock required")
        if gmail_factory is not None and (
            not callable(gmail_factory) or type(clock) is not HostObservedClock
        ):
            raise ValueError("actual Gmail host factory/shared clock required")
        if work_choices is not None:
            from zacai.interfaces.work_choice_web import WorkChoiceWeb

            if type(work_choices) is not WorkChoiceWeb:
                raise ValueError("invalid host work choice controller")
        if not callable(view) or not callable(clock):
            raise TypeError("invalid host callbacks")
        _directory(directory)
        owners = OwnerGrantStore(
            directory / "owner",
            key=configuration.session_key,
            origin=configuration.origin,
            client_id=configuration.client_id,
        )
        owners.load()
        owner = owners.load
        sessions = SqliteSessionStore(directory / "sessions", key=configuration.session_key)
        provider = (
            identities
            if identities is not None
            else AuthlibGoogleIdentity(
                client_id=configuration.client_id, client_secret=configuration.client_secret
            )
        )
        named = None
        if named_factory is not None:
            assert type(clock) is HostObservedClock
            inputs = NamedOwnerHostInputs(
                configuration.origin,
                configuration.client_id,
                configuration.session_key,
                directory,
                owners,
                owner,
                sessions,
                clock,
            )
            named = _named_owner_pair(inputs, named_factory(inputs))
        gmail = None
        if gmail_factory is not None:
            assert type(clock) is HostObservedClock
            gmail_inputs = NamedOwnerHostInputs(
                configuration.origin, configuration.client_id, configuration.session_key,
                directory, owners, owner, sessions, clock,
            )
            gmail = _gmail_owner_controller(gmail_inputs, gmail_factory(gmail_inputs))
        app = create_private_web(
            origin=configuration.origin,
            identities=provider,
            sessions=sessions,
            owner=owner,
            view=view,
            clock=clock,
            work_choices=work_choices,
            named_questions=named.controller if named is not None else None,
            gmail_connections=gmail,
        )
        if named is not None:
            from zacai.interfaces.named_worker_lifecycle import (
                ThreadBoundNamedAskPipeline,
                install_named_worker_drain,
            )

            pipeline = named.controller._pipeline
            if pipeline is not None and type(pipeline) is not ThreadBoundNamedAskPipeline:
                raise ValueError("actual paired worker pipeline required")
            install_named_worker_drain(app, named.workers, pipeline=pipeline)
        result = PreparedOwnerHost(app, owners, sessions, named)
    except Exception:  # noqa: BLE001, S110 - no private diagnostics or exception chaining
        pass
    if result is None:
        raise PrivateHostError("private owner host unavailable")
    return result


def prepare_enrollment_host(
    *,
    configuration: OwnerStartupConfiguration,
    directory: Path,
    clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    identities: IdentityProvider | None = None,
) -> PreparedEnrollmentHost:
    """Explicit short local setup window, never a protected view or auto-fallback.

    Calling this is a trusted local setup decision, including any re-enrollment.
    No source/view callback is accepted. Browser completion captures identity but
    cannot persist it: the local host must separately use owners.confirm_and_save
    with exact pairing, identity, origin and independently approved scopes.
    Restarting setup expires the prior volatile candidate and invalidates all prior
    browser/OIDC sessions before the new window is returned. Do not run enrollment
    and owner serving concurrently: stop setup after confirmation, then prepare
    owner mode. No listener or service transition is performed by this factory.
    """
    result: PreparedEnrollmentHost | None = None
    try:
        _validate(configuration, directory)
        if not callable(clock):
            raise TypeError("invalid host clock")
        opened_at = clock()
        enrollment = OwnerEnrollment(opened_at=opened_at)
        _directory(directory)
        owners = OwnerGrantStore(
            directory / "owner",
            key=configuration.session_key,
            origin=configuration.origin,
            client_id=configuration.client_id,
        )
        sessions = SqliteSessionStore(directory / "sessions", key=configuration.session_key)
        # Explicit setup discards old browser and pending OIDC sessions before
        # any new enrollment can be confirmed, including same-owner recovery.
        sessions.revoke_all()
        provider = (
            identities
            if identities is not None
            else AuthlibGoogleIdentity(
                client_id=configuration.client_id, client_secret=configuration.client_secret
            )
        )
        app = create_owner_enrollment(
            origin=configuration.origin,
            identities=provider,
            sessions=sessions,
            enrollment=enrollment,
            clock=clock,
        )
        result = PreparedEnrollmentHost(app, owners, sessions, enrollment)
    except Exception:  # noqa: BLE001, S110 - no private diagnostics or exception chaining
        pass
    if result is None:
        raise PrivateHostError("private enrollment host unavailable")
    return result
