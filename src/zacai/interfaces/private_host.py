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

from zacai.interfaces.oidc_identity import AuthlibGoogleIdentity, IdentityProvider
from zacai.interfaces.owner_enrollment import OwnerEnrollment, create_owner_enrollment
from zacai.interfaces.owner_store import OwnerGrantStore
from zacai.interfaces.private_startup import OwnerStartupConfiguration, _configuration
from zacai.interfaces.private_web import InterfacePrincipal, create_private_web
from zacai.interfaces.sqlite_sessions import SqliteSessionStore

if TYPE_CHECKING:
    from zacai.interfaces.work_choice_web import WorkChoiceWeb


class PrivateHostError(ValueError):
    """Closed host assembly diagnostic; no private credentials, paths or inputs."""


@dataclass(frozen=True)
class PreparedOwnerHost:
    app: FastAPI = field(repr=False)
    owners: OwnerGrantStore = field(repr=False)
    sessions: SqliteSessionStore = field(repr=False)

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
        sessions = SqliteSessionStore(directory / "sessions", key=configuration.session_key)
        provider = (
            identities
            if identities is not None
            else AuthlibGoogleIdentity(
                client_id=configuration.client_id, client_secret=configuration.client_secret
            )
        )
        app = create_private_web(
            origin=configuration.origin,
            identities=provider,
            sessions=sessions,
            owner=owners.load,
            view=view,
            clock=clock,
            work_choices=work_choices,
        )
        result = PreparedOwnerHost(app, owners, sessions)
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
