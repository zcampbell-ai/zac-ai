"""Dedicated, dormant Slack owner composition; import/configuration is inert.

Actual invocation needs separate fully populated one-attempt owner approval.
Configuration is correlation, never approval. Initial consent/install and a
later fresh-owner saved verification are distinct runs. No discovery, migration,
reset, refresh, history ingestion, bot subscription or sending is enabled.
"""

from __future__ import annotations

import json
import sys
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from zacai.connectors.account_preflight import PreflightPlan
from zacai.connectors.connector_authority import _guard
from zacai.connectors.gmail_client_secret import _file_policy, _path
from zacai.connectors.oauth_configuration import OAuthConfiguration
from zacai.connectors.oauth_exchange import Connection, _direct_tls
from zacai.connectors.provider_oauth_evidence import SlackRotation
from zacai.connectors.slack_client_secret import SlackClientSecretLoader, _configuration
from zacai.host_clock import HostObservedClock
from zacai.interfaces.oidc_identity import IdentityProvider
from zacai.interfaces.private_server_lifecycle import PrivateServerLifecycle
from zacai.interfaces.private_startup import (
    OwnerStartupConfiguration,
    OwnerStartupLoader,
    _explicit_configuration,
)
from zacai.interfaces.slack_connect_host import SlackConnectHost, open_slack_connect_host


class SlackSetupError(RuntimeError):
    """Fixed setup failure without path, owner or native frames."""


class SlackSetupCancelled(BaseException):
    """Interrupted single attempt; preserve history and stop to reconcile."""


def _closed[**P, R](function: Callable[P, R]) -> Callable[P, R]:
    @wraps(function)
    def call(*args: P.args, **kwargs: P.kwargs) -> R:
        try:
            return function(*args, **kwargs)
        except Exception:  # noqa: BLE001 - never expose native/startup/request frames
            kind: type[BaseException] = SlackSetupError
        except BaseException:  # noqa: BLE001 - cancellation remains fatal
            kind = SlackSetupCancelled
        del args, kwargs
        raise kind("Slack setup held; reconcile before any further attempt")

    return call


class SlackSetupConfiguration(BaseModel):
    """Nonsecret reviewed proposal, validated without clock/path/native access."""

    model_config = ConfigDict(
        frozen=True, extra="forbid", strict=True, revalidate_instances="always"
    )
    version: Literal[1] = 1
    mode: Literal["initial_identity", "saved_identity"]
    owner_client_id: str
    configuration: OAuthConfiguration
    expected_user_id: str = Field(pattern=r"^U[A-Z0-9]{8,20}$")
    rotation: SlackRotation
    approved_generation: str = Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")
    console_observed_at: datetime
    review_expires_at: datetime
    directory: Path
    owner_startup_keychain_path: Path
    client_secret_keychain_path: Path | None = None
    native_keychain_path: Path
    owner_keychain_file_policy: Literal["owner_only", "reviewed_login"] = "owner_only"
    client_secret_file_policy: Literal["owner_only", "reviewed_login"] = "owner_only"
    native_keychain_file_policy: Literal["owner_only", "reviewed_login"] = "owner_only"
    foreground_timeout_seconds: int = Field(default=60, strict=True, ge=1, le=120)
    escrow_confirmed_by_operator: Literal[True]

    @field_validator("console_observed_at", "review_expires_at", mode="before")
    @classmethod
    def exact_iso_datetime(cls, value: Any) -> datetime:
        # Strict model-before validation otherwise treats JSON ISO strings as
        # Python values. Decode only this explicit textual representation;
        # integers/floats/bools never become timestamp authority.
        if type(value) is str:
            value = datetime.fromisoformat(
                value.removesuffix("Z") + "+00:00" if value.endswith("Z") else value
            )
        if type(value) is not datetime:
            raise ValueError("explicit ISO datetime required")
        return value

    @model_validator(mode="before")
    @classmethod
    def exact_literal_types(cls, value: Any) -> Any:
        if type(value) is dict and (
            ("version" in value and type(value["version"]) is not int)
            or type(value.get("escrow_confirmed_by_operator")) is not bool
        ):
            raise ValueError("exact literal configuration types required")
        return value

    @model_validator(mode="after")
    def exact_review(self) -> SlackSetupConfiguration:
        checked = _configuration(self.configuration)
        # Reuse actual source validation of console app/client/team/origin/grant.
        from zacai.connectors.slack_registration import _config

        _config(checked)
        _explicit_configuration(self.owner_client_id, checked.private_origin)
        if (
            type(self.version) is not int
            or type(self.escrow_confirmed_by_operator) is not bool
            or self.console_observed_at.utcoffset() != timedelta(0)
            or self.review_expires_at.utcoffset() != timedelta(0)
            or not timedelta(0)
            < self.review_expires_at - self.console_observed_at
            <= timedelta(hours=2)
            or self.mode == "initial_identity"
            and self.client_secret_keychain_path is None
            or self.mode == "saved_identity"
            and self.client_secret_keychain_path is not None
        ):
            raise ValueError("exact reviewed mode and bounded UTC review required")
        _path(self.directory)
        for path, policy in (
            (self.owner_startup_keychain_path, self.owner_keychain_file_policy),
            (self.native_keychain_path, self.native_keychain_file_policy),
        ):
            _file_policy(_path(path), policy)
        if self.client_secret_keychain_path is not None:
            _file_policy(_path(self.client_secret_keychain_path), self.client_secret_file_policy)
        return self

    def oauth(self) -> OAuthConfiguration:
        return _configuration(self.configuration)


def parse_configuration(raw: bytes) -> SlackSetupConfiguration:
    """Pure bounded parser: no default file, environment or credential source."""
    if type(raw) is not bytes or not 1 <= len(raw) <= 16384:
        raise SlackSetupError("bounded nonsecret setup configuration required")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value = dict(items)
        if len(value) != len(items):
            raise ValueError("duplicate configuration key")
        return value

    try:
        json.loads(raw, object_pairs_hook=pairs)
        return SlackSetupConfiguration.model_validate_json(raw)
    except Exception:  # noqa: BLE001,S110 - config can contain accidentally pasted secrets
        pass
    raise SlackSetupError("exact nonsecret setup configuration required")


class SlackSetupPlan:
    """Trusted one-shot operator. Constructor does no clock or filesystem I/O.

    Optional lifecycle/identity/native/network adapters are trusted test seams,
    never selectable from JSON/HTTP. Production creates the existing private
    lifecycle with the exact origin only after actual proxy review. The origin
    field alone cannot establish TLS/proxy isolation or native item association.
    """

    @_closed
    def __init__(
        self,
        *,
        configuration: SlackSetupConfiguration,
        clock: HostObservedClock,
        startup_loader: OwnerStartupLoader | None = None,
        lifecycle: PrivateServerLifecycle | None = None,
        identities: IdentityProvider | None = None,
        client_secret_bindings_factory: Callable[[], Any] | None = None,
        native_bindings_factory: Callable[[], Any] | None = None,
        connection_factory: Callable[[str], Connection] = _direct_tls,
        network_clock: Callable[[], float] | None = None,
    ) -> None:
        if (
            type(configuration) is not SlackSetupConfiguration
            or type(clock) is not HostObservedClock
        ):
            raise ValueError("actual reviewed setup and host clock required")
        config = SlackSetupConfiguration.model_validate(configuration.model_dump())
        loader = startup_loader or OwnerStartupLoader(
            client_id=config.owner_client_id,
            origin=config.configuration.private_origin,
            keychain_path=config.owner_startup_keychain_path,
            mode="foreground",
            foreground_timeout_seconds=config.foreground_timeout_seconds,
            keychain_file_policy=config.owner_keychain_file_policy,
        )
        expected = (
            config.owner_client_id,
            config.configuration.private_origin,
            str(config.owner_startup_keychain_path),
            "foreground",
            config.foreground_timeout_seconds,
            config.owner_keychain_file_policy,
        )
        if type(loader) is not OwnerStartupLoader or loader._settings != expected:
            raise ValueError("same reviewed original owner startup loader required")
        server = lifecycle or PrivateServerLifecycle(
            verified_private_origin=config.configuration.private_origin
        )
        if type(server) is not PrivateServerLifecycle or server._spent or server._stopped:
            raise ValueError("fresh exact private server lifecycle required")
        for adapter in (
            client_secret_bindings_factory,
            native_bindings_factory,
            connection_factory,
            network_clock,
        ):
            if adapter is not None and not callable(adapter):
                raise ValueError("trusted concrete adapters required")
        self._configuration, self._clock, self._loader, self._server = config, clock, loader, server
        self._identities, self._secret_factory, self._native_factory = (
            identities,
            client_secret_bindings_factory,
            native_bindings_factory,
        )
        self._connection_factory, self._network_clock = connection_factory, network_clock
        self._config_pin, self._loader_pin = config.model_dump_json(), loader._settings
        self._dependencies = (
            clock,
            loader,
            server,
            server._factory,
            identities,
            client_secret_bindings_factory,
            native_bindings_factory,
            connection_factory,
            network_clock,
        )
        self._spent = self._running = False
        self._host: SlackConnectHost | None = None
        self._secret_loader: SlackClientSecretLoader | None = None
        self._directory_identity: tuple[int, int] | None = None

    def __repr__(self) -> str:
        return "SlackSetupPlan(held proposal)"

    def _current(self) -> None:
        config = SlackSetupConfiguration.model_validate(self._configuration.model_dump())
        loader = self._loader
        actual = (
            self._clock,
            loader,
            self._server,
            self._server._factory,
            self._identities,
            self._secret_factory,
            self._native_factory,
            self._connection_factory,
            self._network_clock,
        )
        if (
            config.model_dump_json() != self._config_pin
            or loader._settings != self._loader_pin
            or (
                loader.client_id,
                loader.origin,
                str(loader.keychain_path),
                loader.mode,
                loader.foreground_timeout_seconds,
                loader.keychain_file_policy,
            )
            != self._loader_pin
            or any(a is not b for a, b in zip(actual, self._dependencies, strict=True))
        ):
            raise ValueError("original exact setup composition required")

    def _time(self) -> None:
        c = self._configuration
        if not c.console_observed_at <= self._clock() < c.review_expires_at:
            raise ValueError("current bounded console review required")

    def _directory_current(self) -> None:
        # Main thread establishes this identity before serving; thereafter the
        # original serialized worker only revalidates it. No concurrent setup
        # mutation or alternate namespace selection is supported.
        path = self._configuration.directory
        observed = _guard(path, directory=True)
        if path.resolve(strict=True) != path:
            raise ValueError("original canonical OWNER directory required")
        identity = observed.st_dev, observed.st_ino
        if self._directory_identity is None:
            self._directory_identity = identity
        elif self._directory_identity != identity:
            raise ValueError("original OWNER namespace changed")

    def _load(self, *, client_id: str, origin: str) -> OwnerStartupConfiguration:
        self._current()
        self._time()
        self._directory_current()
        result = self._loader(client_id=client_id, origin=origin)
        self._current()
        self._time()
        self._directory_current()
        return result

    def _credential_current(self) -> None:
        self._current()
        self._time()
        self._directory_current()
        host = self._host
        if not self._running or host is None or self._configuration.mode != "initial_identity":
            raise ValueError("actual original initial owner worker required")
        host._preserve()
        controller = host._controller
        controller._preserve_action()
        preview = controller._preview
        if preview is None:
            raise ValueError("same displayed original owner required")
        preview.operation.recheck(preview.view[1])

    def _stop_server(self) -> None:
        # Stop the original retained lifecycle, even if rejected configuration
        # mutation changed an attribute. `_stopped` alone is not an ack: the
        # lifecycle sets it before assigning/checking the listener stop flag.
        server = self._dependencies[2]
        retained = server._server
        if server._stopped is True and (retained is None or retained.should_exit is True):
            return
        server.stop_host()

    @_closed
    def run(self) -> None:
        if (
            self._spent
            or self._running
            or self._server._spent
            or self._server._stopped
            or threading.current_thread() is not threading.main_thread()
            or not all(stream.isatty() for stream in (sys.stdin, sys.stdout, sys.stderr))
        ):
            raise ValueError("one dedicated attended owner attempt required")
        self._spent = self._running = True
        failure: BaseException | None = None
        try:
            self._current()
            self._time()
            self._directory_current()
            c = self._configuration
            children = ("slack-oauth-guard", "slack-connect", "slack-installation")
            for name in children:
                path = c.directory / name
                if c.mode == "initial_identity":
                    if path.exists() or path.is_symlink():
                        raise ValueError("existing or unknown namespace held for reconciliation")
                else:
                    _guard(path, directory=True)
            if c.mode == "initial_identity":
                kwargs = (
                    {}
                    if self._secret_factory is None
                    else {"bindings_factory": self._secret_factory}
                )
                secret_path = c.client_secret_keychain_path
                if secret_path is None:
                    raise ValueError("explicit initial client secret path required")
                self._secret_loader = SlackClientSecretLoader(
                    configuration=c.oauth(),
                    keychain_path=secret_path,
                    keychain_file_policy=c.client_secret_file_policy,
                    current_checker=self._credential_current,
                    **kwargs,
                )

            def secret(configuration: OAuthConfiguration) -> Any:
                if self._secret_loader is None:
                    raise ValueError("saved verification never loads client secret")
                return self._secret_loader(configuration)

            options = {} if self._network_clock is None else {"network_clock": self._network_clock}
            with open_slack_connect_host(
                client_id=c.owner_client_id,
                origin=c.configuration.private_origin,
                directory=c.directory,
                escrow_confirmed_by_operator=c.escrow_confirmed_by_operator,
                clock=self._clock,
                configuration=c.oauth(),
                expected_user_id=c.expected_user_id,
                rotation=c.rotation,
                approved_generation=c.approved_generation,
                console_observed_at=c.console_observed_at.astimezone(UTC),
                review_expires_at=c.review_expires_at.astimezone(UTC),
                client_secret_loader=secret,
                startup_loader=self._load,
                identities=self._identities,
                connection_factory=self._connection_factory,
                initialize_new_guard=c.mode == "initial_identity",
                **options,
            ) as host:
                self._host = host
                host.bind_server_lifecycle(self._server)
                plan = PreflightPlan(
                    attempt_id=uuid4(),
                    provider="slack",
                    client_id=c.configuration.client_id,
                    subject_id=c.expected_user_id,
                    slack_account={
                        "team_id": c.configuration.slack_team_id,
                        "user_id": c.expected_user_id,
                    },
                )
                mount = (
                    host.mount_initial_identity
                    if c.mode == "initial_identity"
                    else host.mount_saved_identity
                )
                native = (
                    {}
                    if self._native_factory is None
                    else {"bindings_factory": self._native_factory}
                )
                mount(
                    plan=plan,
                    keychain_path=c.native_keychain_path,
                    keychain_file_policy=c.native_keychain_file_policy,
                    **native,
                )
                self._current()
                self._time()
                host.serve(server=self._server)
                self._current()
                self._directory_current()
                host.identity_receipt_current()
        except BaseException as primary:  # noqa: BLE001 - preserve actual primary category
            failure = primary
        finally:
            self._running = False
            try:
                self._stop_server()
            except BaseException as cleanup:  # noqa: BLE001 - fatal cleanup cannot be downgraded
                if (
                    failure is None
                    or isinstance(failure, Exception)
                    and not isinstance(cleanup, Exception)
                ):
                    failure = cleanup
        if failure is not None:
            raise failure


def main() -> None:
    """Explicit local entry: no credentials/config discovered from environment.

    Operators must obtain separate live approval before invoking this entry.
    No command-line affirmation is interpreted as authorization.
    """
    try:
        if len(sys.argv) != 2:
            raise ValueError("one explicit reviewed nonsecret configuration file required")
        path = _path(Path(sys.argv[1]))
        with path.open("rb") as stream:
            raw = stream.read(16385)
        config = parse_configuration(raw)
        SlackSetupPlan(
            configuration=config, clock=HostObservedClock(lambda: datetime.now(UTC))
        ).run()
    except Exception:  # noqa: BLE001 - no traceback or accidentally pasted config
        raise SystemExit("Slack setup held; reconcile before another attempt") from None
    except BaseException:  # noqa: BLE001 - fixed cancelled startup/serving diagnostic
        raise SystemExit("Slack setup interrupted; reconcile before another attempt") from None


if __name__ == "__main__":
    main()
