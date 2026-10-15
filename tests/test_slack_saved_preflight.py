"""Actual canonical SDK and mounted owner, invented native and provider only."""

import json
from datetime import timedelta
from urllib.parse import parse_qs, parse_qsl, urlencode, urlsplit
from uuid import uuid4

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from pydantic import SecretStr
from starlette.responses import Response

from test_slack_mounted_host import ORIGIN, STATE, Inputs, RamSlack, enroll, inputs
from zacai.connectors.account_preflight import PreflightPlan
from zacai.connectors.connector_authority import ConnectorAuthority, review_scope_digest
from zacai.connectors.provider_oauth_evidence import SlackRotation
from zacai.connectors.slack_native_installation import _GENERIC, SlackPendingInstallation
from zacai.interfaces.slack_connect_host import open_slack_connect_host


class Native:
    def __init__(self, path, case):
        self.path, self.case = path, case
        self.calls = []
        self.owned = []
        self.released = []
        self.payload = None
        self.serial = 100
        self.on_read = lambda: None

    def own(self, name):
        self.serial += 1
        self.owned.append(self.serial)
        self.calls.append(name)
        return self.serial

    def keychain_open(self, path):
        assert path == str(self.path)
        return self.own("open")

    def keychain_path(self, ref):
        return str(self.path)

    def empty_access(self, label):
        assert label == "Caz BRAINSTORM Slack OAuth generation"
        return self.own("empty_access")

    def add(self, kc, access, service, account, data):
        assert service.startswith("zacai-brainstorm-slack-stage-")
        assert account == "zac-owner-source-access"
        assert self.payload is None
        self.calls.append("add")
        if self.case == "collision":
            return -25299
        self.service, self.account, self.payload = service, account, data
        return 0

    def find_item(self, kc, service, account):
        assert (service, account) == (self.service, self.account)
        return self.own("find")

    def item_keychain(self, ref):
        return self.own("item_keychain")

    def persistent_reference(self, ref):
        return b"invented-persistent-ref"

    def attributes(self, ref):
        return (_GENERIC, self.service.encode(), self.account.encode())

    def copy_access(self, ref):
        return self.own("copy_access")

    def acl_list(self, ref):
        return self.own("acl_list")

    def acl_count(self, ref):
        return 2

    def acl_at(self, ref, index):
        return index + 1

    def acl_authorizations(self, ref):
        return ("change_acl",) if ref == 1 else ("decrypt",)

    def acl_contents(self, ref):
        apps = (b"unexpected-app",) if self.case == "bad_acl" else ()
        return apps, "invented", 1

    def read_item(self, item, maximum):
        assert maximum == 16384
        self.calls.append("data")
        assert self.calls.count("data") == 1
        self.on_read()
        return b"wrong-pair" if self.case == "wrong_pair" else self.payload

    def release(self, ref):
        self.released.append(ref)
        if self.case == "cleanup_failure" and len(self.released) == 1:
            raise OSError("invented release failure")


@pytest.mark.parametrize(
    "case",
    [
        "success",
        "collision",
        "wrong_pair",
        "bad_acl",
        "cleanup_failure",
        "identity_user",
        "identity_team",
        "identity_scope",
        "owner_revoked",
        "active_write_failure",
        "unconfirmed_hold",
        "cancelled_hold",
        "native_path_changed",
        "halt_before_marker_failure",
        "halt_after_marker_failure",
        "guard_observation_interrupted",
        "readiness_and_halt_failure",
    ],
)
def test_saved_pair_to_actual_canonical_preflight(tmp_path, monkeypatch, case):
    now, _, slack, values = inputs(tmp_path)
    enroll(values)
    ram = RamSlack(slack)
    plan = PreflightPlan(
        attempt_id=uuid4(),
        provider="slack",
        client_id=slack.client_id,
        subject_id="U123456789",
        slack_account={"team_id": "T123456789", "user_id": "U123456789"},
    )
    native_path = tmp_path / "invented.keychain-db"
    native_path.write_bytes(b"invented native file")
    native_path.chmod(0o600)
    native = Native(native_path, case)
    with open_slack_connect_host(
        **values,
        initialize_new_guard=True,
        configuration=slack,
        expected_user_id="U123456789",
        rotation=SlackRotation.ROTATING,
        approved_generation="invented-reviewed",
        console_observed_at=now,
        review_expires_at=now + timedelta(hours=1),
        client_secret_loader=lambda _: SecretStr("invented-slack-secret"),
        connection_factory=ram.connect,
        network_clock=lambda: ram.net,
    ) as host:
        handles = {}

        @host._prepared.app.post("/connector-review")
        async def review(request: Request):
            fields = dict(parse_qsl((await request.body()).decode("ascii"), strict_parsing=True))
            handles["sdk"].approve_review(
                plan,
                request=request,
                csrf=fields["csrf"],
                reviewed_scope_digest=fields["digest"],
                payload_digest=None,
            )
            return Response("reviewed")

        @host._prepared.app.post("/connector-execute")
        async def execute(request: Request):
            fields = dict(parse_qsl((await request.body()).decode("ascii"), strict_parsing=True))
            try:
                gateway = handles["sdk"].for_request(request, csrf=fields["csrf"])
                handles["backend"].execute(gateway=gateway)
                return Response("identity checked")
            except BaseException as error:  # noqa: BLE001 - invented test response and diagnostics only
                handles.setdefault("errors", []).append(type(error).__name__)
                return Response("held", status_code=403)

        def browser(app):
            with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
                assert client.post("/login", headers={"Origin": ORIGIN}).status_code == 307
                assert client.get("/auth/callback?state=" + STATE + "&code=toy").status_code == 303
                form = Inputs(client.get("/connections/slack").text).values
                consent = client.post(
                    "/connections/slack/begin", data=form, headers={"Origin": ORIGIN}
                )
                assert consent.status_code == 303
                state = parse_qs(urlsplit(consent.headers["location"]).query)["state"][0]
                assert (
                    client.get(
                        "/connections/slack/callback?" + urlencode({"state": state, "code": "toy"})
                    ).status_code
                    == 200
                )
                fresh = host._controller._fresh
                backend = SlackPendingInstallation.prepare(
                    fresh=fresh,
                    host=host,
                    plan=plan,
                    directory=tmp_path / "installation",
                    keychain_path=native_path,
                    bindings_factory=lambda: native,
                )
                assert native.calls == []
                sdk = ConnectorAuthority(
                    backend._directory / "sdk",
                    key=host._continuity._key,
                    continuity=host._continuity,
                    backend=backend,
                )
                sdk.initialize()
                handles.update(sdk=sdk, backend=backend)
                assert (
                    client.post(
                        "/connector-review",
                        data={"csrf": form["csrf"], "digest": review_scope_digest(plan)},
                        headers={"Origin": ORIGIN},
                    ).status_code
                    == 200
                )
                assert native.calls == []
                if case == "identity_user":
                    ram.identity["user_id"] = "U999999999"
                if case == "identity_team":
                    ram.identity["team_id"] = "T999999999"
                if case == "identity_scope":
                    ram.header_scope = "channels:read"
                if case == "native_path_changed":
                    native.on_read = lambda: native_path.chmod(0o644)
                if case == "owner_revoked":
                    native.on_read = host._prepared.owners.revoke
                if case in {"guard_observation_interrupted", "readiness_and_halt_failure"}:

                    def interrupt_ready():
                        raise KeyboardInterrupt("invented readiness interruption")

                    def change_ready():
                        monkeypatch.setattr(host._guard, "ready", interrupt_ready)

                    native.on_read = change_ready

                if case in {
                    "active_write_failure",
                    "unconfirmed_hold",
                    "cancelled_hold",
                    "halt_before_marker_failure",
                    "halt_after_marker_failure",
                }:
                    original = backend._record

                    def fail(name):
                        original(name)
                        if name == "active":
                            raise OSError("invented active fsync/readback failure")

                    monkeypatch.setattr(backend, "_record", fail)
                if case in {
                    "unconfirmed_hold",
                    "cancelled_hold",
                    "halt_before_marker_failure",
                    "halt_after_marker_failure",
                }:
                    original_write = sdk._write

                    def fail_hold(value):
                        if any(row["state"] == "held" for row in value["rows"].values()):
                            if case == "cancelled_hold":
                                raise KeyboardInterrupt("invented hold interrupt")
                            raise OSError("invented hold write failure")
                        original_write(value)

                    monkeypatch.setattr(sdk, "_write", fail_hold)
                if case in {"halt_before_marker_failure", "readiness_and_halt_failure"}:

                    def fail_create(*_):
                        raise OSError("invented halt marker create failure")

                    monkeypatch.setattr(host._guard, "_create", fail_create)
                if case == "halt_after_marker_failure":

                    def fail_sync():
                        raise OSError("invented halt marker directory fsync failure")

                    monkeypatch.setattr(host._guard, "_sync_directory", fail_sync)

                # Causal proof: exact canonical row is loaded durably before Add.
                original_add = native.add

                def guarded_add(*args):
                    # Direct read/decrypt is observation only. Never reacquire SDK flock.
                    row = sdk._read()["rows"][str(plan.attempt_id)]
                    assert row["state"] == "in_flight" and row["loaded"] is True
                    assert (backend._directory / "slack-installation-pending.bin").is_file()
                    return original_add(*args)

                native.add = guarded_add
                response = client.post(
                    "/connector-execute", data={"csrf": form["csrf"]}, headers={"Origin": ORIGIN}
                )
                assert response.status_code == (200 if case == "success" else 403)
                with sdk._locked():
                    row = sdk._read()["rows"][str(plan.attempt_id)]
                assert row["loaded"] is True
                assert row["state"] == (
                    "completed"
                    if case
                    in {
                        "success",
                        "unconfirmed_hold",
                        "cancelled_hold",
                        "halt_before_marker_failure",
                        "halt_after_marker_failure",
                    }
                    else "held"
                )
                if case in {
                    "unconfirmed_hold",
                    "cancelled_hold",
                    "halt_before_marker_failure",
                    "halt_after_marker_failure",
                }:
                    expected = (
                        "SlackInstallationCancellationUnconfirmed"
                        if case
                        in {
                            "cancelled_hold",
                            "halt_before_marker_failure",
                            "halt_after_marker_failure",
                        }
                        else "SlackInstallationUnconfirmed"
                    )
                    assert handles["errors"] == [expected]
                    assert sdk._issuance_uncertain is True
                    assert backend._failed and backend._saved is None
                    assert fresh._owner._saved_identity_current is None
                    assert host._stop_requested is True
                    assert host._halted is True
                    from zacai.connectors.oauth_host_guard import (
                        OAuthHostGuard,
                        OAuthHostGuardError,
                    )

                    with pytest.raises(OAuthHostGuardError):
                        host._guard.ready()
                    startup = values["startup_loader"](client_id=values["client_id"], origin=ORIGIN)
                    new_guard = OAuthHostGuard(
                        host._guard._directory,
                        key=startup.session_key,
                        origin=ORIGIN,
                        client_id=values["client_id"],
                    )
                    if case in {"halt_before_marker_failure", "readiness_and_halt_failure"}:
                        # Disk refusal before any marker means a different process
                        # cannot infer this lost halt. Manual host-wide stop and
                        # reconciliation remain mandatory; never claim otherwise.
                        assert not host._guard._halt_path.exists()
                        new_guard.ready()
                    else:
                        with pytest.raises(OAuthHostGuardError):
                            new_guard.ready()

                    assert (backend._directory / "slack-installation-active.bin").is_file()

                assert backend._active is (case == "success")
                if case in {"guard_observation_interrupted", "readiness_and_halt_failure"}:
                    assert host._stop_requested and host._halted
                    assert host._guard._halt_path.is_file() is (
                        case == "guard_observation_interrupted"
                    )
                    if case == "guard_observation_interrupted":
                        assert handles["errors"] == ["SlackInstallationCancelled"]
                    else:
                        assert handles["errors"] == ["SlackInstallationCancellationUnconfirmed"]
                        assert host._halt_failed is True
                        from zacai.connectors.oauth_host_guard import OAuthHostGuard

                        startup = values["startup_loader"](
                            client_id=values["client_id"], origin=ORIGIN
                        )
                        new_guard = OAuthHostGuard(
                            host._guard._directory,
                            key=startup.session_key,
                            origin=ORIGIN,
                            client_id=values["client_id"],
                        )
                        # Separate process state cannot infer a halt that disk
                        # refused before publication; manual global stop required.
                        new_guard.ready()

                assert native.calls.count("add") == 1
                assert sorted(native.owned) == sorted(native.released)
                expected_requests = (
                    3
                    if case
                    in {
                        "success",
                        "identity_user",
                        "identity_team",
                        "identity_scope",
                        "active_write_failure",
                        "unconfirmed_hold",
                        "cancelled_hold",
                        "halt_before_marker_failure",
                        "halt_after_marker_failure",
                    }
                    else 2
                )
                assert ram.paths == ["/api/oauth.v2.access"] + ["/api/auth.test"] * (
                    expected_requests - 1
                )
                assert native.calls.count("data") == (0 if case in {"collision", "bad_acl"} else 1)
                # Retry cannot load or write again. Actual gateway denies spent row.
                assert (
                    client.post(
                        "/connector-execute",
                        data={"csrf": form["csrf"]},
                        headers={"Origin": ORIGIN},
                    ).status_code
                    == 403
                )
                assert native.calls.count("add") == 1
                if case == "success":
                    with sdk._locked():
                        assert sdk._read()["rows"][str(plan.attempt_id)]["state"] == "completed"
                    assert backend._active is True
                    assert row["coverage"]["identity_matched"] is True
                    assert row["coverage"]["requests"] == 1
                    # Native pair DATA is canonical and not written as plaintext operational metadata.
                    assert json.loads(native.payload)["access_token"] == "invented-access"
                    for file in backend._directory.rglob("*.bin"):
                        assert b"invented-access" not in file.read_bytes()

        errors = []

        def observed(app):
            try:
                browser(app)
            except BaseException as error:
                errors.append(error)
                raise

        try:
            host.serve(server=observed)
        except BaseException:
            if errors:
                raise errors[0]
            raise
    assert all(c.closed for c in ram.connections)
