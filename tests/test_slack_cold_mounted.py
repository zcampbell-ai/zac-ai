"""Real warm owner closes, real new owner reviews; invented native/provider only."""

import threading
from datetime import timedelta
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import test_slack_saved_preflight as warm
from test_slack_mounted_host import ORIGIN, STATE, Inputs, inputs
from zacai.connectors.account_preflight import PreflightPlan
from zacai.connectors.provider_oauth_evidence import SlackRotation
from zacai.connectors.slack_native_installation import SlackPendingInstallation
from zacai.interfaces.slack_connect_host import open_slack_connect_host


@pytest.mark.parametrize(
    "case",
    [
        "success",
        "old_sdk_held",
        "wrong_account",
        "wrong_pair",
        "native_acl",
        "native_cleanup",
        "owner_revoked",
        "guard_halted",
        "identity_user",
        "missing_pending",
        "missing_active",
        "old_oauth_state",
        "old_oauth_execution",
        "expired",
        "native_pid",
        "native_path_changed",
        "sdk_completion_failure",
        "sdk_hold_failure",
        "sdk_latch_before_invalidate",
        "sdk_latch_during_invalidate",
    ],
)
def test_saved_cold_new_owner_mounted(tmp_path, monkeypatch, case):
    now, _, config, values = inputs(tmp_path)
    captured = {}
    original_prepare = SlackPendingInstallation.prepare

    def capture(**kwargs):
        backend = original_prepare(**kwargs)
        captured.update(
            backend=backend, native=kwargs["bindings_factory"](), old_host=kwargs["host"]
        )
        return backend

    monkeypatch.setattr(SlackPendingInstallation, "prepare", capture)
    monkeypatch.setattr(warm, "inputs", lambda _: (now, None, config, values))
    warm.test_saved_pair_to_actual_canonical_preflight(tmp_path, monkeypatch, "success")
    monkeypatch.setattr(SlackPendingInstallation, "prepare", original_prepare)
    old = captured["backend"]
    assert captured["old_host"]._closed and old._active
    warm_native = captured["native"]
    warm_calls = list(warm_native.calls)
    native = warm.Native(old._path, "success")
    native.payload, native.service, native.account = (
        warm_native.payload,
        warm_native.service,
        warm_native.account,
    )
    ram = captured["old_host"]._controller._factory.__self__
    initial_paths = list(ram.paths)
    initial_data = native.calls.count("data")
    initial_add = native.calls.count("add")
    plan = PreflightPlan(
        attempt_id=uuid4(),
        provider="slack",
        client_id=config.client_id,
        subject_id="U123456789",
        slack_account={"team_id": "T123456789", "user_id": "U123456789"},
    )

    before_review_denials = {
        "old_sdk_held",
        "wrong_account",
        "missing_pending",
        "missing_active",
        "old_oauth_state",
        "old_oauth_execution",
        "expired",
        "native_path_changed",
    }
    injected = []
    if case in {"missing_pending", "missing_active"}:
        state = "pending" if case == "missing_pending" else "active"
        (old._directory / ("slack-installation-" + state + ".bin")).unlink()
    if case in {"old_oauth_state", "old_oauth_execution"}:
        authority = old._fresh._owner._authority
        with authority._locked():
            value = authority._read()
            row = value["rows"][old._record_common["oauth_state_hash"]]
            if case == "old_oauth_state":
                row["state"] = "exchange_started"
            else:
                row["execution"] = "f" * 64
            authority._write(value)
            assert authority._read()["rows"][old._record_common["oauth_state_hash"]] == row
    if case == "expired":
        from zacai.connectors.slack_native_installation import _v2_encode, _v2_read

        active = _v2_read(
            old._directory,
            state="active",
            key=old._host._continuity._key,
            context=old._host._continuity._context,
        )
        active["access_expires_at"] = (now - timedelta(seconds=1)).isoformat()
        (old._directory / "slack-installation-active.bin").write_bytes(
            _v2_encode(
                active,
                state="active",
                key=old._host._continuity._key,
                context=old._host._continuity._context,
            )
        )
    if case == "native_pid":

        def changed_reference(_):
            injected.append("native_pid")
            return b"invented-other-persistent-reference"

        native.persistent_reference = changed_reference
    if case == "native_path_changed":
        old._path.chmod(0o644)
    if case == "old_sdk_held":
        # Existing canonical encrypted ledger, actual persisted state change.
        from zacai.connectors.connector_authority import ConnectorAuthority

        sdk = ConnectorAuthority.open_existing(
            old._directory / "sdk",
            key=old._host._continuity._key,
            continuity=old._host._continuity,
            backend=old,
        )
        with sdk._locked():
            value = sdk._read()
            value["rows"][str(old._plan.attempt_id)]["state"] = "held"
            sdk._write(value)
            assert sdk._read()["rows"][str(old._plan.attempt_id)]["state"] == "held"
    if case == "wrong_account":
        from zacai.connectors.slack_native_installation import _v2_encode, _v2_read

        for state in ("pending", "active"):
            record = _v2_read(
                old._directory,
                state=state,
                key=old._host._continuity._key,
                context=old._host._continuity._context,
            )
            record["account"] = "U999999999"
            path = old._directory / ("slack-installation-" + state + ".bin")
            path.write_bytes(
                _v2_encode(
                    record,
                    state=state,
                    key=old._host._continuity._key,
                    context=old._host._continuity._context,
                )
            )
    if case == "wrong_pair":
        native.payload = b"invented wrong saved pair"
    if case == "native_acl":
        native.case = "bad_acl"
    if case == "native_cleanup":
        native.case = "cleanup_failure"
    if case in {"identity_user", "sdk_hold_failure", "sdk_latch_during_invalidate"}:
        ram.identity["user_id"] = "U999999999"

    def no_exchange(_):
        pytest.fail("cold path attempted client secret/OAuth exchange")

    with open_slack_connect_host(
        **values,
        configuration=config,
        expected_user_id="U123456789",
        rotation=SlackRotation.ROTATING,
        approved_generation="invented-reviewed",
        console_observed_at=now,
        review_expires_at=now + timedelta(hours=1),
        client_secret_loader=no_exchange,
        connection_factory=ram.connect,
        network_clock=lambda: ram.net,
    ) as host:
        host.mount_saved_identity(
            plan=plan, keychain_path=old._path, bindings_factory=lambda: native
        )

        def browser(app):
            with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
                assert client.get("/connections/slack/saved").status_code == 403
                assert native.calls.count("data") == initial_data and ram.paths == initial_paths
                assert client.post("/login", headers={"Origin": ORIGIN}).status_code == 307
                assert client.get("/auth/callback?state=" + STATE + "&code=toy").status_code == 303
                page = client.get("/connections/slack/saved")
                assert page.status_code == 200 and plan.subject_id in page.text
                assert all(scope in page.text for scope in plan.scopes)
                assert "one Slack identity request" in page.text
                assert native.calls.count("data") == initial_data and ram.paths == initial_paths
                form = Inputs(page.text).values
                if case == "success":
                    assert client.get("/connections/slack/saved?ignored=1").status_code == 403
                    assert (
                        client.post(
                            "/connector-review",
                            data=form,
                            headers={"Origin": "https://wrong.invalid"},
                        ).status_code
                        == 403
                    )
                    assert (
                        client.post(
                            "/connector-review?ignored=1", data=form, headers={"Origin": ORIGIN}
                        ).status_code
                        == 403
                    )
                    assert (
                        client.post(
                            "/connector-review",
                            content=b"{}",
                            headers={"Origin": ORIGIN, "Content-Type": "application/json"},
                        ).status_code
                        == 403
                    )
                    assert (
                        client.post(
                            "/connector-review",
                            content=(b"x" * 3000 for _ in range(3)),
                            headers={
                                "Origin": ORIGIN,
                                "Content-Type": "application/x-www-form-urlencoded",
                            },
                        ).status_code
                        == 403
                    )
                    assert host._saved_backend is None and not host._saved_spent
                    assert native.calls.count("data") == initial_data and ram.paths == initial_paths
                if case == "owner_revoked":
                    native.on_read = host._prepared.owners.revoke
                if case == "guard_halted":
                    native.on_read = host._guard.halt_unconfirmed
                review = client.post("/connector-review", data=form, headers={"Origin": ORIGIN})
                assert native.calls.count("data") == initial_data and ram.paths == initial_paths
                if case in before_review_denials:
                    response = review
                else:
                    assert review.status_code == 200
                    execute_form = Inputs(review.text).values
                    if case in {"sdk_completion_failure", "sdk_hold_failure"}:
                        sdk = host._saved_backend._sdk
                        original_write = sdk._write

                        def fault_write(value):
                            row = value["rows"].get(str(plan.attempt_id))
                            target = "completed" if case == "sdk_completion_failure" else "held"
                            if row is not None and row["state"] == target:
                                injected.append(case)
                                if case == "sdk_completion_failure":
                                    original_write(value)
                                raise OSError("invented new SDK persistence failure")
                            original_write(value)

                        monkeypatch.setattr(sdk, "_write", fault_write)
                    if case in {"sdk_latch_before_invalidate", "sdk_latch_during_invalidate"}:
                        from zacai.connectors.connector_authority import ConnectorGateway

                        sdk = host._saved_backend._sdk
                        original_invalidate = ConnectorGateway.invalidate
                        normal_invalidations = []

                        def observed_invalidate(gateway, selected_plan):
                            original_invalidate(gateway, selected_plan)
                            if gateway._authority is sdk:
                                normal_invalidations.append(True)
                                if (
                                    case == "sdk_latch_during_invalidate"
                                    and len(normal_invalidations) == 2
                                ):
                                    sdk._issuance_uncertain = True

                        monkeypatch.setattr(ConnectorGateway, "invalidate", observed_invalidate)
                        if case == "sdk_latch_before_invalidate":
                            native.on_read = lambda: setattr(sdk, "_issuance_uncertain", True)
                    response = client.post(
                        "/connector-execute", data=execute_form, headers={"Origin": ORIGIN}
                    )
                assert response.status_code == (200 if case == "success" else 403)
                if case in {"sdk_latch_before_invalidate", "sdk_latch_during_invalidate"}:
                    assert normal_invalidations == [True, True]
                    assert sdk._issuance_uncertain is True
                    assert host._halted and host._stop_requested
                    assert host._guard._halt_path.is_file()
                    from zacai.connectors.oauth_host_guard import (
                        OAuthHostGuard,
                        OAuthHostGuardError,
                    )

                    startup = values["startup_loader"](client_id=values["client_id"], origin=ORIGIN)
                    reopened_guard = OAuthHostGuard(
                        host._guard._directory,
                        key=startup.session_key,
                        origin=ORIGIN,
                        client_id=values["client_id"],
                    )
                    with pytest.raises(OAuthHostGuardError):
                        reopened_guard.ready()

                assert native.calls.count("add") == initial_add
                expected_reads = (
                    0 if case in before_review_denials | {"native_acl", "native_pid"} else 1
                )
                assert native.calls.count("data") - initial_data == expected_reads
                assert ram.paths[len(initial_paths) :] == (
                    ["/api/auth.test"]
                    if case
                    in {
                        "success",
                        "identity_user",
                        "sdk_completion_failure",
                        "sdk_hold_failure",
                        "sdk_latch_during_invalidate",
                    }
                    else []
                )
                assert sorted(native.owned) == sorted(native.released)
                if case == "success":
                    backend = host._saved_backend
                    assert backend._completed and backend._loaded
                    assert backend._registration._binding != old._record_common["owner_binding"]
                    with backend._sdk._locked():
                        rows = backend._sdk._read()["rows"]
                    assert rows[str(plan.attempt_id)]["state"] == "completed"
                    assert rows[str(old._plan.attempt_id)]["state"] == "completed"
                    assert (
                        client.post(
                            "/connector-execute", data=execute_form, headers={"Origin": ORIGIN}
                        ).status_code
                        == 403
                    )
                    assert native.calls.count("data") - initial_data == 1
                    assert ram.paths[len(initial_paths) :] == ["/api/auth.test"]
                elif host._saved_backend is not None:
                    with host._saved_backend._sdk._locked():
                        rows = host._saved_backend._sdk._read()["rows"]
                    assert rows[str(plan.attempt_id)]["state"] == (
                        "in_flight" if case == "sdk_hold_failure" else "held"
                    )
                    if case == "sdk_hold_failure":
                        assert host._saved_backend._sdk._issuance_uncertain and host._halted
                        assert host._guard._halt_path.is_file()
                if case in {"native_pid", "sdk_completion_failure", "sdk_hold_failure"}:
                    assert injected
                if case in {"missing_pending", "missing_active"}:
                    state = "pending" if case == "missing_pending" else "active"
                    assert not (old._directory / ("slack-installation-" + state + ".bin")).exists()

        failures = []

        def observed(app):
            try:
                browser(app)
            except BaseException as error:
                failures.append(error)
                raise

        try:
            host.serve(server=observed)
        except BaseException:
            if failures:
                raise failures[0]
            raise
    assert all(connection.closed for connection in ram.connections)
    assert warm_native.calls == warm_calls
    if host._saved_backend is not None:
        assert host._saved_backend._is_closed and host._saved_backend._saved is None
        assert host._saved_backend._saved_identity_current is None


def test_actual_cold_worker_logout_responsive_and_physically_drained(tmp_path, monkeypatch):
    now, _, configuration, values = inputs(tmp_path)
    captured = {}
    original_prepare = SlackPendingInstallation.prepare

    def capture(**kwargs):
        backend = original_prepare(**kwargs)
        captured.update(backend=backend, native=kwargs["bindings_factory"](), host=kwargs["host"])
        return backend

    monkeypatch.setattr(SlackPendingInstallation, "prepare", capture)
    monkeypatch.setattr(warm, "inputs", lambda _: (now, None, configuration, values))
    warm.test_saved_pair_to_actual_canonical_preflight(tmp_path, monkeypatch, "success")
    monkeypatch.setattr(SlackPendingInstallation, "prepare", original_prepare)
    old, warm_native = captured["backend"], captured["native"]
    assert captured["host"]._closed and old._active
    warm_history = list(warm_native.calls)
    native = warm.Native(old._path, "success")
    native.payload, native.service, native.account = (
        warm_native.payload,
        warm_native.service,
        warm_native.account,
    )
    ram = captured["host"]._controller._factory.__self__
    original_provider_paths = list(ram.paths)
    plan = PreflightPlan(
        attempt_id=uuid4(),
        provider="slack",
        client_id=configuration.client_id,
        subject_id="U123456789",
        slack_account={"team_id": "T123456789", "user_id": "U123456789"},
    )
    entered, release_native, logout_done = threading.Event(), threading.Event(), threading.Event()
    original_read = native.read_item
    primitive_threads = []

    def blocked_read(*args):
        primitive_threads.append(threading.current_thread())
        entered.set()
        if not release_native.wait(12):
            raise TimeoutError("invented native wait exceeded bounded QA window")
        return original_read(*args)

    native.read_item = blocked_read

    def no_exchange(_):
        raise AssertionError("cold action must not load client secret or exchange code")

    results, errors, responses = {}, [], []
    with open_slack_connect_host(
        **values,
        configuration=configuration,
        expected_user_id="U123456789",
        rotation=SlackRotation.ROTATING,
        approved_generation="invented-reviewed",
        console_observed_at=now,
        review_expires_at=now + timedelta(hours=1),
        client_secret_loader=no_exchange,
        connection_factory=ram.connect,
        network_clock=lambda: ram.net,
    ) as host:
        host.mount_saved_identity(
            plan=plan, keychain_path=old._path, bindings_factory=lambda: native
        )

        def browser(app):
            with TestClient(app, base_url=ORIGIN, follow_redirects=False) as client:
                assert client.post("/login", headers={"Origin": ORIGIN}).status_code == 307
                assert client.get("/auth/callback?state=" + STATE + "&code=toy").status_code == 303
                review_form = Inputs(client.get("/connections/slack/saved").text).values
                review = client.post(
                    "/connector-review", data=review_form, headers={"Origin": ORIGIN}
                )
                assert review.status_code == 200
                execute_form = Inputs(review.text).values
                home = client.get("/")
                assert home.status_code == 200 and 'action="/logout"' in home.text
                logout_form = {"csrf": Inputs(home.text).values["csrf"]}
                original_cookie = client.cookies.get("__Host-zac-session")
                portal = client.portal

                def request(name, path, form, done=None):
                    try:
                        assert client.portal is portal  # Same ASGI event loop, concurrent requests.
                        response = client.post(path, data=form, headers={"Origin": ORIGIN})
                        responses.append(response)
                        results[name] = response.status_code
                        response.close()
                    except BaseException as error:  # noqa: BLE001 - propagate thread failures to main assertion
                        errors.append(error)
                    finally:
                        if done is not None:
                            done.set()

                execution = threading.Thread(
                    target=request,
                    args=("execute", "/connector-execute", execute_form),
                    name="invented-cold-http-execute",
                )
                logout = threading.Thread(
                    target=request,
                    args=("logout", "/logout", logout_form, logout_done),
                    name="invented-cold-http-logout",
                )
                started = []
                try:
                    execution.start()
                    started.append(execution)
                    assert entered.wait(5), "native worker did not enter"
                    assert not release_native.is_set() and execution.is_alive()
                    assert primitive_threads[0] is not threading.main_thread()
                    logout.start()
                    started.append(logout)
                    assert logout_done.wait(3), "logout blocked behind native worker"
                    assert not release_native.is_set(), "native released before logout response"
                    assert results.get("logout") == 303 and not errors
                    assert host._prepared.sessions.peek_user(original_cookie, host._clock()) is None
                    assert execution.is_alive(), "native execution should still be waiting"
                    assert native.calls.count("data") == 0 and ram.paths == original_provider_paths
                finally:
                    release_native.set()
                    for thread in started:
                        thread.join(10)
                assert all(not thread.is_alive() for thread in started)
                assert not errors, errors
                assert results == {"logout": 303, "execute": 403}
                assert all(response.is_closed for response in responses)
                backend = host._saved_backend
                with backend._sdk._locked():
                    rows = backend._sdk._read()["rows"]
                assert rows[str(plan.attempt_id)]["loaded"] is True
                assert rows[str(plan.attempt_id)]["state"] == "held"
                assert rows[str(old._plan.attempt_id)]["state"] == "completed"
                assert native.calls.count("data") == 1 and native.calls.count("add") == 0
                assert ram.paths == original_provider_paths
                assert sorted(native.owned) == sorted(native.released)
                assert backend._failed and backend._saved is None

        failures = []

        def observed(app):
            try:
                browser(app)
            except BaseException as error:
                failures.append(error)
                raise

        try:
            host.serve(server=observed)
        except BaseException:
            if failures:
                raise failures[0]
            raise
    backend = host._saved_backend
    assert backend._is_closed and backend._saved is None
    assert backend._saved_identity_current is None
    assert all(not thread.is_alive() for thread in primitive_threads)
    assert warm_native.calls == warm_history
    assert all(connection.closed for connection in ram.connections)


def _unmounted_saved_host_inputs(tmp_path):
    from pydantic import SecretStr

    from test_slack_mounted_host import RamSlack, enroll

    now, _, configuration, values = inputs(tmp_path)
    enroll(values)
    ram = RamSlack(configuration)
    plan = PreflightPlan(
        attempt_id=uuid4(),
        provider="slack",
        client_id=configuration.client_id,
        subject_id="U123456789",
        slack_account={"team_id": "T123456789", "user_id": "U123456789"},
    )
    arguments = dict(
        **values,
        initialize_new_guard=True,
        configuration=configuration,
        expected_user_id="U123456789",
        rotation=SlackRotation.ROTATING,
        approved_generation="invented-reviewed",
        console_observed_at=now,
        review_expires_at=now + timedelta(hours=1),
        client_secret_loader=lambda _: SecretStr("invented-unused-secret"),
        connection_factory=ram.connect,
        network_clock=lambda: ram.net,
    )
    return arguments, plan, ram


def test_actual_serving_callback_cannot_mount_saved_routes(tmp_path):
    from zacai.interfaces.slack_connect_host import SlackConnectHostError

    arguments, plan, ram = _unmounted_saved_host_inputs(tmp_path)
    with open_slack_connect_host(**arguments) as host:
        failures = []

        def callback(app):
            try:
                assert host._window._active and host._window._serving
                routes = tuple(app.routes)
                with pytest.raises(SlackConnectHostError):
                    host.mount_saved_identity(
                        plan=plan, keychain_path=tmp_path / "unused.keychain-db"
                    )
                assert tuple(app.routes) == routes
                assert not getattr(host, "_saved_action_mounted", False)
                assert ram.paths == []
            except BaseException as error:
                failures.append(error)
                raise

        try:
            host.serve(server=callback)
        except BaseException:
            if failures:
                raise failures[0]
            raise
        routes = tuple(host._prepared.app.routes)
        with pytest.raises(SlackConnectHostError):
            host.mount_saved_identity(plan=plan, keychain_path=tmp_path / "unused.keychain-db")
        assert tuple(host._prepared.app.routes) == routes
        assert not getattr(host, "_saved_action_mounted", False)
    assert ram.paths == []


@pytest.mark.parametrize(
    "collision", ["/connections/slack/saved", "/connector-review", "/connector-execute"]
)
def test_each_saved_route_collision_denies_before_mutation(tmp_path, collision):
    from starlette.responses import Response

    from zacai.interfaces.slack_connect_host import SlackConnectHostError

    arguments, plan, ram = _unmounted_saved_host_inputs(tmp_path)
    with open_slack_connect_host(**arguments) as host:

        async def occupied():
            return Response("invented existing route")

        host._prepared.app.add_api_route(collision, occupied, methods=["GET"])
        routes = tuple(host._prepared.app.routes)
        with pytest.raises(SlackConnectHostError):
            host.mount_saved_identity(plan=plan, keychain_path=tmp_path / "unused.keychain-db")
        assert tuple(host._prepared.app.routes) == routes
        assert not getattr(host, "_saved_action_mounted", False)
        assert not (arguments["directory"] / "slack-installation").exists()
        assert ram.paths == []
