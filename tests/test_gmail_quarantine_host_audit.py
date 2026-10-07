"""Independent HTTP owner action and drain tests; direct held-row seeding only."""

from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from tests.test_gmail_quarantine_host import PATH, fields
from tests.test_gmail_quarantine_host import Fixture as HostFixture
from tests.test_oauth_transactions import Fixture as Transactions
from tests.test_oauth_transactions import Registration
from tests.test_private_host import CONFIG, ORIGIN, OWNER, InventedIdentity
from zacai.connectors.oauth_host_guard import OAuthHostGuard
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.interfaces.gmail_quarantine_host import GmailQuarantineHostFatal
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.private_host import prepare_owner_host


class Fixture(HostFixture):
    def seed(self, monkeypatch):
        async def view(principal):
            return "invented seed view"

        prepared = prepare_owner_host(
            configuration=CONFIG,
            directory=self.directory,
            view=view,
            clock=self.clock,
            identities=InventedIdentity(self.clock),
        )
        self.cookie = prepared.sessions.start_user(OWNER, self.now)
        continuity = NamedSessionContinuity(
            sessions=prepared.sessions,
            owner=prepared.owners.load,
            clock=self.clock,
            key=CONFIG.session_key,
            origin=ORIGIN,
            client_id=CONFIG.client_id,
        )
        guarddir = self.directory / "gmail-oauth-guard"
        guarddir.mkdir(mode=0o700)
        guard = OAuthHostGuard(
            guarddir, key=CONFIG.session_key, origin=ORIGIN, client_id=CONFIG.client_id
        )
        guard.initialize()
        authority = OAuthTransactionAuthority(
            self.directory / "gmail-oauth-transactions",
            key=CONFIG.session_key,
            continuity=continuity,
            registration_backend=Registration(),
        )
        authority.initialize()
        transaction = object.__new__(Transactions)
        transaction.authority = authority
        transaction.configuration = self.configuration
        transaction.rotation = None
        transaction.sessions = SimpleNamespace(
            cookie=self.cookie,
            csrf=prepared.sessions.peek_user(self.cookie, self.now).csrf,
            continuity=continuity,
        )

        # Existing generic transaction fixture uses a different invented host.
        def request(**changes):
            req = Transactions.request(transaction, **changes)
            req.scope["headers"] = [
                (k, v.replace(b"caz.example", b"caz.example.test"))
                if k in {b"host", b"origin"}
                else (k, v)
                for k, v in req.scope["headers"]
            ]
            req.scope["server"] = ("caz.example.test", 443)
            return req

        transaction.request = request
        operation = transaction.callback(transaction.state())
        operation.take_exchange()
        operation.hold()
        guard.halt_unconfirmed()
        lock = self.directory / "private-mode.lock"
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        assert not self.provider_calls and not self.native_factories and not self.secret_reads
        self.prepared_seed = prepared


@pytest.mark.parametrize(
    "kind", ["origin", "host", "csrf", "digest", "action", "duplicate", "oversize"]
)
def test_invalid_owner_post_never_creates_intent_or_source_activity(tmp_path, monkeypatch, kind):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    before = f.operational_snapshot()
    plan = f.quarantine_plan(monkeypatch)
    completed = []
    errors = []

    def browse(browser):
        try:
            form = fields(browser, f)
            headers = {"origin": ORIGIN}
            if kind == "origin":
                headers["origin"] = "null"
            elif kind == "host":
                headers["host"] = "foreign.example"
            elif kind in {"csrf", "digest", "action"}:
                form[
                    {"digest": "reviewed_configuration_digest", "action": "action_generation"}.get(
                        kind, kind
                    )
                ] = "invented-invalid"
            fatal_kind = kind in {"csrf", "digest", "action", "duplicate"}
            if fatal_kind:
                try:
                    if kind == "duplicate":
                        from urllib.parse import urlencode

                        browser.post(
                            PATH,
                            content=urlencode(form) + "&csrf=" + form["csrf"],
                            headers={
                                **headers,
                                "content-type": "application/x-www-form-urlencoded",
                            },
                        )
                    else:
                        browser.post(PATH, data=form, headers=headers)
                except BaseException as fatal:  # noqa: BLE001 - inspect ASGI fatal groups
                    leaves = [fatal]
                    while any(isinstance(item, BaseExceptionGroup) for item in leaves):
                        leaves = [
                            child
                            for item in leaves
                            for child in (
                                item.exceptions if isinstance(item, BaseExceptionGroup) else (item,)
                            )
                        ]
                    assert any(isinstance(item, GmailQuarantineHostFatal) for item in leaves)
                    assert f.servers[-1].should_exit and not plan._admitted()
                else:
                    raise AssertionError("Invalid spent action must retire host")
                assert not (
                    f.directory / "gmail-oauth-transactions" / "gmail-quarantine-intent.bin"
                ).exists()
                f.held_lease()
                f.no_gmail_io()
                completed.append(True)
                return
            if kind == "duplicate":
                from urllib.parse import urlencode

                response = browser.post(
                    PATH,
                    content=urlencode(form) + "&csrf=" + form["csrf"],
                    headers={**headers, "content-type": "application/x-www-form-urlencoded"},
                )
            elif kind == "oversize":
                response = browser.post(
                    PATH,
                    content="x" * 513,
                    headers={**headers, "content-type": "application/x-www-form-urlencoded"},
                )
            else:
                response = browser.post(PATH, data=form, headers=headers)
            assert response.status_code == 403
            assert not (
                f.directory / "gmail-oauth-transactions" / "gmail-quarantine-intent.bin"
            ).exists()
            f.held_lease()
            f.no_gmail_io()
            completed.append(True)
        except BaseException as e:
            errors.append(e)
            raise

    f.browser_action = browse
    if kind in {"csrf", "digest", "action", "duplicate"}:
        with pytest.raises(GmailQuarantineHostFatal):
            plan.run()
    else:
        plan.run()
    if errors:
        raise errors[0]
    assert completed and f.operational_snapshot() == before
    assert plan._captured is None and plan._journal is None and not plan._admitted()


def test_success_stops_actual_listener_after_journal_and_never_opens_new_consent(
    tmp_path, monkeypatch
):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    before = f.operational_snapshot()
    plan = f.quarantine_plan(monkeypatch)
    completed = []
    errors = []

    def browse(browser):
        try:
            form = fields(browser, f)
            response = browser.post(PATH, data=form, headers={"origin": ORIGIN})
            assert response.status_code == 200
            assert response.json()["recorded_only"] is True
            assert f.servers[-1].should_exit
            for method, path in (
                ("get", "/login"),
                ("get", PATH),
                ("post", "/connections/gmail/begin"),
            ):
                assert getattr(browser, method)(path).status_code == 403
            f.held_lease()
            f.no_gmail_io()
            completed.append(True)
        except BaseException as e:
            errors.append(e)
            raise

    f.browser_action = browse
    failure = None
    try:
        plan.run()
    except BaseException as e:  # noqa: BLE001 - rethrow after exposing callback assertions
        failure = e
    if errors:
        raise errors[0]
    if failure:
        raise failure
    assert completed and plan._captured is None and plan._preview is None and plan._journal is None
    for path, witness in before.items():
        assert (path.stat().st_ino, path.stat().st_mode, path.read_bytes()) == witness
    assert (f.directory / "gmail-oauth-transactions" / "gmail-quarantine-intent.bin").exists()
    assert len(f.shared_reads) == 2
    f.no_gmail_io()


@pytest.mark.parametrize("stop_fails", [False, True])
def test_cancelled_writer_route_retires_http_and_drains_under_original_lease(
    tmp_path, monkeypatch, stop_fails
):
    import threading
    from urllib.parse import urlencode, urlsplit

    import anyio
    from starlette.requests import Request

    from zacai.connectors.gmail_quarantine_journal import GmailQuarantineJournal
    from zacai.interfaces.private_server_lifecycle import PrivateServerLifecycle

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    stops = []
    original_stop = PrivateServerLifecycle.stop_host

    def stop(server):
        stops.append(server)
        if stop_fails:
            raise RuntimeError("invented-stop-private-" + f.cookie)
        original_stop(server)

    monkeypatch.setattr(PrivateServerLifecycle, "stop_host", stop)
    plan = f.quarantine_plan(monkeypatch)
    calls = []
    caught = []
    completed = []
    drained = []
    errors = []

    def cancel(writer, **kwargs):
        calls.append(True)
        raise KeyboardInterrupt("invented-cookie-private-" + f.cookie)

    monkeypatch.setattr(GmailQuarantineJournal, "write_once", cancel)

    def browse(browser):
        try:
            form = fields(browser, f)
            endpoint = next(
                route.endpoint
                for route in f.servers[-1].app.routes
                if route.path == PATH and "POST" in route.methods
            )
            body = urlencode(form).encode()

            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}

            request = Request(
                {
                    "type": "http",
                    "method": "POST",
                    "scheme": "https",
                    "path": PATH,
                    "query_string": b"",
                    "headers": [
                        (b"host", urlsplit(ORIGIN).netloc.encode()),
                        (b"origin", ORIGIN.encode()),
                        (b"content-type", b"application/x-www-form-urlencoded"),
                        (b"cookie", ("__Host-zac-session=" + f.cookie).encode()),
                    ],
                    "server": (urlsplit(ORIGIN).netloc, 443),
                    "client": ("127.0.0.1", 1),
                },
                receive,
            )
            before = len(stops)
            with pytest.raises(GmailQuarantineHostFatal) as raised:
                anyio.run(endpoint, request)
            error = raised.value
            caught.append(error)
            assert error.__cause__ is None and error.__context__ is None
            assert len(stops) == before + 1 and stops[-1] is plan._server
            assert f.servers[-1].should_exit is (not stop_fails)
            tb = error.__traceback__
            while tb:
                frame = tb.tb_frame
                if frame.f_globals.get("__name__") == "zacai.interfaces.gmail_quarantine_host":
                    assert (
                        not {"request", "cookie", "csrf", "selected", "receipt", "body"}
                        & frame.f_locals.keys()
                    )
                tb = tb.tb_next
            assert anyio.run(endpoint, request).status_code == 403 and calls == [True]
            assert browser.get("/login").status_code == 403

            def worker():
                try:
                    threading.Event().wait(0.1)
                    f.held_lease()
                    drained.append(True)
                except BaseException as error:  # noqa: BLE001 - rethrow worker assertions after drain
                    errors.append(error)

            threading.Thread(target=worker).start()
            completed.append(True)
        except BaseException as error:
            errors.append(error)
            raise

    f.browser_action = browse
    with pytest.raises(GmailQuarantineHostFatal):
        plan.run()
    if errors:
        raise errors[0]
    assert completed == drained == [True] and len(caught) == 1
    assert plan._preview is None and plan._journal is None and plan._captured is None
    assert not (f.directory / "gmail-oauth-transactions" / "gmail-quarantine-intent.bin").exists()
    f.no_gmail_io()


def test_unknown_child_after_startup_before_first_preview_retires_host(tmp_path, monkeypatch):
    from urllib.parse import urlsplit

    import anyio
    from starlette.requests import Request

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.quarantine_plan(monkeypatch)
    original = f.operational_snapshot()
    completed = []
    errors = []

    def browse(browser):
        try:
            f.held_lease()
            extra = f.directory / "gmail-oauth-transactions" / "invented-unknown-child"
            extra.write_bytes(b"invented-evidence-preserve")
            extra.chmod(0o600)
            endpoint = next(
                route.endpoint
                for route in f.servers[-1].app.routes
                if route.path == PATH and "GET" in route.methods
            )
            request = Request(
                {
                    "type": "http",
                    "method": "GET",
                    "scheme": "https",
                    "path": PATH,
                    "query_string": b"",
                    "headers": [
                        (b"host", urlsplit(ORIGIN).netloc.encode()),
                        (b"cookie", ("__Host-zac-session=" + f.cookie).encode()),
                    ],
                    "server": (urlsplit(ORIGIN).netloc, 443),
                    "client": ("127.0.0.1", 1),
                }
            )
            with pytest.raises(GmailQuarantineHostFatal):
                anyio.run(endpoint, request)
            assert plan._fatal and not plan._admitted() and f.servers[-1].should_exit
            assert plan._preview is None and not plan._post_spent
            assert anyio.run(endpoint, request).status_code == 403
            assert browser.get("/login").status_code == 403
            assert extra.read_bytes() == b"invented-evidence-preserve"
            assert not (extra.parent / "gmail-quarantine-intent.bin").exists()
            for path, witness in original.items():
                assert (path.stat().st_ino, path.stat().st_mode, path.read_bytes()) == witness
            f.held_lease()
            f.no_gmail_io()
            completed.append(True)
        except BaseException as error:
            errors.append(error)
            raise

    f.browser_action = browse
    with pytest.raises(GmailQuarantineHostFatal):
        plan.run()
    if errors:
        raise errors[0]
    assert completed == [True] and plan._journal is None and plan._captured is None
