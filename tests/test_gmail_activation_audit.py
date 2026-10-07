"""Independent activation controls with disposable authority and invented native data."""

import ctypes
from types import SimpleNamespace

import pytest

from zacai.connectors.gmail_native_reader import _AppleInspectionBindings
from zacai.connectors.gmail_native_staging import _MAX_DATA


class Primitive:
    def __init__(self, function):
        self.function = function

    def __call__(self, *args):
        return self.function(*args)


def data_bridge(*, length=32, data_present=True, status=0, free_status=0, cancel_after_copy=False):
    bridge = object.__new__(_AppleInspectionBindings)
    bridge._checker = None
    bridge._primitive_failed = bridge._primitive_cancelled = False
    bridge._item_type = lambda: 41
    bridge._type = lambda ref: 41
    buffer = ctypes.create_string_buffer(b"invented protected payload bytes")
    calls = []
    copied = []
    cancelled = []

    def attributes(item, info, item_class, attrs, out_length, out_data):
        assert item == 77 and info is item_class is attrs is None
        ctypes.cast(out_length, ctypes.POINTER(ctypes.c_uint32))[0] = length
        ctypes.cast(out_data, ctypes.POINTER(ctypes.c_void_p))[0] = (
            ctypes.addressof(buffer) if data_present else None
        )
        copied.append(True)
        calls.append("copy")
        return status

    def free(attrs, data):
        assert attrs is None and data.value == ctypes.addressof(buffer)
        calls.append("free")
        return free_status

    def check():
        if cancel_after_copy and copied and not cancelled:
            cancelled.append(True)
            raise KeyboardInterrupt("invented private native interruption")

    library = SimpleNamespace(
        SecKeychainItemCopyAttributesAndData=Primitive(attributes),
        SecKeychainItemFreeAttributesAndData=Primitive(free),
    )
    bridge._attributes = bridge._function(
        library, "SecKeychainItemCopyAttributesAndData", [], ctypes.c_int32
    )
    bridge._free_attributes = bridge._function(
        library, "SecKeychainItemFreeAttributesAndData", [], ctypes.c_int32
    )
    bridge.bind_check(check)
    return bridge, calls, buffer


def test_real_data_bridge_reads_only_retained_item_and_frees_owned_buffer():
    bridge, calls, buffer = data_bridge()
    assert bridge.read_item(77, _MAX_DATA) == buffer.raw[:32]
    assert calls == ["copy", "free"]
    assert not bridge._primitive_failed and not bridge._primitive_cancelled


@pytest.mark.parametrize("failure", ["zero", "oversized", "missing", "status", "cancel"])
def test_real_data_bridge_rejects_bad_return_and_releases_any_owned_data(failure):
    fields = {
        "zero": {"length": 0},
        "oversized": {"length": _MAX_DATA + 1},
        "missing": {"data_present": False},
        "status": {"status": -1},
        "cancel": {"cancel_after_copy": True},
    }[failure]
    bridge, calls, _ = data_bridge(**fields)
    expected = KeyboardInterrupt if failure == "cancel" else ValueError
    with pytest.raises(expected):
        bridge.read_item(77, _MAX_DATA)
    assert calls == (["copy"] if failure == "missing" else ["copy", "free"])
    if failure == "cancel":
        assert bridge._primitive_failed and bridge._primitive_cancelled


@pytest.mark.parametrize("outcome", [-1, True, None])
def test_real_data_cleanup_failure_is_latched_for_outer_activation_denial(outcome):
    bridge, calls, _ = data_bridge(free_status=outcome)
    bridge.read_item(77, _MAX_DATA)
    assert calls == ["copy", "free"]
    assert bridge._primitive_failed


def test_actual_connector_backend_callback_cannot_drop_lock_or_close_foreign_fd(
    tmp_path, monkeypatch
):
    import fcntl
    import os

    from tests.test_connector_authority import Fixture, read_plan
    from zacai.connectors.connector_authority import ConnectorAuthorityError

    # This negative tests the actual ordinary gateway boundary, not an activation grant.
    f = Fixture(tmp_path)
    selected = read_plan()
    f.approve(selected)
    gateway = f.gateway()
    gateway.consume(selected)
    foreign = tmp_path / "invented foreign descriptor"
    foreign.write_bytes(b"invented unchanged bytes")
    foreign_inode = foreign.stat().st_ino
    raw_open, raw_close, raw_dup2 = os.open, os.close, os.dup2
    opened, foreign_effects, reused = [], [], []
    original_credential = f.backend.credential

    def observe_open(path, *args, **kwargs):
        fd = raw_open(path, *args, **kwargs)
        if str(path) == str(f.authority._lock_path):
            opened.append(fd)
        return fd

    monkeypatch.setattr(os, "open", observe_open)
    for name in ("read", "pread", "write", "fsync", "close"):
        original = getattr(os, name)

        def observe(fd, *args, _name=name, _original=original):
            try:
                if os.fstat(fd).st_ino == foreign_inode:
                    foreign_effects.append(_name)
            except OSError:
                pass
            return _original(fd, *args)

        monkeypatch.setattr(os, name, observe)

    def replace_lock(plan, generation):
        target = opened[0]
        raw_close(target)
        replacement = raw_open(foreign, os.O_RDWR)
        if replacement != target:
            raw_dup2(replacement, target)
            raw_close(replacement)
        reused.append(target)
        probe = raw_open(f.authority._lock_path, os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            raw_close(probe)
        return original_credential(plan, generation)

    monkeypatch.setattr(f.backend, "credential", replace_lock)
    try:
        with pytest.raises(ConnectorAuthorityError):
            gateway.credential(selected)
        assert len(reused) == 1 and not foreign_effects
        assert os.fstat(reused[0]).st_ino == foreign_inode
        assert str(selected.attempt_id) not in gateway._issued
        assert foreign.read_bytes() == b"invented unchanged bytes"
    finally:
        for fd in reused:
            raw_close(fd)


def test_public_checked_candidate_constructor_cannot_supply_activation_provenance(
    tmp_path, monkeypatch
):
    from tests.test_gmail_native_reader import with_fresh
    from zacai.connectors.gmail_native_reader import GmailNativeReadError
    from zacai.connectors.oauth_exchange import CheckedOAuthExchange

    observed = []

    def action(f, consumer, reader, reference, bindings):
        original = consumer._checked_fresh
        consumer._checked_fresh = CheckedOAuthExchange(original.candidate)
        try:
            with pytest.raises(GmailNativeReadError):
                reader.read_once(
                    reference=reference,
                    admission=consumer._admission,
                    candidate=original.candidate,
                )
            assert bindings.events == []
            observed.append(True)
        finally:
            consumer._checked_fresh = original

    with_fresh(tmp_path, monkeypatch, action)
    assert observed == [True]


def activation_fixture(tmp_path, monkeypatch):
    import zacai.interfaces.gmail_recovery_host as host_module
    from tests.test_gmail_native_reader import Bindings
    from tests.test_gmail_recovery_host import Fixture
    from tests.test_gmail_setup import ACCESS, REFRESH, SUBJECT, Connection, Response
    from zacai.connectors.gmail_held_staging import HeldGmailNativeStage
    from zacai.connectors.gmail_native_reader import GmailNativeReader
    from zacai.connectors.oauth_exchange import OAuthExchangeTransport

    f = Fixture(tmp_path, monkeypatch)
    readers = []

    class DynamicConnection(Connection):
        def request(self, method, path, body=None, headers=None):
            self.path = path
            super().request(method, path, body, headers)

        def getresponse(self):
            scope = " ".join(sorted(f.configuration.scopes))
            if self.path == "/token":
                payload = {
                    "access_token": ACCESS,
                    "refresh_token": REFRESH,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": scope,
                }
            elif self.path == "/tokeninfo":
                payload = {
                    "aud": f.configuration.client_id,
                    "azp": f.configuration.client_id,
                    "sub": SUBJECT,
                    "scope": scope,
                    "expires_in": "3600",
                    "exp": str(int(f.now.timestamp()) + 3600),
                    "access_type": "offline",
                }
            else:
                assert self.path == "/gmail/v1/users/me/profile"
                payload = {
                    "emailAddress": f.configuration.gmail_mailbox,
                    "messagesTotal": 0,
                    "threadsTotal": 0,
                    "historyId": "123",
                }
            return Response(payload)

    def connect(host):
        assert host in {"oauth2.googleapis.com", "gmail.googleapis.com"}
        result = DynamicConnection(f, host, None)
        f.connections.append(result)
        return result

    transport = OAuthExchangeTransport(connection_factory=connect)
    monkeypatch.setattr(host_module, "OAuthExchangeTransport", lambda: transport)
    monkeypatch.setattr(
        host_module,
        "HeldGmailNativeStage",
        lambda **kwargs: HeldGmailNativeStage(**kwargs, bindings_factory=f.native_factory),
    )

    def bindings_factory():
        result = Bindings(f.keychain)
        result.data = f.bindings.data
        readers.append(result)
        return result

    monkeypatch.setattr(
        host_module,
        "GmailNativeReader",
        lambda **kwargs: GmailNativeReader(**kwargs, bindings_factory=bindings_factory),
    )
    plan = f.recovery_plan(monkeypatch)

    return f, plan, readers


def test_actual_installation_then_gateway_completes_identity_only_profile(tmp_path, monkeypatch):
    from urllib.parse import parse_qs, urlsplit

    from tests.test_gmail_recovery_audit import run_checked
    from tests.test_gmail_recovery_host import form
    from tests.test_private_host import ORIGIN, sign_in

    f, plan, readers = activation_fixture(tmp_path, monkeypatch)

    def browse(browser):
        sign_in(browser)
        for path in ("/connections/gmail/recover/pair", "/connections/gmail/quarantine"):
            assert (
                browser.post(path, data=form(browser), headers={"origin": ORIGIN}).status_code
                == 303
            )
        response = browser.post(
            "/connections/gmail/recover/begin", data=form(browser), headers={"origin": ORIGIN}
        )
        assert response.status_code == 303
        state = parse_qs(urlsplit(response.headers["location"]).query)["state"][0]
        assert (
            browser.get(
                "/connections/gmail/callback", params={"state": state, "code": "invented-code"}
            ).status_code
            == 200
        )
        assert (
            browser.post(
                "/connections/gmail/install", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 303
        )
        installed = plan._consumer._installer
        installed.current_active()
        assert (
            browser.post(
                "/connector-review", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 303
        )
        before = len(f.provider_calls)
        response = browser.post(
            "/connector-execute", data=form(browser), headers={"origin": ORIGIN}
        )
        assert response.status_code == 200
        assert response.json()["installed"] is response.json()["profile_verified"] is True
        assert response.json()["requests"] == 1
        assert (
            response.json()["processing_authorized"]
            is response.json()["source_capture_authorized"]
            is False
        )
        assert len(f.provider_calls) > before
        assert f.provider_calls[-1] == ("gmail.googleapis.com", "GET", "/gmail/v1/users/me/profile")
        assert len(readers) == 2 and all(
            sum(e[0] == "read_item" for e in r.events) == 1 for r in readers
        )
        with installed._connector._locked():
            rows = installed._connector._read()["rows"]
        assert next(iter(rows.values()))["state"] == "completed"
        f.both_leases()

    run_checked(f, plan, browse, allow_terminal=False)
    assert all(connection.closed for connection in f.connections)


def test_changed_singleton_native_identity_is_quarantined_by_actual_gateway(tmp_path, monkeypatch):
    from tests.test_gmail_installation import fresh, install
    from tests.test_gmail_recovery_audit import run_checked
    from tests.test_gmail_recovery_host import form
    from tests.test_private_host import ORIGIN
    from zacai.connectors.gmail_installation import ACTIVE, QUARANTINED

    f, plan, readers = activation_fixture(tmp_path, monkeypatch)

    def browse(browser):
        fresh(browser)
        install(browser)
        installed = plan._consumer._installer
        assert (installed._directory / ACTIVE).is_file()
        assert (
            browser.post(
                "/connector-review", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 303
        )
        # Change the actual native primitive result, preserving the pinned factory.
        from tests.test_gmail_native_reader import Bindings

        original_reference = Bindings.persistent_reference

        def reference(bindings, item):
            result = original_reference(bindings, item)
            return (
                b"invented-different-singleton-native-item"
                if bindings is not readers[0]
                else result
            )

        with monkeypatch.context() as local:
            local.setattr(Bindings, "persistent_reference", reference)
            before = list(f.provider_calls)
            response = browser.post(
                "/connector-execute", data=form(browser), headers={"origin": ORIGIN}
            )
        assert response.status_code == 403
        assert installed._quarantined and (installed._directory / QUARANTINED).is_file()
        assert f.provider_calls == before
        with installed._connector._locked():
            row = next(iter(installed._connector._read()["rows"].values()))
        assert row["state"] == "held" and row["loaded"] is True
        f.both_leases()

    run_checked(f, plan, browse)


def test_pending_record_readback_failure_stays_uninstalled_without_native_read_or_retry(
    tmp_path, monkeypatch
):
    import os

    from tests.test_gmail_installation import fresh
    from tests.test_gmail_recovery_audit import run_checked
    from tests.test_gmail_recovery_host import form
    from tests.test_private_host import ORIGIN
    from zacai.connectors.gmail_installation import ACTIVE, PENDING

    f, plan, readers = activation_fixture(tmp_path, monkeypatch)
    raw_pread = os.pread
    faults = []

    def corrupted_readback(fd, amount, offset):
        installer = plan._consumer._installer if plan._consumer is not None else None
        writing = installer._writing if installer is not None else None
        if writing is not None and writing[0] == PENDING and writing[1] == fd:
            faults.append(True)
            return b"invented incorrect pending readback"
        return raw_pread(fd, amount, offset)

    monkeypatch.setattr(os, "pread", corrupted_readback)

    def browse(browser):
        fresh(browser)
        before = list(f.provider_calls)
        response = browser.post(
            "/connections/gmail/install", data=form(browser), headers={"origin": ORIGIN}
        )
        assert response.status_code == 403 and faults == [True]
        installer = plan._consumer._installer
        assert installer._spent and not installer._active
        assert (installer._directory / PENDING).is_file() and not (
            installer._directory / ACTIVE
        ).exists()
        assert readers == [] and f.provider_calls == before
        assert (
            browser.post(
                "/connections/gmail/install", data={}, headers={"origin": ORIGIN}
            ).status_code
            == 403
        )
        assert faults == [True] and f.servers[-1].should_exit
        f.both_leases()

    run_checked(f, plan, browse)
    secrets = list(f.secret_reads)
    next_plan = f.recovery_plan(monkeypatch)

    def denied_reopen(browser):
        from tests.test_private_host import sign_in

        sign_in(browser)
        response = browser.post(
            "/connections/gmail/recover/pair", data=form(browser), headers={"origin": ORIGIN}
        )
        assert response.status_code == 403
        f.both_leases()

    run_checked(f, next_plan, denied_reopen)
    assert f.secret_reads == secrets and readers == []


def test_activation_expiry_clock_revocation_blocks_actual_provider_dispatch(tmp_path, monkeypatch):
    import inspect

    from tests.test_gmail_installation import fresh
    from tests.test_gmail_recovery_audit import run_checked
    from tests.test_gmail_recovery_host import form
    from tests.test_private_host import ORIGIN
    from zacai.connectors.gmail_installation import ACTIVE, PENDING

    f, plan, readers = activation_fixture(tmp_path, monkeypatch)
    raw_clock = f.clock._read
    revoked = []
    work_at_revoke = []

    def expiry_clock():
        frame = inspect.currentframe()
        at_verification_expiry = False
        try:
            while frame:
                if (
                    frame.f_code.co_name == "__call__"
                    and frame.f_globals.get("__name__") == "zacai.interfaces.host_clock"
                    and frame.f_back is not None
                    and frame.f_back.f_code.co_name == "_current"
                    and frame.f_back.f_globals.get("__name__")
                    == "zacai.connectors.gmail_installation"
                    and frame.f_back.f_back is not None
                    and frame.f_back.f_back.f_code.co_name == "_verify_live"
                ):
                    at_verification_expiry = True
                    break
                frame = frame.f_back
        finally:
            del frame
        if at_verification_expiry and not revoked:
            action = plan._consumer._action
            plan._hr_continuity._sessions.revoke(action._hr_cookie)
            revoked.append(True)
            work_at_revoke.append(
                (list(f.provider_calls), [list(reader.events) for reader in readers])
            )
        return raw_clock()

    monkeypatch.setattr(f.clock, "_read", expiry_clock)

    def browse(browser):
        fresh(browser)
        response = browser.post(
            "/connections/gmail/install", data=form(browser), headers={"origin": ORIGIN}
        )
        assert response.status_code == 403 and revoked == [True]
        installed = plan._consumer._installer
        assert not installed._active
        assert (installed._directory / PENDING).is_file()
        assert not (installed._directory / ACTIVE).exists()
        assert (f.provider_calls, [reader.events for reader in readers]) == work_at_revoke[0]
        assert len(readers) == 1 and f.servers[-1].should_exit
        f.both_leases()

    run_checked(f, plan, browse)
