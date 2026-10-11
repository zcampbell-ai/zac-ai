"""Actual owner/callback composition with invented provider and native boundaries."""

from urllib.parse import parse_qs, urlsplit

import pytest

from tests.test_gmail_installation import fixture, run
from tests.test_gmail_recovery_host import form
from tests.test_gmail_terminal_chain_v3 import begin
from tests.test_private_host import ORIGIN, sign_in
from zacai.connectors.oauth_exchange import OAuthExchangeTransport


def failed_v2(tmp_path, monkeypatch):
    f, first = fixture(tmp_path, monkeypatch)
    run(f, first, lambda browser: begin(browser))
    prior = OAuthExchangeTransport.exchange

    def fail(self, material, client_secret):
        f.both_leases()
        raise ValueError("invented failure before dispatch")

    monkeypatch.setattr(OAuthExchangeTransport, "exchange", fail)
    second = f.recovery_plan(
        monkeypatch, action_generation="invented-v2-loaded", recovery_profile="legacy_repeat_v2"
    )

    def callback(browser):
        state = begin(browser)
        assert (
            browser.get(
                "/connections/gmail/callback", params={"state": state, "code": "invented"}
            ).status_code
            == 403
        )

    run(f, second, callback)
    monkeypatch.setattr(OAuthExchangeTransport, "exchange", prior)
    with f.authority._locked():
        rows = f.authority._read()["rows"]
    assert any(
        row["loaded"] and row["state"] == "held" for s, row in rows.items() if s != f.old_state
    )
    return f, rows, {p.name: p.read_bytes() for p in f.authority._directory.iterdir()}


class AbsenceBindings:
    def __init__(self, f, events, outcome="missing"):
        self.f, self.events, self.outcome = f, events, outcome
        self._primitive_failed = self._primitive_cancelled = False

    def keychain_open(self, path):
        self.events.append(("open", path))
        return 101

    def keychain_path(self, ref):
        assert ref == 101
        return str(self.f.keychain)

    def require_absent(self, ref, service, account):
        self.f.both_leases()
        self.events.append(("query", service, account))
        if self.outcome == "cancel":
            raise KeyboardInterrupt("invented")
        if self.outcome != "missing":
            raise ValueError("invented native denial")
        return -25300

    def release(self, ref):
        self.events.append(("release", ref))
        if self.outcome == "cleanup":
            raise ValueError("invented cleanup denial")


def test_real_loaded_failure_owner_inspection_and_one_new_begin(tmp_path, monkeypatch):
    import zacai.connectors.gmail_recovery_native_absence as module

    f, rows, files = failed_v2(tmp_path, monkeypatch)
    events = []
    monkeypatch.setattr(module, "_AbsenceBindings", lambda: AbsenceBindings(f, events))
    plan = f.recovery_plan(
        monkeypatch,
        action_generation="invented-v4-current",
        recovery_profile="terminal_native_absence_v4",
    )

    def browser_action(browser):
        sign_in(browser)
        page = browser.get("/connections/gmail/recover")
        assert "Pair and check the earlier attempt" in page.text
        assert "does not read tokens or mail" in page.text
        for path in ("/connections/gmail/recover/pair", "/connections/gmail/quarantine"):
            assert (
                browser.post(path, data=form(browser), headers={"origin": ORIGIN}).status_code
                == 303
            )
        response = browser.post(
            "/connections/gmail/recover/begin", data=form(browser), headers={"origin": ORIGIN}
        )
        assert response.status_code == 303
        assert parse_qs(urlsplit(response.headers["location"]).query)["state"]

    run(f, plan, browser_action)
    assert sum(e[0] == "query" for e in events) == 2
    assert sum(e[0] == "release" for e in events) == 2
    with f.authority._locked():
        after = f.authority._read()["rows"]
    assert len(after) == len(rows) + 1 and all(after[s] == r for s, r in rows.items())
    assert all(
        (f.authority._directory / n).read_bytes() == raw
        for n, raw in files.items()
        if n != f.authority._path.name
    )
    assert not f.connections and not f.native_factories


@pytest.mark.parametrize("outcome", ["present", "ambiguous", "permission", "cleanup", "cancel"])
def test_native_uncertainty_denies_before_new_publication(tmp_path, monkeypatch, outcome):
    import zacai.connectors.gmail_recovery_native_absence as module

    f, rows, files = failed_v2(tmp_path, monkeypatch)
    events = []
    monkeypatch.setattr(module, "_AbsenceBindings", lambda: AbsenceBindings(f, events, outcome))
    plan = f.recovery_plan(
        monkeypatch,
        action_generation="invented-v4-denied",
        recovery_profile="terminal_native_absence_v4",
    )

    def browser_action(browser):
        sign_in(browser)
        try:
            response = browser.post(
                "/connections/gmail/recover/pair", data=form(browser), headers={"origin": ORIGIN}
            )
            assert response.status_code == 403
        except BaseException:
            if outcome != "cancel":
                raise

    run(f, plan, browser_action)
    assert any(e[0] == "release" for e in events)
    with f.authority._locked():
        assert f.authority._read()["rows"] == rows
    assert all((f.authority._directory / n).read_bytes() == raw for n, raw in files.items())
    assert not f.connections and not f.native_factories


def test_item_appears_on_requery_denies_before_new_journal(tmp_path, monkeypatch):
    import zacai.connectors.gmail_recovery_native_absence as module

    f, rows, files = failed_v2(tmp_path, monkeypatch)
    events = []
    factories = []

    def factory():
        factories.append(True)
        return AbsenceBindings(f, events, "missing" if len(factories) == 1 else "present")

    monkeypatch.setattr(module, "_AbsenceBindings", factory)
    plan = f.recovery_plan(
        monkeypatch,
        action_generation="invented-v4-late-item",
        recovery_profile="terminal_native_absence_v4",
    )

    def action(browser):
        sign_in(browser)
        assert (
            browser.post(
                "/connections/gmail/recover/pair", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 303
        )
        assert (
            browser.post(
                "/connections/gmail/quarantine", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 403
        )

    run(f, plan, action)
    assert len(factories) == 2
    with f.authority._locked():
        assert f.authority._read()["rows"] == rows
    assert all((f.authority._directory / n).read_bytes() == raw for n, raw in files.items())


@pytest.mark.parametrize("status", [-25300, 0, 0.0, -25300.0, True, -25293, -128])
def test_actual_metadata_bridge_only_exact_notfound_after_cleanup(status):
    import ctypes

    from zacai.connectors.gmail_recovery_native_absence import _AbsenceBindings

    bridge = object.__new__(_AbsenceBindings)
    bridge._primitive_failed = bridge._primitive_cancelled = False
    released = []
    bridge._typed = lambda ref, typ: ref
    bridge._kc_type = lambda: 1
    bridge._query = lambda service, account: (10, [11, 12])
    bridge._ref = lambda ref: ref
    bridge._array = lambda *args: 13
    bridge._callbacks = lambda name: ctypes.c_void_p()
    bridge._set = lambda *args: None
    bridge._constant = lambda *args, **kwargs: 14
    bridge._copy = lambda *args: status
    bridge.release = lambda ref: released.append(ref)
    if type(status) is int and status == -25300:
        assert bridge.require_absent(1, "exact-service", "exact-account") == -25300
    else:
        with pytest.raises(ValueError):
            bridge.require_absent(1, "exact-service", "exact-account")
    assert released == [10, 13, 12, 11]


def test_actual_loaded_reconciliation_installs_and_reopens_under_new_owner(tmp_path, monkeypatch):
    import zacai.connectors.gmail_recovery_native_absence as module
    from tests.test_gmail_installation import fresh, install
    from tests.test_gmail_installed_load_audit import paired_restart, reopen_form, run_restarted

    f, old_rows, old_files = failed_v2(tmp_path, monkeypatch)
    owner_bytes = [
        (root / "owner/owner.json").read_bytes() for root in (f.directory, f.hr_directory)
    ]
    markers = [
        (f.directory / "gmail-oauth-guard" / n).read_bytes()
        for n in ("oauth-host.ready", "oauth-host.halted")
    ]
    events = []
    monkeypatch.setattr(module, "_AbsenceBindings", lambda: AbsenceBindings(f, events))
    plan = f.recovery_plan(
        monkeypatch,
        action_generation="invented-v4-install",
        recovery_profile="terminal_native_absence_v4",
    )

    def completed(browser):
        fresh(browser)
        install(browser)
        assert (
            browser.post(
                "/connector-review", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 303
        )
        reply = browser.post("/connector-execute", data=form(browser), headers={"origin": ORIGIN})
        assert reply.status_code == 200 and reply.json()["profile_verified"] is True

    run(f, plan, completed)
    assert sum(e[0] == "query" for e in events) == 2
    assert all(
        (f.authority._directory / name).read_bytes() == raw
        for name, raw in old_files.items()
        if name != f.authority._path.name
    )
    assert owner_bytes == [
        (root / "owner/owner.json").read_bytes() for root in (f.directory, f.hr_directory)
    ]
    assert markers == [
        (f.directory / "gmail-oauth-guard" / n).read_bytes()
        for n in ("oauth-host.ready", "oauth-host.halted")
    ]
    with f.authority._locked():
        assert all(f.authority._read()["rows"][s] == row for s, row in old_rows.items())
    restart = f.recovery_plan(
        monkeypatch,
        action_generation="invented-v4-new-owner-reopen",
        recovery_profile="terminal_native_absence_v4",
        load_existing=True,
    )

    def reopened(browser):
        paired_restart(browser)
        assert (
            browser.post(
                "/connector-review", data=reopen_form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 303
        )
        reply = browser.post(
            "/connector-execute", data=reopen_form(browser), headers={"origin": ORIGIN}
        )
        assert reply.status_code == 200 and reply.json()["profile_verified"] is True

    run_restarted(f, restart, reopened)
    # Historical absence remains history, not a new owner/source/current-token grant.
    assert sum(e[0] == "query" for e in events) == 2
    assert all(
        (f.authority._directory / name).read_bytes() == raw
        for name, raw in old_files.items()
        if name != f.authority._path.name
    )


@pytest.mark.parametrize("change", ["clone", "state", "record", "revoke", "source", "namespace", "methods"])
def test_actual_capability_provenance_or_current_owner_denial_before_requery(
    tmp_path, monkeypatch, change
):
    import json

    import zacai.connectors.gmail_recovery_native_absence as module

    f, rows, files = failed_v2(tmp_path, monkeypatch)
    events = []
    monkeypatch.setattr(module, "_AbsenceBindings", lambda: AbsenceBindings(f, events))
    plan = f.recovery_plan(
        monkeypatch,
        action_generation="invented-v4-pin-denial",
        recovery_profile="terminal_native_absence_v4",
    )

    def action(browser):
        sign_in(browser)
        assert (
            browser.post(
                "/connections/gmail/recover/pair", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 303
        )
        history = plan._consumer._history
        cap = module._HISTORY_CAPABILITIES[history][1][0]
        assert cap.remote_grant_outcome == "UNKNOWN"
        assert (
            cap.credential_authority
            is cap.processing_authorized
            is cap.execution_authorized
            is cap.live_access_proven
            is False
        )
        assert (
            json.loads(cap._record_bytes)["native_generation"]
            != json.loads(cap._record_bytes)["epoch_generation"]
        )
        body = form(browser)
        if change == "clone":
            clone = object.__new__(module.GmailNativeAbsenceCapability)
            clone.__dict__.update(cap.__dict__)
            with pytest.raises(ValueError):
                clone.consume_once()
            with pytest.raises(ValueError):
                clone.current()
            cap._state = "0" * 64
        elif change == "state":
            cap._state = "0" * 64
        elif change == "record":
            cap._record_bytes = b"{}"
        elif change == "revoke":
            cap._action._authority._continuity._sessions.revoke(cap._action._original_cookie)
        elif change == "source":
            cap._source = "0" * 64
        elif change == "methods":
            monkeypatch.setattr(AbsenceBindings, "require_absent", lambda *args: None)
        else:
            (f.authority._directory / "invented-unknown.bin").write_bytes(b"invented")
        response = browser.post(
            "/connections/gmail/quarantine", data=body, headers={"origin": ORIGIN}
        )
        assert response.status_code == 403

    run(f, plan, action)
    assert sum(e[0] == "query" for e in events) == 1
    with f.authority._locked():
        assert f.authority._read()["rows"] == rows
    assert all((f.authority._directory / name).read_bytes() == raw for name, raw in files.items())


def test_invalid_quarantine_csrf_does_not_consume_or_requery(tmp_path, monkeypatch):
    import zacai.connectors.gmail_recovery_native_absence as module

    f, rows, files = failed_v2(tmp_path, monkeypatch)  # noqa: RUF059
    events = []
    monkeypatch.setattr(module, "_AbsenceBindings", lambda: AbsenceBindings(f, events))
    plan = f.recovery_plan(
        monkeypatch,
        action_generation="invented-v4-csrf",
        recovery_profile="terminal_native_absence_v4",
    )

    def action(browser):
        sign_in(browser)
        assert (
            browser.post(
                "/connections/gmail/recover/pair", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 303
        )
        cap = module._HISTORY_CAPABILITIES[plan._consumer._history][1][0]
        body = form(browser)
        body["csrf"] = "invented-wrong"
        assert (
            browser.post(
                "/connections/gmail/quarantine", data=body, headers={"origin": ORIGIN}
            ).status_code
            == 403
        )
        assert module._USED[cap] is False

    run(f, plan, action)
    assert sum(e[0] == "query" for e in events) == 1
    assert all((f.authority._directory / name).read_bytes() == raw for name, raw in files.items())


def test_actual_collection_replay_after_publication_cannot_authorize_again(tmp_path, monkeypatch):
    import zacai.connectors.gmail_recovery_native_absence as module

    f, rows, files = failed_v2(tmp_path, monkeypatch)
    events = []
    monkeypatch.setattr(module, "_AbsenceBindings", lambda: AbsenceBindings(f, events))
    plan = f.recovery_plan(
        monkeypatch,
        action_generation="invented-v4-replay",
        recovery_profile="terminal_native_absence_v4",
    )

    def action(browser):
        sign_in(browser)
        assert (
            browser.post(
                "/connections/gmail/recover/pair", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 303
        )
        history = plan._consumer._history
        assert (
            browser.post(
                "/connections/gmail/quarantine", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 303
        )
        with pytest.raises(ValueError):
            module.consume_capabilities(history)
        cap = module._HISTORY_CAPABILITIES[history][1][0]
        with pytest.raises(ValueError):
            cap.consume_once()

    run(f, plan, action)
    assert sum(e[0] == "query" for e in events) == 2
    with f.authority._locked():
        assert f.authority._read()["rows"] == rows
    assert all((f.authority._directory / name).read_bytes() == raw for name, raw in files.items())


def test_late_duplicate_native_add_holds_without_overwrite_or_old_item_adoption(
    tmp_path, monkeypatch
):
    import zacai.connectors.gmail_recovery_native_absence as module

    f, rows, files = failed_v2(tmp_path, monkeypatch)
    events = []
    monkeypatch.setattr(module, "_AbsenceBindings", lambda: AbsenceBindings(f, events))
    collision = b"invented unrelated native item"
    f.bindings.data = collision

    def duplicate(keychain, access, service, account, data):
        f.bindings.record("add", keychain, access, service, account)
        assert f.bindings.data == collision
        return -25299  # exact native duplicate; never adopt or replace

    monkeypatch.setattr(f.bindings, "add", duplicate)
    plan = f.recovery_plan(
        monkeypatch,
        action_generation="invented-v4-native-collision",
        recovery_profile="terminal_native_absence_v4",
    )

    def action(browser):
        state = begin(browser)
        response = browser.get(
            "/connections/gmail/callback", params={"state": state, "code": "invented"}
        )
        assert response.status_code == 403

    run(f, plan, action)
    assert f.bindings.data == collision
    assert sum(e[0] == "query" for e in events) == 2
    assert any(e[0] == "add" for e in f.bindings.events)
    assert not any(e[0] == "readback" for e in f.bindings.events)
    with f.authority._locked():
        after = f.authority._read()["rows"]
    assert all(after[s] == row for s, row in rows.items())
    added = set(after) - set(rows)
    assert len(added) == 1 and after[next(iter(added))]["state"] == "held"
    assert after[next(iter(added))]["loaded"] is True
    assert all(
        (f.authority._directory / name).read_bytes() == raw
        for name, raw in files.items()
        if name != f.authority._path.name
    )


def test_failed_new_journal_publication_keeps_capability_spent_and_no_fresh_state(
    tmp_path, monkeypatch
):
    import os

    import zacai.connectors.gmail_recovery_native_absence as module

    f, rows, files = failed_v2(tmp_path, monkeypatch)
    events = []
    monkeypatch.setattr(module, "_AbsenceBindings", lambda: AbsenceBindings(f, events))
    plan = f.recovery_plan(
        monkeypatch,
        action_generation="invented-v4-publication-failure",
        recovery_profile="terminal_native_absence_v4",
    )

    def action(browser):
        sign_in(browser)
        assert (
            browser.post(
                "/connections/gmail/recover/pair", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 303
        )
        history = plan._consumer._history
        cap = module._HISTORY_CAPABILITIES[history][1][0]
        original = os.link

        def failing_link(src, dst, *args, **kwargs):
            if str(dst).endswith(plan._consumer._journal_name):
                raise ValueError("invented publication unavailable")
            return original(src, dst, *args, **kwargs)

        monkeypatch.setattr(os, "link", failing_link)
        assert (
            browser.post(
                "/connections/gmail/quarantine", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 403
        )
        assert module._USED[cap] is True
        with pytest.raises(ValueError):
            cap.consume_once()

    run(f, plan, action)
    assert sum(e[0] == "query" for e in events) == 2
    with f.authority._locked():
        assert f.authority._read()["rows"] == rows
    assert all((f.authority._directory / name).read_bytes() == raw for name, raw in files.items())


def test_concurrent_current_workers_have_one_requery_winner(tmp_path, monkeypatch):
    import threading

    import zacai.connectors.gmail_recovery_native_absence as module

    f, rows, _files = failed_v2(tmp_path, monkeypatch)
    events = []
    factories = []
    entered = threading.Event()
    release = threading.Event()

    class BlockingBindings(AbsenceBindings):
        def require_absent(self, *args):
            status = super().require_absent(*args)
            if len(factories) == 2:
                entered.set()
                assert release.wait(5)
            return status

    def factory():
        factories.append(True)
        return BlockingBindings(f, events)

    monkeypatch.setattr(module, "_AbsenceBindings", factory)
    plan = f.recovery_plan(
        monkeypatch,
        action_generation="invented-v4-concurrent",
        recovery_profile="terminal_native_absence_v4",
    )
    responses = []
    errors = []

    def action(browser):
        sign_in(browser)
        assert (
            browser.post(
                "/connections/gmail/recover/pair", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 303
        )
        body = form(browser)

        def post():
            try:
                responses.append(
                    browser.post(
                        "/connections/gmail/quarantine", data=body, headers={"origin": ORIGIN}
                    ).status_code
                )
            except BaseException as error:  # noqa: BLE001 - collect physical worker cancellation
                errors.append(type(error))

        first = threading.Thread(target=post)
        second = threading.Thread(target=post)
        first.start()
        assert entered.wait(5)
        second.start()
        release.set()
        first.join(10)
        second.join(10)
        assert not first.is_alive() and not second.is_alive()
        assert not errors and sorted(responses) == [303, 403]

    run(f, plan, action)
    assert len(factories) == 2
    with f.authority._locked():
        assert f.authority._read()["rows"] == rows


def test_pending_inspection_cannot_be_consumed_from_factory_callback(tmp_path, monkeypatch):
    import zacai.connectors.gmail_recovery_native_absence as module

    f, _rows, _files = failed_v2(tmp_path, monkeypatch)
    events = []
    attempted = []

    def factory():
        pending = [c for c in module._CAPABILITIES if module._ISSUED.get(c) is False]
        assert len(pending) == 1
        cap = pending[0]
        with pytest.raises(ValueError):
            cap.consume_once()
        assert module._USED[cap] is False
        attempted.append(True)
        return AbsenceBindings(f, events)

    monkeypatch.setattr(module, "_AbsenceBindings", factory)
    plan = f.recovery_plan(monkeypatch, action_generation="invented-v4-pending",
                           recovery_profile="terminal_native_absence_v4")

    def action(browser):
        sign_in(browser)
        assert browser.post("/connections/gmail/recover/pair", data=form(browser),
                            headers={"origin": ORIGIN}).status_code == 303
        cap = module._HISTORY_CAPABILITIES[plan._consumer._history][1][0]
        assert module._ISSUED[cap] is True

    run(f, plan, action)
    assert attempted == [True]
    assert sum(e[0] == "query" for e in events) == 1


def test_new_source_path_denies_capability_before_second_factory(tmp_path, monkeypatch):
    from pathlib import Path

    import zacai.connectors.gmail_recovery_native_absence as module

    f, _rows, _files = failed_v2(tmp_path, monkeypatch)
    events = []
    monkeypatch.setattr(module, "_AbsenceBindings", lambda: AbsenceBindings(f, events))
    plan = f.recovery_plan(monkeypatch, action_generation="invented-v4-source-added",
                           recovery_profile="terminal_native_absence_v4")
    added = Path(module.__file__).resolve().parents[2] / "invented_source_addition.py"
    assert not added.exists()

    def action(browser):
        sign_in(browser)
        assert browser.post("/connections/gmail/recover/pair", data=form(browser),
                            headers={"origin": ORIGIN}).status_code == 303
        body = form(browser)
        added.write_text("# invented disposable addition\n")
        try:
            assert browser.post("/connections/gmail/quarantine", data=body,
                                headers={"origin": ORIGIN}).status_code == 403
        finally:
            added.unlink()

    run(f, plan, action)
    assert sum(e[0] == "query" for e in events) == 1


@pytest.mark.parametrize("field", ["review_action_generation", "hr_binding", "original_binding", "observed_at"])
def test_new_observation_correlates_to_containing_authenticated_record(field):
    from datetime import UTC, datetime
    from types import SimpleNamespace

    from zacai.connectors.gmail_recovery_native_absence import (
        native_generation,
        recorded_observations,
    )

    digest = "a" * 64
    observed = {
        "epoch_generation": "old-epoch", "state": digest, "row_sha256": digest,
        "native_generation": native_generation(digest), "configuration": digest,
        "account": digest, "review_action_generation": "review", "hr_binding": digest,
        "original_binding": digest, "issuer": "https://accounts.google.com", "subject": "saved-owner",
        "observed_at": "2026-10-11T12:00:00+00:00", "keychain_namespace_sha256": digest,
        "source_graph_sha256": digest, "native_status": "errSecItemNotFound", "remote_grant_outcome": "UNKNOWN",
    }
    record = SimpleNamespace(review_generation_claim="review", reviewer_binding_claim=digest,
                             reviewer_issuer_hint=observed["issuer"], reviewer_subject_hint=observed["subject"],
                             reviewed_at_claim=datetime(2026, 10, 11, 12, 1, tzinfo=UTC))
    spend = {"hr_binding": digest, "original_binding": digest}
    recorded_observations({"native_absence_observations": [observed]}, record, spend, [])
    wrong = dict(observed)
    wrong[field] = "other-review" if field == "review_action_generation" else (
        "2026-10-11T12:02:00+00:00" if field == "observed_at" else "b" * 64)
    with pytest.raises(ValueError):
        recorded_observations({"native_absence_observations": [wrong]}, record, spend, [])
    # Already authenticated inherited metadata is immutable history, not new-session equality.
    recorded_observations({"native_absence_observations": [observed]},
                          SimpleNamespace(), {}, [observed])


def test_same_inode_symlink_cannot_replace_canonical_source_path(tmp_path, monkeypatch):
    import os

    import zacai.connectors.gmail_recovery_native_absence as module

    source = tmp_path / "public-src"
    module_dir = source / "zacai" / "connectors"
    module_dir.mkdir(parents=True)
    monkeypatch.setattr(module, "__file__", str(module_dir / "gmail_recovery_native_absence.py"))
    original = source / "public_fixture.py"
    original.write_text("# invented public source fixture\n")
    _digest, witness = module._source_graph()
    backup = tmp_path / "original-inode.py"
    os.link(original, backup)
    original.unlink()
    original.symlink_to(backup)
    assert original.stat().st_ino == witness[0][2]
    assert tuple(sorted(source.rglob("*.py"))) == tuple(row[0] for row in witness)
    with pytest.raises(ValueError):
        module._source_names(witness)


def test_callback_selector_alias_mutation_cannot_query_another_native_item(tmp_path, monkeypatch):
    import zacai.connectors.gmail_recovery_native_absence as module

    f, _rows, _files = failed_v2(tmp_path, monkeypatch)
    events = []

    class SelectorBindings(AbsenceBindings):
        def keychain_path(self, ref):
            monkeypatch.setattr(module, "_SERVICE", "foreign-selector-", raising=False)
            monkeypatch.setattr(module, "_ACCOUNT", "foreign-account", raising=False)
            return super().keychain_path(ref)

        def require_absent(self, ref, service, account):
            assert service.startswith("zacai-brainstorm-gmail-stage-")
            assert account == "zac-owner-source-access"
            return super().require_absent(ref, service, account)

    monkeypatch.setattr(module, "_AbsenceBindings", lambda: SelectorBindings(f, events))
    plan = f.recovery_plan(monkeypatch, action_generation="invented-v4-fixed-selector",
                           recovery_profile="terminal_native_absence_v4")

    def action(browser):
        sign_in(browser)
        assert browser.post("/connections/gmail/recover/pair", data=form(browser),
                            headers={"origin": ORIGIN}).status_code == 303
        cap = module._HISTORY_CAPABILITIES[plan._consumer._history][1][0]
        query = next(event for event in events if event[0] == "query")
        assert query[1:] == ("zacai-brainstorm-gmail-stage-" + cap._native, "zac-owner-source-access")

    run(f, plan, action)
    assert sum(e[0] == "query" for e in events) == 1


@pytest.mark.parametrize("name", ["_json", "native_generation", "_file", "_path_witness", "_source_names", "validate_observations", "_stage"])
def test_native_callback_cannot_rebind_semantic_helper_before_query(tmp_path, monkeypatch, name):
    import zacai.connectors.gmail_recovery_native_absence as module

    f, rows, files = failed_v2(tmp_path, monkeypatch)
    events, foreign = [], []

    def replaced(*args, **kwargs):
        foreign.append(name)
        raise AssertionError("replacement semantic helper must not execute")

    class MutatingBindings(AbsenceBindings):
        def keychain_path(self, ref):
            monkeypatch.setattr(module, name, replaced)
            return super().keychain_path(ref)

    monkeypatch.setattr(module, "_AbsenceBindings", lambda: MutatingBindings(f, events))
    plan = f.recovery_plan(monkeypatch, action_generation="invented-v4-helper-change",
                           recovery_profile="terminal_native_absence_v4")

    def action(browser):
        sign_in(browser)
        assert browser.post("/connections/gmail/recover/pair", data=form(browser),
                            headers={"origin": ORIGIN}).status_code == 403

    run(f, plan, action)
    assert not foreign and not any(event[0] == "query" for event in events)
    assert [event[0] for event in events] == ["open", "release"]
    with f.authority._locked():
        assert f.authority._read()["rows"] == rows
    assert all((f.authority._directory / name).read_bytes() == raw for name, raw in files.items())


@pytest.mark.parametrize("method", ["action", "inspection_inner"])
def test_native_callback_in_place_owner_method_code_change_denied_before_query(tmp_path, monkeypatch, method):
    import zacai.connectors.gmail_recovery_native_absence as module

    f, rows, files = failed_v2(tmp_path, monkeypatch)
    events, replacements = [], []
    original = (module.GmailRecoveryAction.current if method == "action" else
                module.HeldGmailReconciliation.inspect_historical_recovery.__wrapped__)
    original_code = original.__code__

    def replacement(self):
        raise AssertionError("altered owner method must never execute")

    class MutatingBindings(AbsenceBindings):
        def keychain_path(self, ref):
            original.__code__ = replacement.__code__
            replacements.append(True)
            return super().keychain_path(ref)

    monkeypatch.setattr(module, "_AbsenceBindings", lambda: MutatingBindings(f, events))
    plan = f.recovery_plan(monkeypatch, action_generation="invented-v4-owner-code-change",
                           recovery_profile="terminal_native_absence_v4")

    def action(browser):
        sign_in(browser)
        try:
            assert browser.post("/connections/gmail/recover/pair", data=form(browser),
                                headers={"origin": ORIGIN}).status_code == 403
        finally:
            original.__code__ = original_code

    try:
        run(f, plan, action)
    finally:
        original.__code__ = original_code
    assert replacements == [True]
    assert [event[0] for event in events] == ["open", "release"]
    with f.authority._locked():
        assert f.authority._read()["rows"] == rows
    assert all((f.authority._directory / name).read_bytes() == raw for name, raw in files.items())
