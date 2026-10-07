"""Invented foreground quarantine journal; no native/provider/live storage calls."""

from __future__ import annotations

import re
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from tests.gmail_preservation_fixture import Fixture as PreservationFixture
from tests.test_private_host import CONFIG, ORIGIN
from zacai.connectors.gmail_quarantine_journal import (
    GmailQuarantineIntentReceipt,
    GmailQuarantineJournal,
)
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.interfaces.gmail_quarantine_host import (
    GmailQuarantineHostError,
    GmailQuarantineHostFatal,
)

PATH = "/connections/gmail/quarantine"
ACTION = "invented-quarantine-review-v1"


class Fixture(PreservationFixture):
    def seed(self, monkeypatch):
        super().seed(monkeypatch)
        halt = self.directory / "gmail-oauth-guard" / "oauth-host.halted"
        halt.write_bytes(b"zac-oauth-host-halted-v1\n")
        halt.chmod(0o600)

    def quarantine_plan(self, monkeypatch, **changes):
        from zacai.interfaces.gmail_quarantine_host import GmailQuarantineHostPlan

        values = {
            "configuration": self.configuration,
            "owner_client_id": CONFIG.client_id,
            "directory": self.directory,
            "startup_loader": self.startup,
            "clock": self.clock,
            "escrow_confirmed_by_operator": True,
            "action_generation": ACTION,
        }
        values.update(changes)
        plan = GmailQuarantineHostPlan(**values)
        monkeypatch.setattr(plan._server, "_factory", self.server_factory)
        return plan


def fields(browser, f):
    browser.cookies.set("__Host-zac-session", f.cookie)
    page = browser.get(PATH)
    assert page.status_code == 200
    return dict(re.findall(r'name="([^"]+)" value="([^"]+)"', page.text))


def test_inert_exact_foreground_journal_preserves_original_hold_and_no_source_routes(
    tmp_path, monkeypatch
):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    original = f.operational_snapshot()
    plan = f.quarantine_plan(monkeypatch)
    assert f.operational_snapshot() == original and not f.shared_reads
    assert not f.server_runs and not f.provider_calls

    def forbidden(*args, **kwargs):
        raise AssertionError("Original transaction mutation forbidden")

    for method in ("_write", "_persist", "_now", "initialize", "begin", "consume_callback"):
        monkeypatch.setattr(OAuthTransactionAuthority, method, forbidden)

    def browse(browser):
        f.held_lease()
        form = fields(browser, f)
        assert set(form) == {"csrf", "reviewed_configuration_digest", "action_generation"}
        assert form["reviewed_configuration_digest"] == f.configuration.configuration_digest
        assert form["action_generation"] == ACTION
        assert plan._preview is plan._original_preview is not None
        private = (
            plan._preview._reference.generation,
            plan._preview._reference._state_hash,
            f.cookie,
            str(f.directory),
            f.configuration.gmail_mailbox,
        )
        page = browser.get(PATH)
        assert page.headers["cache-control"] == "no-store"
        assert all(value not in page.text for value in private)
        for method, path in (
            ("get", "/connections/gmail"),
            ("post", "/connections/gmail/begin"),
            ("get", "/connections/gmail/callback"),
            ("post", "/connections/gmail/install"),
            ("get", "/connections/gmail/native-review"),
            ("get", "/enroll"),
        ):
            assert getattr(browser, method)(path).status_code == 404
        response = browser.post(PATH, data=form, headers={"origin": ORIGIN})
        assert response.status_code == 200
        assert response.json()["recorded_only"] is True
        assert all(
            response.json()[name] is False
            for name in (
                "quarantine_committed",
                "quarantine_authorized",
                "recovery_authorized",
                "installed",
                "credential_authority",
                "processing_authorized",
                "execution_authorized",
            )
        )
        assert all(value not in response.text for value in private)
        assert not plan._admitted() and plan._post_spent
        assert browser.post(PATH, data=form, headers={"origin": ORIGIN}).status_code == 403
        f.held_lease()
        f.no_gmail_io()

    f.browser_action = browse
    plan.run()
    assert f.operational_snapshot().keys() == original.keys() | {
        f.directory / "gmail-oauth-transactions" / "gmail-quarantine-intent.bin"
    }
    for path, witness in original.items():
        assert f.operational_snapshot()[path] == witness
    journal = f.directory / "gmail-oauth-transactions" / "gmail-quarantine-intent.bin"
    raw = journal.read_bytes()
    assert len(raw) > 29 and ACTION.encode() not in raw and f.cookie.encode() not in raw
    assert not (journal.parent / ".gmail-quarantine-intent.stage").exists()
    assert f.shared_reads == [
        "zacai-shared-owner-google-client-secret",
        "zacai-shared-owner-session-key",
    ]
    assert plan._journal is plan._original_journal is None
    assert plan._preview is plan._original_preview is None and plan._captured is None
    assert f.servers[0].should_exit
    before = (f.server_runs, list(f.shared_reads), journal.read_bytes())
    with pytest.raises(GmailQuarantineHostError):
        plan.run()
    assert before == (f.server_runs, f.shared_reads, journal.read_bytes())
    f.no_gmail_io()


@pytest.mark.parametrize(
    "name", ["gmail-quarantine-intent.bin", ".gmail-quarantine-intent.stage", "unknown-child"]
)
def test_preexisting_journal_or_other_child_denies_before_startup(tmp_path, monkeypatch, name):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    extra = f.directory / "gmail-oauth-transactions" / name
    extra.write_bytes(b"invented-residue")
    extra.chmod(0o600)
    plan = f.quarantine_plan(monkeypatch)
    with pytest.raises(GmailQuarantineHostError):
        plan.run()
    assert not f.shared_reads and not f.server_runs
    assert extra.read_bytes() == b"invented-residue"
    f.no_gmail_io()


@pytest.mark.parametrize("stream", ["stdin", "stdout", "stderr"])
def test_three_actual_ttys_and_one_run_admission_precede_shared_reads(
    tmp_path, monkeypatch, stream
):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.quarantine_plan(monkeypatch)
    monkeypatch.setattr(getattr(sys, stream), "isatty", lambda: False)
    with pytest.raises(GmailQuarantineHostError):
        plan.run()
    monkeypatch.setattr(getattr(sys, stream), "isatty", lambda: True)
    with pytest.raises(GmailQuarantineHostError):
        plan.run()
    assert not f.shared_reads and not f.server_runs


def test_worker_bootstrap_denied_without_reads(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.quarantine_plan(monkeypatch)
    with ThreadPoolExecutor(max_workers=1) as pool, pytest.raises(GmailQuarantineHostError):
        pool.submit(plan.run).result()
    assert not f.shared_reads and not f.server_runs


@pytest.mark.parametrize("change", ["csrf", "reviewed_configuration_digest", "action_generation"])
def test_bad_reviewed_form_spends_post_stops_without_journal(tmp_path, monkeypatch, change):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.quarantine_plan(monkeypatch)

    def browse(browser):
        form = fields(browser, f)
        form[change] = "invented-wrong"
        with pytest.raises((GmailQuarantineHostFatal, BaseExceptionGroup)):
            browser.post(PATH, data=form, headers={"origin": ORIGIN})
        assert plan._post_spent and not plan._admitted()
        assert browser.get("/login").status_code == 403
        f.held_lease()

    f.browser_action = browse
    with pytest.raises(GmailQuarantineHostFatal):
        plan.run()
    assert not (f.directory / "gmail-oauth-transactions" / "gmail-quarantine-intent.bin").exists()
    assert f.servers[0].should_exit
    f.no_gmail_io()


@pytest.mark.parametrize("body", [b"x" * 513, b""])
def test_bounded_body_no_journal(tmp_path, monkeypatch, body):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.quarantine_plan(monkeypatch)

    def browse(browser):
        fields(browser, f)
        if len(body) > 512:
            response = browser.post(
                PATH,
                content=body,
                headers={"origin": ORIGIN, "content-type": "application/x-www-form-urlencoded"},
            )
            assert response.status_code == 403 and not plan._post_spent
        else:
            with pytest.raises((GmailQuarantineHostFatal, BaseExceptionGroup)):
                browser.post(
                    PATH,
                    content=body,
                    headers={"origin": ORIGIN, "content-type": "application/x-www-form-urlencoded"},
                )

    f.browser_action = browse
    if body:
        plan.run()
    else:
        with pytest.raises(GmailQuarantineHostFatal):
            plan.run()
    assert not (f.directory / "gmail-oauth-transactions" / "gmail-quarantine-intent.bin").exists()
    f.no_gmail_io()


@pytest.mark.parametrize("replacement", [None, object(), GmailQuarantineIntentReceipt])
def test_only_actual_fixed_writer_receipt_can_acknowledge(tmp_path, monkeypatch, replacement):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.quarantine_plan(monkeypatch)
    monkeypatch.setattr(GmailQuarantineJournal, "write_once", lambda *args, **kwargs: replacement)

    def browse(browser):
        form = fields(browser, f)
        with pytest.raises((GmailQuarantineHostFatal, BaseExceptionGroup)):
            browser.post(PATH, data=form, headers={"origin": ORIGIN})
        assert not plan._admitted()

    f.browser_action = browse
    with pytest.raises(GmailQuarantineHostFatal):
        plan.run()
    assert f.servers[0].should_exit


def test_posix_directory_link_convention_accepts_only_owned_names(tmp_path, monkeypatch):
    import os

    import zacai.connectors.gmail_quarantine_journal as journal_module

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    directory = f.directory / "gmail-oauth-transactions"
    baseline_links = directory.stat().st_nlink
    original_guard = journal_module._guard

    def posix_guard(path, **kwargs):
        observed = original_guard(path, **kwargs)
        if path == directory and kwargs.get("directory"):
            fields = list(observed)
            fields[3] = baseline_links
            return os.stat_result(fields)
        return observed

    monkeypatch.setattr(journal_module, "_guard", posix_guard)
    plan = f.quarantine_plan(monkeypatch)

    def browse(browser):
        form = fields(browser, f)
        response = browser.post(PATH, data=form, headers={"origin": ORIGIN})
        assert response.status_code == 200
        assert response.json()["recorded_only"] is True

    f.browser_action = browse
    plan.run()
    assert (directory / "gmail-quarantine-intent.bin").is_file()
    assert not (directory / ".gmail-quarantine-intent.stage").exists()
    f.no_gmail_io()


@pytest.mark.parametrize("change", ["unknown_child", "unexplained_links", "non_none_validator"])
def test_after_preview_namespace_change_is_fatal_before_journal_write(
    tmp_path, monkeypatch, change
):
    import os

    import zacai.connectors.gmail_quarantine_journal as journal_module

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    directory = f.directory / "gmail-oauth-transactions"
    plan = f.quarantine_plan(monkeypatch)

    def browse(browser):
        form = fields(browser, f)
        if change == "unknown_child":
            extra = directory / "unknown-child"
            extra.write_bytes(b"invented-other-child")
            extra.chmod(0o600)
        elif change == "unexplained_links":
            original_guard = journal_module._guard

            def changed_guard(path, **kwargs):
                observed = original_guard(path, **kwargs)
                if path == directory and kwargs.get("directory"):
                    fields = list(observed)
                    fields[3] += 7
                    return os.stat_result(fields)
                return observed

            monkeypatch.setattr(journal_module, "_guard", changed_guard)
        else:
            monkeypatch.setattr(GmailQuarantineJournal, "namespace_current", lambda self: True)
        with pytest.raises(GmailQuarantineHostFatal):
            browser.post(PATH, data=form, headers={"origin": ORIGIN})
        assert plan._fatal and not plan._admitted()
        assert f.servers[-1].should_exit
        assert not (directory / "gmail-quarantine-intent.bin").exists()
        assert not (directory / ".gmail-quarantine-intent.stage").exists()
        f.held_lease()

    f.browser_action = browse
    with pytest.raises(GmailQuarantineHostFatal):
        plan.run()
    assert plan._journal is None and plan._captured is None
    f.no_gmail_io()


@pytest.mark.parametrize("change", ["missing_halt", "forged_halt", "forged_ready"])
def test_required_authenticated_existing_markers_deny_before_serving(tmp_path, monkeypatch, change):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    path = (
        f.directory
        / "gmail-oauth-guard"
        / ("oauth-host.ready" if change == "forged_ready" else "oauth-host.halted")
    )
    if change == "missing_halt":
        path.unlink()
    else:
        path.write_bytes(b"invented-forged-marker")
    original = f.operational_snapshot()
    plan = f.quarantine_plan(monkeypatch)
    with pytest.raises(GmailQuarantineHostError):
        plan.run()
    assert not f.server_runs and not f.servers
    assert not plan._admitted() and plan._journal is None and plan._captured is None
    assert f.operational_snapshot() == original
    assert not (f.directory / "gmail-oauth-transactions/gmail-quarantine-intent.bin").exists()
    assert not (f.directory / "gmail-oauth-transactions/.gmail-quarantine-intent.stage").exists()
    if change == "missing_halt":
        assert not f.shared_reads
    else:
        assert len(f.shared_reads) == 2
    f.no_gmail_io()


def test_action_generation_grammar_matches_journal_before_startup(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    with pytest.raises(GmailQuarantineHostError):
        f.quarantine_plan(monkeypatch, action_generation="invalid:action")
    assert not f.shared_reads and not f.server_runs


def test_marker_access_time_changes_do_not_weaken_modification_witness(tmp_path, monkeypatch):
    import os

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    for name in ("oauth-host.ready", "oauth-host.halted"):
        path = f.directory / "gmail-oauth-guard" / name
        info = path.stat()
        os.utime(path, ns=(0, info.st_mtime_ns))
    plan = f.quarantine_plan(monkeypatch)

    def browse(browser):
        form = fields(browser, f)
        assert browser.post(PATH, data=form, headers={"origin": ORIGIN}).status_code == 200

    f.browser_action = browse
    plan.run()
    assert not plan._fatal
    f.no_gmail_io()


def test_concurrent_get_waits_through_owned_publication_without_false_fatal(tmp_path, monkeypatch):
    import asyncio
    import threading
    from urllib.parse import urlencode, urlsplit

    import anyio
    from starlette.requests import Request

    import zacai.connectors.gmail_quarantine_journal as journal_module

    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.quarantine_plan(monkeypatch)
    entered, release = threading.Event(), threading.Event()
    actual_link = journal_module.os.link

    def blocked_publication(*args, **kwargs):
        actual_link(*args, **kwargs)
        entered.set()
        assert release.wait(3)

    monkeypatch.setattr(journal_module.os, "link", blocked_publication)

    def browse(browser):
        form = fields(browser, f)
        routes = {
            method: route.endpoint
            for route in f.servers[-1].app.routes
            if route.path == PATH
            for method in route.methods
        }

        def request(method):
            body = urlencode(form).encode() if method == "POST" else b""

            async def receive():
                return {"type": "http.request", "body": body, "more_body": False}

            return Request(
                {
                    "type": "http",
                    "method": method,
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

        async def simultaneous():
            post = asyncio.create_task(routes["POST"](request("POST")))
            assert await asyncio.to_thread(entered.wait, 3)
            get = asyncio.create_task(routes["GET"](request("GET")))
            try:
                await asyncio.sleep(0.02)
                assert not get.done() and not plan._fatal
                f.held_lease()
            finally:
                release.set()
            post_response, get_response = await asyncio.gather(post, get)
            assert post_response.status_code == 200 and get_response.status_code == 403
            assert not plan._fatal

        anyio.run(simultaneous)

    f.browser_action = browse
    plan.run()
    assert entered.is_set() and not plan._fatal
    f.no_gmail_io()


def test_unknown_child_before_first_preview_cannot_be_normalized(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    f.seed(monkeypatch)
    plan = f.quarantine_plan(monkeypatch)

    def browse(browser):
        browser.cookies.set("__Host-zac-session", f.cookie)
        extra = f.directory / "gmail-oauth-transactions" / "unknown-before-preview"
        extra.write_bytes(b"invented-unowned-child")
        extra.chmod(0o600)
        with pytest.raises(GmailQuarantineHostFatal):
            browser.get(PATH)
        assert plan._fatal and not plan._admitted() and plan._preview is None
        assert f.servers[-1].should_exit
        assert not (extra.parent / "gmail-quarantine-intent.bin").exists()
        f.held_lease()

    f.browser_action = browse
    with pytest.raises(GmailQuarantineHostFatal):
        plan.run()
    f.no_gmail_io()
