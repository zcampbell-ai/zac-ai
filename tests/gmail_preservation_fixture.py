"""Invented preservation fixture only; no test cases or native review implementation."""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlsplit

from tests.test_gmail_setup import Fixture as SetupFixture
from tests.test_private_host import ORIGIN, sign_in


class Fixture(SetupFixture):
    def seed(self, monkeypatch):
        self.cookie = None

        def browse(browser):
            self.cookie = sign_in(browser)
            page = browser.get("/connections/gmail")
            fields = dict(re.findall(r'name="([^"]+)" value="([^"]+)"', page.text))
            consent = browser.post(
                "/connections/gmail/begin", data=fields, headers={"origin": ORIGIN}
            )
            assert consent.status_code == 303
            state = parse_qs(urlsplit(consent.headers["location"]).query)["state"][0]
            callback = browser.get(
                "/connections/gmail/callback", params={"state": state, "code": "invented-code"}
            )
            assert callback.status_code == 303

        self.browser_action = browse
        self.plan(monkeypatch).run()
        self.owner_loads = self.server_runs = 0
        self.shared_reads.clear()
        self.secret_reads.clear()
        self.provider_calls.clear()
        self.native_factories.clear()
        self.servers.clear()
        self.bindings.events.clear()
        self.browser_action = None

    def operational_snapshot(self):
        return {
            p: (p.stat().st_ino, p.stat().st_mode, p.read_bytes())
            for name in ("gmail-oauth-guard", "gmail-oauth-transactions")
            for p in (self.directory / name).iterdir()
        }

    def no_gmail_io(self):
        assert (
            not self.secret_reads
            and not self.provider_calls
            and not self.native_factories
            and not self.bindings.events
        )
