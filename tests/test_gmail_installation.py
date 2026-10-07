"""Actual fresh-owner consumer and gateway; disposable native/provider inventions."""

from urllib.parse import parse_qs, urlsplit

from tests.test_gmail_native_reader import Bindings
from tests.test_gmail_recovery_host import Fixture, form
from tests.test_private_host import ORIGIN, sign_in
from zacai.connectors.gmail_held_staging import HeldGmailNativeStage
from zacai.connectors.gmail_native_reader import GmailNativeReader
from zacai.interfaces.gmail_recovery_host import GmailRecoveryHostError, GmailRecoveryHostFatal


def fixture(tmp_path, monkeypatch):
    import zacai.interfaces.gmail_recovery_host as module
    from tests.test_gmail_setup import Connection, Response
    from tests.test_oauth_exchange import ACCESS, REFRESH, SUBJECT
    from zacai.connectors.oauth_exchange import OAuthExchangeTransport

    f = Fixture(tmp_path, monkeypatch)

    class DynamicConnection(Connection):
        def request(self, method, path, body, headers):
            self.path = path
            super().request(method, path, body, headers)

        def getresponse(self):
            scope = " ".join(sorted(f.configuration.scopes))
            if self.path == "/token":
                value = {
                    "access_token": ACCESS,
                    "refresh_token": REFRESH,
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": scope,
                }
            elif self.path == "/tokeninfo":
                value = {
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
                value = {
                    "emailAddress": f.configuration.gmail_mailbox,
                    "messagesTotal": 0,
                    "threadsTotal": 0,
                    "historyId": "123",
                }
            return Response(value)

    def connect(host):
        assert host in {"oauth2.googleapis.com", "gmail.googleapis.com"}
        result = DynamicConnection(f, host, None)
        f.connections.append(result)
        return result

    f.transport = OAuthExchangeTransport(connection_factory=connect)
    stage = HeldGmailNativeStage
    monkeypatch.setattr(
        module, "HeldGmailNativeStage", lambda **kw: stage(**kw, bindings_factory=f.native_factory)
    )
    monkeypatch.setattr(module, "OAuthExchangeTransport", lambda: f.transport)
    f.reader_bindings = []

    def bindings():
        value = Bindings(f.keychain)
        value.data = f.bindings.data
        f.reader_bindings.append(value)
        return value

    monkeypatch.setattr(
        module, "GmailNativeReader", lambda **kw: GmailNativeReader(**kw, bindings_factory=bindings)
    )
    return f, f.recovery_plan(monkeypatch)


def fresh(browser):
    sign_in(browser)
    for path in ("/connections/gmail/recover/pair", "/connections/gmail/quarantine"):
        assert browser.post(path, data=form(browser), headers={"origin": ORIGIN}).status_code == 303
    reply = browser.post(
        "/connections/gmail/recover/begin", data=form(browser), headers={"origin": ORIGIN}
    )
    assert reply.status_code == 303
    state = parse_qs(urlsplit(reply.headers["location"]).query)["state"][0]
    reply = browser.get(
        "/connections/gmail/callback", params={"state": state, "code": "invented-fresh-code"}
    )
    assert reply.status_code == 200 and reply.json()["installed"] is False


def run(f, plan, action):
    errors = []
    done = []

    def browse(browser):
        try:
            action(browser)
            done.append(True)
        except BaseException as error:
            errors.append(error)
            raise

    f.browser_action = browse
    try:
        plan.run()
    except (GmailRecoveryHostError, GmailRecoveryHostFatal):
        pass
    if errors:
        raise errors[0]
    assert done == [True]
    with f.authority._locked():
        assert f.authority._read()["rows"][f.old_state] == f.old_row


def install(browser):
    response = browser.post(
        "/connections/gmail/install", data=form(browser), headers={"origin": ORIGIN}
    )
    assert response.status_code == 303


def test_actual_install_then_durable_gateway_profile_completion(tmp_path, monkeypatch):
    from zacai.connectors.gmail_installation import ACTIVE, PENDING

    f, plan = fixture(tmp_path, monkeypatch)
    observed = []

    def action(browser):
        fresh(browser)
        install(browser)
        installer = plan._consumer._installer
        assert installer._active
        assert (f.authority._directory / PENDING).is_file()
        assert (f.authority._directory / ACTIVE).is_file()
        assert (
            browser.post(
                "/connector-review", data=form(browser), headers={"origin": ORIGIN}
            ).status_code
            == 303
        )
        reply = browser.post("/connector-execute", data=form(browser), headers={"origin": ORIGIN})
        assert reply.status_code == 200
        assert reply.json() == {
            "installed": True,
            "profile_verified": True,
            "live_access_proven": True,
            "credential_authority": True,
            "processing_authorized": False,
            "execution_authorized": False,
            "source_capture_authorized": False,
            "requests": 1,
        }
        with installer._connector._locked():
            rows = installer._connector._read()["rows"]
        assert len(rows) == 1
        row = next(iter(rows.values()))
        assert (
            row["state"] == "completed"
            and row["loaded"] is True
            and row["coverage"]["requests"] == 1
        )
        observed.append(row)
        assert "Gmail connected" in browser.get("/connections/gmail/recover").text
        f.both_leases()

    run(f, plan, action)
    assert len(observed) == 1 and len(f.reader_bindings) == 2 and len(f.provider_calls) == 8
