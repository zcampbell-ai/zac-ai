"""Actual disposable operator lease and Gmail assembly, invented host inputs only."""

from __future__ import annotations

import errno
import fcntl
import os

import pytest
from fastapi.testclient import TestClient

from tests.test_gmail_connection_web import Fixture as GmailFixture
from tests.test_private_host import CONFIG, ORIGIN, InventedIdentity, sign_in
from zacai.connectors.oauth_transactions import OAuthTransactionAuthority
from zacai.interfaces.gmail_connection_web import GmailConnectionWeb
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.private_operator import (
    PrivateOperatorError,
    PrivateOperatorMode,
    open_private_operator,
)


def lease_is_held(directory):
    fd = os.open(directory / "private-mode.lock", os.O_RDWR)
    try:
        with pytest.raises(BlockingIOError) as raised:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert raised.value.errno in {errno.EAGAIN, errno.EWOULDBLOCK}
    finally:
        os.close(fd)


def arguments(f, loader):
    async def view(principal):
        return "<main>Invented owner page</main>"

    return {
        "mode": PrivateOperatorMode.OWNER,
        "client_id": CONFIG.client_id,
        "origin": ORIGIN,
        "directory": f.directory,
        "escrow_confirmed_by_operator": True,
        "view": view,
        "startup_loader": loader,
        "clock": f.clock,
        "identities": InventedIdentity(f.clock),
    }


def test_retained_actual_lease_precedes_loader_and_gmail_factory(tmp_path):
    f = GmailFixture(tmp_path)
    events = []

    def loader(**kwargs):
        lease_is_held(f.directory)
        events.append("loader")
        return CONFIG

    def factory(inputs):
        lease_is_held(f.directory)
        events.append("factory")
        assert inputs.directory == f.directory and inputs.clock is f.clock
        continuity = NamedSessionContinuity(
            sessions=inputs.sessions,
            owner=inputs.owner,
            clock=inputs.clock,
            key=inputs.session_key,
            origin=inputs.origin,
            client_id=inputs.client_id,
        )
        authority = OAuthTransactionAuthority(
            inputs.directory / "operator-gmail",
            key=inputs.session_key,
            continuity=continuity,
            registration_backend=f.registration,
        )
        authority.initialize()
        return GmailConnectionWeb(
            configuration=f.configuration,
            authority=authority,
            client_secret_loader=f.load,
            transport=f.transport,
            stage_checked=f.stage,
            host_guard=f.guard,
            stop_host=f.stop,
        )

    with open_private_operator(**arguments(f, loader), gmail_factory=factory) as window:

        def probe(app):
            with TestClient(app, base_url=ORIGIN, follow_redirects=False) as browser:
                sign_in(browser)
                assert browser.get("/connections/gmail").status_code == 200

        window.serve(server=probe)
        lease_is_held(f.directory)
        assert events == ["loader", "factory"]
        inode = (f.directory / "private-mode.lock").stat().st_ino
    fd = os.open(f.directory / "private-mode.lock", os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert (f.directory / "private-mode.lock").stat().st_ino == inode
    finally:
        os.close(fd)
    assert not f.requests and f.loads == 0


def test_default_operator_owner_mounts_no_gmail_routes(tmp_path):
    f = GmailFixture(tmp_path)
    with open_private_operator(**arguments(f, lambda **kwargs: CONFIG)) as window:

        def probe(app):
            with TestClient(app, base_url=ORIGIN, follow_redirects=False) as browser:
                sign_in(browser)
                assert browser.get("/connections/gmail").status_code == 404
                assert browser.post("/connections/gmail/begin").status_code == 404
                assert browser.get("/connections/gmail/callback").status_code == 404

        window.serve(server=probe)
    assert not f.requests and f.loads == 0


@pytest.mark.parametrize(
    "mode,factory",
    [
        (PrivateOperatorMode.ENROLLMENT, lambda inputs: None),
        (PrivateOperatorMode.PERSONAL_ENROLLMENT, lambda inputs: None),
        (PrivateOperatorMode.OWNER, 1),
    ],
)
def test_invalid_or_enrollment_gmail_factory_denies_before_lease_and_startup(
    tmp_path, mode, factory
):
    directory = tmp_path / "not-created"
    calls = []

    async def view(principal):
        return "<main>Invented</main>"

    arguments = {
        "mode": mode,
        "client_id": CONFIG.client_id,
        "origin": ORIGIN,
        "directory": directory,
        "escrow_confirmed_by_operator": True,
        "gmail_factory": factory,
        "startup_loader": lambda **kwargs: calls.append("loader"),
    }
    if mode is PrivateOperatorMode.OWNER:
        arguments["view"] = view
    with pytest.raises(PrivateOperatorError) as raised, open_private_operator(**arguments):
        pass
    assert not calls and not directory.exists()
    assert raised.value.__context__ is None and raised.value.__cause__ is None


def test_gmail_operator_requires_original_observed_clock_before_startup(tmp_path):
    from tests.test_private_host import NOW

    calls = []
    directory = tmp_path / "not-created-clock"

    async def view(principal):
        return "<main>Invented</main>"

    with (
        pytest.raises(PrivateOperatorError),
        open_private_operator(
            mode=PrivateOperatorMode.OWNER,
            client_id=CONFIG.client_id,
            origin=ORIGIN,
            directory=directory,
            escrow_confirmed_by_operator=True,
            view=view,
            clock=lambda: NOW,
            gmail_factory=lambda inputs: calls.append("factory"),
            startup_loader=lambda **kwargs: calls.append("loader"),
        ),
    ):
        pass
    assert calls == [] and not directory.exists()
