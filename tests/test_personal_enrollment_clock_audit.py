"""Invented trusted-clock boundary: no remote attack or filesystem sandbox claim."""

import pytest
from starlette.testclient import TestClient

from tests.test_personal_owner_operator import confirm
from tests.test_personal_owner_operator import setup as setup  # noqa: PLC0414
from tests.test_private_host import NOW, ORIGIN, enroll
from tests.test_private_operator import browser_enrollment
from zacai.interfaces import private_operator as m


def test_clock_replaces_pinned_directory_before_store_creation(setup, tmp_path):
    values, calls = setup
    directory = values["directory"]
    previous = tmp_path / "existing-brainstorm"
    enroll(previous, lambda: NOW)
    originals = {
        str(p.relative_to(previous)): p.read_bytes() for p in previous.rglob("*") if p.is_file()
    }
    fired, returned = [], []

    def clock():
        if not fired:
            assert {entry.name for entry in directory.iterdir()} == {"private-mode.lock"}
            directory.rename(tmp_path / "admitted-personal-displaced")
            previous.rename(directory)
            fired.append(True)
        return NOW

    values["clock"] = clock
    held = None
    try:
        with m.open_private_operator(
            mode=m.PrivateOperatorMode.PERSONAL_ENROLLMENT, **values
        ) as window:
            window.serve(server=browser_enrollment)
            returned.append(confirm(window))
    except m.PrivateOperatorError as error:
        held = error
    assert fired == [True] and len(calls) == 1
    assert held is not None, "clock directory replacement accepted"
    assert returned == []
    assert {
        str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*") if p.is_file()
    } == originals


@pytest.mark.parametrize("phase", ["before-browser", "before-confirm"])
def test_later_clock_calls_reject_directory_replacement(setup, tmp_path, phase):
    values, _ = setup
    directory = values["directory"]
    previous = tmp_path / "existing-brainstorm"
    enroll(previous, lambda: NOW)
    originals = {
        str(p.relative_to(previous)): p.read_bytes() for p in previous.rglob("*") if p.is_file()
    }
    mutate, fired = [False], []

    def clock():
        if mutate[0] and not fired:
            directory.rename(tmp_path / "displaced")
            previous.rename(directory)
            fired.append(True)
        return NOW

    values["clock"] = clock
    with m.open_private_operator(
        mode=m.PrivateOperatorMode.PERSONAL_ENROLLMENT, **values
    ) as window:
        if phase == "before-browser":
            mutate[0] = True
            statuses = []

            def browser(app):
                with TestClient(app, base_url=ORIGIN, raise_server_exceptions=False) as client:
                    statuses.append(client.get("/enroll").status_code)

            window.serve(server=browser)
            assert statuses == [500]
        else:
            window.serve(server=browser_enrollment)
            pending = window.pending_owner()
            mutate[0] = True
            with pytest.raises(m.PrivateOperatorError):
                window.confirm_owner(
                    pairing_code=pending.pairing_code,
                    expected_identity=pending.identity,
                    confirmation="CONFIRM PERSONAL / HIGHLY_RESTRICTED",
                )
    assert fired == [True]
    assert {
        str(p.relative_to(directory)): p.read_bytes() for p in directory.rglob("*") if p.is_file()
    } == originals


def test_first_clock_cannot_prepopulate_owner_directory(setup):
    values, _ = setup
    directory = values["directory"]
    fired = []

    def clock():
        (directory / "owner").mkdir(mode=0o700)
        fired.append(True)
        return NOW

    values["clock"] = clock
    with (
        pytest.raises(m.PrivateOperatorError),
        m.open_private_operator(mode=m.PrivateOperatorMode.PERSONAL_ENROLLMENT, **values),
    ):
        pass
    assert fired == [True]
    assert not (directory / "sessions").exists()
    assert not (directory / "owner" / "owner.json").exists()


def test_default_enrollment_keeps_exact_clock_object(setup):
    values, _ = setup
    clock = values["clock"]
    with m.open_private_operator(mode=m.PrivateOperatorMode.ENROLLMENT, **values) as window:
        assert window._clock is clock


def test_actual_personal_factory_and_window_share_guarded_clock(setup, monkeypatch):
    values, _ = setup
    supplied = []
    actual = m.prepare_enrollment_host

    def factory(**kwargs):
        supplied.append(kwargs["clock"])
        return actual(**kwargs)

    monkeypatch.setattr(m, "prepare_enrollment_host", factory)
    with m.open_private_operator(
        mode=m.PrivateOperatorMode.PERSONAL_ENROLLMENT, **values
    ) as window:
        assert len(supplied) == 1
        assert window._clock is supplied[0] and window._clock is not values["clock"]
        window.serve(server=browser_enrollment)
        grant = confirm(window)
        assert [scope.boundary.value for scope in grant.scopes] == ["PERSONAL"]
