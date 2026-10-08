"""Fixed phase diagnostics injected through actual invented owner host startup."""

from contextlib import contextmanager

import pytest

from tests.test_gmail_recovery_host import PATH, Fixture
from tests.test_private_host import sign_in
from zacai.interfaces.gmail_recovery_host import GmailRecoveryHostError

PHASES = (
    "markers_lock",
    "marker_ready",
    "marker_halt",
    "marker_post_time",
    "marker_post_proposal",
    "marker_post_graph",
    "marker_post_files",
    "recovery_join",
)
PRIVATE_INVENTION = "invented-private-input-must-not-escape"


@pytest.mark.parametrize("phase", PHASES)
def test_fixed_failure_phase_no_private_error_and_no_gmail_effect(tmp_path, monkeypatch, phase):
    import zacai.connectors.gmail_recovery_authorization as join_module
    import zacai.interfaces.gmail_recovery_host as host_module

    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch, startup_only=phase != "recovery_join")
    if phase == "markers_lock":
        original = host_module.OAuthHostGuard._locked

        @contextmanager
        def locked(guard):
            if plan.startup_stage == phase:
                raise OSError(PRIVATE_INVENTION)
            with original(guard):
                yield

        monkeypatch.setattr(host_module.OAuthHostGuard, "_locked", locked)
    elif phase in ("marker_ready", "marker_halt"):
        original = host_module._guard

        def guarded(path, **kwargs):
            if plan.startup_stage == phase:
                raise OSError(PRIVATE_INVENTION)
            return original(path, **kwargs)

        monkeypatch.setattr(host_module, "_guard", guarded)
    elif phase == "marker_post_time":
        original = f.clock._read

        def read():
            if plan.startup_stage == phase:
                raise OSError(PRIVATE_INVENTION)
            return original()

        monkeypatch.setattr(f.clock, "_read", read)
    elif phase in ("marker_post_proposal", "marker_post_graph", "marker_post_files"):
        name = {
            "marker_post_proposal": "_proposal_current",
            "marker_post_graph": "_graph",
            "marker_post_files": "_files",
        }[phase]
        original = getattr(plan, name)

        def check():
            if plan.startup_stage == phase:
                raise OSError(PRIVATE_INVENTION)
            return original()

        monkeypatch.setattr(plan, name, check)
    else:

        def join(**kwargs):
            assert plan.startup_stage == phase
            raise OSError(PRIVATE_INVENTION)

        monkeypatch.setattr(join_module, "GmailRecoveryJoin", join)
    with pytest.raises(GmailRecoveryHostError) as failure:
        plan.run()
    assert plan.startup_stage == phase
    assert PRIVATE_INVENTION not in str(failure.value)
    assert (
        not f.server_runs and not f.secret_reads and not f.provider_calls and not f.native_factories
    )


def test_recurring_checks_keep_serving_and_phase_label_is_closed(tmp_path, monkeypatch):
    from zacai.interfaces.gmail_recovery_host import GmailRecoveryHostPlan

    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)

    def browse(browser):
        assert plan.startup_stage == "serving"
        sign_in(browser)
        assert browser.get(PATH).status_code == 200
        assert plan.startup_stage == "serving"

    f.browser_action = browse
    plan.run()
    assert plan.startup_stage == "serving"
    probe = object.__new__(GmailRecoveryHostPlan)
    for value in PHASES:
        probe._startup_stage = value
        assert probe.startup_stage == value

    class Foreign:
        def __str__(self):
            raise AssertionError("private coercion")

        __repr__ = __str__
        __hash__ = __str__

    for value in (Foreign(), PRIVATE_INVENTION):
        probe._startup_stage = value
        assert probe.startup_stage == "unavailable"


def test_startup_only_closed_pinned_and_no_routes_gmail_or_provider(tmp_path, monkeypatch):
    import zacai.connectors.gmail_recovery_authorization as joins

    f = Fixture(tmp_path, monkeypatch)
    for value in (None, 1, "true"):
        with pytest.raises(GmailRecoveryHostError):
            f.recovery_plan(monkeypatch, startup_only=value)
    changed = f.recovery_plan(monkeypatch, startup_only=True)
    changed._startup_only = False
    with pytest.raises(GmailRecoveryHostError):
        changed.run()
    changed = f.recovery_plan(monkeypatch, startup_only=True)
    changed._startup_only = 1
    with pytest.raises(GmailRecoveryHostError):
        changed.run()
    assert not f.shared_reads
    plan = f.recovery_plan(monkeypatch, startup_only=True)

    def forbidden(**kwargs):
        raise AssertionError("diagnostic startup must never construct recovery join")

    monkeypatch.setattr(joins, "GmailRecoveryJoin", forbidden)
    plan.run()
    assert plan.startup_stage == "marker_post_files"
    assert len(f.shared_reads) == 2
    assert (
        not f.server_runs and not f.secret_reads and not f.provider_calls and not f.native_factories
    )
    assert plan._windows is plan._runtime is plan._join is None
    assert plan._spent is True
    with pytest.raises(GmailRecoveryHostError):
        plan.run()
    assert len(f.shared_reads) == 2
