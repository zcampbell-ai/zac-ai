"""Independent legacy action revocation controls; invented stores only."""

import pytest

from tests.test_gmail_legacy_original_profile import LEGACY, LEGACY_SCOPE
from tests.test_gmail_recovery_audit import pair, run_checked
from tests.test_gmail_recovery_host import Fixture
from tests.test_private_host import enroll


@pytest.mark.parametrize("domain", ["original", "hr"])
def test_legacy_action_denies_session_revoked_inside_current_clock_callback(
    tmp_path, monkeypatch, domain
):
    f = Fixture(tmp_path, monkeypatch)
    enroll(f.directory, f.clock, scopes=LEGACY_SCOPE)
    owner_before = (f.directory / "owner/owner.json").read_bytes()
    plan = f.recovery_plan(monkeypatch, original_grant_profile=LEGACY)
    revoked = []

    def browse(browser):
        pair(browser)
        action = plan._join._action
        action.current()
        reader = f.clock._read

        def read_and_revoke():
            if not revoked:
                continuity = (
                    plan._original_continuity if domain == "original" else plan._hr_continuity
                )
                cookie = action._original_cookie if domain == "original" else action._hr_cookie
                continuity._sessions.revoke(cookie)
                revoked.append(True)
            return reader()

        monkeypatch.setattr(f.clock, "_read", read_and_revoke)
        with pytest.raises(ValueError):
            action.current()
        assert revoked == [True]
        f.both_leases()
        assert not plan._consumer._spent
        assert not f.secret_reads and not f.provider_calls and not f.native_factories

    run_checked(f, plan, browse)
    assert revoked == [True]
    assert (f.directory / "owner/owner.json").read_bytes() == owner_before
    with f.authority._locked():
        assert f.authority._read()["rows"] == {f.old_state: f.old_row}


def test_fixed_startup_label_does_not_inspect_or_render_untrusted_value(tmp_path, monkeypatch):
    f = Fixture(tmp_path, monkeypatch)
    plan = f.recovery_plan(monkeypatch)

    class ForeignLabel:
        def __repr__(self):
            raise AssertionError("diagnostic rendered foreign object")

        def __eq__(self, other):
            raise AssertionError("diagnostic compared foreign object")

        def __hash__(self):
            raise AssertionError("diagnostic hashed foreign object")

    for value in (ForeignLabel(), "invented-private-value", None, True):
        plan._startup_stage = value
        assert plan.startup_stage == "unavailable"
    assert not f.shared_reads and not f.secret_reads and not f.provider_calls
