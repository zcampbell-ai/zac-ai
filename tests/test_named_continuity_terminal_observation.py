"""Actual encrypted lookup with simulated SQL transport; no live store/grant."""

import pytest

from tests.test_fragment_publication_post import case as case  # noqa: PLC0414
from tests.test_fragment_publication_post import (
    declaration_case as declaration_case,  # noqa: PLC0414
)
from tests.test_fragment_publication_post import post_case as post_case  # noqa: PLC0414
from zacai.interfaces.named_session_binding import NamedSessionBindingError


@pytest.mark.parametrize("fault", ["cookie", "grant"])
def test_checked_now_revocation_precedes_last_actual_lookup(post_case, monkeypatch, fault):
    f = post_case
    actual_owner = [f.owner]
    revoked = []
    lookup = f.sessions.peek_user
    monkeypatch.setattr(f.continuity, "_owner", lambda: actual_owner[0])
    calls = []

    def clock():
        calls.append(True)
        if len(calls) == 3:
            revoked.append(fault)
            if fault == "grant":
                actual_owner[0] = None
        return f.now[0]

    def peek(cookie, now):
        # Database revocation is explicitly simulated; actual decrypted lookup
        # remains used before that transition, never a fabricated session.
        return None if revoked and fault == "cookie" else lookup(cookie, now)

    monkeypatch.setattr(f.clock, "_read", clock)
    monkeypatch.setattr(f.sessions, "peek_user", peek)
    with pytest.raises(NamedSessionBindingError):
        f.continuity.for_cookie(f.cookie).recheck(f.g.original_session_binding)
    assert revoked == [fault] and len(calls) == 3
    assert not any(statement.startswith("UPDATE") for statement in f.sql)


def test_terminal_observation_keeps_original_expiry_without_idle_refresh(post_case):
    f = post_case
    before = tuple(f.row)
    actual = f.continuity.for_cookie(f.cookie).recheck(f.g.original_session_binding)
    assert actual.effective_expires_at == f.g.original_session_expires_at
    assert actual.issued_at == f.g.original_session_issued_at
    assert tuple(f.row) == before
    assert not any(statement.startswith("UPDATE") for statement in f.sql)


from tests.test_fragment_publication_admission import (
    action_protection as action_protection,  # noqa: PLC0414
)
from tests.test_fragment_publication_admission import (
    authority as authority,  # noqa: PLC0414
)
from tests.test_fragment_publication_admission import (
    consent_case as consent_case,  # noqa: PLC0414
)
from tests.test_fragment_publication_admission import (
    declaration_protection as declaration_protection,  # noqa: PLC0414
)
from tests.test_fragment_publication_admission import (
    packet_case as packet_case,  # noqa: PLC0414
)
from tests.test_fragment_publication_admission import (
    protect_action,
)
from zacai import contextual_protection as protection


def test_operation_clock_crosses_original_processing_expiry_no_receipt(
    action_protection, monkeypatch
):
    f = action_protection
    armed = []
    fired = []
    observe = f.p._reobserve_objects
    owner_read = f.p._operation._read

    def reobserve(observations, access):
        observe(observations, access)
        if "/receipt-" in observations[-1][0]:
            armed.append(True)

    def owner():
        import inspect

        frame = inspect.currentframe()
        caller = frame.f_back.f_back if frame and frame.f_back else None
        value = owner_read()
        if armed and caller and caller.f_code.co_name == "_admission_execute":
            monkeypatch.setattr(f.p._clock, "_read", lambda: f.action.expires_at)
            f.p._clock()
            fired.append("signed operation observed original processing expiry")
        return value

    monkeypatch.setattr(f.p, "_reobserve_objects", reobserve)
    monkeypatch.setattr(f.p._operation, "_read", owner)
    f.p._operation_settings = (owner, f.p._operation._host_clock)
    with pytest.raises(protection.ContextualProtectionError):
        protect_action(f)
    assert fired and f.events.count("restore") == 1


def test_final_owner_shared_clock_watermark_expires_cookie_before_last_lookup(
    post_case, monkeypatch
):
    from datetime import timedelta

    f = post_case
    calls = []
    fired = []

    def owner():
        calls.append(True)
        if len(calls) == 3:
            f.now[0] = f.g.original_session_expires_at + timedelta(hours=8)
            f.clock()
            fired.append("final owner advanced shared clock beyond cookie expiry")
        return f.owner

    monkeypatch.setattr(f.continuity, "_owner", owner)
    with pytest.raises(NamedSessionBindingError):
        f.continuity.for_cookie(f.cookie).recheck(f.g.original_session_binding)
    assert fired == ["final owner advanced shared clock beyond cookie expiry"]
    assert not any(statement.startswith("UPDATE") for statement in f.sql)
