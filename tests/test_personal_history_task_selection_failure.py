from datetime import timedelta
from threading import Event, Thread
from types import SimpleNamespace

import pytest

from tests.test_personal_history_task_selection import case as case  # noqa: PLC0414
from tests.test_personal_history_task_selection import prepare
from zacai import personal_history_task_selection as m
from zacai.personal_history_task_selection import PersonalTaskSelectionError

SUCCESS = 'Summarize Icon Park'
CLARIFY = 'Summarize Sales Audit'


def test_successful_control_reports_processing_authorized_false(case):
    app = case.make()
    outcome = app.propose(operation=case.operation, instruction=SUCCESS)
    assert outcome.selection.outcome == 'PROPOSED'
    result = prepare(case, app, SUCCESS)
    assert result.processing_authorized is False
    assert len(case.preparations) == 1  # fixture canonical preparation is a spy


def test_concurrent_prepare_while_first_final_callback_runs(case, monkeypatch):
    app = case.make()
    assert app.propose(operation=case.operation, instruction=SUCCESS).selection.outcome == 'PROPOSED'
    entered, release = Event(), Event()
    calls = []
    def callback(configuration, **kw):
        calls.append(configuration)
        entered.set()
        assert release.wait(5)
        return SimpleNamespace(processing_authorized=False)
    monkeypatch.setattr(m, 'prepare_personal_history_task', callback)
    first_results, first_errors = [], []
    second_results, second_errors = [], []
    def first():
        try:
            first_results.append(prepare(case, app, SUCCESS))
        except BaseException as exc:  # noqa: BLE001
            first_errors.append(exc)
    def second():
        try:
            second_results.append(prepare(case, app, SUCCESS))
        except BaseException as exc:  # noqa: BLE001
            second_errors.append(exc)
    first_thread, second_thread = Thread(target=first), Thread(target=second)
    first_thread.start()
    second_started = False
    try:
        assert entered.wait(5)
        second_thread.start()
        second_started = True
        second_thread.join(5)
        assert not second_thread.is_alive()
    finally:
        release.set()
        if second_started:
            second_thread.join(5)
        first_thread.join(5)
    assert not first_thread.is_alive()
    assert len(calls) == 1
    assert len(first_results) == 1 and first_results[0].processing_authorized is False
    assert not first_errors
    assert not second_results
    assert len(second_errors) == 1 and isinstance(second_errors[0], PersonalTaskSelectionError)
    with pytest.raises(PersonalTaskSelectionError):
        prepare(case, app, SUCCESS)
    assert len(calls) == 1


@pytest.mark.parametrize(
    'exc_type,side_effect',
    [(RuntimeError, False), (RuntimeError, True), (KeyboardInterrupt, False), (KeyboardInterrupt, True)],
)
def test_final_callback_exception_is_terminal(case, monkeypatch, exc_type, side_effect):
    app = case.make()
    assert app.propose(operation=case.operation, instruction=SUCCESS).selection.outcome == 'PROPOSED'
    calls, effects = [], []
    def callback(configuration, **kw):
        calls.append(configuration)
        if side_effect:
            effects.append('acknowledged')
        raise exc_type('invented')
    monkeypatch.setattr(m, 'prepare_personal_history_task', callback)
    with pytest.raises(PersonalTaskSelectionError):
        prepare(case, app, SUCCESS)
    assert len(calls) == 1
    assert len(effects) == (1 if side_effect else 0)
    with pytest.raises(PersonalTaskSelectionError):
        prepare(case, app, SUCCESS)
    assert len(calls) == 1
    with pytest.raises(PersonalTaskSelectionError):
        app.propose(operation=case.operation, instruction=SUCCESS)
    assert len(calls) == 1


@pytest.mark.parametrize('bad', [0, -1, True, False, 1.0, '1', 'too_large'])
def test_clarification_invalid_choice_never_calls_canonical(case, monkeypatch, bad):
    app = case.make()
    outcome = app.propose(operation=case.operation, instruction=CLARIFY)
    assert outcome.selection.outcome == 'CLARIFICATION'
    assert outcome.selection.options
    value = len(outcome.selection.options) + 1 if bad == 'too_large' else bad
    calls = []
    def callback(configuration, **kw):
        calls.append(configuration)
        return SimpleNamespace(processing_authorized=False)
    monkeypatch.setattr(m, 'prepare_personal_history_task', callback)
    with pytest.raises(PersonalTaskSelectionError):
        prepare(case, app, CLARIFY, option_number=value)
    assert calls == []
    with pytest.raises(PersonalTaskSelectionError):
        prepare(case, app, CLARIFY, option_number=1)
    assert calls == []


def _expire(case):
    case.now = case.configuration.expires_at + timedelta(seconds=1)


def _revoke(case):
    case.sessions.revoke(case.cookie)


@pytest.mark.parametrize('kind', ['revocation', 'deadline'])
@pytest.mark.parametrize('when', ['before', 'during'])
def test_session_state_change_before_or_during_callback_is_terminal(case, monkeypatch, kind, when):
    app = case.make()
    assert app.propose(operation=case.operation, instruction=SUCCESS).selection.outcome == 'PROPOSED'
    mutate = _revoke if kind == 'revocation' else _expire
    if when == 'before':
        mutate(case)
    calls, effects = [], []
    def callback(configuration, **kw):
        calls.append(configuration)
        if when == 'during':
            effects.append('acknowledged')
            mutate(case)
        return SimpleNamespace(processing_authorized=False)
    monkeypatch.setattr(m, 'prepare_personal_history_task', callback)
    with pytest.raises(PersonalTaskSelectionError):
        prepare(case, app, SUCCESS)
    assert len(calls) == (0 if when == 'before' else 1)
    assert len(effects) == (0 if when == 'before' else 1)
    with pytest.raises(PersonalTaskSelectionError):
        prepare(case, app, SUCCESS)
    assert len(calls) == (0 if when == 'before' else 1)
