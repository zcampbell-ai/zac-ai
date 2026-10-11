"""Actual issued history must reject composition changes before file access."""

import pytest

from tests.test_gmail_installation import fixture, run
from tests.test_gmail_legacy_repeat_v2 import previous_attempt
from tests.test_gmail_recovery_host import form
from tests.test_private_host import ORIGIN, sign_in


def test_changed_authority_directory_denies_before_any_history_read(tmp_path, monkeypatch):
    import zacai.connectors.gmail_recovery_history as history_module

    f, _ = fixture(tmp_path, monkeypatch)
    previous_attempt(f, monkeypatch)
    plan = f.recovery_plan(
        monkeypatch,
        action_generation="invented-root-preread-audit",
        recovery_profile="legacy_repeat_v2",
    )
    observed = []

    def browse(browser):
        sign_in(browser)
        paired = browser.post(
            "/connections/gmail/recover/pair", data=form(browser), headers={"origin": ORIGIN}
        )
        assert paired.status_code == 303
        history = plan._consumer._history
        authority = history._authority
        original_directory = authority._directory
        original_file = history_module._file
        attempted = []

        def forbidden_file(directory, name):
            attempted.append((directory, name))
            raise AssertionError("changed authority must be denied before file access")

        try:
            authority._directory = tmp_path / "invented-alternate-directory"
            monkeypatch.setattr(history_module, "_file", forbidden_file)
            with pytest.raises(ValueError):
                history.current()
            assert attempted == []
            observed.append(True)
        finally:
            authority._directory = original_directory
            monkeypatch.setattr(history_module, "_file", original_file)

    run(f, plan, browse)
    assert observed == [True]
    assert f.secret_reads == f.provider_calls == f.native_factories == []


def test_regular_replacement_denies_before_reading_opened_file(tmp_path, monkeypatch):
    import zacai.connectors.gmail_recovery_history as history_module

    path = tmp_path / history_module.LEGACY_JOURNAL
    replacement = tmp_path / "invented-replacement"
    path.write_bytes(b"invented original")
    replacement.write_bytes(b"invented replacement")
    path.chmod(0o600)
    replacement.chmod(0o600)
    original_open = history_module.os.open
    attempted = []

    def replacing_open(name, flags, *args, **kwargs):
        if name == path:
            replacement.replace(path)
        return original_open(name, flags, *args, **kwargs)

    def forbidden_read(*args, **kwargs):
        attempted.append(True)
        raise AssertionError("replacement descriptor must be denied before reading")

    monkeypatch.setattr(history_module.os, "open", replacing_open)
    monkeypatch.setattr(history_module.os, "pread", forbidden_read)
    with pytest.raises(ValueError):
        history_module._file(tmp_path, history_module.LEGACY_JOURNAL)
    assert attempted == []


def test_retained_history_same_path_replacement_denies_before_read(tmp_path, monkeypatch):
    import zacai.connectors.gmail_recovery_history as history_module

    f, _ = fixture(tmp_path, monkeypatch)
    previous_attempt(f, monkeypatch)
    plan = f.recovery_plan(
        monkeypatch,
        action_generation="invented-root-retained-witness-audit",
        recovery_profile="legacy_repeat_v2",
    )
    observed = []

    def browse(browser):
        sign_in(browser)
        paired = browser.post(
            "/connections/gmail/recover/pair", data=form(browser), headers={"origin": ORIGIN}
        )
        assert paired.status_code == 303
        history = plan._consumer._history
        path = history._authority._directory / history_module.LEGACY_JOURNAL
        replacement = path.with_name("invented-same-bytes-replacement")
        replacement.write_bytes(path.read_bytes())
        replacement.chmod(0o600)
        replacement.replace(path)
        attempted = []
        original_read = history_module.os.pread

        def forbidden_read(*args, **kwargs):
            attempted.append(True)
            raise AssertionError("retained witness must be checked before reading replacement")

        monkeypatch.setattr(history_module.os, "pread", forbidden_read)
        try:
            with pytest.raises(ValueError):
                history.current()
            assert attempted == []
            observed.append(True)
        finally:
            monkeypatch.setattr(history_module.os, "pread", original_read)

    # Changed synthetic retained evidence must stop the host; the harness allows
    # that fixed failure and still verifies the original ledger row is retained.
    run(f, plan, browse)
    assert observed == [True]
    assert f.secret_reads == f.provider_calls == f.native_factories == []
