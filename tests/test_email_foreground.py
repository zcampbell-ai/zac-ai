"""Invented private-folder bytes and pure proposal; no credentials/SQL/age/models."""

import json
import os
from datetime import timedelta

import pytest

from tests.test_gmail_app_observation import NOW, args, observation
from zacai.host_clock import HostObservedClock
from zacai.interfaces import email_foreground as e


@pytest.fixture
def folder(tmp_path):
    path = tmp_path / "owned-inputs"
    path.mkdir(mode=0o700)
    returned = observation()
    returned["payload"]["parts"][0]["body"]["content"] += "\n"
    values = args(returned)
    scope = values["scope"].model_dump(mode="json")
    for name in ("format", "reported_tool_origin", "inspected_at", "boundary", "classification"):
        scope.pop(name)
    config = {
        "format": "zac-owner-email-app-folder-v1",
        "messages": [{"filename": "message-1.json", **scope}],
        "recipient": None,
    }
    for name, raw in [
        ("selection.json", json.dumps(config).encode()),
        ("message-1.json", values["raw"]),
    ]:
        (path / name).write_bytes(raw)
        (path / name).chmod(0o600)
    return path, config, values["raw"], returned["payload"]["parts"][0]["body"]["content"]


def test_default_proposal_performs_no_file_metadata_credential_operator_or_model_effects(
    monkeypatch, capsys
):
    def forbidden(*args, **kwargs):
        raise AssertionError("proposal must not invoke an execution dependency")

    monkeypatch.setattr(e, "open_private_operator", forbidden)
    monkeypatch.setattr(e, "load_selected_app_folder", forbidden)
    monkeypatch.setattr(e.Path, "open", forbidden)
    monkeypatch.setattr(e.Path, "lstat", forbidden)
    monkeypatch.setattr(e.Path, "read_bytes", forbidden)
    assert e.main([]) == 0
    proposal = json.loads(capsys.readouterr().out)
    assert proposal["mode"] == "PROPOSAL_ONLY" and proposal["execution_enabled"] is False
    assert proposal["input_folder"] == "OWNER_REQUIRED"
    assert "HISTORICAL" in proposal["historical_owner_sign_in"]["status"]
    assert "this CLI performs no inspection" in proposal["known_location_metadata"]["basis"]
    assert (
        proposal["known_backup_gateway"]["writer_services"]
        != proposal["known_backup_gateway"]["reader_services"]
    )
    assert "INVENTED_PRIVATE_MARKER" not in json.dumps(proposal)
    assert "https://zacharys-mac-studio.taila3938c.ts.net/auth/callback" not in json.dumps(proposal)


def test_exact_structured_serialization_unknown_fields_and_whole_newline_preserved(folder):
    path, _, raw, literal = folder
    plans, recipient = e.load_selected_app_folder(
        path, HostObservedClock(lambda: NOW + timedelta(seconds=1))
    )
    p = plans[0]
    assert recipient is None and p.artifacts[0].original_bytes == raw
    assert p.literal_text == literal and p.literal_text.endswith("\n")
    assert json.loads(raw)["unknown_top_level"]["processing_authorized"] is True
    assert p.processing_authorized is False and p.capture_authorized is False
    assert p.companion.scope.inspected_at == NOW + timedelta(seconds=1)
    assert p.companion.scope.reported_acquired_at is None
    assert p.companion.reported_message_at != p.companion.scope.inspected_at
    assert p.companion.acquisition_account_verified is False
    assert all(a.source_occurred_at is None for a in p.artifacts)


@pytest.mark.parametrize(
    "bad",
    [
        "folder_symlink",
        "folder_mode",
        "owner",
        "file_symlink",
        "file_mode",
        "hardlink",
        "duplicate_config",
        "nonfinite_config",
        "duplicate_file",
        "traversal",
        "bad_message",
    ],
)
def test_closed_folder_and_json_fail_fixed_private_safe_boundary(
    folder, tmp_path, monkeypatch, bad
):
    path, config, raw, _ = folder
    if bad == "folder_symlink":
        linked = tmp_path / "linked"
        linked.symlink_to(path, target_is_directory=True)
        path = linked
    elif bad == "folder_mode":
        path.chmod(0o755)
    elif bad == "owner":
        monkeypatch.setattr(e.os, "getuid", lambda: os.stat(path).st_uid + 1)
    elif bad == "file_symlink":
        (path / "message-1.json").unlink()
        outside = tmp_path / "outside"
        outside.write_bytes(raw)
        outside.chmod(0o600)
        (path / "message-1.json").symlink_to(outside)
    elif bad == "file_mode":
        (path / "message-1.json").chmod(0o644)
    elif bad == "hardlink":
        os.link(path / "message-1.json", tmp_path / "extra-link")
    elif bad == "duplicate_config":
        (path / "selection.json").write_bytes(
            b'{"format":"INVENTED_PRIVATE_MARKER","format":"zac-owner-email-app-folder-v1"}'
        )
    elif bad == "nonfinite_config":
        (path / "selection.json").write_bytes(
            b'{"format":"zac-owner-email-app-folder-v1","unknown":NaN}'
        )
    elif bad == "duplicate_file":
        config["messages"] *= 2
        (path / "selection.json").write_bytes(json.dumps(config).encode())
    elif bad == "traversal":
        config["messages"][0]["filename"] = "../outside.json"
        (path / "selection.json").write_bytes(json.dumps(config).encode())
    else:
        (path / "message-1.json").write_bytes(
            b'{"id":"INVENTED_PRIVATE_MARKER","id":"invented-m1"}'
        )
    with pytest.raises(
        e.EmailForegroundError, match="^selected email app inputs unavailable$"
    ) as error:
        e.load_selected_app_folder(path, HostObservedClock(lambda: NOW))
    assert error.value.__context__ is None and "INVENTED_PRIVATE_MARKER" not in str(error.value)


def test_invalid_public_config_never_reaches_operator_or_echoes_argument(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("no operator call")

    monkeypatch.setattr(e, "open_private_operator", forbidden)
    with pytest.raises(
        e.EmailForegroundError, match="^public foreground proposal configuration unavailable$"
    ) as error:
        e.proposal(
            client_id="INVENTED_PRIVATE_MARKER",
            origin=None,
            owner_directory=None,
            input_folder=None,
        )
    assert error.value.__context__ is None
    with (
        pytest.raises(
            e.EmailForegroundError, match="^foreground email window unavailable$"
        ) as error,
        e.foreground_email_window(
            client_id="INVENTED_PRIVATE_MARKER",
            origin="https://invalid.example",
            owner_directory=e.Path("/invented"),
            input_folder=e.Path("/invented"),
            protector=object(),
            runtime=object(),
            escrow_confirmed_by_operator=False,
        ),
    ):
        raise AssertionError("no window can be yielded")
    assert error.value.__context__ is None and "INVENTED_PRIVATE_MARKER" not in str(error.value)
