"""Invented authenticated record/namespace selection, never owner or native authority."""

import copy
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from zacai.connectors.connector_authority import _json
from zacai.connectors.gmail_installed_load import (
    _FILES,
    CONNECTOR,
    PENDING,
    GmailInstallationLoader,
    _installation_history,
)
from zacai.connectors.gmail_recovery_history import LEGACY_JOURNAL, LEGACY_SPEND, recovery_names

CONFIGURATION = "a" * 64
ACCOUNT = "b" * 64
GENERATION = "invented-current-action"


def history():
    journal, _, spend = recovery_names(CONFIGURATION, ACCOUNT, GENERATION)
    row = {
        "configuration": CONFIGURATION, "account": ACCOUNT, "binding": "c" * 64,
        "generation": "invented-old-action", "rotation": None,
        "expires": "2026-10-11T12:00:00+00:00", "state": "held", "verifier": None,
        "execution": "d" * 64, "loaded": True,
    }
    return {
        "version": 2, "profile": "legacy_repeat_v2", "configuration": CONFIGURATION,
        "account": ACCOUNT, "generation": GENERATION, "journal": journal, "spend": spend,
        "legacy_files": {name: {"sha256": "e" * 64, "witness": [1] * 8}
                         for name in (LEGACY_JOURNAL, LEGACY_SPEND)},
        "state": "f" * 64, "rows": {"f" * 64: row},
    }


def pending(version=2):
    value = {
        "version": version, "state": "installation_pending", "configuration": CONFIGURATION,
        "state_hash": "0" * 64, "row_hash": "1" * 64, "native_generation": "2" * 32,
        "pair_hash": "3" * 64, "subject": "invented-subject", "owner_binding": "4" * 64,
        "spend_hash": "5" * 64,
    }
    if version == 2:
        value["history"] = history()
    return value


def test_record_selector_preserves_legacy_and_deep_copies_v2_history():
    assert _installation_history(pending(1), configuration=CONFIGURATION, account=ACCOUNT) is None
    source = pending()
    checked = _installation_history(source, configuration=CONFIGURATION, account=ACCOUNT)
    assert checked == source["history"]
    checked["rows"]["f" * 64]["state"] = "denied"
    assert source["history"]["rows"]["f" * 64]["state"] == "held"


@pytest.mark.parametrize("change", [
    lambda p: p.update(version=True), lambda p: p.update(version=3),
    lambda p: p.update(extra="invented"), lambda p: p.pop("history"),
    lambda p: p["history"].update(journal="../foreign.bin"),
    lambda p: p["history"].update(spend="foreign.bin"),
    lambda p: p["history"].update(configuration="0" * 64),
    lambda p: p["history"].update(account="0" * 64),
    lambda p: p["history"].update(generation="another-action"),
    lambda p: p["history"]["rows"]["f" * 64].update(state="exchange_started"),
])
def test_authenticated_selector_syntax_cannot_select_foreign_or_uncertain_history(change):
    value = pending()
    change(value)
    with pytest.raises(ValueError):
        _installation_history(value, configuration=CONFIGURATION, account=ACCOUNT)


def inventory(tmp_path, value):
    """Exercise concrete file inventory only; never construct a load capability."""
    root = tmp_path / "invented-installed"
    root.mkdir(mode=0o700)
    names = set(_FILES)
    if value["version"] == 2:
        names |= {value["history"]["journal"], value["history"]["spend"]}
    cipher = AESGCM(b"I" * 32)
    context = b"invented-disposable-installation-record"
    for name in names:
        data = b"invented-immutable-bytes"
        if name == PENDING:
            nonce = b"N" * 12
            data = nonce + cipher.encrypt(nonce, _json(value), context)
        (root / name).write_bytes(data)
        (root / name).chmod(0o600)
    connector = root / CONNECTOR
    connector.mkdir(mode=0o700)
    for name in ("connector-authority.lock", "connector-authority.bin"):
        (connector / name).write_bytes(b"invented")
        (connector / name).chmod(0o600)
    loader = object.__new__(GmailInstallationLoader)
    loader._directory = root
    loader._recovery_profile = "legacy_repeat_v2" if value["version"] == 2 else "fresh_v1"
    principal = object()
    operation = SimpleNamespace(recheck=lambda binding: SimpleNamespace(principal=principal))
    loader._action = SimpleNamespace(_hr_operation=operation, _hr_binding="invented-hr",
                                    _hr_principal=principal, _original_operation=operation,
                                    _original_binding="invented-original", _original_principal=principal)
    loader._configuration = SimpleNamespace(configuration_digest=CONFIGURATION)
    loader._account = ACCOUNT
    loader._cipher = cipher
    loader._context = context
    loader._quarantine_identity = loader._quarantine_fd = loader._quarantine_witness = None
    loader._snapshot = None
    return loader, root


@pytest.mark.parametrize("version", [1, 2])
def test_concrete_inventory_includes_exact_authenticated_history_names(tmp_path, version):
    loader, root = inventory(tmp_path, pending(version))
    snapshot = loader._files()
    names = {item[0] for item in snapshot[2]}
    assert names == set(_FILES) | ({history()["journal"], history()["spend"]} if version == 2 else set())
    assert {p.name for p in root.iterdir()} == names | {CONNECTOR}
    if version == 2:
        (root / history()["journal"]).write_bytes(b"changed")
        assert loader._files() != snapshot


@pytest.mark.parametrize("change", ["extra", "missing", "foreign-generation"])
def test_concrete_inventory_rejects_extra_missing_or_foreign_generation_files(tmp_path, change):
    loader, root = inventory(tmp_path, pending())
    if change == "extra":
        (root / "unrelated.bin").write_bytes(b"invented")
    else:
        old = root / history()["journal"]
        if change == "missing":
            old.unlink()
        else:
            other = copy.deepcopy(history())
            other["generation"] = "another-action"
            foreign, _, _ = recovery_names(CONFIGURATION, ACCOUNT, other["generation"])
            old.rename(root / foreign)
    with pytest.raises(ValueError):
        loader._files()


def test_repeat_descriptor_denied_in_default_fresh_profile(tmp_path):
    loader, _ = inventory(tmp_path, pending())
    loader._recovery_profile = "fresh_v1"
    with pytest.raises(ValueError, match="exact installed recovery profile"):
        loader._files()


def test_current_owner_denied_before_authenticated_selector_read(tmp_path):
    loader, _ = inventory(tmp_path, pending())
    loader._action._hr_operation = SimpleNamespace(recheck=lambda binding: SimpleNamespace(principal=object()))
    calls = []
    loader._file = lambda *args, **kwargs: calls.append(args)
    with pytest.raises(ValueError, match="current paired installation owner"):
        loader._files()
    assert calls == []
