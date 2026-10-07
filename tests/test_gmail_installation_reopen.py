"""Existing encrypted authority reopen never creates or reinitializes evidence."""

import pytest

from tests.test_connector_authority import Fixture, read_plan
from zacai.connectors.connector_authority import (
    ConnectorAuthority,
    ConnectorAuthorityError,
    review_scope_digest,
)
from zacai.connectors.gmail_installation import GmailInstallation
from zacai.connectors.gmail_recovery_authorization import GmailRecoveryAuthorizationError


def test_open_existing_authenticates_without_modifying_ciphertext(tmp_path, monkeypatch):
    f = Fixture(tmp_path)
    before = {p.name: p.read_bytes() for p in f.directory.iterdir()}

    def forbidden(*args, **kwargs):
        pytest.fail("existing authority must not initialize or create directories")

    monkeypatch.setattr(ConnectorAuthority, "initialize", forbidden)
    reopened = ConnectorAuthority.open_existing(
        f.directory, key=f.key, continuity=f.continuity, backend=f.backend
    )
    assert {p.name: p.read_bytes() for p in f.directory.iterdir()} == before
    plan = read_plan()
    reopened.approve_review(
        plan,
        request=f.request(),
        csrf=f.csrf,
        reviewed_scope_digest=review_scope_digest(plan),
        payload_digest=None,
    )
    with reopened._locked():
        assert len(reopened._read()["rows"]) == 1


@pytest.mark.parametrize(
    "missing", ["directory", "connector-authority.lock", "connector-authority.bin"]
)
def test_open_existing_missing_evidence_never_creates(tmp_path, missing):
    f = Fixture(tmp_path)
    root = f.directory
    if missing == "directory":
        root = tmp_path / "never-created"
    else:
        (root / missing).unlink()
    before = {p.name: p.read_bytes() for p in root.iterdir()} if root.exists() else None
    with pytest.raises(ConnectorAuthorityError):
        ConnectorAuthority.open_existing(
            root, key=f.key, continuity=f.continuity, backend=f.backend
        )
    after = {p.name: p.read_bytes() for p in root.iterdir()} if root.exists() else None
    assert before == after


def test_public_object_does_not_mint_reopened_installation():
    with pytest.raises(GmailRecoveryAuthorizationError):
        GmailInstallation.reopen(capability=object(), reader=object(), transport=object())


@pytest.mark.parametrize("fault", ["key", "ciphertext", "foreign_child"])
def test_open_existing_rejects_unauthenticated_or_extra_evidence(tmp_path, fault):
    f = Fixture(tmp_path)
    key = f.key
    if fault == "key":
        key = b"X" * 32
    elif fault == "ciphertext":
        (f.directory / "connector-authority.bin").write_bytes(b"x" * 100)
    else:
        child = f.directory / "unknown.bin"
        child.write_bytes(b"invented-extra")
        child.chmod(0o600)
    before = {p.name: p.read_bytes() for p in f.directory.iterdir()}
    with pytest.raises(ConnectorAuthorityError):
        ConnectorAuthority.open_existing(
            f.directory, key=key, continuity=f.continuity, backend=f.backend
        )
    assert {p.name: p.read_bytes() for p in f.directory.iterdir()} == before
