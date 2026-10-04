"""Operator default/approval-file/one-attempt guards; no credentials or databases."""

import importlib.util
import json
import os
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from zacai.schema_rollout import SchemaRolloutApproval


@pytest.fixture
def operator(tmp_path, monkeypatch):
    path = Path(__file__).resolve().parents[1] / "scripts/protected_schema_rollout.py"
    spec = importlib.util.spec_from_file_location("rollout_operator", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "PRIVATE", tmp_path)
    return module


def scope():
    now = datetime.now(UTC)
    return SchemaRolloutApproval(
        target_database="zacai_dev",
        code_revision="a" * 40,
        migration_hash="b" * 64,
        human_reference="synthetic human record",
        approved_at=now,
        expires_at=now + timedelta(minutes=15),
    )


def test_default_only_prints_proposal(operator, monkeypatch, capsys):
    def forbidden(*a, **kw):
        pytest.fail("proposal mode must not touch secrets, Git or a database")

    monkeypatch.setattr(operator, "credential", forbidden)
    monkeypatch.setattr(operator, "create_engine", forbidden)
    monkeypatch.setattr(operator.subprocess, "run", forbidden)
    monkeypatch.setattr(sys, "argv", ["protected_schema_rollout.py"])
    operator.main()
    assert json.loads(capsys.readouterr().out)["live_actions"] is False


def test_claim_is_private_stable_and_never_reused(operator):
    approval = scope()
    receipt = operator.claim_approval(approval)
    claim = next(operator.PRIVATE.glob("*.used"))
    assert claim.stat().st_mode & 0o777 == 0o600
    assert receipt.parent == operator.PRIVATE
    assert not receipt.exists()
    with pytest.raises(FileExistsError):
        operator.claim_approval(
            SchemaRolloutApproval.model_validate_json(approval.model_dump_json())
        )


def test_scope_file_is_private_bounded_and_no_symlinks(operator):
    path = operator.PRIVATE / "scope.json"
    path.write_text(scope().model_dump_json())
    os.chmod(path, 0o600)
    assert operator.approval_from_private_file(path).target_database == "zacai_dev"
    linked = operator.PRIVATE / "linked.json"
    linked.symlink_to(path)
    with pytest.raises(OSError):
        operator.approval_from_private_file(linked)
    os.chmod(path, 0o644)
    with pytest.raises(ValueError):
        operator.approval_from_private_file(path)
    path.write_bytes(b"x" * 8193)
    os.chmod(path, 0o600)
    with pytest.raises(ValueError):
        operator.approval_from_private_file(path)


def test_equivalent_or_modified_scope_cannot_replay_same_human_consent(operator):
    from datetime import timezone

    approval = scope()
    operator.claim_approval(approval)
    encoded = approval.model_copy(
        update={
            "human_reference": "  " + approval.human_reference + "  ",
            "approved_at": approval.approved_at.astimezone(timezone(timedelta(hours=1))),
            "expires_at": approval.expires_at.astimezone(timezone(timedelta(hours=1))),
        }
    )
    with pytest.raises(FileExistsError):
        operator.claim_approval(encoded)
    changed = approval.model_copy(update={"expires_at": approval.expires_at + timedelta(seconds=1)})
    with pytest.raises(FileExistsError):
        operator.claim_approval(changed)
