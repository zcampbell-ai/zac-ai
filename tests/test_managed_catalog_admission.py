"""Invented private filesystem birth controls; no SQL, providers or crypto."""

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
from uuid import uuid4

import pytest

from zacai import managed_catalog_admission as m


@pytest.fixture
def case():
    with TemporaryDirectory(prefix="caz-catalog-admission-", dir="/private/tmp") as name:
        parent = Path(name)
        cache = parent / "manifest.json"
        cache.write_bytes(b"invented cache FILE, never a claim directory")
        cache.chmod(0o600)
        yield {
            "root": m.catalog_claim_root(cache),
            "request_id": uuid4(),
            "selection_digest": "a" * 64,
            "original_binding": "b" * 64,
            "owner_fingerprint": "c" * 64,
            "expires_at": datetime(2026, 10, 15, tzinfo=UTC) + timedelta(minutes=5),
        }


def held(case):
    with pytest.raises(
        m.CatalogAdmissionError, match="^catalog claim unavailable; reconcile before retry$"
    ) as error:
        m.claim_catalog_capture(**case)
    assert error.value.__context__ is None


def initialize_other(case):
    return m.claim_catalog_capture(**{**case, "request_id": uuid4()})


def test_lexical_derivation_is_inert_and_cache_remains_file(case):
    cache = case["root"].parent / "manifest.json"
    assert cache.is_file() and not case["root"].exists()
    assert m.catalog_claim_root(cache) == cache.parent / "manifest.json.managed-catalog-claims"
    missing = cache.parent / "not-created" / "cache"
    assert m.catalog_claim_root(missing).parent == missing.parent
    assert not missing.parent.exists()


def test_exclusive_private_birth_has_exact_comparison_record_and_live_guard(case):
    guard = m.claim_catalog_capture(**case)
    root = case["root"]
    request = root / str(case["request_id"])
    raw = (request / "birth.json").read_bytes()
    data = json.loads(raw)
    assert set(data) == {
        "format",
        "request_id",
        "selection_digest",
        "original_binding",
        "owner_fingerprint",
        "expires_at",
        "action",
    }
    assert data["request_id"] == str(case["request_id"])
    assert data["selection_digest"] == case["selection_digest"]
    assert root.stat().st_mode & 0o777 == request.stat().st_mode & 0o777 == 0o700
    assert (request / "birth.json").stat().st_mode & 0o777 == 0o600
    assert (root / "format.json").stat().st_mode & 0o777 == 0o600
    guard.recheck()
    held(case)
    assert (request / "birth.json").read_bytes() == raw
    assert cache_file(case).is_file()


def cache_file(case):
    return case["root"].parent / "manifest.json"


@pytest.mark.parametrize("shape", ["empty", "partial-record", "file", "symlink"])
def test_any_existing_request_shape_is_terminal_and_not_adopted(case, shape):
    initialize_other(case)
    path = case["root"] / str(case["request_id"])
    if shape == "file":
        path.write_bytes(b"foreign")
    elif shape == "symlink":
        path.symlink_to(cache_file(case))
    else:
        path.mkdir(mode=0o700)
        if shape == "partial-record":
            (path / "birth.json").write_bytes(b'{"partial":')
    held(case)
    assert path.exists()
    if shape == "partial-record":
        assert (path / "birth.json").read_bytes() == b'{"partial":'


@pytest.mark.parametrize("shape", ["unmarked", "corrupt-format", "wrong-mode", "symlink"])
def test_existing_unknown_or_partial_root_is_never_repaired(case, shape):
    root = case["root"]
    if shape == "symlink":
        root.symlink_to(root.parent, target_is_directory=True)
    else:
        root.mkdir(mode=0o700)
        if shape == "corrupt-format":
            (root / "format.json").write_bytes(b"unknown")
            (root / "format.json").chmod(0o600)
        if shape == "wrong-mode":
            root.chmod(0o755)
    held(case)
    assert not (root / str(case["request_id"])).exists()


@pytest.mark.parametrize("failure_number", range(1, 7))
def test_each_uncertain_fsync_leaves_birth_or_partial_root_held(case, monkeypatch, failure_number):
    real = m.os.fsync
    calls = []

    def fail(fd):
        calls.append(fd)
        if len(calls) == failure_number:
            raise OSError("invented synchronization uncertainty")
        return real(fd)

    monkeypatch.setattr(m.os, "fsync", fail)
    held(case)
    assert len(calls) == failure_number
    monkeypatch.setattr(m.os, "fsync", real)
    held(case)


def test_concurrent_same_request_has_exactly_one_birth(case):
    initialize_other(case)

    def compete():
        try:
            return m.claim_catalog_capture(**case)
        except m.CatalogAdmissionError:
            return None

    with ThreadPoolExecutor(max_workers=2) as workers:
        values = list(workers.map(lambda _: compete(), range(2)))
    winners = [value for value in values if value is not None]
    assert len(winners) == 1
    winners[0].recheck()


@pytest.mark.parametrize("target", ["record", "format", "request", "root"])
def test_live_guard_detects_removal_replacement_and_content_changes(case, target):
    guard = m.claim_catalog_capture(**case)
    root, request = case["root"], case["root"] / str(case["request_id"])
    if target == "record":
        path = request / "birth.json"
        raw = path.read_bytes()
        path.unlink()
        path.write_bytes(raw)
        path.chmod(0o600)
    elif target == "format":
        (root / "format.json").write_bytes(b"corrupt")
    elif target == "request":
        request.rename(root / "moved-original-request")
        request.mkdir(mode=0o700)
    else:
        root.rename(root.with_name("moved-original-root"))
        root.mkdir(mode=0o700)
    with pytest.raises(m.CatalogAdmissionError):
        guard.recheck()


def test_guard_rejects_extra_children_and_forged_issued_identity(case):
    guard = m.claim_catalog_capture(**case)
    with pytest.raises(m.CatalogAdmissionError):
        replace(guard, _key=object()).recheck()
    (case["root"] / str(case["request_id"]) / "unexpected").write_bytes(b"unknown")
    with pytest.raises(m.CatalogAdmissionError):
        guard.recheck()


def test_comparison_changes_cannot_reinterpret_existing_request_as_fresh(case):
    m.claim_catalog_capture(**case)
    held({**case, "selection_digest": "d" * 64})
    held({**case, "original_binding": "e" * 64})


def test_uncertain_birth_closes_every_owned_descriptor(case, monkeypatch):
    real_open, real_close = m.os.open, m.os.close
    opened = set()

    def tracked_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.add(fd)
        return fd

    def tracked_close(fd):
        real_close(fd)
        opened.remove(fd)

    def fail(fd):
        raise OSError("invented synchronization failure")

    monkeypatch.setattr(m.os, "open", tracked_open)
    monkeypatch.setattr(m.os, "close", tracked_close)
    monkeypatch.setattr(m.os, "fsync", fail)
    held(case)
    assert opened == set()


def test_hardlinked_claim_record_is_not_an_acceptable_live_birth(case):
    guard = m.claim_catalog_capture(**case)
    source = case["root"] / str(case["request_id"]) / "birth.json"
    m.os.link(source, source.with_name("second-name"))
    with pytest.raises(m.CatalogAdmissionError):
        guard.recheck()


@pytest.mark.parametrize("name", ["format.json", "birth.json"])
def test_corrupt_fifo_record_is_nonblocking_and_held(case, monkeypatch, name):
    import os

    guard = m.claim_catalog_capture(**case)
    path = (
        case["root"] / "format.json"
        if name == "format.json"
        else (case["root"] / str(case["request_id"]) / "birth.json")
    )
    path.unlink()
    os.mkfifo(path, 0o600)
    original = m.os.open
    observed = []

    def checked_open(target, flags, *args, **kwargs):
        if target == name:
            observed.append(flags)
            # Causal preimage refusal avoids hanging this test on a FIFO.
            assert flags & os.O_NONBLOCK
        return original(target, flags, *args, **kwargs)

    monkeypatch.setattr(m.os, "open", checked_open)
    with pytest.raises(m.CatalogAdmissionError):
        guard.recheck()
    assert observed
    assert all(flags & os.O_NONBLOCK for flags in observed)
