"""Invented local files and injected S3 client; no network, SQL or crypto."""

import io
import os
from types import SimpleNamespace

import pytest

from zacai.backup_artifacts import BackupArtifactsError, LocalDirectoryBackupStore
from zacai.backup_artifacts_s3 import RemoteBackupError, S3CompatibleBackupObjectStore


def test_local_exact_empty_and_ordinary_get_unchanged(tmp_path):
    store = LocalDirectoryBackupStore(tmp_path / "root")
    for raw in (b"", b"invented"):
        key = "PERSONAL/a/object.age"
        store.put_object(key, raw)
        assert store.get_object_bounded(key, max_bytes=max(1, len(raw))) == raw
        assert store.get_object(key) == raw


def test_local_oversize_before_fdopen(tmp_path, monkeypatch):
    store = LocalDirectoryBackupStore(tmp_path)
    store.put_object("x.age", b"invented")
    calls = []
    monkeypatch.setattr(os, "fdopen", lambda *a, **k: calls.append(1))
    with pytest.raises(BackupArtifactsError):
        store.get_object_bounded("x.age", max_bytes=7)
    assert calls == []


@pytest.mark.parametrize("key", ["/x", "../x", "a/../x", "a//x", "a\\x", "x\x00"])
def test_local_bad_path_before_io(tmp_path, monkeypatch, key):
    store = LocalDirectoryBackupStore(tmp_path)
    calls = []
    monkeypatch.setattr(os, "open", lambda *a, **k: calls.append(1))
    with pytest.raises(BackupArtifactsError):
        store.get_object_bounded(key, max_bytes=8)
    assert calls == []


@pytest.mark.parametrize("kind", ["file_link", "directory_link", "hardlink"])
def test_local_link_confinement(tmp_path, kind):
    root = tmp_path / "root"
    store = LocalDirectoryBackupStore(root)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "x.age").write_bytes(b"invented")
    if kind == "file_link":
        (root / "x.age").symlink_to(outside / "x.age")
        key = "x.age"
    elif kind == "directory_link":
        (root / "linked").symlink_to(outside, target_is_directory=True)
        key = "linked/x.age"
    else:
        os.link(outside / "x.age", root / "x.age")
        key = "x.age"
    with pytest.raises(BackupArtifactsError):
        store.get_object_bounded(key, max_bytes=8)


def test_local_growth_after_stat_reads_size_plus_one_and_holds(tmp_path, monkeypatch):
    store = LocalDirectoryBackupStore(tmp_path)
    store.put_object("x.age", b"invented")
    original = os.fdopen
    amounts = []

    class Growing:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, amount):
            amounts.append(amount)
            with (tmp_path / "x.age").open("ab") as writer:
                writer.write(b"!")
            return self.stream.read(amount)

    monkeypatch.setattr(os, "fdopen", lambda *a, **k: Growing(original(*a, **k)))
    with pytest.raises(BackupArtifactsError):
        store.get_object_bounded("x.age", max_bytes=100_000_000)
    assert amounts == [9]


class Body(io.BytesIO):
    def __init__(self, raw, *, fail_read=False, fail_close=False):
        super().__init__(raw)
        self.amounts = []
        self.fail_read = fail_read
        self.fail_close = fail_close

    def read(self, amount=-1):
        self.amounts.append(amount)
        if self.fail_read:
            raise OSError("invented private provider diagnostic")
        return super().read(amount)

    def close(self):
        super().close()
        if self.fail_close:
            raise OSError("invented private close diagnostic")


def remote(body, size):
    # Only transport injection is mocked. This test does not authenticate S3.
    store = object.__new__(S3CompatibleBackupObjectStore)
    calls = []

    def get_object(**kwargs):
        calls.append(kwargs)
        return {"Body": body, "ContentLength": size}

    store._bucket = "invented-bucket"
    store._client = SimpleNamespace(get_object=get_object)
    return store, calls


def test_remote_tiny_actual_declared_size_limits_read_and_closes():
    body = Body(b"invented")
    store, calls = remote(body, 8)
    assert store.get_object_bounded("PERSONAL/x.age", max_bytes=100_000_000) == b"invented"
    assert body.amounts == [9, 1]
    assert body.closed
    assert calls == [{"Bucket": "invented-bucket", "Key": "PERSONAL/x.age"}]


@pytest.mark.parametrize(
    "kind", ["oversize", "short", "growth", "read_error", "close_error", "bad_size"]
)
def test_remote_fault_fixed_and_closed(kind):
    body = Body(
        b"invented" + (b"!" if kind == "growth" else b""),
        fail_read=kind == "read_error",
        fail_close=kind == "close_error",
    )
    size = {"oversize": 9, "short": 9, "bad_size": True}.get(kind, 8)
    store, _ = remote(body, size)
    with pytest.raises(RemoteBackupError) as error:
        store.get_object_bounded("invented-key", max_bytes=8 if kind == "oversize" else 10)
    assert str(error.value) == "bounded remote backup object unavailable"
    assert error.value.__cause__ is error.value.__context__ is None
    assert body.closed
    if kind in ("oversize", "bad_size"):
        assert body.amounts == []


@pytest.mark.parametrize("limit", [0, -1, True, 1.0])
def test_bad_limit_before_local_or_remote_io(tmp_path, monkeypatch, limit):
    local = LocalDirectoryBackupStore(tmp_path)
    body = Body(b"invented")
    store, calls = remote(body, 8)
    opens = []
    monkeypatch.setattr(os, "open", lambda *a, **k: opens.append(1))
    for target in (local, store):
        with pytest.raises(BackupArtifactsError):
            target.get_object_bounded("x", max_bytes=limit)
    assert opens == calls == []
    assert body.amounts == []
    body.close()


def test_remote_cancellation_propagates_after_close():
    class Cancel(BaseException):
        pass

    class Interrupted(Body):
        def read(self, amount=-1):
            raise Cancel()

    body = Interrupted(b"invented")
    store, _ = remote(body, 8)
    with pytest.raises(Cancel):
        store.get_object_bounded("x", max_bytes=8)
    assert body.closed


def test_local_cancel_closes_all_opened_descriptors(tmp_path, monkeypatch):
    store = LocalDirectoryBackupStore(tmp_path)
    store.put_object("x.age", b"invented")
    real_open, real_close, real_fdopen = os.open, os.close, os.fdopen
    opened, closed = [], []

    class Cancel(BaseException):
        pass

    class Interrupted:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, amount):
            raise Cancel()

    def opening(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        opened.append(fd)
        return fd

    def closing(fd):
        closed.append(fd)
        return real_close(fd)

    monkeypatch.setattr(os, "open", opening)
    monkeypatch.setattr(os, "close", closing)
    monkeypatch.setattr(os, "fdopen", lambda *a, **k: Interrupted(real_fdopen(*a, **k)))
    with pytest.raises(Cancel):
        store.get_object_bounded("x.age", max_bytes=8)
    assert opened and sorted(opened) == sorted(closed)


def test_local_root_alias_is_host_configuration(tmp_path):
    physical = tmp_path / "physical"
    store = LocalDirectoryBackupStore(physical)
    store.put_object("x.age", b"invented")
    alias = tmp_path / "alias"
    alias.symlink_to(physical, target_is_directory=True)
    aliased = LocalDirectoryBackupStore(alias)
    assert aliased.get_object_bounded("x.age", max_bytes=8) == b"invented"


def test_actual_botocore_valid_streaming_body_checks_eof():
    from botocore.response import StreamingBody

    raw = io.BytesIO(b"invented")
    body = StreamingBody(raw, 8)
    store, _ = remote(body, 8)
    assert store.get_object_bounded("x", max_bytes=8) == b"invented"
    assert raw.closed


def test_actual_botocore_internal_content_length_mismatch_holds():
    from botocore.response import StreamingBody

    raw = io.BytesIO(b"invented")
    # Response declares8 but SDK wrapper expects9. The old sized-only read
    # returned success; EOF must exercise the SDK's independent assurance.
    body = StreamingBody(raw, 9)
    store, _ = remote(body, 8)
    with pytest.raises(RemoteBackupError) as error:
        store.get_object_bounded("x", max_bytes=8)
    assert str(error.value) == "bounded remote backup object unavailable"
    assert raw.closed


@pytest.mark.parametrize("valid", [True, False])
def test_actual_botocore_checksum_wrapper(valid):
    import base64
    import hashlib

    from botocore.httpchecksum import Sha256Checksum, StreamingChecksumBody

    raw = io.BytesIO(b"invented")
    expected = base64.b64encode(
        hashlib.sha256(b"invented" if valid else b"wrong").digest()
    ).decode()
    body = StreamingChecksumBody(raw, 8, Sha256Checksum(), expected)
    store, _ = remote(body, 8)
    if valid:
        assert store.get_object_bounded("x", max_bytes=8) == b"invented"
    else:
        with pytest.raises(RemoteBackupError):
            store.get_object_bounded("x", max_bytes=8)
    assert raw.closed


def test_actual_botocore_oversize_before_any_body_read():
    from botocore.response import StreamingBody

    class Observed(io.BytesIO):
        def __init__(self):
            super().__init__(b"invented")
            self.calls = []

        def read(self, amount=-1):
            self.calls.append(amount)
            return super().read(amount)

    raw = Observed()
    body = StreamingBody(raw, 8)
    store, _ = remote(body, 8)
    with pytest.raises(RemoteBackupError):
        store.get_object_bounded("x", max_bytes=7)
    assert raw.calls == [] and raw.closed


def test_actual_moto_bounded_get_and_ordinary_get_compatibility(monkeypatch):
    import boto3
    from moto import mock_aws

    monkeypatch.delenv("AWS_ENDPOINT_URL", raising=False)
    monkeypatch.delenv("AWS_ENDPOINT_URL_S3", raising=False)
    with mock_aws():
        client = boto3.client("s3", region_name="us-east-1")
        client.create_bucket(Bucket="invented-bounded-object")
        store = S3CompatibleBackupObjectStore(
            bucket="invented-bounded-object",
            region="us-east-1",
            access_key_id="invented",
            secret_access_key="invented",
        )
        store.put_object("x.age", b"invented")
        assert store.get_object_bounded("x.age", max_bytes=8) == b"invented"
        assert store.get_object("x.age") == b"invented"
        with pytest.raises(RemoteBackupError):
            store.get_object_bounded("x.age", max_bytes=7)


def test_local_same_length_inplace_rewrite_after_read_holds(tmp_path, monkeypatch):
    store = LocalDirectoryBackupStore(tmp_path)
    store.put_object("x.age", b"invented")
    original = os.fdopen

    class Rewriting:
        def __init__(self, stream):
            self.stream = stream

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.stream.close()

        def read(self, amount):
            raw = self.stream.read(amount)
            with (tmp_path / "x.age").open("r+b") as writer:
                writer.write(b"changed!")
                writer.flush()
            os.utime(tmp_path / "x.age", ns=(1, 1))
            return raw

    monkeypatch.setattr(os, "fdopen", lambda *a, **k: Rewriting(original(*a, **k)))
    with pytest.raises(BackupArtifactsError):
        store.get_object_bounded("x.age", max_bytes=8)


def test_local_fifo_rejected_before_read(tmp_path, monkeypatch):
    store = LocalDirectoryBackupStore(tmp_path)
    os.mkfifo(tmp_path / "x.age")
    calls = []
    monkeypatch.setattr(os, "fdopen", lambda *a, **k: calls.append(1))
    with pytest.raises(BackupArtifactsError):
        store.get_object_bounded("x.age", max_bytes=8)
    assert calls == []


def test_remote_missing_length_still_closes_body():
    body = Body(b"invented")
    store, _ = remote(body, 8)
    store._client = SimpleNamespace(get_object=lambda **kwargs: {"Body": body})
    with pytest.raises(RemoteBackupError):
        store.get_object_bounded("x", max_bytes=8)
    assert body.closed and body.amounts == []


def test_platform_integer_bound_before_io(tmp_path, monkeypatch):
    import sys

    store = LocalDirectoryBackupStore(tmp_path)
    body = Body(b"invented")
    remote_store, calls = remote(body, 8)
    opened = []
    monkeypatch.setattr(os, "open", lambda *a, **k: opened.append(1))
    for target in (store, remote_store):
        with pytest.raises(BackupArtifactsError):
            target.get_object_bounded("x", max_bytes=sys.maxsize)
    assert opened == calls == []
    body.close()


@pytest.mark.parametrize("failure", ["missing", "read", "ancestor"])
def test_local_fixed_error_has_no_internal_cause_or_context(tmp_path, monkeypatch, failure):
    # Normal execution only: an existing caller exception context is not cleared.
    store = LocalDirectoryBackupStore(tmp_path / "root")
    store.put_object("invented-private-key.age", b"invented")
    if failure == "read":

        def deny_read(*args, **kwargs):
            raise OSError("invented-private-key and confidential diagnostic")

        monkeypatch.setattr(os, "fdopen", deny_read)
        key = "invented-private-key.age"
    elif failure == "ancestor":

        def deny_directory(*args, **kwargs):
            raise PermissionError("invented ancestor diagnostic")

        monkeypatch.setattr(os, "open", deny_directory)
        key = "invented-private-key.age"
    else:
        key = "missing-private-key.age"
    with pytest.raises(BackupArtifactsError) as error:
        store.get_object_bounded(key, max_bytes=8)
    assert str(error.value) == "bounded local backup object unavailable"
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert error.value.__suppress_context__ is False
