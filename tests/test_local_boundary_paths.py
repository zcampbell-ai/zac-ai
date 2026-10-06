"""Invented filesystem content only; no canonical DB/private artifacts."""
import os

import pytest

from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore, content_hash_of
from zacai.policy import TrustBoundary as B


def test_personal_crossover_is_denied(tmp_path):
    store = LocalFilesystemArtifactStore(tmp_path/'artifacts')
    payload = b'invented PERSONAL bytes'
    location = store.put(B.PERSONAL, content_hash_of(payload), payload)
    assert store.get(B.PERSONAL, location) == payload
    own = b'invented BRAINSTORM bytes'
    store.put(B.BRAINSTORM, content_hash_of(own), own)
    with pytest.raises(ValueError):
        store.get(B.BRAINSTORM, '../PERSONAL/'+location)


@pytest.mark.parametrize('kind', ('boundary', 'shard', 'file', 'hardlink'))
def test_canonical_shape_link_crossover_is_denied(tmp_path, kind):
    store = LocalFilesystemArtifactStore(tmp_path/'artifacts')
    payload = b'invented personal canonical suffix'
    location = store.put(B.PERSONAL, content_hash_of(payload), payload)
    source = store.root/B.PERSONAL.value/location
    boundary = store.root/B.BRAINSTORM.value
    if kind == 'boundary':
        boundary.symlink_to(source.parent.parent, target_is_directory=True)
    else:
        boundary.mkdir()
        shard = boundary/source.parent.name
        if kind == 'shard':
            shard.symlink_to(source.parent, target_is_directory=True)
        else:
            shard.mkdir()
            if kind == 'file':
                (shard/source.name).symlink_to(source)
            else:
                os.link(source, shard/source.name)
    with pytest.raises((ValueError, OSError)):
        store.get(B.BRAINSTORM, location)


@pytest.mark.parametrize('location', ('/etc/passwd','../PERSONAL/x','aa/../bb/x','AA/'+'a'*64+'.bin',
    'bb/'+'a'*64+'.bin','aa/'+'a'*64+'.bin/extra','aa/'+'a'*64+'.bin\x00'))
def test_invalid_location_rejected_before_file_open(tmp_path, monkeypatch, location):
    store = LocalFilesystemArtifactStore(tmp_path/'artifacts')
    opened = []
    monkeypatch.setattr(os, 'open', lambda *a, **kw: opened.append(True))
    with pytest.raises(ValueError):
        store.get(B.BRAINSTORM, location)
    assert not opened


def test_corrupt_content_address_is_denied(tmp_path):
    store = LocalFilesystemArtifactStore(tmp_path/'artifacts')
    raw = b'invented original'
    location = store.put(B.BRAINSTORM, content_hash_of(raw), raw)
    (store.root/B.BRAINSTORM.value/location).write_bytes(b'invented drift')
    with pytest.raises(OSError):
        store.get(B.BRAINSTORM, location)


def test_backup_read_failure_remains_typed_without_encryption_or_put(tmp_path, monkeypatch):
    from zacai import backup_artifacts as backup
    store = LocalFilesystemArtifactStore(tmp_path/'artifacts')
    original = b'invented backup input'
    digest = content_hash_of(original)
    location = store.put(B.BRAINSTORM, digest, original)
    (store.root/B.BRAINSTORM.value/location).write_bytes(b'invented local corruption')
    calls = []
    def encrypt(*args):
        calls.append('encrypt')
        raise AssertionError('corrupt artifact reached encryption')
    monkeypatch.setattr(backup, 'age_encrypt', encrypt)
    objects = backup.LocalDirectoryBackupStore(tmp_path/'objects')
    key = backup.backup_object_key_for(B.BRAINSTORM, digest)
    with pytest.raises(backup.BackupArtifactsError):
        backup._verify_or_repair(None, trust_boundary=B.BRAINSTORM,
            content_hash=digest, content_location=location, key=key,
            artifact_store=store, backup_store=objects, recipient='invented unused recipient')
    assert not calls and not objects.exists(key)


@pytest.mark.parametrize('kind', ('boundary', 'shard', 'file', 'hardlink'))
def test_put_rejects_links_without_chmod_or_repair(tmp_path, kind):
    store = LocalFilesystemArtifactStore(tmp_path/'artifacts')
    raw = b'invented cross-write bytes'
    digest = content_hash_of(raw)
    location = store.put(B.PERSONAL, digest, raw)
    source = store.root/B.PERSONAL.value/location
    boundary = store.root/B.BRAINSTORM.value
    if kind == 'boundary':
        boundary.symlink_to(source.parent.parent, target_is_directory=True)
    else:
        boundary.mkdir()
        shard = boundary/source.parent.name
        if kind == 'shard':
            shard.symlink_to(source.parent, target_is_directory=True)
        else:
            shard.mkdir()
            if kind == 'file':
                (shard/source.name).symlink_to(source)
            else:
                os.link(source, shard/source.name)
    os.chmod(source.parent, 0o750)
    os.chmod(source.parent.parent, 0o750)
    with pytest.raises(OSError):
        store.put(B.BRAINSTORM, digest, raw)
    assert source.read_bytes() == raw
    assert source.parent.stat().st_mode & 0o777 == 0o750
    assert source.parent.parent.stat().st_mode & 0o777 == 0o750


@pytest.mark.parametrize('case', ('hash', 'raw_hash', 'raw_type', 'boundary'))
def test_put_validates_before_any_file_operation(tmp_path, monkeypatch, case):
    from types import SimpleNamespace
    store = LocalFilesystemArtifactStore(tmp_path/'artifacts')
    raw = b'invented valid'
    boundary, digest = B.BRAINSTORM, content_hash_of(raw)
    if case == 'hash':
        digest = '../PERSONAL'
    elif case == 'raw_hash':
        raw = b'invented mismatch'
    elif case == 'raw_type':
        raw = bytearray(raw)
    else:
        boundary = SimpleNamespace(value='PERSONAL')
    calls = []
    monkeypatch.setattr(os, 'open', lambda *a, **kw: calls.append('open'))
    monkeypatch.setattr(os, 'mkdir', lambda *a, **kw: calls.append('mkdir'))
    with pytest.raises(ValueError):
        store.put(boundary, digest, raw)
    assert not calls


def test_existing_corruption_holds_without_repair(tmp_path):
    store = LocalFilesystemArtifactStore(tmp_path/'artifacts')
    raw = b'invented genuine'
    digest = content_hash_of(raw)
    location = store.put(B.BRAINSTORM, digest, raw)
    target = store.root/B.BRAINSTORM.value/location
    target.write_bytes(b'invented corrupt')
    with pytest.raises(OSError):
        store.put(B.BRAINSTORM, digest, raw)
    assert target.read_bytes() == b'invented corrupt'
    assert not tuple(target.parent.glob('.tmp-*'))


def test_configured_root_alias_is_resolved_once_and_safety_guard_preserved(tmp_path):
    from zacai.backup_artifacts import assert_safe_restore_target
    fixed, other = tmp_path/'fixed', tmp_path/'other'
    fixed.mkdir(); other.mkdir()
    alias = tmp_path/'trusted-config-alias'
    alias.symlink_to(fixed, target_is_directory=True)
    store = LocalFilesystemArtifactStore(alias)
    assert store.root == fixed.resolve()
    with pytest.raises(RuntimeError, match='live artifact store'):
        assert_safe_restore_target(store.root, fixed)
    alias.unlink(); alias.symlink_to(other, target_is_directory=True)
    raw = b'invented stable root'
    location = store.put(B.BRAINSTORM, content_hash_of(raw), raw)
    assert (fixed/B.BRAINSTORM.value/location).read_bytes() == raw
    assert not tuple(other.iterdir())


def test_constructor_resolved_root_replacement_does_not_follow_or_chmod(tmp_path, monkeypatch):
    outside = tmp_path/'outside'
    outside.mkdir(mode=0o750)
    root = tmp_path/'new-root'
    original_mkdir = os.mkdir
    fired = []
    def replace(part, *args, **kwargs):
        result = original_mkdir(part, *args, **kwargs)
        if part == root.name and kwargs.get('dir_fd') is not None:
            root.rename(tmp_path/'retained-original')
            root.symlink_to(outside, target_is_directory=True)
            fired.append(True)
        return result
    monkeypatch.setattr(os, 'mkdir', replace)
    with pytest.raises(OSError):
        LocalFilesystemArtifactStore(root)
    assert fired == [True]
    assert outside.stat().st_mode & 0o777 == 0o750
    assert not tuple(outside.iterdir())


def test_interrupted_write_closes_descriptor_and_cleans_only_temp(tmp_path, monkeypatch):
    store = LocalFilesystemArtifactStore(tmp_path/'artifacts')
    raw = b'invented interrupt'
    digest = content_hash_of(raw)
    fdopen, close = os.fdopen, os.close
    created, closed = [], []
    def recorded_close(fd):
        closed.append(fd)
        return close(fd)
    monkeypatch.setattr(os, 'close', recorded_close)
    def interrupt(fd, mode, **kwargs):
        if mode == 'wb':
            created.append(fd)
            raise KeyboardInterrupt()
        return fdopen(fd, mode, **kwargs)
    monkeypatch.setattr(os, 'fdopen', interrupt)
    with pytest.raises(KeyboardInterrupt):
        store.put(B.BRAINSTORM, digest, raw)
    assert len(created) == 1
    assert created[0] in closed
    assert not tuple((store.root/B.BRAINSTORM.value/digest[:2]).iterdir())


def test_macos_var_alias_is_compatible(tmp_path):
    from pathlib import Path
    if not str(tmp_path).startswith('/private/var/') or Path('/var').resolve() != Path('/private/var'):
        pytest.skip('macOS var alias only')
    alias = Path('/var')/tmp_path.relative_to('/private/var')/'artifacts'
    store = LocalFilesystemArtifactStore(alias)
    raw = b'invented var alias'
    location = store.put(B.BRAINSTORM, content_hash_of(raw), raw)
    assert store.root == (tmp_path/'artifacts').resolve()
    assert store.get(B.BRAINSTORM, location) == raw


def test_macos_tmp_alias_is_compatible():
    from pathlib import Path
    from tempfile import TemporaryDirectory
    if Path('/tmp').resolve() != Path('/private/tmp'):
        pytest.skip('macOS tmp alias only')
    with TemporaryDirectory(prefix='caz-invented-artifacts-', dir='/private/tmp') as temporary:
        real = Path(temporary)
        store = LocalFilesystemArtifactStore(Path('/tmp')/real.name/'artifacts')
        raw = b'invented tmp alias'
        location = store.put(B.PERSONAL, content_hash_of(raw), raw)
        assert store.root == real/'artifacts'
        assert store.get(B.PERSONAL, location) == raw


def test_existing_directories_never_mkdir_and_valid_repeat_preserves_inode(tmp_path, monkeypatch):
    store = LocalFilesystemArtifactStore(tmp_path/'artifacts')
    raw = b'invented repeat'
    digest = content_hash_of(raw)
    location = store.put(B.BRAINSTORM, digest, raw)
    target = store.root/B.BRAINSTORM.value/location
    before = target.stat()
    def denied(*args, **kwargs):
        raise AssertionError('mkdir attempted for existing directory')
    monkeypatch.setattr(os, 'mkdir', denied)
    assert store.put(B.BRAINSTORM, digest, raw) == location
    after = target.stat()
    assert (after.st_dev, after.st_ino, after.st_mtime_ns) == (before.st_dev, before.st_ino, before.st_mtime_ns)


def test_actual_macos_var_alias_restore_guard_denies_same_target(tmp_path):
    from pathlib import Path

    from zacai.backup_artifacts import assert_safe_restore_target
    if not str(tmp_path).startswith('/private/var/') or Path('/var').resolve() != Path('/private/var'):
        pytest.skip('macOS var alias only')
    alias = Path('/var')/tmp_path.relative_to('/private/var')/'artifacts'
    store = LocalFilesystemArtifactStore(tmp_path/'artifacts')
    with pytest.raises(RuntimeError, match='live artifact store'):
        assert_safe_restore_target(store.root, alias)
    with pytest.raises(RuntimeError, match='live artifact store'):
        assert_safe_restore_target(alias, store.root)


def test_fifo_final_target_fails_promptly_without_read(tmp_path):
    import importlib
    import subprocess
    import sys
    module = importlib.import_module("zacai.ingestion.artifact_store")
    store = LocalFilesystemArtifactStore(tmp_path/'artifacts')
    raw = b'invented FIFO address'
    digest = content_hash_of(raw)
    location = store.put(B.BRAINSTORM, digest, raw)
    target = store.root/B.BRAINSTORM.value/location
    target.unlink()
    os.mkfifo(target)
    code = '''import importlib.util,sys
sys.path.insert(0,"/Users/brainstormzac/zac-ai/src")
spec=importlib.util.spec_from_file_location("artifact_check",sys.argv[1])
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
from zacai.policy import TrustBoundary as B
from pathlib import Path
s=m.LocalFilesystemArtifactStore(Path(sys.argv[2]))
try:s.get(B.BRAINSTORM,sys.argv[3])
except OSError:sys.exit(0)
sys.exit(1)
'''
    result = subprocess.run([sys.executable, '-c', code, module.__file__, str(store.root), location],
                            timeout=2, capture_output=True, check=False)
    assert result.returncode == 0


def test_directory_final_target_is_rejected(tmp_path):
    store = LocalFilesystemArtifactStore(tmp_path/'artifacts')
    raw = b'invented directory address'
    digest = content_hash_of(raw)
    location = store.put(B.BRAINSTORM, digest, raw)
    target = store.root/B.BRAINSTORM.value/location
    target.unlink(); target.mkdir()
    with pytest.raises(OSError):
        store.get(B.BRAINSTORM, location)
    with pytest.raises(OSError):
        store.put(B.BRAINSTORM, digest, raw)
