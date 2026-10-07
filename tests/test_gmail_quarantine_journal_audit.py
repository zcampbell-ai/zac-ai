"""Independent first-intent publication tests; disposable owner/AEAD only."""

from __future__ import annotations

import json
import os
import stat
from urllib.parse import urlencode

import pytest
from starlette.requests import Request

from tests.test_gmail_held_reconciliation import Fixture as HeldFixture
from tests.test_gmail_held_reconciliation import inspector
from zacai.connectors.gmail_quarantine_journal import (
    JOURNAL_NAME,
    STAGING_NAME,
    GmailQuarantineJournal,
    GmailQuarantineJournalCancellationUnconfirmed,
    GmailQuarantineJournalCancelled,
    GmailQuarantineJournalError,
    GmailQuarantineJournalUnconfirmed,
)
from zacai.connectors.oauth_host_guard import OAuthHostGuard

ACTION = "invented-quarantine-action"


class Fixture(HeldFixture):
    def __init__(self, temporary, monkeypatch):
        super().__init__(temporary, monkeypatch)
        self.guard = OAuthHostGuard(
            temporary / "guard",
            key=b"S" * 32,
            origin=self.configuration.private_origin,
            client_id=self.owner_client,
        )
        self.guard._directory.mkdir(mode=0o700)
        self.guard.initialize()
        self.guard.halt_unconfirmed()
        self.markers = {
            p: (p.stat().st_ino, p.read_bytes()) for p in self.guard._directory.iterdir()
        }
        self.original = self.snapshot()
        self.stops = []
        self.callback = None
        self.reconciliation = inspector(self)

        def check():
            assert self.guard._ready_path.read_bytes() == self.guard._ready_bytes
            assert self.guard._halt_path.read_bytes() == self.guard._halt_bytes
            assert {
                p: (p.stat().st_ino, p.read_bytes()) for p in self.guard._directory.iterdir()
            } == self.markers
            if self.callback:
                self.callback()

        self.check = check
        self.writer = self.new_writer()

    def new_writer(self, **changes):
        fields = {
            "authority": self.authority,
            "reconciliation": self.reconciliation,
            "configuration": self.configuration,
            "key": b"S" * 32,
            "action_generation": ACTION,
            "preservation_check": self.check,
            "stop": lambda: self.stops.append(True),
        }
        fields.update(changes)
        return GmailQuarantineJournal(**fields)

    def request(self, **changes):
        if not hasattr(self, "writer") or "callback" in changes:
            return super().request(**changes)
        scope = {
            "type": "http",
            "method": "POST",
            "scheme": "https",
            "path": "/connections/gmail/quarantine",
            "query_string": b"",
            "server": ("caz.example", 443),
            "client": ("127.0.0.1", 1),
            "headers": [
                (b"host", b"caz.example"),
                (b"origin", b"https://caz.example"),
                (b"content-type", b"application/x-www-form-urlencoded"),
                (b"cookie", ("__Host-zac-session=" + self.sessions.cookie).encode()),
            ],
        }
        scope.update(changes)
        return Request(scope)

    def form(self, **changes):
        fields = {
            "csrf": self.sessions.csrf,
            "reviewed_configuration_digest": self.configuration.configuration_digest,
            "action_generation": ACTION,
        }
        fields.update(changes)
        return urlencode(fields).encode()

    def write(self, **changes):
        fields = {
            "request": self.request(),
            "body": self.form(),
            "preview": self.writer.preview(cookie=self.sessions.cookie),
        }
        fields.update(changes)
        return self.writer.write_once(**fields)

    def preserved(self):
        for p, expected in self.original.items():
            assert (p.stat().st_ino, p.stat().st_mode, p.read_bytes()) == expected
        assert {
            p: (p.stat().st_ino, p.read_bytes()) for p in self.guard._directory.iterdir()
        } == self.markers
        assert not self.side_effects


@pytest.fixture
def f(tmp_path, monkeypatch):
    return Fixture(tmp_path, monkeypatch)


def test_actual_private_preview_exclusive_publication_originals_preserved(f, monkeypatch):
    preview = f.writer.preview(cookie=f.sessions.cookie)
    assert f.snapshot() == f.original
    links = []
    original_link = os.link

    def link(src, dst, **kwargs):
        assert src.name == STAGING_NAME and dst.name == JOURNAL_NAME
        assert src.stat().st_nlink == 1 and not dst.exists()
        original_link(src, dst, **kwargs)
        links.append((src.stat().st_ino, dst.stat().st_ino, src.stat().st_nlink))

    monkeypatch.setattr(os, "link", link)
    receipt = f.writer.write_once(request=f.request(), body=f.form(), preview=preview)
    assert len(links) == 1 and links[0][0] == links[0][1] and links[0][2] == 2
    target = f.directory / JOURNAL_NAME
    assert target.stat().st_nlink == 1 and stat.S_IMODE(target.stat().st_mode) == 0o600
    assert not (f.directory / STAGING_NAME).exists()
    raw = target.read_bytes()
    record = json.loads(f.writer._cipher.decrypt(raw[:12], raw[12:], f.writer._context))
    _, state = f.row()
    assert record["original_row"] == json.loads(preview._reference._row)
    assert record["state_hash"] == state and record["native_generation"] == f.generation
    assert record["remote_grant_status"] == "unknown"
    assert receipt.status == "quarantine_intent_recorded"
    assert all(
        getattr(receipt, name) is False
        for name in (
            "installed",
            "quarantine_committed",
            "quarantine_authorized",
            "recovery_authorized",
            "current_reviewer_verified",
            "original_actor_verified",
            "native_material_verified",
            "source_subject_verified",
            "live_access_proven",
            "credential_authority",
            "processing_authorized",
            "execution_authorized",
        )
    )
    f.preserved()
    with pytest.raises(GmailQuarantineJournalError):
        f.writer.write_once(request=f.request(), body=f.form(), preview=preview)
    assert target.read_bytes() == raw


@pytest.mark.parametrize(
    "kind",
    [
        "origin",
        "host",
        "cookie",
        "csrf",
        "digest",
        "action",
        "duplicate",
        "extra",
        "query",
        "content_type",
    ],
)
def test_owner_form_failures_zero_publication_and_spent(f, kind):
    preview = f.writer.preview(cookie=f.sessions.cookie)
    request, body = f.request(), f.form()
    if kind in {"origin", "host", "cookie", "content_type"}:
        key = {"content_type": b"content-type"}.get(kind, kind.encode())
        headers = [(k, b"invented-invalid" if k == key else v) for k, v in request.scope["headers"]]
        request = f.request(headers=headers)
    elif kind == "query":
        request = f.request(query_string=b"unexpected=1")
    elif kind == "duplicate":
        body += b"&csrf=" + f.sessions.csrf.encode()
    elif kind == "extra":
        body += b"&approved=true"
    else:
        body = f.form(
            **{
                {"digest": "reviewed_configuration_digest", "action": "action_generation"}.get(
                    kind, kind
                ): "invented-invalid"
            }
        )
    with pytest.raises(GmailQuarantineJournalError):
        f.writer.write_once(request=request, body=body, preview=preview)
    assert (
        f.writer._spent
        and not (f.directory / JOURNAL_NAME).exists()
        and not (f.directory / STAGING_NAME).exists()
    )
    f.preserved()


@pytest.mark.parametrize("name", [JOURNAL_NAME, STAGING_NAME])
def test_existing_target_or_crash_stage_never_overwritten(f, name):
    target = f.directory / name
    target.write_bytes(b"invented-owned-residue")
    target.chmod(0o600)
    before = (target.stat().st_ino, target.read_bytes())
    with pytest.raises(GmailQuarantineJournalError):
        f.writer.preview(cookie=f.sessions.cookie)
    assert (target.stat().st_ino, target.read_bytes()) == before
    f.preserved()


def test_foreign_private_preview_cannot_substitute(f):
    other = f.new_writer()
    preview = other.preview(cookie=f.sessions.cookie)
    with pytest.raises(GmailQuarantineJournalError):
        f.writer.write_once(request=f.request(), body=f.form(), preview=preview)
    assert not (f.directory / JOURNAL_NAME).exists()
    f.preserved()


@pytest.mark.parametrize("change", ["revoke", "row_inode", "halt", "new_child"])
def test_callback_tampering_denies_before_publication(f, change):
    preview = f.writer.preview(cookie=f.sessions.cookie)

    def mutate():
        f.callback = None
        if change == "revoke":
            f.sessions.sessions.revoke(f.sessions.cookie)
        elif change == "row_inode":
            path = f.authority._path
            replacement = f.directory / "invented-replacement"
            replacement.write_bytes(path.read_bytes())
            replacement.chmod(0o600)
            os.replace(replacement, path)
        elif change == "halt":
            f.guard._halt_path.write_bytes(b"wrong-halt")
        else:
            path = f.directory / "unexpected-child"
            path.write_bytes(b"invented")
            path.chmod(0o600)

    f.callback = mutate
    with pytest.raises(GmailQuarantineJournalError):
        f.writer.write_once(request=f.request(), body=f.form(), preview=preview)
    assert not (f.directory / JOURNAL_NAME).exists() and f.stops


@pytest.mark.parametrize(
    "seam", ["link", "unlink", "directory_fsync", "pread", "cancel_after_link"]
)
def test_uncertain_publication_stops_preserves_evidence_without_retry(f, monkeypatch, seam):
    preview = f.writer.preview(cookie=f.sessions.cookie)
    link, fsync, pread = os.link, os.fsync, os.pread

    def fail(*args, **kwargs):
        raise OSError("invented-private-fault")

    if seam == "link":
        monkeypatch.setattr(os, "link", fail)
    elif seam == "unlink":
        monkeypatch.setattr(os, "unlink", fail)
    elif seam == "directory_fsync":

        def sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                fail()
            return fsync(fd)

        monkeypatch.setattr(os, "fsync", sync)
    elif seam == "pread":

        def read(fd, size, offset):
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) == f.writer._stage_inode:
                return b"wrong-authenticated-readback"
            return pread(fd, size, offset)

        monkeypatch.setattr(os, "pread", read)
    else:

        def cancel(src, dst, **kwargs):
            link(src, dst, **kwargs)
            raise KeyboardInterrupt("invented-private-cancel")

        monkeypatch.setattr(os, "link", cancel)
    expected = (
        GmailQuarantineJournalCancellationUnconfirmed
        if seam == "cancel_after_link"
        else GmailQuarantineJournalUnconfirmed
    )
    with pytest.raises(expected) as caught:
        f.writer.write_once(request=f.request(), body=f.form(), preview=preview)
    assert f.writer._spent and f.stops
    assert caught.value.__cause__ is None and caught.value.__context__ is None
    assert "invented-private" not in str(caught.value)
    if seam != "link":
        assert (f.directory / JOURNAL_NAME).exists()
    f.preserved()
    before = {p: p.read_bytes() for p in f.directory.iterdir()}
    with pytest.raises(GmailQuarantineJournalError):
        f.writer.write_once(request=f.request(), body=f.form(), preview=preview)
    assert {p: p.read_bytes() for p in f.directory.iterdir()} == before


@pytest.mark.parametrize("mutation", ["extra_link", "stage_swap"])
def test_link_publication_substitution_never_unlinks_foreign_stage(f, monkeypatch, mutation):
    preview = f.writer.preview(cookie=f.sessions.cookie)
    original_link = os.link
    foreign = f.directory.parent / "invented-foreign-stage"
    foreign.write_bytes(b"invented-foreign-owned-evidence")
    foreign.chmod(0o600)
    foreign_inode = foreign.stat().st_ino

    def link(src, dst, **kwargs):
        original_link(src, dst, **kwargs)
        if mutation == "extra_link":
            original_link(src, f.directory.parent / "invented-extra-link")
        else:
            os.replace(foreign, src)

    monkeypatch.setattr(os, "link", link)
    with pytest.raises(GmailQuarantineJournalUnconfirmed):
        f.writer.write_once(request=f.request(), body=f.form(), preview=preview)
    assert (f.directory / JOURNAL_NAME).exists() and f.stops and f.writer._spent
    if mutation == "stage_swap":
        assert (f.directory / STAGING_NAME).stat().st_ino == foreign_inode
        assert (f.directory / STAGING_NAME).read_bytes() == b"invented-foreign-owned-evidence"
    else:
        assert (f.directory / JOURNAL_NAME).stat().st_nlink == 3
    f.preserved()


@pytest.mark.parametrize(
    "seam",
    [
        "stage_reuse",
        "published_stage_reuse",
        "directory_reuse",
        "owned_denial",
        "owned_mode_denial",
    ],
)
def test_final_cleanup_closes_only_retained_owned_descriptor(f, monkeypatch, seam):
    preview = f.writer.preview(cookie=f.sessions.cookie)
    foreign = f.directory.parent / "invented-foreign-descriptor"
    foreign.write_bytes(b"foreign-descriptor-must-remain-open")
    foreign.chmod(0o600)
    foreign_inode = foreign.stat().st_ino
    open_original, close_original = os.open, os.close
    directory_fd = []
    selected = []
    closed = []
    foreign_effects = []
    originals = {name: getattr(os, name) for name in ("write", "read", "pread", "fsync")}

    def observe(name):
        def effect(fd, *args, **kwargs):
            try:
                if os.fstat(fd).st_ino == foreign_inode:
                    foreign_effects.append(name)
            except OSError:
                pass
            return originals[name](fd, *args, **kwargs)

        return effect

    for name in originals:
        monkeypatch.setattr(os, name, observe(name))

    def opened(path, flags, *args, **kwargs):
        fd = open_original(path, flags, *args, **kwargs)
        if path == f.directory and flags & os.O_DIRECTORY:
            directory_fd.append(fd)
        return fd

    def close(fd):
        try:
            info = os.fstat(fd)
        except OSError:
            info = None
        closed.append((fd, info.st_ino if info else None))
        return close_original(fd)

    monkeypatch.setattr(os, "open", opened)
    monkeypatch.setattr(os, "close", close)

    def change():
        if selected:
            return
        target = (
            (directory_fd[-1] if directory_fd else None)
            if seam == "directory_reuse"
            else f.writer._stage_fd
        )
        if target is None:
            return
        if seam == "published_stage_reuse" and not f.writer._stage_removed:
            return
        selected.append(target)
        if seam == "owned_mode_denial":
            os.fchmod(target, 0o400)
            return
        if seam == "owned_denial":
            raise RuntimeError("invented-owner-preservation-denial")
        close_original(target)
        replacement = open_original(foreign, os.O_RDONLY)
        if replacement != target:
            os.dup2(replacement, target)
            close_original(replacement)

    f.callback = change
    with pytest.raises(GmailQuarantineJournalUnconfirmed):
        f.writer.write_once(request=f.request(), body=f.form(), preview=preview)
    assert selected and f.stops and f.writer._spent
    assert foreign_effects == []
    assert foreign.read_bytes() == b"foreign-descriptor-must-remain-open"
    if seam in {"owned_denial", "owned_mode_denial"}:
        assert any(fd == selected[0] and inode == f.writer._stage_inode[1] for fd, inode in closed)
        with pytest.raises(OSError):
            os.fstat(selected[0])
    else:
        try:
            assert os.fstat(selected[0]).st_ino == foreign_inode
            assert not any(fd == selected[0] and inode == foreign_inode for fd, inode in closed)
        finally:
            try:
                close_original(selected[0])
            except OSError:
                pass
    f.preserved()


@pytest.mark.parametrize("seam", ["preview_clock", "write_preservation"])
@pytest.mark.parametrize("interrupt", [False, True])
def test_original_transaction_lock_reuse_cannot_publish_or_touch_foreign_fd(
    f, monkeypatch, seam, interrupt
):
    preview = None
    if seam == "write_preservation":
        preview = f.writer.preview(cookie=f.sessions.cookie)
    foreign = f.directory.parent / "invented-foreign-lock-fd"
    foreign.write_bytes(b"invented-foreign-lock-evidence")
    foreign.chmod(0o600)
    inode = foreign.stat().st_ino
    opened_original, closed_original = os.open, os.close
    original_effects = {name: getattr(os, name) for name in ("read", "pread", "write", "fsync")}
    import fcntl

    lockfds = []
    retained_flock = []
    selected = []
    effects = []

    def opened(path, flags, *args, **kwargs):
        fd = opened_original(path, flags, *args, **kwargs)
        if path == f.authority._lock_path and flags & os.O_RDWR:
            lockfds.append(fd)
        return fd

    def close(fd):
        try:
            if os.fstat(fd).st_ino == inode:
                effects.append("close")
        except OSError:
            pass
        return closed_original(fd)

    def observe(name):
        def call(fd, *args, **kwargs):
            if os.fstat(fd).st_ino == inode:
                effects.append(name)
            return original_effects[name](fd, *args, **kwargs)

        return call

    monkeypatch.setattr(os, "open", opened)
    monkeypatch.setattr(os, "close", close)
    for name in original_effects:
        monkeypatch.setattr(os, name, observe(name))

    def reuse():
        if selected or not lockfds:
            return
        target = lockfds[-1]
        selected.append(target)
        closed_original(target)
        new = opened_original(foreign, os.O_RDWR)
        if new != target:
            os.dup2(new, target)
            closed_original(new)
        probe = opened_original(f.authority._lock_path, os.O_RDWR | os.O_NOFOLLOW)
        try:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                retained_flock.append(True)
            else:
                retained_flock.append(False)
        finally:
            closed_original(probe)
        if interrupt:
            raise KeyboardInterrupt("invented-interrupted-original-lock")

    if seam == "write_preservation":
        f.callback = reuse
    else:
        clock_read = f.sessions.clock._read

        def read():
            reuse()
            return clock_read()

        monkeypatch.setattr(f.sessions.clock, "_read", read)
    try:
        if seam == "write_preservation":
            failure = (
                GmailQuarantineJournalCancellationUnconfirmed
                if interrupt
                else GmailQuarantineJournalUnconfirmed
            )
            with pytest.raises(failure):
                f.writer.write_once(request=f.request(), body=f.form(), preview=preview)
            assert f.writer._spent and f.stops
        else:
            failure = GmailQuarantineJournalCancelled if interrupt else GmailQuarantineJournalError
            with pytest.raises(failure):
                f.writer.preview(cookie=f.sessions.cookie)
            assert f.writer._preview is None
        assert selected and effects == [] and retained_flock == [True]
        assert os.fstat(selected[0]).st_ino == inode
        assert (
            not (f.directory / JOURNAL_NAME).exists() and not (f.directory / STAGING_NAME).exists()
        )
        assert foreign.read_bytes() == b"invented-foreign-lock-evidence"
        f.preserved()
    finally:
        if selected:
            try:
                closed_original(selected[0])
            except OSError:
                pass
