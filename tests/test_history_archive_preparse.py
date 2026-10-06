"""Discriminating pre-parser controls. Constructor-call assertions are outside
public exception handling, so swallowed spy failures cannot make tests pass.
"""

import io
import struct
import zipfile

import pytest

from zacai import history_archive_inventory as m


def build(*, names=("x",), extra=b"", comment=b""):
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w") as z:
        for name in names:
            info = zipfile.ZipInfo(name)
            info.extra = extra
            info.comment = comment
            z.writestr(info, b"invented metadata test payload")
    return b.getvalue()


def hold_before_constructor(raw, monkeypatch):
    calls = []

    def constructor(*args, **kwargs):
        calls.append("constructed")
        raise AssertionError("constructor must not be reached")

    monkeypatch.setattr(zipfile, "ZipFile", constructor)
    with pytest.raises(m.HistoryArchiveError):
        m.inspect_history_archive(raw, provider=m.HistoryProvider.CLAUDE)
    assert calls == []


def test_actual_count_greater_than_declared_never_constructs_zipfile(monkeypatch):
    raw = bytearray(build(names=tuple(f"member{i}" for i in range(12))))
    end = raw.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", raw, end + 8, 1, 1)
    hold_before_constructor(bytes(raw), monkeypatch)


@pytest.mark.parametrize("container", ["member-comment", "unknown-extra"])
def test_zip64_embedded_override_never_constructs_zipfile(monkeypatch, container):
    record = struct.pack("<4sQ2H2L4Q", b"PK\x06\x06", 44, 45, 45, 0, 0, 1, 1, 0, 0)
    locator = struct.pack("<4sLQL", b"PK\x06\x07", 0, 0, 1)
    tail = record + locator
    raw = (
        build(comment=tail)
        if container == "member-comment"
        else build(extra=struct.pack("<HH", 0x1234, len(tail)) + tail)
    )
    assert raw[raw.rfind(b"PK\x05\x06") - 20 :][:4] == b"PK\x06\x07"
    hold_before_constructor(raw, monkeypatch)


def test_unsupported_member_comment_rejected_before_constructor(monkeypatch):
    hold_before_constructor(build(comment=b"invented hidden metadata"), monkeypatch)


def test_actual_directory_start_checked_after_parser(monkeypatch):
    raw = build()
    actual = zipfile.ZipFile
    calls = []

    def altered(*args, **kwargs):
        result = actual(*args, **kwargs)
        result.start_dir += 1
        calls.append("parser")
        return result

    monkeypatch.setattr(zipfile, "ZipFile", altered)
    with pytest.raises(m.HistoryArchiveError):
        m.inspect_history_archive(raw, provider=m.HistoryProvider.CLAUDE)
    assert calls == ["parser"]


@pytest.mark.parametrize("field,value", [(10, 1), (10, 31 << 11), (12, 0)])
def test_invalid_or_disagreeing_local_dos_metadata_holds(field, value):
    raw = bytearray(build())
    struct.pack_into("<H", raw, field, value)
    with pytest.raises(m.HistoryArchiveError):
        m.inspect_history_archive(bytes(raw), provider=m.HistoryProvider.CLAUDE)


def test_central_member_disk_number_holds_before_constructor(monkeypatch):
    raw = bytearray(build())
    pos = raw.index(b"PK\x01\x02")
    struct.pack_into("<H", raw, pos + 34, 1)
    hold_before_constructor(bytes(raw), monkeypatch)


def descriptor_archive():
    class Stream(io.BytesIO):
        def seekable(self):
            return False

        def seek(self, *a, **kw):
            raise io.UnsupportedOperation

    stream = Stream()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as z:
        z.writestr("x", b"invented descriptor bytes")
    return stream.getvalue()


def test_unsigned_descriptor_positive():
    raw = bytearray(descriptor_archive())
    central = raw.index(b"PK\x01\x02")
    assert raw[central - 16 : central - 12] == b"PK\x07\x08"
    del raw[central - 16 : central - 12]
    end = raw.rfind(b"PK\x05\x06")
    struct.pack_into("<L", raw, end + 16, central - 4)
    assert (
        m.inspect_history_archive(bytes(raw), provider=m.HistoryProvider.CLAUDE).members[0].filename
        == "x"
    )


def test_corrupt_descriptor_specific_local_guard():
    raw = bytearray(descriptor_archive())
    central = raw.index(b"PK\x01\x02")
    raw[central - 12] ^= 1
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        info = archive.infolist()[0]
    # Direct invariant assertion distinguishes intended failure from outer catch.
    with pytest.raises(ValueError, match="^descriptor$"):
        m._local(bytes(raw), info, central)


def test_actual_overlap_specific_local_guard():
    raw = build()
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        info = archive.infolist()[0]
    central = raw.index(b"PK\x01\x02")
    with pytest.raises(ValueError, match="^payload overlaps$"):
        m._local(raw, info, central - 1)
