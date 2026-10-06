"""Independent invented malformed ZIP controls, frozen implementation unchanged."""

import io
import struct
import zipfile

import pytest

from zacai import history_archive_inventory as m


def make(*, extra=b"", name="invented-private-client-secret-name"):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as z:
        info = zipfile.ZipInfo(name)
        info.extra = extra
        z.writestr(info, b"invented private body marker")
    return stream.getvalue()


def inspect(raw):
    return m.inspect_history_archive(raw, provider=m.HistoryProvider.CLAUDE)


@pytest.mark.parametrize(
    "raw",
    [
        b"private client filename bad archive",
        b"PK\x03\x04private body marker",
        make(extra=b"\x75\x70\xff\xff"),
    ],
)
def test_malformed_archive_has_no_private_text_or_chained_diagnostic(raw):
    with pytest.raises(m.HistoryArchiveError) as caught:
        inspect(raw)
    error = caught.value
    assert error.args == ("history archive envelope rejected",)
    assert error.__cause__ is None and error.__context__ is None
    assert "private" not in str(error) and "marker" not in repr(error)


@pytest.mark.parametrize(
    "extra",
    [
        struct.pack("<HH", 0x0001, 8) + b"12345678",
        struct.pack("<HH", 0x6375, 4) + b"fake",
        struct.pack("<HH", 0x9901, 4) + b"fake",
        b"\x55",
        struct.pack("<HH", 0x5455, 3) + b"x",
    ],
)
def test_unsupported_or_truncated_extra_metadata_holds(extra):
    with pytest.raises(m.HistoryArchiveError):
        inspect(make(extra=extra))


def test_declared_directory_count_mismatch_and_hidden_second_member_hold():
    raw = bytearray(make())
    end = raw.rfind(b"PK\x05\x06")
    # EOCD can lie about both counts consistently while actual directory has one.
    for count in (0, 2):
        changed = bytearray(raw)
        struct.pack_into("<HH", changed, end + 8, count, count)
        with pytest.raises(m.HistoryArchiveError):
            inspect(bytes(changed))


def test_metadata_inventory_does_not_materialize_payload_or_accept_capture_flags(monkeypatch):
    raw = make()
    calls = []

    def forbidden(*a, **kw):
        calls.append("payload")
        raise AssertionError("no archive member body")

    monkeypatch.setattr(zipfile.ZipFile, "open", forbidden)
    monkeypatch.setattr(zipfile.ZipFile, "read", forbidden)
    value = inspect(raw)
    assert not calls
    assert all("body" not in field for field in value.__dataclass_fields__)
    assert value.capture_authorized is False and value.fact_promotion_authorized is False
    with pytest.raises(TypeError):
        m.HistoryArchiveInventory(
            provider=value.provider,
            archive_hash=value.archive_hash,
            archive_bytes=value.archive_bytes,
            members=value.members,
            capture_authorized=True,
        )
