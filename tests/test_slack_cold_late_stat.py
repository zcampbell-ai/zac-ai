import os

import pytest

from test_slack_cold_record import CONTEXT, KEY, read, record, save
from zacai.connectors.slack_native_installation import _v2_encode


@pytest.mark.parametrize("fault", ["mode", "link"])
def test_late_stat_change_visible_in_linked_stat_is_rejected(tmp_path, monkeypatch, fault):
    encoded = _v2_encode(record(), state="pending", key=KEY, context=CONTEXT)
    path = save(tmp_path, encoded)
    original = os.fstat
    calls = []

    def observed(fd):
        result = original(fd)
        calls.append(fd)
        if len(calls) == 2:
            if fault == "mode":
                path.chmod(0o644)
            else:
                os.link(path, tmp_path / "late-link.bin")
        return result

    monkeypatch.setattr(os, "fstat", observed)
    with pytest.raises(ValueError, match="original installation file"):
        read(tmp_path)
