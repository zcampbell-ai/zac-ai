"""Exercise actual inherited Slack read algorithm with invented C primitives."""

import ctypes

import pytest

from zacai.connectors.slack_native_installation import _SlackBindings


@pytest.mark.parametrize("case", ["success", "oversize", "cancel", "free_failure"])
def test_actual_slack_retained_read_frees_owned_buffer_exactly_once(case):
    bridge = object.__new__(_SlackBindings)
    payload = ctypes.create_string_buffer(b"invented-pair")
    calls = []
    bridge._typed = lambda reference, expected: reference
    bridge._item_type = lambda: 1

    def attributes(item, info, item_class, metadata, length, data):
        calls.append("data")
        assert item == 123
        length._obj.value = 16385 if case == "oversize" else len(b"invented-pair")
        data._obj.value = ctypes.addressof(payload)
        return 0

    def free(attributes, data):
        calls.append("free")
        assert data.value == ctypes.addressof(payload)
        return 1 if case == "free_failure" else 0

    def current():
        calls.append("current")
        if case == "cancel":
            raise KeyboardInterrupt("invented interruption after allocation")

    bridge._attributes = attributes
    bridge._free_attributes = free
    bridge._checker = current
    if case == "success":
        assert bridge.read_item(123, 16384) == b"invented-pair"
    else:
        with pytest.raises(KeyboardInterrupt if case == "cancel" else ValueError):
            bridge.read_item(123, 16384)
    assert calls.count("data") == 1
    assert calls.count("free") == 1
