"""Invented nullable leaf representations; no mail, credentials or model use."""

import json

import pytest

from tests.test_gmail_app_observation import BODY, args, observation
from zacai.ingestion.gmail_app_observation import (
    GmailAppObservationError,
    prepare_gmail_app_observation,
)


def test_null_leaf_parts_preserve_exact_raw_and_literal_body():
    value = observation()
    for child in value["payload"]["parts"]:
        child["parts"] = None
    supplied = args(value)
    result = prepare_gmail_app_observation(**supplied)
    assert result.artifacts[0].original_bytes == supplied["raw"]
    assert all(
        child["parts"] is None
        for child in json.loads(result.artifacts[0].original_bytes)["payload"]["parts"]
    )
    assert result.literal_text == BODY
    assert len(result.companion.parts) == 4
    assert result.companion.parts[-1].attachment_reference == "invented-image-ref"
    assert result.companion.provider_raw_available is False
    assert result.companion.acquisition_account_verified is False


def test_selected_root_text_with_null_parts_is_a_whole_body():
    value = observation()
    value["payload"] = {"mime_type": "text/plain", "body": {"content": BODY}, "parts": None}
    supplied = args(value, selected_part_path=())
    result = prepare_gmail_app_observation(**supplied)
    assert result.literal_text == BODY
    assert len(result.companion.parts) == 1
    assert result.artifacts[0].original_bytes == supplied["raw"]


@pytest.mark.parametrize("invalid", [False, 0, "", {}, [None], [False]])
def test_other_non_list_or_invalid_children_still_hold(invalid):
    value = observation()
    value["payload"]["parts"][0]["parts"] = invalid
    with pytest.raises(GmailAppObservationError):
        prepare_gmail_app_observation(**args(value))


def test_null_container_does_not_manufacture_selected_descendant():
    value = observation()
    value["payload"]["parts"] = None
    with pytest.raises(GmailAppObservationError):
        prepare_gmail_app_observation(**args(value))
