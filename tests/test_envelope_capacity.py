"""Actual public parser/composer; SQL/savepoints simulated, no max proof."""

import json
from dataclasses import replace
from uuid import UUID

import pytest

from tests.test_native_source_capture import m
from tests.test_native_source_capture import setup as setup  # noqa: PLC0414 - pytest fixture
from zacai.ingestion.artifact_store import content_hash_of
from zacai.ingestion.native_source_preparation import (
    NativeSourcePreparationError,
    prepare_gmail_source,
)


def test_actual_parser_rejects_3000_char_labels_before_composer(setup):
    _, args = setup
    mail = args["gmail_inputs"][0]
    value = json.loads(mail.message_response)
    value["labelIds"] = ["L" + str(n) + "x" * 3000 for n in range(100)]
    with pytest.raises(NativeSourcePreparationError):
        prepare_gmail_source(
            scope=mail.scope,
            profile_response=mail.profile_response,
            message_response=json.dumps(value).encode(),
            expected_message_id=mail.expected_message_id,
            captured_at=args["captured_at"],
        )


def test_six_public_mail_selections_with_100_maxwidth_labels_remain_valid(setup):
    sql, args = setup
    mail = args["gmail_inputs"][0]
    value = json.loads(mail.message_response)
    value["labelIds"] = ["L" + str(n).zfill(2) + "x" * 197 for n in range(100)]
    assert all(len(label) == 200 for label in value["labelIds"])
    mails = []
    for n in range(6):
        altered = {**value, "id": "abc" + str(n)}
        changed = replace(
            mail, message_response=json.dumps(altered).encode(), expected_message_id=altered["id"]
        )
        parsed = prepare_gmail_source(
            scope=changed.scope,
            profile_response=changed.profile_response,
            message_response=changed.message_response,
            expected_message_id=changed.expected_message_id,
            captured_at=args["captured_at"],
        )
        assert len(json.loads(parsed.declared_selection_bytes)["labels"]) == 100
        mails.append(changed)
    bid = UUID(json.loads(args["proposal_raw"])["batch_id"])
    raw = m.prepare_native_batch_proposal(
        batch_id=bid, gmail_inputs=tuple(mails), slack_inputs=args["slack_inputs"]
    )
    receipt = m.record_native_batch(
        sql,
        **{
            **args,
            "gmail_inputs": tuple(mails),
            "proposal_raw": raw,
            "approved_proposal_hash": content_hash_of(raw),
        },
    )
    source = sql.get(m.Source, receipt.batch_reference.source_id)
    retained = args["artifacts"].get(source.trust_boundary, source.content_location)
    assert 120_000 < len(retained) <= 256_000 and len(receipt.artifact_references) == 7
