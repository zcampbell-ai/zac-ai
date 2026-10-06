"""Offline EMAIL/SLACK artifact preparation from exact original provider replies.

No account login, token access, source/artifact write, approval, backup or model.
Parsed replies remain untrusted source evidence. Host-declared scope is not a
permission grant. The caller must authenticate current accounts/classification,
commit canonical rows and independently protect them before saved knowledge.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Literal

from zacai.connectors.gmail_wire import GmailScope, inspect_profile, inspect_raw_message
from zacai.connectors.slack_wire import (
    HistorySelection,
    RepliesSelection,
    prepare_account_reply,
    prepare_history_reply,
    prepare_replies_reply,
    slack_timestamp_datetime,
)
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.policy import AccessRequest, Destination, evaluate_access
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.state import SourceSystem


class NativeSourcePreparationError(ValueError):
    """Fixed diagnostic, no source prose/account/private exception chains."""


ArtifactKind = Literal[
    'provider-profile-json', 'provider-message-json', 'decoded-rfc822',
    'provider-account-json', 'provider-page-json', 'canonical-message-json',
]


@dataclass(frozen=True, repr=False)
class OriginalWireReference:
    external_ref: str
    content_hash: str


@dataclass(frozen=True, repr=False)
class SourceArtifactPlan:
    system: SourceSystem
    external_ref: str
    original_bytes: bytes
    content_hash: str
    source_occurred_at: datetime | None
    artifact_kind: ArtifactKind
    derives_from: OriginalWireReference | None
    boundary: B = field(default=B.BRAINSTORM, init=False)
    classification: C = field(default=C.CONFIDENTIAL, init=False)


@dataclass(frozen=True, repr=False)
class NativeSourcePreparation:
    provider: Literal['gmail','slack']
    captured_at: datetime
    artifacts: tuple[SourceArtifactPlan,...]
    declared_selection_bytes: bytes
    next_cursor: str | None
    selected_page_exhausted: bool | None
    retention_limited: bool | None
    capture_authorized: Literal[False] = field(default=False,init=False)
    recovery_verified: Literal[False] = field(default=False,init=False)
    complete_history_verified: Literal[False] = field(default=False,init=False)


def _time(captured_at: datetime) -> None:
    if type(captured_at) is not datetime or captured_at.utcoffset() is None:
        raise ValueError('trusted aware capture observation required')


def _artifact(system: SourceSystem, reference: str, raw: bytes, occurred: datetime | None,
              kind: ArtifactKind, origin: OriginalWireReference | None = None) -> SourceArtifactPlan:
    return SourceArtifactPlan(system,reference,raw,content_hash_of(raw),occurred,kind,origin)


def prepare_gmail_source(*, scope: GmailScope, profile_response: bytes,
                         message_response: bytes, expected_message_id: str,
                         captured_at: datetime) -> NativeSourcePreparation:
    result=None
    try:
        _time(captured_at)
        if type(scope) is not GmailScope or scope.boundary is not B.BRAINSTORM or scope.classification is not C.CONFIDENTIAL:
            raise ValueError('fixed business family required')
        profile=inspect_profile(profile_response,scope)
        message=inspect_raw_message(message_response,scope,expected_message_id=expected_message_id).value
        if message.internal_at>captured_at:
            raise ValueError('source ordering timestamp is future')
        mailbox=profile.value.email_address.casefold()
        account=content_hash_of(canonical_bytes({'account_ref':scope.account_ref,'observed_mailbox':mailbox}))
        identity=message.reference.message_id
        wire_ref=f'gmail/wire/{account}/message/{identity}'
        wire_origin=OriginalWireReference(wire_ref,content_hash_of(message_response))
        artifacts=(
            _artifact(SourceSystem.EMAIL,f'gmail/account/{account}',profile_response,None,'provider-profile-json'),
            _artifact(SourceSystem.EMAIL,wire_ref,message_response,message.internal_at,'provider-message-json'),
            _artifact(SourceSystem.EMAIL,f'gmail/rfc822/{account}/message/{identity}',message.original_bytes,message.internal_at,'decoded-rfc822',wire_origin),
        )
        declared=canonical_bytes({'format':'zac-gmail-offline-source-selection-v2','account_ref':scope.account_ref,'observed_mailbox':mailbox,'account_namespace':account,
            'expected_email':profile.value.email_address,'message_id':identity,'thread_id':message.reference.thread_id,
            'history_id':message.history_id,'labels':list(message.labels),'boundary':B.BRAINSTORM.value,
            'classification':C.CONFIDENTIAL.value,'coverage':'selected-message-only','attachments':'embedded-rfc822-only-not-extracted'})
        result=NativeSourcePreparation('gmail',captured_at,artifacts,declared,None,None,None)
    except Exception:  # noqa: BLE001,S110 - fixed error outside except, never provider/body details
        pass
    if result is None:raise NativeSourcePreparationError('native Gmail source preparation held')
    return result


def prepare_slack_sources(*, selection: HistorySelection | RepliesSelection,
                          account_response: bytes, page_response: bytes,
                          captured_at: datetime, boundary: B, classification: C,
                          requestor_boundaries: frozenset[B],
                          allowed_classifications: frozenset[C]) -> NativeSourcePreparation:
    result=None
    try:
        _time(captured_at)
        if (boundary is not B.BRAINSTORM or classification is not C.CONFIDENTIAL
            or type(requestor_boundaries) is not frozenset or type(allowed_classifications) is not frozenset
            or any(type(value) is not B for value in requestor_boundaries)
            or any(type(value) is not C for value in allowed_classifications)
            or classification not in allowed_classifications
            or not evaluate_access(AccessRequest(data_boundary=boundary,data_classification=classification,
                requestor_boundaries=requestor_boundaries,destination=Destination.LOCAL)).allowed):
            raise ValueError('declared fixed business source scope denied')
        if type(selection) not in (HistorySelection,RepliesSelection):
            raise ValueError('closed channel selection required')
        account=prepare_account_reply(account_response,expected=selection.account).account
        page=(prepare_replies_reply(page_response,selection=selection)
            if type(selection) is RepliesSelection else prepare_history_reply(page_response,selection=selection))
        if slack_timestamp_datetime(selection.latest)>captured_at:
            raise ValueError('selected window extends into future')
        declared=canonical_bytes({'format':'zac-slack-offline-source-selection-v2',
            'selection':selection.model_dump(mode='json'),'method':page.method.value,
            'boundary':B.BRAINSTORM.value,'classification':C.CONFIDENTIAL.value,
            'coverage':'selected-page-only','files':'references-only-not-downloaded'})
        # A different user/token/method/thread can yield a different representation
        # without a provider edit. Keep revisions within one observation view.
        view=content_hash_of(canonical_bytes({'account':account.model_dump(mode='json'),
            'method':page.method.value,'parent_ts':selection.parent_ts if type(selection) is RepliesSelection else None}))
        wire_ref=f'slack/wire/{account.team_id}/{selection.channel_id}/{content_hash_of(declared)}'
        wire_origin=OriginalWireReference(wire_ref,content_hash_of(page_response))
        artifacts=[_artifact(SourceSystem.SLACK,
            f'slack/account/{account.team_id}/{account.user_id}/{account.token_kind}',account_response,None,'provider-account-json'),
            _artifact(SourceSystem.SLACK,wire_ref,page_response,None,'provider-page-json')]
        for raw in page.record_bytes:
            record=json.loads(raw)
            timestamp=record['ts']
            occurred=slack_timestamp_datetime(timestamp)
            if occurred>captured_at:raise ValueError('provider message timestamp is future')
            artifacts.append(_artifact(SourceSystem.SLACK,
                f'slack/message/{account.team_id}/{selection.channel_id}/{timestamp}/view/{view}',raw,occurred,'canonical-message-json',wire_origin))
        result=NativeSourcePreparation('slack',captured_at,tuple(artifacts),declared,
            page.next_cursor,page.pagination_exhausted,page.retention_limited)
    except Exception:  # noqa: BLE001,S110 - no source/body/account error diagnostics
        pass
    if result is None:raise NativeSourcePreparationError('native Slack source preparation held')
    return result
