"""ROOT-ONLY definitions: actual disposable PG + enrolled owner + native age.

Not executed by the worker. All data is invented. No source/physical/current-row/
owner/checkpoint/recovery success mock. Raw artifact inventory is limited to this
fixture's new Sources, as test_text_turn_protection_sql does; complete State/journal
snapshot/restore and selected source verification remain real. This is local fixture
recovery, not off-device/production or processing permission.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from urllib.parse import urlencode
from uuid import uuid4

import pytest
from sqlalchemy import select
from starlette.requests import Request

from tests import test_chatgpt_native_pair_sql as native_fixture
from tests.test_complete_history_contextual_storage_sql import (
    clean_factory as clean_factory,  # noqa: PLC0414
)
from tests.test_fireflies_protection import keypair
from zacai import backup_artifacts, contextual_protection
from zacai.backup_artifacts import LocalDirectoryBackupStore
from zacai.contextual_protection import BrainstormContextualProtector
from zacai.host_clock import HostObservedClock
from zacai.ingestion.artifact_store import LocalFilesystemArtifactStore
from zacai.interfaces.email_input import (
    CanonicalBrainstormEmailInput,
    EmailInputCheckpointScope,
    EmailInputError,
    EmailInputSelectionV1,
    EmailNativeSelectionV1,
    observe_email_input_post,
)
from zacai.interfaces.email_input_protection import BrainstormEmailInputProtection
from zacai.interfaces.named_session_binding import NamedSessionContinuity
from zacai.interfaces.owner_enrollment import OwnerEnrollment
from zacai.interfaces.owner_store import OwnerGrantStore
from zacai.interfaces.private_web import _USER, BoundaryScope
from zacai.interfaces.session_store import Identity
from zacai.interfaces.sqlite_sessions import SqliteSessionStore
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B
from zacai.review_protection import DisposableStateRestoreVerifier
from zacai.state import Source
from zacai.state_repository import elevate_source_classification, record_source


@pytest.fixture
def genuine_case(clean_factory, tmp_path, monkeypatch):
    now = datetime.now(UTC)
    monkeypatch.setattr(native_fixture, "AT", now - timedelta(seconds=2))
    maker = native_fixture.pair_case.__wrapped__(clean_factory, tmp_path)
    pair = maker(boundary=B.BRAINSTORM, label=C.CONFIDENTIAL)
    offset = [timedelta(0)]
    clock = HostObservedClock(lambda: datetime.now(UTC) + offset[0])
    owner_id = Identity("https://accounts.google.com", "invented-email-owner")
    origin, client_id = "https://owner.example", "123456-invented.apps.googleusercontent.com"
    owners = OwnerGrantStore(tmp_path / "owners", key=b"a" * 32, origin=origin, client_id=client_id)
    enrollment = OwnerEnrollment(opened_at=clock())
    candidate = enrollment.capture(owner_id, clock(), origin=origin)
    owners.confirm_and_save(
        enrollment=enrollment,
        candidate_id=candidate.candidate_id,
        pairing_code=candidate.pairing_code,
        origin=origin,
        identity=owner_id,
        scopes=(BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),),
        now=clock(),
    )
    sessions = SqliteSessionStore(tmp_path / "sessions", key=b"b" * 32)
    cookie = sessions.start_user(owner_id, clock())
    continuity = NamedSessionContinuity(
        sessions=sessions,
        owner=owners.load,
        clock=clock,
        key=b"c" * 32,
        origin=origin,
        client_id=client_id,
    )
    operation = continuity.for_cookie(cookie)
    first = operation.establish()
    identity_file = tmp_path / "throwaway-email.agekey"
    recipient = keypair(identity_file)
    objects = LocalDirectoryBackupStore(tmp_path / "objects")
    reader = LocalDirectoryBackupStore(tmp_path / "objects")
    protector = BrainstormContextualProtector(
        factory=clean_factory,
        engine=clean_factory.kw["bind"],
        artifacts=pair.artifacts,
        objects=objects,
        verification_objects=reader,
        recipient=recipient,
        identity_path=identity_file,
        manifest_cache=tmp_path / "manifest",
        restoration=DisposableStateRestoreVerifier(),
    )
    gate = BrainstormEmailInputProtection(
        protector=protector, operation=operation, original_binding=first.binding_digest
    )
    capture = CanonicalBrainstormEmailInput(gate)
    selection = EmailInputSelectionV1(
        format="zac-brainstorm-email-input-selection-v1",
        native=(
            EmailNativeSelectionV1(
                capture_id=pair.capture_id,
                original_reference=pair.original,
                companion_reference=pair.companion_reference,
                companion=pair.companion,
            ),
        ),
        recipient=None,
        max_output_tokens=1000,
        max_latency_ms=120000,
        max_estimated_cost_usd=0.0,
    )

    # Single isolated clean schema starts with this pair; subsequent instruction
    # Source is also fixture-owned. Do not replace complete snapshot/restore logic.
    def source_rows(session, *, trust_boundary):
        return [
            (h, loc)
            for h, loc in session.execute(
                select(Source.content_hash, Source.content_location).where(
                    Source.trust_boundary == trust_boundary
                )
            ).all()
            if h is not None
        ]

    def scoped_hashes(conn):
        return {
            h
            for (h,) in conn.execute(
                select(Source.content_hash).where(Source.trust_boundary == B.BRAINSTORM)
            ).all()
            if h is not None
        }

    monkeypatch.setattr(backup_artifacts, "_source_rows_for_boundary", source_rows)
    monkeypatch.setattr(contextual_protection, "_snapshot_artifact_hashes", scoped_hashes)

    def post(text="Follow up on the estimate.\nKeep it concise.", *, request_id=None):
        request_id = request_id or uuid4()
        current = sessions.peek_user(cookie, clock())
        request = Request(
            {
                "type": "http",
                "http_version": "1.1",
                "method": "POST",
                "scheme": "https",
                "server": ("owner.example", 443),
                "path": "/prepare-caz-email",
                "query_string": b"",
                "headers": [
                    (b"host", b"owner.example"),
                    (b"origin", origin.encode()),
                    (b"content-type", b"application/x-www-form-urlencoded"),
                    (b"cookie", (_USER + "=" + cookie).encode()),
                ],
            }
        )
        body = urlencode(
            {
                "csrf": current.csrf,
                "request_id": str(request_id),
                "selection_digest": selection.digest(),
                "instruction": text,
            }
        ).encode()
        return observe_email_input_post(
            request, body=body, operation=operation, request_id=request_id, selection=selection
        )

    return SimpleNamespace(
        pair=pair,
        gate=gate,
        capture=capture,
        post=post,
        owners=owners,
        sessions=sessions,
        cookie=cookie,
        operation=operation,
        continuity=continuity,
        clock=clock,
        offset=offset,
        reader=reader,
        objects=objects,
        identity_file=identity_file,
    )


def test_genuine_capture_reopen_recovery_assembly_exact_original_bytes(genuine_case):
    f = genuine_case
    original = "Follow up on the estimate.\nKeep it concise."
    token = f.post(original)
    saved = f.capture.capture(token)
    assert saved.instruction.original_text.encode() == original.encode()
    assert saved.specification.task().instruction.encode() == original.encode()
    assert saved.specification.task().context[0].untrusted_text == "a🙂"
    assert saved.specification.sources[0].reported_role == "UNKNOWN"
    assert saved.specification.task().event.trust_boundary is B.BRAINSTORM
    assert not saved.processing_authorized and not saved.recovery_receipt.processing_authorized
    scope = EmailInputCheckpointScope(
        saved.reference.source_id, saved.reference.content_hash, saved.instruction.recorded_at
    )
    assert f.reader.get_object(saved.recovery_receipt.receipt_object)
    assert f.capture.load(scope, saved.recovery_receipt).instruction == saved.instruction
    f.gate.recheck(scope, saved.recovery_receipt)
    with pytest.raises(EmailInputError):
        f.capture.capture(token)


@pytest.mark.parametrize("change", ["owner", "expired"])
def test_owner_or_expiry_holds_before_private_artifact_read(genuine_case, monkeypatch, change):
    f = genuine_case
    token = f.post()
    if change == "owner":
        f.owners.revoke()
    else:
        f.offset[0] = timedelta(hours=9)
    monkeypatch.setattr(
        LocalFilesystemArtifactStore,
        "get_bounded",
        lambda *a, **kw: pytest.fail("revoked/expired owner read private artifact"),
    )
    with pytest.raises(EmailInputError):
        f.capture.capture(token)


def test_personal_reference_cannot_enter_business_selection(genuine_case):
    pair = genuine_case.pair
    with pytest.raises(ValueError):
        EmailNativeSelectionV1(
            capture_id=pair.capture_id,
            original_reference=pair.original.model_copy(update={"trust_boundary": B.PERSONAL}),
            companion_reference=pair.companion_reference,
            companion=pair.companion,
        )


@pytest.mark.parametrize("mutation", ["acl", "revision"])
def test_actual_source_mutation_after_native_artifact_callback_holds(
    genuine_case, monkeypatch, mutation
):
    f = genuine_case
    get = LocalFilesystemArtifactStore.get_bounded
    touched = [False]

    def changed(store, boundary, location, *, max_bytes):
        raw = get(store, boundary, location, max_bytes=max_bytes)
        if not touched[0] and location == f.pair.locations[0]:
            touched[0] = True
            with f.pair.factory() as session, session.begin():
                if mutation == "acl":
                    elevate_source_classification(
                        session,
                        source_id=f.pair.original.source_id,
                        trust_boundary=B.BRAINSTORM,
                        new_classification=C.HIGHLY_RESTRICTED,
                        reason="invented test elevation",
                        elevated_by="invented owner",
                    )
                else:
                    src = session.get(Source, f.pair.original.source_id)
                    record_source(
                        session,
                        trust_boundary=B.BRAINSTORM,
                        data_classification=C.CONFIDENTIAL,
                        system=src.system,
                        external_ref=src.external_ref,
                        content_hash="f" * 64,
                        content_location=src.content_location,
                        captured_at=datetime.now(UTC),
                    )
        return raw

    monkeypatch.setattr(LocalFilesystemArtifactStore, "get_bounded", changed)
    with pytest.raises(EmailInputError):
        f.capture.capture(f.post())
    assert touched[0]


def test_ciphertext_mutation_holds_real_recovery(genuine_case):
    f = genuine_case
    saved = f.capture.capture(f.post())
    scope = EmailInputCheckpointScope(
        saved.reference.source_id, saved.reference.content_hash, saved.instruction.recorded_at
    )
    # Mutate the actual local ciphertext object; no decryption/restore success mock.
    path = f.reader._root / saved.recovery_receipt.state_object
    path.write_bytes(b"corrupted invented ciphertext")
    with pytest.raises(EmailInputError):
        f.capture.load(scope, saved.recovery_receipt)


def test_fresh_observation_same_request_id_hits_canonical_replay_guard(genuine_case):
    f = genuine_case
    first = f.post()
    saved = f.capture.capture(first)
    fresh = f.post(saved.instruction.original_text, request_id=saved.instruction.request_id)
    assert fresh is not first
    assert fresh.instruction.request_id == saved.instruction.request_id
    with pytest.raises(
        EmailInputError, match="^email input not captured and protected; reconcile pending custody$"
    ) as error:
        f.capture.capture(fresh)
    assert error.value.__context__ is None
    with f.pair.factory() as session:
        rows = tuple(
            session.scalars(
                select(Source).where(
                    Source.external_ref == f"email-owner-instruction/{saved.instruction.request_id}"
                )
            ).all()
        )
        assert len(rows) == 1 and rows[0].id == saved.reference.source_id


def _pending_after_real_receipt_failure(f, monkeypatch):
    from zacai.interfaces.email_input import email_input_receipt_key

    token = f.post()
    original_put = f.objects.put_object
    attempted = []

    def receipt_failure(key, data):
        if "/receipt-" in key:
            attempted.append(key)
            raise OSError("invented real receipt write failure")
        return original_put(key, data)

    monkeypatch.setattr(f.objects, "put_object", receipt_failure)
    with pytest.raises(
        EmailInputError, match="^email input not captured and protected; reconcile pending custody$"
    ):
        f.capture.capture(token)
    assert attempted
    with f.pair.factory() as session:
        source = session.scalars(
            select(Source).where(
                Source.external_ref == f"email-owner-instruction/{token.instruction.request_id}"
            )
        ).one()
        before = (source.id, source.content_hash, source.content_location, source.captured_at)
    assert not f.reader.exists(email_input_receipt_key(before[0], before[1]))
    monkeypatch.setattr(f.objects, "put_object", original_put)
    return token, before


def test_real_receipt_store_failure_leaves_original_custody_then_reconciles(
    genuine_case, monkeypatch
):
    f = genuine_case
    token, before = _pending_after_real_receipt_failure(f, monkeypatch)
    recovered = f.capture.reconcile(token.instruction.request_id)
    assert recovered.reference.source_id == before[0]
    assert recovered.reference.content_hash == before[1]
    assert recovered.instruction == token.instruction
    assert not recovered.processing_authorized
    assert f.reader.exists(recovered.recovery_receipt.receipt_object)
    with f.pair.factory() as session:
        source = session.get(Source, before[0])
        assert (
            source.id,
            source.content_hash,
            source.content_location,
            source.captured_at,
        ) == before
    # Preservation can reopen again; it never replays POST/capture or renews action.
    assert f.capture.reconcile(token.instruction.request_id).instruction == token.instruction
    with pytest.raises(EmailInputError):
        f.capture.capture(token)


def test_verified_native_preimage_must_survive_final_owner_callback(genuine_case, monkeypatch):
    f = genuine_case
    saved = f.capture.capture(f.post())
    scope = EmailInputCheckpointScope(
        saved.reference.source_id, saved.reference.content_hash, saved.instruction.recorded_at
    )
    actual_owner = f.capture._owner
    calls = [0]
    changed = [False]

    def after_real_owner(value):
        actual_owner(value)
        calls[0] += 1
        # load's third owner check follows native verification AND real recovery;
        # the predecessor then established a new unbound baseline after this callback.
        if calls[0] == 3:
            with f.pair.factory() as session, session.begin():
                elevate_source_classification(
                    session,
                    source_id=f.pair.original.source_id,
                    trust_boundary=B.BRAINSTORM,
                    new_classification=C.HIGHLY_RESTRICTED,
                    reason="invented final owner callback elevation",
                    elevated_by="invented owner",
                )
            changed[0] = True

    monkeypatch.setattr(f.capture, "_owner", after_real_owner)
    with pytest.raises(
        EmailInputError, match="^email canonical input unavailable or unprotected$"
    ) as error:
        f.capture.load(scope, saved.recovery_receipt)
    assert changed[0] and error.value.__context__ is None


@pytest.mark.parametrize("changed", ["owner", "session", "expired"])
def test_pending_reconcile_refuses_other_original_owner_session_or_expiry(
    genuine_case, monkeypatch, changed
):
    f = genuine_case
    token, before = _pending_after_real_receipt_failure(f, monkeypatch)
    target = f.capture
    if changed == "owner":
        identity = Identity("https://accounts.google.com", "different-invented-email-owner")
        enrollment = OwnerEnrollment(opened_at=f.clock())
        candidate = enrollment.capture(identity, f.clock(), origin="https://owner.example")
        f.owners.confirm_and_save(
            enrollment=enrollment,
            candidate_id=candidate.candidate_id,
            pairing_code=candidate.pairing_code,
            origin="https://owner.example",
            identity=identity,
            scopes=(BoundaryScope(B.BRAINSTORM, frozenset({C.CONFIDENTIAL})),),
            now=f.clock(),
        )
    elif changed == "session":
        # A fresh concrete host with a valid new signed cookie cannot adopt the
        # committed Source's OLD session/action as its own original instruction.
        cookie = f.sessions.start_user(f.owners.load().identity, f.clock())
        operation = f.continuity.for_cookie(cookie)
        binding = operation.establish().binding_digest
        assert binding != token.instruction.original_session_binding
        gate = BrainstormEmailInputProtection(
            protector=f.gate._protector, operation=operation, original_binding=binding
        )
        target = CanonicalBrainstormEmailInput(gate)
    else:
        f.offset[0] = timedelta(hours=9)
    with pytest.raises(
        EmailInputError, match="^original email custody reconciliation unavailable$"
    ) as error:
        target.reconcile(token.instruction.request_id)
    assert error.value.__context__ is None
    with f.pair.factory() as session:
        source = session.get(Source, before[0])
        assert (
            source.id,
            source.content_hash,
            source.content_location,
            source.captured_at,
        ) == before
