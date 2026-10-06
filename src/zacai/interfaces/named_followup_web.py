"""Optional native named-question host controller, default presentation-only.

Injected display/pipeline adapters are trusted actual canonical gates, never
proof by callback/record shape. No production gate or pipeline is supplied here.
Host validates HTTP/session/CSRF; this controller rechecks the exact original
actual session around worker operations and before final canonical release reads.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from html import escape
from threading import RLock
from typing import Protocol
from urllib.parse import parse_qs

from zacai.ingestion.artifact_store import content_hash_of
from zacai.interfaces.host_clock import HostObservedClock
from zacai.interfaces.named_admission_store import (
    NamedAdmissionRecord,
    SqliteNamedAdmissionStore,
)
from zacai.interfaces.named_browser_pointer import (
    NamedAdmissionReuseCoordinator,
    ReusedNamedAdmission,
)
from zacai.interfaces.named_followup_decision import named_manifest_digest
from zacai.interfaces.named_session_binding import (
    NamedSessionContinuity,
    NamedSessionOperation,
)
from zacai.interfaces.text_reply_capture import SavedTextReply

_POINTER = "__Host-zac-named-action"
_TOKEN = re.compile(r"[A-Za-z0-9_-]{43}")


class NamedFollowupWebError(ValueError):
    """Fixed private-safe errors; no raw fields or provider exceptions exposed."""


class NamedPublishedDisplayGate(Protocol):
    def verify_fresh(self, operation: NamedSessionOperation, record: NamedAdmissionRecord) -> object:
        """Actual source/recovery/runtime checks OUTSIDE canonical SQL; None only."""
        ...

    def verify_rows(self, record: NamedAdmissionRecord, now: datetime) -> object:
        """Final actual canonical row/ACL/proof binding read, no external callbacks."""
        ...


class NamedAskPipeline(Protocol):
    def submit(self, *, operation: NamedSessionOperation, admission_handle: str,
               admitted_record: NamedAdmissionRecord, original_utf8: bytes) -> SavedTextReply:
        """Actual protected question/decision/v2 claim/runtime/semantic/reply pipeline."""
        ...

    def recheck(self, *, operation: NamedSessionOperation, admission_handle: str,
                admitted_record: NamedAdmissionRecord, original_utf8: bytes,
                saved: SavedTextReply) -> SavedTextReply:
        """Current canonical owner/ACL/recovery release; final rows after callbacks."""
        ...


@dataclass(frozen=True)
class NamedQuestionPage:
    reused: ReusedNamedAdmission = field(repr=False)
    html: str = field(repr=False)
    deadline: datetime


@dataclass(frozen=True)
class NamedQuestionResult:
    admission_handle: str = field(repr=False)
    admitted: NamedAdmissionRecord = field(repr=False)
    original_utf8: bytes = field(repr=False)
    saved: SavedTextReply = field(repr=False)


@dataclass(frozen=True)
class NamedQuestionForm:
    original_utf8: bytes = field(repr=False)
    manifest_digest: str = field(repr=False)


def parse_named_question_form(body: bytes, csrf: str) -> NamedQuestionForm:
    result: NamedQuestionForm | None = None
    try:
        if type(body) is not bytes or not 0 < len(body) <= 32768 or type(csrf) is not str or _TOKEN.fullmatch(csrf) is None:
            raise ValueError("bounded host form required")
        text = body.decode("utf-8", errors="strict")
        if re.search(r"%(?![0-9a-fA-F]{2})", text):
            raise ValueError("bad percent encoding")
        values = parse_qs(text, keep_blank_values=True, strict_parsing=True,
            max_num_fields=4, encoding="utf-8", errors="strict")
        if (set(values) != {"csrf", "question", "action", "manifest_digest"}
            or any(len(items) != 1 for items in values.values())
            or values["action"][0] != "ask_caz_locally"):
            raise ValueError("closed named action required")
        import secrets
        if not secrets.compare_digest(csrf, values["csrf"][0]):
            raise ValueError("host csrf changed")
        question = values["question"][0]
        raw = question.encode("utf-8", errors="strict")
        if not question.strip() or len(question) > 2000 or len(raw) > 8000:
            raise ValueError("bounded original question required")
        digest = values["manifest_digest"][0]
        if re.fullmatch(r"[0-9a-f]{64}", digest) is None:
            raise ValueError("exact published manifest digest required")
        result = NamedQuestionForm(raw, digest)
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise NamedFollowupWebError("named question form unavailable")
    return result


class NamedFollowupWeb:
    def __init__(self, *, coordinator: NamedAdmissionReuseCoordinator,
                 continuity: NamedSessionContinuity, store: SqliteNamedAdmissionStore,
                 clock: HostObservedClock, display_gate: NamedPublishedDisplayGate,
                 pipeline: NamedAskPipeline | None = None) -> None:
        if (type(coordinator) is not NamedAdmissionReuseCoordinator
            or type(continuity) is not NamedSessionContinuity
            or type(store) is not SqliteNamedAdmissionStore or type(clock) is not HostObservedClock
            or coordinator._store is not store or coordinator._clock is not clock
            or continuity._clock is not clock or store._clock is not clock
            or any(not callable(getattr(display_gate, name, None)) for name in ("verify_fresh", "verify_rows"))
            or (pipeline is not None and any(not callable(getattr(pipeline, name, None)) for name in ("submit", "recheck")))):
            raise NamedFollowupWebError("named question host unavailable")
        self._coordinator, self._continuity, self._store = coordinator, continuity, store
        self._clock, self._display, self._pipeline, self._submit_lock = clock, display_gate, pipeline, RLock()

    @property
    def submission_enabled(self) -> bool:
        return self._pipeline is not None

    @property
    def host_clock(self) -> HostObservedClock:
        return self._clock

    def for_cookie(self, cookie: str) -> NamedSessionOperation:
        return self._continuity.for_cookie(cookie)

    def _display_check(self, operation: NamedSessionOperation, reused: ReusedNamedAdmission) -> datetime:
        record = reused.record
        if self._display.verify_fresh(operation, record) is not None:
            raise ValueError("published display held")
        operation.recheck(record.session_binding)
        # Store continuity then actual canonical rows; no owner/session callbacks after rows.
        decoded = self._coordinator._codec.decode(reused.sealed_pointer, operation.recheck(record.session_binding))
        current = self._store.get(handle=decoded.handle, session_binding=record.session_binding)
        if current != record or self._display.verify_rows(record, self._clock()) is not None:
            raise ValueError("published display changed")
        deadline = record.manifest.admission_expires_at if record.phase == "ISSUED" else record.processing_expires_at
        if deadline is None or self._clock() >= deadline:
            raise ValueError("published display expired")
        return deadline

    def page(self, *, operation: NamedSessionOperation, pointer: str | None, csrf: str) -> NamedQuestionPage:
        result: NamedQuestionPage | None = None
        try:
            if type(csrf) is not str or _TOKEN.fullmatch(csrf) is None:
                raise ValueError("host csrf required")
            reused = self._coordinator.reuse_or_issue(operation=operation, pointer=pointer)
            deadline = self._display_check(operation, reused)
            record, manifest = reused.record, reused.record.manifest
            references = (manifest.packet_reference, *manifest.evidence_references,
                          *(p.reference for p in manifest.parents))
            evidence = ''.join('<li>Source ' + escape(str(ref.source_id)) + '</li>' for ref in references)
            details = '<details><summary>Scope and evidence</summary><p>This selected review, its original sources and explicitly selected earlier questions.</p><p>Published ' + escape(manifest.issued_at.isoformat()) + '</p><ul>' + evidence + '</ul></details>'
            if record.phase != "ISSUED":
                content = '<p>This request has already started. Its processing and recovery status requires a protected review.</p>'
            else:
                disabled = '' if self.submission_enabled else ' disabled'
                content = ('<form method="post" action="/ask-caz-locally"><input type="hidden" name="csrf" value="'
                    + escape(csrf, quote=True) + '"><input type="hidden" name="manifest_digest" value="'
                    + named_manifest_digest(manifest) + '"><label for="caz-question">Your question</label>'
                    '<textarea id="caz-question" name="question" maxlength="2000" rows="4" required' + disabled + '></textarea>'
                    '<button type="submit" name="action" value="ask_caz_locally"' + disabled + '>Ask Caz locally</button></form>')
                if not self.submission_enabled:
                    content += '<p>Local questions are being connected. You can review the published scope here.</p>'
            html = '<section class="decision-card"><h1>Ask Caz locally</h1><p>Runs on your Mac with the selected review. No external actions are included.</p>' + content + details + '</section>'
            result = NamedQuestionPage(reused, html, deadline)
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise NamedFollowupWebError("private local question unavailable")
        return result

    def recheck_page(self, *, operation: NamedSessionOperation, page: NamedQuestionPage) -> NamedQuestionPage:
        if type(page) is not NamedQuestionPage:
            raise NamedFollowupWebError("private local question unavailable")
        failed = True
        try:
            deadline = self._display_check(operation, page.reused)
            if deadline != page.deadline:
                raise ValueError("page deadline changed")
            failed = False
        except Exception:  # noqa: BLE001,S110
            pass
        if failed:
            raise NamedFollowupWebError("private local question unavailable")
        return page

    def submit(self, *, operation: NamedSessionOperation, pointer: str, original_utf8: bytes, manifest_digest: str) -> NamedQuestionResult:
        result: NamedQuestionResult | None = None
        try:
            if self._pipeline is None:
                raise ValueError("actual protected pipeline required")
            if type(pointer) is not str or not pointer:
                raise ValueError("existing published pointer required for POST")
            if type(original_utf8) is not bytes or not 0 < len(original_utf8) <= 8000:
                raise ValueError("bounded original UTF8 required")
            text = original_utf8.decode("utf-8", errors="strict")
            if not text.strip() or len(text) > 2000:
                raise ValueError("bounded question required")
            reused = self._coordinator.reuse_or_issue(operation=operation, pointer=pointer)
            import secrets
            if (type(manifest_digest) is not str or re.fullmatch(r"[0-9a-f]{64}", manifest_digest) is None
                or not secrets.compare_digest(manifest_digest, named_manifest_digest(reused.record.manifest))):
                raise ValueError("published card differs from browser pointer")
            # Recovery/runtime probes are outside the short admission mutex.
            self._display_check(operation, reused)
            with self._submit_lock:
                verified = operation.recheck(reused.record.session_binding)
                decoded = self._coordinator._codec.decode(pointer, verified)
                if reused.sealed_pointer != pointer:
                    raise ValueError("original published pointer changed")
                current = self._store.get(handle=decoded.handle, session_binding=verified.binding_digest)
                if current != reused.record or current.phase != "ISSUED":
                    raise ValueError("existing request cannot redispatch")
                if self._display.verify_rows(current, self._clock()) is not None:
                    raise ValueError("published sources changed before admission")
                if self._clock() >= current.manifest.admission_expires_at:
                    raise ValueError("published admission expired")
                from zacai.interfaces.named_worker_lifecycle import ThreadBoundNamedAskPipeline
                if type(self._pipeline) is ThreadBoundNamedAskPipeline:
                    if self._pipeline._store is not self._store or self._pipeline._workers.host_clock is not self._clock:
                        raise ValueError("actual worker admission store differs")
                    admitted = self._pipeline.admit_reserved(issued_record=current,
                        admission_handle=decoded.handle, original_utf8=original_utf8)
                else:
                    # Explicit invented/legacy pipeline seam; production host
                    # composition requires the exact worker-bound wrapper.
                    admitted = self._store.admit(handle=decoded.handle, session_binding=verified.binding_digest,
                        question_digest=content_hash_of(original_utf8), question_bytes=len(original_utf8))
                if admitted.manifest != current.manifest or admitted.session_binding != current.session_binding:
                    raise ValueError("admitted original action differs")
            operation.recheck(admitted.session_binding)
            # Serialize only publication/admission. The atomic consumed record
            # prevents replay; long processing must not hold unrelated actions.
            saved = self._pipeline.submit(operation=operation, admission_handle=decoded.handle,
                admitted_record=admitted, original_utf8=original_utf8)
            if type(saved) is not SavedTextReply:
                raise ValueError("exact protected saved reply required")
            result = NamedQuestionResult(decoded.handle, admitted, original_utf8, saved)
        except Exception:  # noqa: BLE001,S110
            pass
        if result is None:
            raise NamedFollowupWebError("local question not acknowledged; review request status")
        return result

    def recheck_result(self, *, operation: NamedSessionOperation, result: NamedQuestionResult) -> SavedTextReply:
        if self._pipeline is None or type(result) is not NamedQuestionResult:
            raise NamedFollowupWebError("private local reply unavailable")
        checked: SavedTextReply | None = None
        try:
            operation.recheck(result.admitted.session_binding)
            saved = self._pipeline.recheck(operation=operation, admission_handle=result.admission_handle,
                admitted_record=result.admitted, original_utf8=result.original_utf8, saved=result.saved)
            if type(saved) is not SavedTextReply or saved != result.saved:
                raise ValueError("protected result changed")
            if result.admitted.processing_expires_at is None or self._clock() >= result.admitted.processing_expires_at:
                raise ValueError("original processing window expired")
            checked = saved
        except Exception:  # noqa: BLE001,S110
            pass
        if checked is None:
            raise NamedFollowupWebError("private local reply unavailable")
        return checked
