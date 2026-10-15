"""Bounded owner task selection over one approved retained PERSONAL cohort.

Application composition only, not a mounted transport or general retrieval.
The trusted caller must verify its request/CSRF before supplying the existing
NamedSessionOperation. Session continuity authenticates an owner, not authority
to process history. Preparing a declaration still requires a separate later
processing approval through the existing publication host.
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, fields, replace
from datetime import datetime, timedelta
from threading import RLock
from typing import Literal
from uuid import UUID

from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from zacai.claude_original_capture import ClaudeArtifactRootIdentity, observe_claude_artifact_root
from zacai.claude_original_read import ReadClaudeCustody, load_claude_original
from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.intelligence.claude_task_selection import (
    ClaudeTaskResolution,
    ClaudeTaskSelection,
    prepare_claude_task_resolution,
    propose_claude_task_context,
)
from zacai.intelligence.contracts import EvidenceReference, IntelligenceTask, ModelRoute
from zacai.intelligence.fragment_review_retention import _physical, _same
from zacai.intelligence.history_context_metadata import ClaudeMessageMetadata, HistoryMessageSpan
from zacai.intelligence.history_generation_review_declaration import HistoryReviewPurposeProfileV1
from zacai.intelligence.meeting_review import ReviewContext
from zacai.intelligence.ollama_token_counter import OllamaQwenContextualTokenCounter
from zacai.interfaces.fragment_preparation_web import _instruction
from zacai.interfaces.named_session_binding import NamedSessionOperation
from zacai.interfaces.personal_fragment_factory import _owner
from zacai.interfaces.personal_history_factory import (
    PersonalHistoryTaskConfiguration,
    PreparedPersonalHistoryDeclaration,
    prepare_personal_history_task,
)
from zacai.interfaces.private_host import NamedOwnerHostInputs
from zacai.policy import DataClassification as C
from zacai.policy import Destination
from zacai.policy import TrustBoundary as B
from zacai.review_protection import assert_local_review_state_engine


class PersonalTaskSelectionError(ValueError):
    """Fixed hold: never publish private source, configuration or traceback locals."""


@dataclass(frozen=True, repr=False)
class PersonalTaskContextOutcome:
    selection: ClaudeTaskSelection
    processing_authorized: Literal[False] = field(default=False, init=False)
    current_facts_verified: Literal[False] = field(default=False, init=False)


def _validate_configuration(c: PersonalHistoryTaskConfiguration) -> None:
    """Mirror the existing factory pre-read guards before this earlier read.

    Keep in step with prepare_personal_history_task's validation. Extracting
    that existing validation is a separate reviewed refactor; this stage does
    not change the factory. The initial configured spans may be empty here:
    only the accepted nonempty whole-message selection reaches that factory.
    """
    if (
        type(c) is not PersonalHistoryTaskConfiguration
        or type(c.original_context) is not ReviewContext
        or c.original_context.task.event.trust_boundary is not B.PERSONAL
        or c.original_context.task.event.data_classification is not C.HIGHLY_RESTRICTED
        or type(c.route) is not ModelRoute
        or c.route.destination is not Destination.LOCAL
        or type(c.generation_counter) is not OllamaQwenContextualTokenCounter
        or type(c.review_profile) is not HistoryReviewPurposeProfileV1
        or type(c.generation_runtime_digest) is not str
        or re.fullmatch(r"[0-9a-f]{64}", c.generation_runtime_digest) is None
        or not isinstance(c.engine, Engine)
        or type(c.factory) is not sessionmaker
        or c.factory.kw.get("bind") is not c.engine
        or c.factory.kw.get("binds")
        or type(c.selections) is not tuple
        or not 0 <= len(c.selections) <= 64
        or any(type(selection) is not HistoryMessageSpan for selection in c.selections)
        or type(c.expires_at) is not datetime
        or c.expires_at.utcoffset() is None
        or type(c.expected_root) is not ClaudeArtifactRootIdentity
        or any(type(r) is not EvidenceReference
               or r.trust_boundary is not B.PERSONAL
               or r.effective_classification is not C.HIGHLY_RESTRICTED
               for r in (c.original_reference, c.companion_reference,
                         *c.original_context.task.event.provenance,
                         *(item.reference for item in c.original_context.task.context)))
    ):
        raise ValueError("fixed reviewed PERSONAL configuration required")


def _configuration_binding(c: PersonalHistoryTaskConfiguration) -> str:
    # Object pins cover concrete stores/runtimes. Value pins also detect changes
    # within mutable Pydantic configuration objects without reading any source.
    values = {
        "pins": [(f.name, id(getattr(c, f.name))) for f in fields(c)],
        "original": c.original_reference.model_dump(mode="json"),
        "companion": c.companion_reference.model_dump(mode="json"),
        "root": asdict(c.expected_root),
        "account": c.expected_account_ref,
        "exported": c.expected_exported_at.isoformat() if c.expected_exported_at else None,
        "task": c.original_context.task.model_dump(mode="json"),
        "route": c.route.model_dump(mode="json"),
        "review": c.review_profile.model_dump(mode="json"),
        "deadline": c.expires_at.isoformat(),
    }
    return content_hash_of(canonical_bytes(values))


class PersonalHistoryTaskPreparation:
    """One transient proposal/answer/preparation for one exact host cohort.

    No disk challenge, cookie exposure, processing consent or automatic model
    invocation. The cohort is host-approved read scope, not relevance proof.
    A new cookie cannot answer an old proposal. A failure consumes this instance;
    canonical preparation may have committed, so callers must reconcile it.
    """

    def __init__(
        self,
        *,
        configuration: PersonalHistoryTaskConfiguration,
        inputs: NamedOwnerHostInputs,
        approved_message_ids: tuple[UUID, ...],
    ) -> None:
        ready = False
        try:
            if (
                type(configuration) is not PersonalHistoryTaskConfiguration
                or type(inputs) is not NamedOwnerHostInputs
                or type(approved_message_ids) is not tuple
                or not 1 <= len(approved_message_ids) <= 64
                or any(type(v) is not UUID or not v.int for v in approved_message_ids)
                or len(set(approved_message_ids)) != len(approved_message_ids)
            ):
                raise ValueError("exact task preparation inputs required")
            _validate_configuration(configuration)
            self._configuration = configuration
            self._inputs = inputs
            self._ids = approved_message_ids
            self._binding = _configuration_binding(configuration)
            ready = True
        except BaseException:  # noqa: BLE001,S110 - private-safe constructor failure
            pass
        if not ready:
            raise PersonalTaskSelectionError("task context preparation unavailable")
        self._phase = "NEW"
        self._selection: ClaudeTaskSelection | None = None
        self._proposed_digest: str | None = None
        self._resolved: ClaudeTaskSelection | None = None
        self._resolved_option: int | None = None
        self._resolved_digest: str | None = None
        self._instruction: str | None = None
        self._session_binding: str | None = None
        self._lock = RLock()

    def _check(self, operation: NamedSessionOperation) -> datetime:
        c, i = self._configuration, self._inputs
        _validate_configuration(c)
        if (
            type(operation) is not NamedSessionOperation
            or _configuration_binding(c) != self._binding
        ):
            raise ValueError("fixed PERSONAL task configuration changed")
        current = _owner(i, operation, self._session_binding)
        now = i.clock()
        if not now < c.expires_at <= current.effective_expires_at:
            raise ValueError("original preparation deadline unavailable")
        if c.expires_at - now > timedelta(minutes=15):
            raise ValueError("bounded original preparation deadline required")
        if self._session_binding is None:
            self._session_binding = current.binding_digest
        return now

    def _read(self, operation: NamedSessionOperation) -> ReadClaudeCustody:
        c = self._configuration
        self._check(operation)  # Actual owner before any private source IO.
        assert_local_review_state_engine(c.engine)
        if observe_claude_artifact_root(c.artifacts) != c.expected_root:
            raise ValueError("original custody root changed")
        with c.factory() as session:
            session.begin()
            entry = _physical(session)
            read = load_claude_original(
                session, artifacts=c.artifacts, expected_root=c.expected_root,
                original_reference=c.original_reference,
                companion_reference=c.companion_reference,
                expected_account_ref=c.expected_account_ref,
                expected_exported_at=c.expected_exported_at,
                requestor_boundaries=frozenset({B.PERSONAL}),
                allowed_classifications=frozenset({C.HIGHLY_RESTRICTED}),
            )
            _same(session, entry)
        self._check(operation)
        return read

    def _select(
        self, operation: NamedSessionOperation, instruction: str, *, option_number: int | None = None,
    ) -> ClaudeTaskSelection:
        c = self._configuration
        read = self._read(operation)
        task = IntelligenceTask.model_validate({
            **c.original_context.task.model_dump(), "instruction": instruction,
        })
        if task.instruction != instruction:
            raise ValueError("exact owner task required")
        original = ReviewContext(
            task, c.original_context.meeting_source_id, c.original_context.related_source_ids,
        )
        observed_at = self._check(operation)

        def select(resolution: ClaudeTaskResolution | None = None) -> ClaudeTaskSelection:
            return propose_claude_task_context(
                original, read, approved_message_ids=self._ids,
                expected_original=c.original_reference,
                expected_companion=c.companion_reference,
                observed_at=observed_at, route=c.route, resolution=resolution,
            )

        fresh = select()
        if self._selection is not None:
            # Observations within a preview differ on each read. Selection
            # binding instead covers exact task/pair/cohort/proposal/route.
            if fresh.selection_binding_digest != self._selection.selection_binding_digest:
                raise ValueError("task context proposal changed")
            if (fresh.outcome, fresh.options) != (
                self._selection.outcome, self._selection.options
            ):
                raise ValueError("task context options changed")
        if option_number is not None:
            resolution = prepare_claude_task_resolution(fresh, option_number=option_number)
            fresh = select(resolution)
        self._check(operation)
        return fresh

    def propose(
        self, *, operation: NamedSessionOperation, instruction: str,
    ) -> PersonalTaskContextOutcome:
        if not self._lock.acquire(blocking=False):
            raise PersonalTaskSelectionError("task context preparation unavailable")
        try:
            if self._phase != "NEW":
                raise ValueError("single proposal required")
            self._phase = "ENTERED"
            self._instruction = _instruction(instruction)
            self._selection = self._select(operation, self._instruction)
            if self._selection.outcome == "PROPOSED":
                self._proposed_digest = self._selected_digest(self._selection)
            self._phase = "PROPOSED"
            return PersonalTaskContextOutcome(self._selection)
        except BaseException:  # noqa: BLE001 - an interruption also consumes the attempt
            self._phase = "HELD"
        finally:
            self._lock.release()
        raise PersonalTaskSelectionError("task context preparation unavailable")

    @staticmethod
    def _selected_digest(selection: ClaudeTaskSelection) -> str:
        if selection.outcome != "PROPOSED" or selection.preview is None:
            raise ValueError("complete resolved context required")
        return content_hash_of(canonical_bytes({
            "binding": selection.selection_binding_digest,
            "instruction": selection.instruction,
            "selected": [entry.model_dump(mode="json", exclude={"projection_observed_at"})
                         for entry in selection.preview.sidecar.entries],
        }))

    def resolve_choice(
        self, *, operation: NamedSessionOperation, instruction: str,
        approved_message_ids: tuple[UUID, ...], option_number: int,
    ) -> PersonalTaskContextOutcome:
        """Read/revalidate one answer for disclosure; no declaration or processing.

        Original task/cohort/session/deadline remain fixed. The retained initial
        proposal remains the comparison basis. Later prepare() must confirm this
        exact resolved choice without supplying another option.
        """
        if not self._lock.acquire(blocking=False):
            raise PersonalTaskSelectionError("task context preparation unavailable")
        try:
            if (
                self._phase != "PROPOSED" or self._selection is None
                or self._selection.outcome != "CLARIFICATION"
                or instruction != self._instruction or approved_message_ids != self._ids
                or type(option_number) is not int
                or not 1 <= option_number <= len(self._selection.options)
            ):
                raise ValueError("exact original context answer required")
            self._phase = "ENTERED"
            selected = self._select(operation, instruction, option_number=option_number)
            digest = self._selected_digest(selected)
            self._check(operation)
            self._resolved, self._resolved_option, self._resolved_digest = selected, option_number, digest
            self._phase = "RESOLVED"
            return PersonalTaskContextOutcome(selected)
        except BaseException:  # noqa: BLE001 - interrupted read consumes the transient operation
            self._phase = "HELD"
        finally:
            self._lock.release()
        raise PersonalTaskSelectionError("task context preparation unavailable")

    def prepare(
        self, *, operation: NamedSessionOperation, instruction: str,
        approved_message_ids: tuple[UUID, ...], option_number: int | None = None,
    ) -> PreparedPersonalHistoryDeclaration:
        """Explicit owner confirmation, or one answer to the offered question.

        A transport must authenticate the action and CSRF independently; this
        method rechecks the original actual session before and after fresh reads.
        Its result is a prospective declaration, never processing permission.
        """
        if not self._lock.acquire(blocking=False):
            raise PersonalTaskSelectionError("task context preparation unavailable")
        try:
            if (
                self._phase not in {"PROPOSED", "RESOLVED"} or self._selection is None
                or instruction != self._instruction or approved_message_ids != self._ids
                or self._selection.outcome not in {"PROPOSED", "CLARIFICATION"}
            ):
                raise ValueError("exact original task/cohort/choice required")
            resolved = self._phase == "RESOLVED"
            selected_option: int | None
            if resolved:
                if (option_number is not None or self._resolved is None
                    or self._resolved_option is None or self._resolved_digest is None):
                    raise ValueError("confirm the exact resolved context without another choice")
                selected_option = self._resolved_option
            else:
                if (self._selection.outcome == "CLARIFICATION") != (option_number is not None):
                    raise ValueError("exact original task/cohort/choice required")
                selected_option = option_number
            self._phase = "ENTERED"
            selected = self._select(operation, instruction, option_number=selected_option)
            if resolved and self._selected_digest(selected) != self._resolved_digest:
                raise ValueError("previously disclosed context changed")
            if (not resolved and self._selection.outcome == "PROPOSED"
                and (self._proposed_digest is None
                     or self._selected_digest(selected) != self._proposed_digest)):
                raise ValueError("previously proposed context changed")
            if selected.outcome != "PROPOSED" or selected.preview is None:
                raise ValueError("available whole context selection required")
            spans_list: list[HistoryMessageSpan] = []
            for entry in selected.preview.sidecar.entries:
                if type(entry) is not ClaudeMessageMetadata:
                    raise ValueError("exact retained Claude message scope required")
                spans_list.append(HistoryMessageSpan(
                    message_id=entry.message_id, character_start=entry.character_start,
                    character_end=entry.character_end,
                ))
            spans = tuple(spans_list)
            self._check(operation)
            prepared = prepare_personal_history_task(
                replace(self._configuration, selections=spans), inputs=self._inputs,
                operation=operation, instruction=instruction,
            )
            self._check(operation)
            self._phase = "PREPARED"
            return prepared
        except BaseException:  # noqa: BLE001 - an interruption also consumes the attempt
            self._phase = "HELD"
        finally:
            self._lock.release()
        raise PersonalTaskSelectionError("task context preparation unavailable")
