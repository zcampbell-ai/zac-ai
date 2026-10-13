"""Closed app-observation selection for the existing original-owner email input.

Plans preallocate deterministic canonical EMAIL identities but grant nothing.
The existing actual owner POST/capture/protection host must consume these plans.
No provider RAW/profile, native ChatGPT pair or generic capture adapter is supplied.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Self
from uuid import UUID, uuid5

from pydantic import AwareDatetime, Field, model_validator

from zacai.ingestion.artifact_store import canonical_bytes, content_hash_of
from zacai.ingestion.gmail_app_observation import (
    GmailAppObservationPreparationV1,
    prepare_gmail_app_observation,
)
from zacai.intelligence.contracts import EvidenceReference
from zacai.intelligence.email_draft import EmailContract, EmailRecipientComparisonV1
from zacai.policy import DataClassification as C
from zacai.policy import TrustBoundary as B

_NAMESPACE = UUID("4aefcc16-4ae8-4c1a-8c04-052c2d2e4173")


class EmailAppInputError(ValueError):
    """Closed public diagnostic; suppress traceback-local capture."""


class EmailAppObservationSelectionV1(EmailContract):
    original_reference: EvidenceReference
    companion_reference: EvidenceReference
    raw_namespace: str = Field(
        strict=True,
        max_length=500,
        pattern=r"^gmail-app-observation/[0-9a-f]{64}/message/[A-Za-z0-9_-]{1,200}$",
    )
    companion_namespace: str = Field(
        strict=True,
        max_length=600,
        pattern=r"^gmail-app-observation-companion/[0-9a-f]{64}/message/[A-Za-z0-9_-]{1,200}/raw/[0-9a-f]{64}$",
    )
    inspected_at: AwareDatetime

    @model_validator(mode="after")
    def exact_pair(self) -> Self:
        refs = (self.original_reference, self.companion_reference)
        if (
            any(
                r.source_id.int == 0
                or r.trust_boundary is not B.BRAINSTORM
                or r.effective_classification is not C.CONFIDENTIAL
                for r in refs
            )
            or refs[0].source_id == refs[1].source_id
            or self.companion_namespace
            != self.raw_namespace.replace(
                "gmail-app-observation/", "gmail-app-observation-companion/", 1
            )
            + "/raw/"
            + refs[0].content_hash
        ):
            raise ValueError("exact business app observation pair required")
        return self


class EmailAppInputSelectionV1(EmailContract):
    format: Literal["zac-brainstorm-email-app-input-selection-v1"] = (
        "zac-brainstorm-email-app-input-selection-v1"
    )
    app: tuple[EmailAppObservationSelectionV1, ...] = Field(min_length=1, max_length=2)
    recipient: EmailRecipientComparisonV1 | None
    max_output_tokens: int = Field(strict=True, ge=1, le=2048)
    max_latency_ms: int = Field(strict=True, ge=1, le=120000)
    max_estimated_cost_usd: float = Field(strict=True, ge=0, le=0, allow_inf_nan=False)

    def references(self) -> tuple[EvidenceReference, ...]:
        return tuple(r for p in self.app for r in (p.original_reference, p.companion_reference))

    def digest(self) -> str:
        return content_hash_of(canonical_bytes(self.model_dump(mode="json")))

    @model_validator(mode="after")
    def finite(self) -> Self:
        if (
            len({r.source_id for r in self.references()}) != len(self.references())
            or len({p.raw_namespace for p in self.app}) != len(self.app)
            or len({p.raw_namespace.split("/")[1] for p in self.app}) != 1
            or len(canonical_bytes(self.model_dump(mode="json"))) > 20000
        ):
            raise ValueError("distinct finite app observation selection required")
        return self


def prepare_email_app_input_selection(
    *,
    preparations: tuple[GmailAppObservationPreparationV1, ...],
    recipient: EmailRecipientComparisonV1 | None,
    max_output_tokens: int,
    max_latency_ms: int,
    max_estimated_cost_usd: float,
) -> EmailAppInputSelectionV1:
    from zacai.intelligence.gmail_app_email_source import GmailAppEmailSourceV1

    result = None
    try:
        if type(preparations) is not tuple or not 1 <= len(preparations) <= 2:
            raise ValueError("finite exact server-held app preparations required")
        selections = []
        for preparation in preparations:
            if type(preparation) is not GmailAppObservationPreparationV1:
                raise ValueError("closed exact app preparation required")
            rebuilt = prepare_gmail_app_observation(
                raw=preparation.artifacts[0].original_bytes,
                scope=preparation.companion.scope,
                requestor_boundaries=frozenset({B.BRAINSTORM}),
                allowed_classifications=frozenset({C.CONFIDENTIAL}),
            )
            if rebuilt != preparation:
                raise ValueError("server-held app preparation changed")
            refs = tuple(
                EvidenceReference(
                    source_id=uuid5(_NAMESPACE, a.external_ref + "/" + a.content_hash),
                    content_hash=a.content_hash,
                    trust_boundary=B.BRAINSTORM,
                    effective_classification=C.CONFIDENTIAL,
                )
                for a in rebuilt.artifacts
            )
            # Data-only preflight through the reader's literal-context API.
            # Empty row preimages cannot represent canonical read/capture proof.
            inspection = rebuilt.companion.scope.inspected_at
            GmailAppEmailSourceV1(
                refs[0], refs[1], rebuilt, (), inspection, inspection, inspection
            ).context_items()
            selections.append(
                EmailAppObservationSelectionV1(
                    original_reference=refs[0],
                    companion_reference=refs[1],
                    raw_namespace=rebuilt.artifacts[0].external_ref,
                    companion_namespace=rebuilt.artifacts[1].external_ref,
                    inspected_at=rebuilt.companion.scope.inspected_at,
                )
            )
        result = EmailAppInputSelectionV1(
            app=tuple(selections),
            recipient=recipient,
            max_output_tokens=max_output_tokens,
            max_latency_ms=max_latency_ms,
            max_estimated_cost_usd=max_estimated_cost_usd,
        )
    except Exception:  # noqa: BLE001,S110
        pass
    if result is None:
        raise EmailAppInputError("email app input selection unavailable")
    return result


def check_email_app_preparations(
    selection: EmailAppInputSelectionV1,
    preparations: tuple[GmailAppObservationPreparationV1, ...],
    observed_at: datetime,
) -> None:
    expected = prepare_email_app_input_selection(
        preparations=preparations,
        recipient=selection.recipient,
        max_output_tokens=selection.max_output_tokens,
        max_latency_ms=selection.max_latency_ms,
        max_estimated_cost_usd=selection.max_estimated_cost_usd,
    )
    # Actual canonical same-hash identities may predate this inspection. The
    # host resolves them under the current original session; this declaration
    # validates exact plan/hash/namespace/time, never authenticates supplied IDs.
    selected = selection.model_dump(mode="json")
    reconstructed = expected.model_dump(mode="json")
    for data in (selected, reconstructed):
        for pair in data["app"]:
            pair["original_reference"].pop("source_id")
            pair["companion_reference"].pop("source_id")
    if selected != reconstructed or any(p.inspected_at > observed_at for p in selection.app):
        raise ValueError("exact server-held app bytes/scope before original action required")
