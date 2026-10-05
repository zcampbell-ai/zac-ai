"""Closed contextual draft rejection metadata; never private prose or evidence IDs."""
from enum import Enum


class GenerationFailure(str, Enum):
    REQUEST = "REQUEST"
    DRAFT_SCHEMA = "DRAFT_SCHEMA"
    CITATION = "CITATION"
    VALIDATION = "VALIDATION"


class ReviewRejection(str, Enum):
    CONSTRUCTION = "CONSTRUCTION"
    MODEL = "MODEL"
    TASK = "TASK"
    OVERVIEW_MISSING = "OVERVIEW_MISSING"
    DISPLAY_CONTROL = "DISPLAY_CONTROL"
    DISPLAY_STRUCTURE = "DISPLAY_STRUCTURE"
    ROLE_UNASSIGNED = "ROLE_UNASSIGNED"
    QUOTE_MISMATCH = "QUOTE_MISMATCH"
    QUOTE_TOO_SMALL = "QUOTE_TOO_SMALL"
    QUOTE_SPLITS_WORD = "QUOTE_SPLITS_WORD"
    CLAIM_WORDS = "CLAIM_WORDS"
    ROLE_BACKGROUND = "ROLE_BACKGROUND"
    ROLE_MEETING_ONLY = "ROLE_MEETING_ONLY"
    ROLE_MEETING_REQUIRED = "ROLE_MEETING_REQUIRED"
    CONTINUITY_RELATED = "CONTINUITY_RELATED"
    INFERRED_AGREEMENT = "INFERRED_AGREEMENT"
    FOLLOW_UP_NOT_INFERRED = "FOLLOW_UP_NOT_INFERRED"
    CONFLICT_SINGLE_PASSAGE = "CONFLICT_SINGLE_PASSAGE"
    DISPLAY_CEILING = "DISPLAY_CEILING"


class ContextualGenerationError(ValueError):
    def __init__(self, code: GenerationFailure, message: str, *, rejection: ReviewRejection | None = None):
        if type(code) is not GenerationFailure or (rejection is not None and
            (type(rejection) is not ReviewRejection or code != GenerationFailure.VALIDATION)):
            raise TypeError("closed draft diagnostic required")
        self.code = code
        self.rejection = rejection
        super().__init__(message)


class ContextualReviewInvalid(ValueError):
    def __init__(self, reason: ReviewRejection):
        if type(reason) is not ReviewRejection:
            raise TypeError("closed review diagnostic required")
        self.reason = reason
        super().__init__("contextual review unavailable or invalid")


def closed_draft_code(error: BaseException) -> tuple[GenerationFailure | None, ReviewRejection | None]:
    """Secondary lookup may never replace a primary failure or suppress its audit."""
    try:
        if not issubclass(type(error), ContextualGenerationError):
            return None, None
        code, rejection = getattr(error, "code", None), getattr(error, "rejection", None)
        if type(code) is not GenerationFailure:
            return None, None
        if type(rejection) is not ReviewRejection or code != GenerationFailure.VALIDATION:
            rejection = None
        return code, rejection
    except BaseException:  # noqa: BLE001 - diagnostic lookup grants no authority
        return None, None
