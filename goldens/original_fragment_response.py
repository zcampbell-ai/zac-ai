from __future__ import annotations
def _parse_fragment_response(
    reply: object,
    request: HistoryFragmentContextualRequestV1,
    route: ModelRoute,
    elapsed: float,
    expected_count: int,
) -> tuple[ContextualDraft, UsageObservation]:
    failure = F.RESPONSE_SHAPE
    try:
        if type(reply) is not dict:
            raise ValueError("fragment response shape")
        failure = F.RESPONSE_MODEL
        if reply.get("model") != route.identity.model_id:
            raise ValueError("fragment response model")
        failure = F.RESPONSE_INCOMPLETE
        if reply.get("done") is not True:
            raise ValueError("fragment response incomplete")
        failure = F.RESPONSE_SHAPE
        message = reply.get("message")
        if type(message) is not dict:
            raise ValueError("fragment response message shape")
        failure = F.RESPONSE_AUTHORITY
        if (
            message.get("role") != "assistant"
            or message.get("tool_calls")
            or message.get("thinking")
        ):
            raise ValueError("fragment response authority")
        if reply.get("done_reason") == "length":
            failure = F.RESPONSE_USAGE
            length_input = reply.get("prompt_eval_count")
            length_output = reply.get("eval_count")
            if type(length_input) is not int or type(length_output) is not int:
                raise ValueError("fragment length count type")
            reported = (length_input, length_output)
            if (
                any(n < 0 for n in reported)
                or reported[1] > request.task.max_output_tokens
                or sum(reported) > _context_tokens(route)
            ):
                raise ValueError("fragment length usage")
            failure = (
                F.OUTPUT_LIMIT
                if reported[1] == request.task.max_output_tokens
                and sum(reported) < _context_tokens(route)
                else F.RESPONSE_LENGTH
            )
            raise ValueError("fragment length completion")
        failure = F.RESPONSE_STOP_REASON
        if reply.get("done_reason") != "stop":
            raise ValueError("fragment response stop")
        failure = F.RESPONSE_USAGE
        input_count = reply.get("prompt_eval_count")
        output_count = reply.get("eval_count")
        if (
            type(input_count) is not int
            or type(output_count) is not int
            or input_count < 0
            or output_count < 0
        ):
            raise ValueError("fragment response counts")
        counts = (input_count, output_count)
        if counts[0] != expected_count:
            raise LocalContextualRuntimeError(
                "fragment prompt count mismatch", code=F.PROMPT_COUNT_MISMATCH
            )
        if counts[1] > request.task.max_output_tokens or sum(counts) > _context_tokens(route):
            raise ValueError("fragment response capacity")
        failure = F.RESPONSE_LATENCY
        if not 0 <= elapsed <= request.task.max_latency_ms:
            raise ValueError("fragment response latency")
        failure = F.RESPONSE_SCHEMA
        content = message.get("content")
        if type(content) is not str:
            raise ValueError("fragment response content")
        draft = parse_contextual_draft(content.encode())
        return draft, UsageObservation(
            input_tokens=counts[0], output_tokens=counts[1], latency_ms=elapsed, cost_usd=0
        )
    except Exception as error:  # noqa: BLE001 - no model/provider causes escape
        failure = closed_runtime_code(error) or failure
    raise LocalContextualRuntimeError("fragment contextual response rejected", code=failure)
