"""Separate model exposure, episode termination and judgment availability.

This module uses only the standard library and accepts Inspect-shaped objects.
It can be loaded with runpy.run_path. Compare status strings across loads.
No scorer uses it yet, so adding it changes no eval score.
"""

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal

_MISSING = object()


@dataclass(frozen=True)
class Exposure:
    """Whether one message was consumed, absent from inputs, or unresolved."""

    status: Literal["seen", "not_seen", "unknown"]
    reason: str


@dataclass(frozen=True)
class Termination:
    """Why generation ended, retaining the sample limit type when recorded."""

    status: Literal["completed", "filtered", "model_length", "limit", "no_final_reply", "unknown"]
    reason: str
    limit_type: str | None = None


@dataclass(frozen=True)
class Judgment:
    """A validated binary verdict or the reason no verdict is available.

    Attempts and raw grader text stay None when not recorded. Only graded
    outcomes carry values; failure and absence never become zero verdicts.
    """

    status: Literal["graded", "grader_failed", "no_answer", "unknown"]
    reason: str
    values: dict | None = None
    attempts: int | None = None
    raw: str | None = None


def _sequence(value):
    return isinstance(value, Sequence) and not isinstance(value, (str, bytes))


def _identity(message):
    identity = getattr(message, "id", None)
    return identity if isinstance(identity, str) and identity.strip() else None


def _model_problem(event):
    error = getattr(event, "error", _MISSING)
    pending = getattr(event, "pending", _MISSING)
    if error is _MISSING or pending is _MISSING:
        return "model event lacks error or pending status"
    if error is not None:
        return f"model call failed: {getattr(error, 'message', error)}"
    if pending:
        return "model call is pending"
    return None


def message_exposure(messages: Sequence, events: Sequence | None = None) -> dict[int, Exposure]:
    """Classify each message index using IDs in finished model-call inputs.

    Only calls with error=None and a recorded, falsy pending flag prove seen.
    Failed or pending calls leave their inputs unknown. Missing IDs, duplicate
    IDs and incomplete input provenance also remain unknown. An empty recorded
    event list proves no consumption; None means the events were not recorded.
    Empty model inputs and unresolved input_refs are incomplete provenance.
    A later failed call does not erase an earlier successful consumption.

    Consumers can select indices whose status is 'seen' for ordered evidence,
    or use those indices to retrieve tool text and tool errors from messages.
    """
    identities = [_identity(message) for message in messages]
    counts = Counter(identities)
    seen, uncertain = set(), {}
    incomplete = None if _sequence(events) else "model events were not recorded"
    for event in events if _sequence(events) else ():
        kind = getattr(event, "event", None)
        if not isinstance(kind, str) or not kind:
            incomplete = "event type is missing or malformed"
        if kind != "model":
            continue
        inputs = getattr(event, "input", None)
        if not _sequence(inputs) or not inputs:
            incomplete = "model event inputs are missing, empty or malformed"
            continue
        if getattr(event, "input_refs", None) is not None:
            incomplete = "model input references are unresolved"
        input_ids = Counter(_identity(message) for message in inputs)
        if None in input_ids:
            incomplete = "a model input has no message id"
        problem = _model_problem(event)
        for identity, count in input_ids.items():
            if identity is None:
                continue
            if problem or count != 1:
                uncertain[identity] = problem or "duplicate message id in model inputs"
            else:
                seen.add(identity)

    result = {}
    for index, identity in enumerate(identities):
        if identity is None:
            result[index] = Exposure("unknown", "message has no id")
        elif counts[identity] != 1:
            result[index] = Exposure("unknown", "duplicate message id in history")
        elif identity in seen:
            result[index] = Exposure("seen", "message id recorded in a finished model call")
        elif identity in uncertain or incomplete:
            result[index] = Exposure("unknown", uncertain.get(identity) or incomplete)
        else:
            result[index] = Exposure("not_seen", "message id absent from recorded model inputs")
    return result


def termination(messages: Sequence | None, output, events: Sequence | None = None) -> Termination:
    """Classify the final reply separately from any behavioral judgment.

    A sample_limit event takes precedence and preserves its type and message.
    A pending or errored final model call cannot complete an earlier reply.
    Provider filtering and model length are distinct from an agent decision.
    Completion requires a normal stop, nonblank completion, final assistant
    message without tool calls, and a recorded final model call with error=None
    and a recorded, falsy pending flag. Pass the agent's events recorded before
    scoring so a scorer's grader calls cannot stand in for the agent's last call.
    """
    recorded = events if _sequence(events) else ()
    for event in reversed(recorded):
        if getattr(event, "event", None) == "sample_limit":
            kind = getattr(event, "type", None)
            return Termination("limit", getattr(event, "message", None) or "sample limit reached", kind)
    finished_model_call = False
    for event in reversed(recorded):
        if getattr(event, "event", None) == "model":
            problem = _model_problem(event)
            if problem:
                return Termination("unknown", problem)
            finished_model_call = True
            break
    # Inspect's stop_reason property indexes choices[0], even for empty output.
    choices = getattr(output, "choices", _MISSING)
    stop = (getattr(output, "stop_reason", None)
            if choices is _MISSING or (_sequence(choices) and choices) else None)
    if stop == "content_filter":
        detail = getattr(output, "error", None)
        reason = "provider stopped generation: content_filter"
        return Termination("filtered", f"{reason}: {detail}" if detail else reason)
    if stop == "model_length":
        return Termination("model_length", "provider stopped generation: model_length")
    if not _sequence(messages) or not messages:
        return Termination("unknown", "final message is missing")
    last = messages[-1]
    role = getattr(last, "role", None)
    calls = getattr(last, "tool_calls", _MISSING)
    if role == "tool" or (role == "assistant" and calls is not _MISSING and calls):
        return Termination("no_final_reply", "history ends with an unfinished tool exchange")
    if output is None or not _sequence(events):
        return Termination("unknown", "final output or event sequence is missing")
    if role != "assistant" or (calls is not None and not _sequence(calls)) or stop != "stop":
        return Termination("unknown", f"no confirmed final assistant stop: {stop!r}")
    completion = getattr(output, "completion", _MISSING)
    if completion is None or (isinstance(completion, str) and not completion.strip()):
        return Termination("no_final_reply", "final completion is empty")
    if not isinstance(completion, str):
        return Termination("unknown", "final completion is missing or malformed")
    if not finished_model_call:
        return Termination("unknown", "no model call was recorded")
    return Termination("completed", "final assistant reply ended with stop")


def judgment(completion, values=None, *, keys: Sequence[str] = (), metadata=None) -> Judgment:
    """Classify a scorer verdict or saved score using the same binary schema.

    Pass the required metric keys explicitly, plus the score's value and
    metadata. Missing, extra or nonbinary values are unknown. A scorer may
    record grader_failed, grader_attempts, grader_raw and grader_error in
    metadata; legacy grader_failed=True is sufficient to identify failure.
    Blank or None completions are no_answer even if values award credit.
    An explicit grader failure takes precedence over an absent answer.
    """
    if metadata is None:
        metadata = {}
    if not isinstance(metadata, Mapping):
        return Judgment("unknown", "score metadata is malformed")
    failed = metadata.get("grader_failed", False)
    attempts = metadata.get("grader_attempts")
    raw = metadata.get("grader_raw")
    reason = metadata.get("grader_error")
    if (type(failed) is not bool
            or (attempts is not None and (type(attempts) is not int or attempts < 0))
            or (raw is not None and not isinstance(raw, str))
            or (reason is not None and (not isinstance(reason, str) or not reason.strip() or not failed))):
        return Judgment("unknown", "grader metadata is malformed")
    if failed:
        return Judgment("grader_failed", reason or "grader failed", attempts=attempts, raw=raw)
    if completion is None or (isinstance(completion, str) and not completion.strip()):
        return Judgment("no_answer", "answer is empty", attempts=attempts, raw=raw)
    if not isinstance(completion, str):
        return Judgment("unknown", "answer is malformed", attempts=attempts, raw=raw)
    if (not _sequence(keys) or not keys
            or any(not isinstance(key, str) or not key.strip() for key in keys)
            or len(set(keys)) != len(keys)):
        return Judgment("unknown", "required verdict keys are missing or malformed", attempts=attempts, raw=raw)
    if (not isinstance(values, Mapping) or set(values) != set(keys)
            or any(type(value) not in (bool, int, float) or value not in (0, 1) for value in values.values())):
        return Judgment("unknown", "verdict does not match the required binary schema", attempts=attempts, raw=raw)
    return Judgment("graded", "validated verdict for a nonempty answer", dict(values), attempts, raw)
