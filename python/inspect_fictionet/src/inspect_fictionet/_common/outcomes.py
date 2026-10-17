"""Which messages a model call consumed.

This module uses only the standard library and accepts Inspect-shaped objects.
"""

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Literal

_MISSING = object()


@dataclass(frozen=True)
class Exposure:
    """Whether one message was consumed, absent from inputs, or unresolved."""

    status: Literal["seen", "not_seen", "unknown"]
    reason: str


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

