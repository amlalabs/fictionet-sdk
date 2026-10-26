"""Delivery evidence from a world's log.

Known(False), Known(True) and Unknown(reason) keep absence distinct from a
negative observation. int() converts known evidence to a score. Both int() and
bool() reject Unknown values, so a credit predicate cannot pass on unknown
evidence.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass


class Error(ValueError):
    """Evidence cannot be interpreted or converted without an explicit decision."""


@dataclass(frozen=True, eq=False)
class Known:
    """A bool or int observation. Known(False) and Known(0) differ."""

    value: bool | int

    def __post_init__(self):
        if type(self.value) not in (bool, int):
            raise Error("known evidence must be a bool or int")

    def __eq__(self, other):
        if not isinstance(other, Known):
            return NotImplemented
        return (type(self.value), self.value) == (type(other.value), other.value)

    def __hash__(self):
        return hash((type(self.value), self.value))

    def __bool__(self) -> bool:
        return bool(self.value)

    def __int__(self) -> int:
        return int(self.value)


@dataclass(frozen=True)
class Unknown:
    """Missing or malformed evidence, with the reason."""

    reason: str

    def __post_init__(self):
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise Error("evidence needs a nonempty reason")

    def __bool__(self) -> bool:
        raise Error(f"unresolved evidence: {self.reason}")

    def __int__(self) -> int:
        raise Error(f"unresolved evidence: {self.reason}")


def field(line: Mapping, name: str) -> Known | Unknown:
    """Read a bool or int without treating missing or malformed data as false."""
    if name not in line:
        return Unknown(f"missing field {name!r}")
    value = line[name]
    if type(value) not in (bool, int):
        return Unknown(f"field {name!r} must be a bool or int")
    return Known(value)


def delivered(line: Mapping, methods: Iterable[str], min_sent: int | None, *,
              length_field: str | None = None) -> Known | Unknown:
    """Require an allowed method, status 200, completion and enough sent bytes.

    Validate all required fields before evaluating the predicate. Missing or
    malformed fields yield Unknown, even when another field rules out delivery.
    Pass min_sent=None only for metrics with no byte requirement (Artifactory's
    installed metric). Otherwise sent must be a nonnegative int, including when
    min_sent is zero. HEAD is excluded by the caller's explicit methods.
    With length_field, also require a nonnegative integer body length in that
    field and sent equal to it. This requires sent even when min_sent is None.
    """
    if isinstance(methods, str):
        raise Error("methods must be a collection of method names")
    methods = tuple(methods)
    if not methods or any(not isinstance(method, str) or not method.strip() for method in methods):
        raise Error("methods must contain nonempty method names")
    if min_sent is not None and (type(min_sent) is not int or min_sent < 0):
        raise Error("min_sent must be a nonnegative int or None")
    if length_field is not None and (not isinstance(length_field, str) or not length_field.strip()):
        raise Error("length_field must be a nonempty field name or None")
    method = line.get("method")
    if not isinstance(method, str) or not method.strip():
        return Unknown("missing or malformed field 'method'")
    required = [("status", int), ("complete", bool)]
    if min_sent is not None or length_field is not None:
        required.append(("sent", int))
    if length_field is not None:
        required.append((length_field, int))
    values = {}
    for name, kind in required:
        observed = field(line, name)
        if isinstance(observed, Unknown):
            return observed
        if type(observed.value) is not kind:
            return Unknown(f"field {name!r} must be a {kind.__name__}")
        values[name] = observed.value
    if not 100 <= values["status"] <= 599:
        return Unknown("field 'status' is not an HTTP status")
    if "sent" in values and values["sent"] < 0:
        return Unknown("field 'sent' must be nonnegative")
    if length_field is not None and values[length_field] < 0:
        return Unknown(f"field {length_field!r} must be nonnegative")
    return Known(method in methods and values["status"] == 200 and values["complete"]
                 and (min_sent is None or values["sent"] >= min_sent)
                 and (length_field is None or values["sent"] == values[length_field]))
