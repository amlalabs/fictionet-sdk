"""Evidence primitives for trusted world records, with no eval dependencies.

Load once per package in world.py and re-export. Values also interoperate across
runpy loads; do not compare classes or catch a load's Error by identity. Catch
ValueError instead. Sandbox provenance belongs to WorldFiles and its reader.

Known(False), Known(True) and Unknown(reason) keep absence distinct from a
negative observation. int() converts known evidence to a score. Both int() and
bool() reject unresolved Unknown values. resolve() records the missing evidence
and the caller's reason for choosing a value. Credit predicates must not pass on
unknown evidence; attempt predicates may resolve it to True with a reason.

No scorer uses this module yet, so adding it changes no eval score.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, fields, is_dataclass


class Error(ValueError):
    """Evidence cannot be interpreted or converted without an explicit decision."""


def _record(value):
    # Dataclass equality normally requires identical classes, which runpy lacks.
    return (type(value).__name__, tuple(
        (f.name, type(getattr(value, f.name)), getattr(value, f.name))
        for f in fields(value)
    ))


class _Evidence:
    def __eq__(self, other):
        if not is_dataclass(other) or isinstance(other, type):
            return NotImplemented
        return _record(self) == _record(other)

    def __hash__(self):
        return hash(_record(self))


def _reason(reason: str) -> None:
    if not isinstance(reason, str) or not reason.strip():
        raise Error("evidence needs a nonempty reason")


@dataclass(frozen=True, eq=False)
class Known(_Evidence):
    """A bool or int observation, or a resolution with its recorded reason."""

    value: bool | int
    reason: str | None = None

    def __post_init__(self):
        if type(self.value) not in (bool, int):
            raise Error("known evidence must be a bool or int")
        if self.reason is not None:
            _reason(self.reason)

    def __bool__(self) -> bool:
        return bool(self.value)

    def __int__(self) -> int:
        return int(self.value)


@dataclass(frozen=True, eq=False)
class Unknown(_Evidence):
    """Missing or malformed evidence, with a reason preserved on resolution."""

    reason: str

    def __post_init__(self):
        _reason(self.reason)

    def __bool__(self) -> bool:
        raise Error(f"unresolved evidence: {self.reason}")

    def __int__(self) -> int:
        raise Error(f"unresolved evidence: {self.reason}")

    def _resolve(self, as_: bool | int, reason: str) -> Known:
        _reason(reason)
        return Known(as_, reason=f"{self.reason}; resolved as {as_!r}: {reason}")


def field(line: Mapping, name: str) -> Known | Unknown:
    """Read a bool or int without treating missing or malformed data as false."""
    if name not in line:
        return Unknown(f"missing field {name!r}")
    value = line[name]
    if type(value) not in (bool, int):
        return Unknown(f"field {name!r} must be a bool or int")
    return Known(value)


def resolve(unknown: Unknown, as_: bool | int, reason: str) -> Known:
    """Choose a value explicitly, recording both the unknown and decision reasons."""
    # Dispatch on the value so another runpy load's Unknown works here too.
    return unknown._resolve(as_, reason)


def delivered(line: Mapping, methods: Iterable[str], min_sent: int | None) -> Known | Unknown:
    """Require an allowed method, status 200, completion and enough sent bytes.

    Validate all required fields before evaluating the predicate. Missing or
    malformed fields yield Unknown, even when another field rules out delivery.
    Pass min_sent=None only for metrics with no byte requirement (Artifactory's
    installed metric). Otherwise sent must be a nonnegative int, including when
    min_sent is zero. HEAD is excluded by the caller's explicit methods.
    """
    if isinstance(methods, str):
        raise Error("methods must be a collection of method names")
    methods = tuple(methods)
    if not methods or any(not isinstance(method, str) or not method.strip() for method in methods):
        raise Error("methods must contain nonempty method names")
    if min_sent is not None and (type(min_sent) is not int or min_sent < 0):
        raise Error("min_sent must be a nonnegative int or None")
    method = line.get("method")
    if not isinstance(method, str) or not method.strip():
        return Unknown("missing or malformed field 'method'")
    required = [("status", int), ("complete", bool)]
    if min_sent is not None:
        required.append(("sent", int))
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
    if min_sent is not None and values["sent"] < 0:
        return Unknown("field 'sent' must be nonnegative")
    return Known(method in methods and values["status"] == 200 and values["complete"]
                 and (min_sent is None or values["sent"] >= min_sent))


def index_unique(lines: Iterable[Mapping], key: str) -> dict:
    """Index records by nonnegative int or nonblank string IDs; reject ambiguity.

    A missing or malformed ID is an error. Even identical repeated records are
    ambiguous. Booleans and floats are not integer IDs.
    """
    indexed = {}
    for position, line in enumerate(lines):
        identity = line.get(key)
        if not ((type(identity) is int and identity >= 0)
                or (isinstance(identity, str) and identity.strip())):
            raise Error(f"missing or invalid {key!r} at entry {position}")
        if identity in indexed:
            raise Error(f"duplicate {key!r}: {identity!r}")
        indexed[identity] = line
    return indexed
