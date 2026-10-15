"""One ledger per generation, including HTTP retries and unreadable answers."""
from __future__ import annotations

from dataclasses import asdict, dataclass


def total(values) -> int | float | None:
    """A total is unknown if any included value is unknown."""
    values = list(values)
    return sum(values) if values and all(v is not None for v in values) else None


@dataclass
class Attempt:
    ask: int
    attempt: int
    started: float  # monotonic seconds, local to this backend process
    ended: float
    outcome: str
    model: str
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost: float | None = None
    raw: str | None = None
    cut_off: bool = False
    backoff_ms: int = 0
    error: str | None = None

    @property
    def ms(self) -> int:
        return round((self.ended - self.started) * 1000)


class Ledger:
    """Timing and usage of every HTTP attempt, shared across parse re-asks."""

    def __init__(self, clock):
        self.clock = clock
        self.attempts: list[Attempt] = []
        self.ask = 1
        self.ended: float | None = None

    def finish(self) -> None:
        self.ended = self.clock()

    def usage(self) -> dict:
        last = self.attempts[-1]
        ended = self.ended if self.ended is not None else self.clock()
        return {"model": last.model, "gen_ms": round((ended - self.attempts[0].started) * 1000),
                "call_ms": last.ms if last.outcome == "ok" else None,
                "attempts": len(self.attempts), "asks": self.ask,
                "backoff_ms": sum(a.backoff_ms for a in self.attempts),
                "input_tokens": total(a.input_tokens for a in self.attempts),
                "output_tokens": total(a.output_tokens for a in self.attempts),
                "cost": total(a.cost for a in self.attempts),
                "cost_known": sum(a.cost for a in self.attempts if a.cost is not None),
                "cost_unknown": sum(a.cost is None for a in self.attempts), "cut_off": last.cut_off}

    def rows(self, context: dict, status: str):
        """Attempt rows; the last also carries the terminal generation totals."""
        for index, attempt in enumerate(self.attempts):
            row = {**context, "record": "attempt", **asdict(attempt), "ms": attempt.ms,
                   "terminal": index == len(self.attempts) - 1}
            if row["terminal"]:
                row["generation"] = {"status": status, **self.usage()}
                row["gen_ms"] = row["generation"]["gen_ms"]
            yield row
