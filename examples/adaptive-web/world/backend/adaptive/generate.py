"""Generators make result lists and pages. `Model` asks a model API;
`stub.Stub` makes them offline. Both return a `Made`: the parsed answer
and what it cost.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import llm, prompts
from .attempts import Ledger, total as _total
from .llm import Anthropic, OpenRouter
from .seed import Seed

# Output budgets, in tokens. A page asks for 200 to 450 words of content plus
# a few header lines; a result list is ten short results. The limits leave
# room above that, and cut off an answer that runs on.
SEARCH_TOKENS = 1800
PAGE_TOKENS = 2000
CAST_TOKENS = 800


@dataclass
class Made:
    """Parsed output and total usage, including failed attempts and backoff."""
    fields: dict
    model: str
    ms: int
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost: float | None = None
    raw: str | None = None
    cut_off: bool = False  # the model stopped at the output budget
    call_ms: int | None = None
    attempts: int = 1
    asks: int = 1
    cost_known: float = 0
    cost_unknown: int = 1
    backoff_ms: int = 0

    def usage(self) -> dict:
        return {"model": self.model, "gen_ms": self.ms, "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens, "cost": self.cost, "cut_off": self.cut_off,
                "call_ms": self.call_ms, "attempts": self.attempts, "asks": self.asks,
                "cost_known": self.cost_known, "cost_unknown": self.cost_unknown, "backoff_ms": self.backoff_ms}


@dataclass
class PageAsk:
    """What a new page is made from."""
    url: str
    host: str
    target: str
    mentions: list[dict]  # the results and links that pointed here
    profile: dict | None  # the host's layout, if it has one yet
    host_pages: list[dict]  # the host's earlier pages
    claims: list[dict]  # recent claims from anywhere in the world
    cast: list[dict]  # the people the world names


class Model:
    """Makes result lists and pages with a model, through `client`."""

    def __init__(self, seed: Seed, client: Anthropic | OpenRouter):
        self.seed = seed
        # Only _ask can reach the client, so every generator method records
        # its attempts through the same path.
        self.__complete = client.complete
        self.provider = client.provider
        self.reasoning = getattr(client, "reasoning", "")
        self.model = client.model
        self.record = None  # World binds this to its store before generation.

    def _ask(self, system: str, user: str, max_tokens: int, read, **context) -> Made:
        """Read an answer, re-asking once if it is unreadable, then raise.

        `gen_ms` spans the first HTTP start through parsing the final answer,
        including retries, backoff and re-asks. `call_ms` is the accepted
        answer's HTTP time alone. Every attempt is recorded even on failure.
        Model and parsing errors carry the finalized ledger to the handler.
        """
        ledger = Ledger(llm._clock)
        status = "error"
        try:
            for ask in (1, 2):
                ledger.ask = ask
                c = self.__complete(system, user, max_tokens, ledger=ledger)
                try:
                    fields = read(c.text)
                    status = "ok"
                    break
                except prompts.Error as err:
                    ledger.attempts[-1].outcome = "unreadable"
                    ledger.attempts[-1].error = str(err)
                    if ask == 2:
                        raise
                    user += f"\n\nThe previous answer could not be read: {err}\nAnswer again in the requested format."
        except (llm.Error, prompts.Error) as err:
            err.ledger = ledger
            raise
        finally:
            ledger.finish()
            if self.record is not None:
                for row in ledger.rows(context, status):
                    self.record(row)
        usage = ledger.usage()
        return Made(fields, ms=usage.pop("gen_ms"), raw=c.text, **usage)

    def cast(self) -> Made:
        system, user = prompts.cast(self.seed)
        return self._ask(system, user, CAST_TOKENS, prompts.read_cast, kind="cast")

    def search(self, query: str, known: list[dict], claims: list[dict], cast: list[dict]) -> Made:
        system, user = prompts.search(self.seed, cast, query, known, claims)
        return self._ask(system, user, SEARCH_TOKENS, prompts.read_search, kind="search", query=query)

    def page(self, ask: PageAsk) -> Made:
        system, user = prompts.page(self.seed, ask.cast, ask.url, ask.mentions, ask.profile, ask.host_pages,
                                    ask.claims)
        expected = prompts.expected_type(ask.url)
        return self._ask(system, user, PAGE_TOKENS,
                         lambda text: prompts.read_page(text, expected, referenced=bool(ask.mentions)),
                         kind="page", url=ask.url)
