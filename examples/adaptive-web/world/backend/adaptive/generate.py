"""Generators make result lists and pages. `Model` asks a model API;
`stub.Stub` makes them offline. Both return a `Made`: the parsed answer
and what it cost.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import prompts
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
    fields: dict
    model: str
    ms: int
    input_tokens: int | None = None
    output_tokens: int | None = None
    cost: float | None = None
    raw: str | None = None
    cut_off: bool = False  # the model stopped at the output budget

    def usage(self) -> dict:
        return {"model": self.model, "gen_ms": self.ms, "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens, "cost": self.cost, "cut_off": self.cut_off}


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
        self.client = client
        self.model = client.model

    def _ask(self, system: str, user: str, max_tokens: int, read) -> Made:
        """One call, read with `read`. An answer that cannot be read is asked
        for once more, and the second failure is raised. The tokens, cost
        and time of both calls are counted."""
        spent = []
        while True:
            c = self.client.complete(system, user, max_tokens)
            spent.append(c)
            try:
                fields = read(c.text)
                break
            except prompts.Error:
                if len(spent) == 2:
                    raise
        return Made(fields, c.model, sum(x.ms for x in spent), _total(x.input_tokens for x in spent),
                    _total(x.output_tokens for x in spent), _total(x.cost for x in spent), c.text, c.cut_off)

    def cast(self) -> Made:
        system, user = prompts.cast(self.seed)
        return self._ask(system, user, CAST_TOKENS, prompts.read_cast)

    def search(self, query: str, known: list[dict], claims: list[dict], cast: list[dict]) -> Made:
        system, user = prompts.search(self.seed, cast, query, known, claims)
        return self._ask(system, user, SEARCH_TOKENS, prompts.read_search)

    def page(self, ask: PageAsk) -> Made:
        system, user = prompts.page(self.seed, ask.cast, ask.url, ask.mentions, ask.profile, ask.host_pages,
                                    ask.claims)
        expected = prompts.expected_type(ask.url)
        return self._ask(system, user, PAGE_TOKENS, lambda text: prompts.read_page(text, expected))


def _total(values) -> float | None:
    known = [v for v in values if v is not None]
    return sum(known) if known else None
