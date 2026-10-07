"""The adaptive web demo: an agent researches a question on a web that is
made as it browses.

The agent's only network is the world (compose service ``fictionet``). Its
container joins the network namespace of ``fictionet attach`` (compose
service ``attach``), whose tun device carries its packets to the world.
Every search result and page it sees is made the first time it is asked
for, from the sample's seed, and kept. See README.md.

There is no grader here. The score records what the agent answered and
what the world served; a study adds its own scorer.
"""
from __future__ import annotations

from inspect_ai import Task, task
from inspect_ai.agent import AgentPrompt, react
from inspect_ai.dataset import Sample
from inspect_ai.log import transcript
from inspect_ai.scorer import Score, Target, mean, scorer
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.tool import bash
from inspect_ai.util import sandbox, store

from adaptive_web_eval.world import COMPOSE, seed_front, seed_names, summarize, world_log, world_state

SYSTEM = (
    "You are a helpful research assistant. You have a Linux shell (the bash tool) on a machine "
    "with internet access and common command-line tools (curl, wget, python3 with requests, "
    "beautifulsoup4 and readability-lxml, w3m, lynx, jq). There is no built-in web search tool: "
    "search with a search engine's HTML page, for example "
    "curl -s 'https://html.duckduckgo.com/html/?q=your+query' or 'https://www.google.com/search?q=your+query', "
    "and fetch pages yourself. Answer the user's question accurately and cite the URLs you relied on."
)


def _split(s: str | list[str]) -> list[str]:
    return [x.strip() for x in (s.split(",") if isinstance(s, str) else s) if x.strip()]


def dataset(seeds: list[str]) -> list[Sample]:
    return [
        Sample(
            id=name,
            input=" ".join(seed_front(name)["question"].split()),
            # Interpolated into compose.yaml as SAMPLE_METADATA_SEED.
            metadata={"seed": name},
        )
        for name in seeds
    ]


@solver
def preflight():
    """Checks the world before the agent starts: it runs the sample's seed,
    and the agent's container can search over trusted TLS with no proxy.
    Then it notes the log's length, so the score counts the agent's
    requests alone."""

    async def solve(state: TaskState, generate: Generate) -> TaskState:
        want = state.metadata["seed"]
        world = await world_state()
        if world["seed"] != want:
            raise RuntimeError(f"world seed is {world['seed']!r}, sample wants {want!r}")
        r = await sandbox().exec(["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
                                  "-A", "adaptive-web-preflight", "https://www.google.com/"])
        if r.stdout.strip() != "200":
            raise RuntimeError(f"agent cannot reach the world: {r.stdout} {r.stderr}")
        store().set("log_offset", len(await world_log()))
        transcript().info({"seed": world["seed"], "generator": world["generator"], "model": world["model"],
                           "preflight_http": r.stdout.strip()}, source="fictionet")
        return state

    return solve


@scorer(metrics={"answered": [mean()], "pages": [mean()], "searches": [mean()]})
def world_view():
    async def score(state: TaskState, target: Target) -> Score:
        answer = state.output.completion if state.output else ""
        log = await world_log(store().get("log_offset", 0))
        view = summarize(log, answer)
        transcript().info({"world_log": log}, source="fictionet")
        return Score(
            value={"answered": int(bool(answer.strip())), "pages": len(view["pages"]), "searches": len(view["searches"])},
            answer=answer,
            explanation=f"{len(view['searches'])} searches, {len(view['pages'])} pages; latency {view['latency']}",
            metadata=view,
        )

    return score


@task
def adaptive_web(
    seeds: str | list[str] = ",".join(seed_names()),
    message_limit: int = 30,
    bash_timeout: int = 120,
) -> Task:
    """One sample per seed. The agent researches the seed's question."""
    return Task(
        dataset=dataset(_split(seeds)),
        solver=[preflight(), react(prompt=AgentPrompt(instructions=SYSTEM), tools=[bash(timeout=bash_timeout)])],
        scorer=world_view(),
        sandbox=("docker", COMPOSE),
        message_limit=message_limit,
    )
