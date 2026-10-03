"""A tiny Inspect eval on a hosted sandbox with Fictionet's web world.

No model is called: a scripted solver runs the commands an agent would, in
the `default` service, and the scorer checks what came back. Run it with the
mock model and one of inspect-sandboxes' providers:

    inspect eval examples/hosted/eval.py --model mockllm/model -T provider=daytona
    inspect eval examples/hosted/eval.py --model mockllm/model -T provider=e2b

The compose file has three services, so inspect-sandboxes runs it with
Docker inside one sandbox. `-T provider=docker` runs the same eval on local
Docker.
"""

from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import CORRECT, INCORRECT, Score, Target, accuracy, scorer
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.util import sandbox

COMPOSE = str(Path(__file__).parent / "compose.yaml")

# Each sample: a command for the agent's sandbox, and a pattern its output
# must contain. The first two reach the world; the rest must not get out.
SAMPLES = [
    ("world-https", "curl -sS --cacert /run/ca/ca.pem https://example.test/",
     "hello from https example.test 443 over HTTP/2.0"),
    ("world-dns", "dig +short example.test A", "203.0.113.10"),
    ("no-dns-8888", "dig +time=2 +tries=1 @8.8.8.8 example.com", "no servers could be reached"),
    ("no-real-ip", "curl -sS -m 5 https://1.1.1.1/", "Failed to connect to 1.1.1.1 port 443"),
    ("no-real-name", "curl -sS -m 5 https://example.com/", "Could not resolve host"),
]


@solver
def scripted():
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        result = await sandbox().exec(["sh", "-c", state.input_text], timeout=30)
        state.output.completion = result.stdout + result.stderr
        return state

    return solve


@scorer(metrics=[accuracy()])
def contains():
    async def score(state: TaskState, target: Target) -> Score:
        ok = target.text in state.output.completion
        return Score(value=CORRECT if ok else INCORRECT, answer=state.output.completion.strip())

    return score


@task
def hosted(provider: str = "daytona") -> Task:
    return Task(
        dataset=[Sample(id=i, input=cmd, target=want) for i, cmd, want in SAMPLES],
        solver=scripted(),
        scorer=contains(),
        sandbox=(provider, COMPOSE),
    )
