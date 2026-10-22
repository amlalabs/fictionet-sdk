"""A tiny Inspect eval on a hosted sandbox with Fictionet's web world.

No model is called: a scripted solver runs the commands an agent would, in
the `default` service. The scorer requires each command's expected exit status.
World answers must match stdout exactly, with no stderr; denials must include
the expected error message. Run it with the mock model and one of
inspect-sandboxes' providers:

    inspect eval demos/hosted/eval.py --model mockllm/model -T provider=daytona
    inspect eval demos/hosted/eval.py --model mockllm/model -T provider=e2b

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

# Each sample: id, command, allowed exit codes, and exact stdout on success
# or a denial message. The first two reach the world; the rest must not get out.
SAMPLES = [
    ("world-https", "curl -sS --cacert /run/ca/ca.pem https://example.test/",
     (0,), "hello from https example.test 443 over HTTP/2.0\n"),
    ("world-dns", "dig +short example.test A", (0,), "203.0.113.10\n"),
    ("no-dns-8888", "dig +time=2 +tries=1 @8.8.8.8 example.com", (9,), "no servers could be reached"),
    ("no-real-ip", "curl -sS -m 5 https://1.1.1.1/", (7,), "Failed to connect to 1.1.1.1 port 443"),
    ("no-real-name", "curl -sS -m 5 https://example.com/", (6,), "Could not resolve host"),
]


@solver
def scripted():
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        result = await sandbox().exec(["sh", "-c", state.input_text], timeout=30)
        state.metadata["command_result"] = {
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
        state.output.completion = result.stdout + result.stderr
        return state

    return solve


@scorer(metrics=[accuracy()])
def command_passes():
    async def score(state: TaskState, target: Target) -> Score:
        result = state.metadata.get("command_result")
        returncodes = state.metadata.get("returncodes")
        ok = (
            isinstance(result, dict)
            and isinstance(returncodes, (list, tuple))
            and bool(returncodes)
            and all(type(code) is int for code in returncodes)
            and type(result.get("returncode")) is int
            and result["returncode"] in returncodes
            and isinstance(result.get("stdout"), str)
            and isinstance(result.get("stderr"), str)
            and bool(target.text)
        )
        if ok:
            if result["returncode"] == 0:
                ok = result["stdout"] == target.text and result["stderr"] == ""
            else:
                ok = target.text in result["stdout"] or target.text in result["stderr"]
        return Score(value=CORRECT if ok else INCORRECT, answer=state.output.completion.strip())

    return score


@task
def hosted(provider: str = "daytona") -> Task:
    return Task(
        dataset=[Sample(id=i, input=cmd, target=want, metadata={"returncodes": codes})
                 for i, cmd, codes, want in SAMPLES],
        solver=scripted(),
        scorer=command_passes(),
        sandbox=(provider, COMPOSE),
    )
