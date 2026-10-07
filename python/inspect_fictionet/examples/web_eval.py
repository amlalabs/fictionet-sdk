"""examples/hosted/eval.py, ported to inspect_fictionet.

The eval is the same: a scripted solver runs the commands an agent would,
in the agent's sandbox, and the scorer checks what came back. No model is
called. What changed is the sandbox: one call to `fictionet_sandbox`
instead of a hand-written compose.yaml, with the published web_world and
attach images instead of images built from the repository.

    inspect eval examples/web_eval.py --model mockllm/model
    inspect eval examples/web_eval.py --model mockllm/model -T backend=k8s -T agent_image=<image>

On Kubernetes, the agent's image must be one the cluster can pull or
already has, such as tests/k8s/agent.Dockerfile built and loaded into kind.
"""

from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import CORRECT, INCORRECT, Score, Target, accuracy, scorer
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.util import sandbox

from inspect_fictionet import WEB_WORLD_IMAGE, Build, fictionet_sandbox, read_world_file

# Each sample: a command for the agent's sandbox, and a text its output must
# contain. The first three reach the world; the rest must not get out.
SAMPLES = [
    ("world-https", "curl -sS --cacert /run/ca/ca.pem https://example.test/",
     "hello from https example.test 443 over HTTP/2.0"),
    ("world-dns", "dig +short example.test A", "203.0.113.10"),
    ("world-ca", "cat /run/ca/ca.pem", "the world's CA"),
    ("no-dns-8888", "dig +time=2 +tries=1 @8.8.8.8 example.com", "no servers could be reached"),
    ("no-real-ip", "curl -sS -m 5 https://1.1.1.1/", "Failed to connect to 1.1.1.1 port 443"),
    ("no-real-name", "curl -sS -m 5 https://example.com/", "Could not resolve host"),
]  # fmt: skip


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
        out = state.output.completion
        if target.text == "the world's CA":
            # The ground truth is in the world's container: the CA it wrote.
            # The agent must see the same file.
            ca = await read_world_file("/run/ca/ca.pem")
            ok = ca.startswith("-----BEGIN CERTIFICATE-----") and out == ca
        else:
            ok = target.text in out
        return Score(value=CORRECT if ok else INCORRECT, answer=out.strip())

    return score


@task
def web(backend: str = "docker", agent_image: str | None = None) -> Task:
    samples = SAMPLES
    if backend == "k8s":
        # The scratch world image has no shell, which reading files on
        # Kubernetes needs.
        samples = [s for s in SAMPLES if s[0] != "world-ca"]
    return Task(
        dataset=[Sample(id=i, input=cmd, target=want) for i, cmd, want in samples],
        solver=scripted(),
        scorer=contains(),
        sandbox=fictionet_sandbox(
            WEB_WORLD_IMAGE,
            world_args=["/run/relay/relay.sock", "/run/ca/ca.pem"],
            world_ca="/run/ca/ca.pem",
            agent_image=agent_image or Build(Path(__file__).parent / "agent.Dockerfile"),
            backend=backend,
        ),
    )
