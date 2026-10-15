"""examples/hosted/eval.py, ported to inspect_fictionet.

The eval is the same: a scripted solver runs the commands an agent would,
in the agent's sandbox. The scorer requires each command's expected exit status.
World answers must match stdout exactly, with no stderr; denials must include
the expected error message. No model is called. What changed is the sandbox:
one call to `fictionet_sandbox`
instead of a hand-written compose.yaml, with the published web_world and
attach images instead of images built from the repository.

    inspect eval examples/web_eval.py --model mockllm/model
    inspect eval examples/web_eval.py --model mockllm/model -T backend=k8s -T agent_image=<image>

On Kubernetes, the agent's image must be one the cluster can pull or
already has, such as the agent stage of deploy/Dockerfile built and loaded into kind.
"""

from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import CORRECT, INCORRECT, Score, Target, accuracy, scorer
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.util import sandbox

from inspect_fictionet import WEB_WORLD_IMAGE, Build, fictionet_sandbox, read_world_file

# Each sample: id, command, allowed exit codes, and exact stdout on success
# or a denial message. The CA comes from the world's container when scoring.
SAMPLES = [
    ("world-https", "curl -sS --cacert /run/ca/ca.pem https://example.test/",
     (0,), "hello from https example.test 443 over HTTP/2.0\n"),
    ("world-dns", "dig +short example.test A", (0,), "203.0.113.10\n"),
    ("world-ca", "cat /run/ca/ca.pem", (0,), "the world's CA"),
    ("no-dns-8888", "dig +time=2 +tries=1 @8.8.8.8 example.com", (9,), "no servers could be reached"),
    ("no-real-ip", "curl -sS -m 5 https://1.1.1.1/", (7,), "Failed to connect to 1.1.1.1 port 443"),
    ("no-real-name", "curl -sS -m 5 https://example.com/", (6,), "Could not resolve host"),
]  # fmt: skip


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
        out = state.output.completion
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
            if target.text == "the world's CA":
                # The ground truth is in the world's container: the CA it wrote.
                # The agent must see the same file.
                ca = await read_world_file("/run/ca/ca.pem")
                ok = (result["returncode"] == 0 and ca.startswith("-----BEGIN CERTIFICATE-----")
                      and result["stdout"] == ca and result["stderr"] == "")
            elif result["returncode"] == 0:
                ok = result["stdout"] == target.text and result["stderr"] == ""
            else:
                ok = target.text in result["stdout"] or target.text in result["stderr"]
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
        dataset=[Sample(id=i, input=cmd, target=want, metadata={"returncodes": codes})
                 for i, cmd, codes, want in samples],
        solver=scripted(),
        scorer=command_passes(),
        sandbox=fictionet_sandbox(
            WEB_WORLD_IMAGE,
            world_args=["/run/relay/relay.sock", "/run/ca/ca.pem"],
            world_ca="/run/ca/ca.pem",
            agent_image=agent_image or Build(Path(__file__).parent / "agent.Dockerfile"),
            backend=backend,
        ),
    )
