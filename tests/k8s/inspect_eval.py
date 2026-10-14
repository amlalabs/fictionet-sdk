"""One Inspect eval on Kubernetes, through inspect_k8s_sandbox with the
fictionet-sandbox chart. No model is called: the solver runs fixed
commands in the sandbox, so `--model mockllm/model` works with no API key.
Each check scores only its own exit status and output. Direct internet access
must fail to connect or time out. The transcript is only for diagnostics.

    inspect eval tests/k8s/inspect_eval.py --model mockllm/model

Needs kubectl access to a cluster (KUBECONFIG), helm on PATH, and the
images in examples/attach/k8s-tun.yaml on the cluster's nodes. tests/k8s/run.sh
sets all of that up on kind.
"""

from pathlib import Path

from inspect_ai import Task, task
from inspect_ai.dataset import Sample
from inspect_ai.scorer import CORRECT, INCORRECT, Score, Target, accuracy, scorer
from inspect_ai.solver import Generate, TaskState, solver
from inspect_ai.util import sandbox
from k8s_sandbox import K8sSandboxEnvironmentConfig

HERE = Path(__file__).parent
CHART = HERE.parent.parent / "charts" / "fictionet-sandbox"
VALUES = HERE.parent.parent / "examples" / "attach" / "k8s-tun.yaml"

# Each command, its allowed exit codes, and text its output must contain.
CHECKS = [
    ("curl -sS --cacert /run/ca/ca.pem https://example.test/", (0,), "hello from https example.test 443"),
    ("dig +short example.test", (0,), "203.0.113.10"),
    ("curl -sS -m 5 http://1.1.1.1/", (7, 28), ""),
    ("ip link set eth0 up", (2,), "Operation not permitted"),
    ("ls /run/relay", (2,), "No such file or directory"),
]


@solver
def run_checks():
    async def solve(state: TaskState, generate: Generate) -> TaskState:
        lines = []
        results = {}
        for command, _, _ in CHECKS:
            result = await sandbox().exec(["sh", "-c", command], timeout=30)
            results[command] = {
                "returncode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            }
            lines.append(f"$ {command}\n{result.stdout}{result.stderr}\nexit: {result.returncode}")
        state.metadata["check_results"] = results
        state.output.completion = "\n".join(lines)
        return state

    return solve


@scorer(metrics=[accuracy()])
def all_checks_pass():
    async def score(state: TaskState, target: Target) -> Score:
        out = state.output.completion
        results = state.metadata.get("check_results", {})
        failed = []
        for command, returncodes, want in CHECKS:
            result = results.get(command)
            if (
                result is None
                or result["returncode"] not in returncodes
                or not (want in result["stdout"] or want in result["stderr"])
            ):
                failed.append(command)
        return Score(value=INCORRECT if failed else CORRECT, answer=out, explanation=f"failed: {failed}")

    return score


@task
def fictionet_k8s():
    return Task(
        dataset=[Sample(input="Fetch https://example.test/ from the world.", target="hello")],
        solver=run_checks(),
        scorer=all_checks_pass(),
        sandbox=("k8s", K8sSandboxEnvironmentConfig(chart=str(CHART), values=VALUES)),
    )
