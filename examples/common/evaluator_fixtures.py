"""Offline inputs for the evaluator inventory, loaded only in a project environment.

Reuse the instance suites' evidence builders. Mock transport and model replies,
never the production parsers or predicates under contract.
"""
import asyncio
from contextlib import ExitStack, redirect_stdout
from copy import deepcopy
import importlib
import io
import json
from pathlib import Path
import runpy
import sys
import tempfile
from types import SimpleNamespace as NS
from unittest.mock import AsyncMock, Mock, patch

from check_evaluators import Fixture, ROOT


def load(path):
    path = ROOT / path
    with patch.object(sys, "path", [str(path.parent), *sys.path]):
        return runpy.run_path(str(path))


def category(ok):
    return "scored" if ok else "invalid-unknown"


def edit(evidence, path, *, remove=False):
    parent = evidence
    for key in path[:-1]:
        parent = parent[next(iter(parent)) if key == "*" else key]
    key = next(iter(parent)) if path[-1] == "*" else path[-1]
    if remove:
        del parent[key]
    else:
        parent[key] = None


def probes(entry):
    module = importlib.import_module(entry["module"])
    builder = load(entry["project"] + "/tests/test_probes.py")[entry["builder"]]
    if hasattr(builder, "__wrapped__"):
        builder = builder.__wrapped__
    original = builder()
    checks, _ = module.score_evidence(original, entry["argument"])
    if set(checks) != set(entry["checks"]):
        raise AssertionError(f"{entry['id']}: probe checks changed; update their removal fixtures")
    for name, spec in entry["checks"].items():
        finding, path = spec["finding"], spec["remove"]
        def run(ev, name=name):
            result = module.score_evidence(deepcopy(ev), entry["argument"])[0]
            if set(result) != set(entry["checks"]):
                raise AssertionError("probe check disappeared for adversarial evidence")
            return category(result[name] is True)
        missing = deepcopy(original)
        edit(missing, path, remove=True)
        yield Fixture(name + "/valid", "valid", finding, lambda run=run: run(original), "scored")
        yield Fixture(name + "/empty", "missing", finding, lambda run=run: run({}), "invalid-unknown")
        yield Fixture(name + "/missing-record", "missing", finding,
                      lambda run=run, ev=missing: run(ev), "invalid-unknown")
    yield Fixture("non-object", "malformed", entry["findings"][0],
                  lambda: category(any(module.score_evidence([], entry["argument"])[0].values())),
                  entry["non_object"], (AttributeError,))
    # A transfer may print HTTP 200 after failing halfway through its body.
    broken = deepcopy(original)
    record = broken
    for key in entry["transfer"]:
        record = record[next(iter(record)) if key == "*" else key]
    record["rc"] = 18
    yield Fixture("truncated-200", "malformed", "RH-090",
                  lambda: category(module.score_evidence(broken, entry["argument"])[0][entry["transfer_check"]]),
                  "invalid-unknown")


def preflight(entry):
    tasks = importlib.import_module(entry["module"])
    border = entry["project"].endswith("/border")
    world = {"seed": "fixture", "variant": "control", "task": "read", "generator": "stub", "model": "stub"}
    def run(mode):
        async def execute(argv, **kwargs):
            if argv == ["env"]:
                return NS(returncode=127 if mode == "missing" else 0,
                          stdout="PATH=/usr/bin\n", stderr="env missing" if mode == "missing" else "")
            if argv[0] == "ip":
                return NS(returncode=0, stdout="default via 10.0.0.1 dev tun0\n", stderr="")
            if "http://1.1.1.1/" in argv:
                return NS(returncode=7, stdout="", stderr="curl: (7) Failed to connect")
            return NS(returncode=18 if mode == "malformed" else 0,
                      stdout="200 verify=0" if border else "200", stderr="")
        with patch.multiple(tasks, sandbox=lambda: NS(exec=execute), world_state=AsyncMock(return_value=world),
                            store=Mock(), transcript=Mock()), ExitStack() as stack:
            stack.enter_context(patch.object(tasks, "log_size" if border else "world_log",
                                             AsyncMock(return_value=0 if border else [])))
            asyncio.run(tasks.preflight()(NS(metadata=world), None))
        return "scored"
    for kind in ("valid", "missing", "malformed"):
        yield Fixture(kind, kind, "RH-090" if kind == "malformed" else "RH-089",
                      lambda kind=kind: run(kind), "scored" if kind == "valid" else "raised", (RuntimeError,))


def world(entry):
    """Exercise the real private-file boundary before its domain consumer.

    A complete empty log can describe an idle episode. A missing file cannot.
    """
    project = entry["project"]
    module = importlib.import_module(entry["module"])
    if project.endswith("artifactory"):
        domain = importlib.import_module("artifactory_eval.world")
        truth = load(project + "/tests/conftest.py")["state"].__wrapped__()
        consume = lambda lines: domain.assess(lines, truth, "I could not install it.")
        reader = module.finalized_log
    elif project.endswith("border"):
        samples = load(project + "/tests/test_tasks.py")
        consume = lambda lines: samples["score"](samples["episode"](), lines)
        reader = module.world_log
    else:
        consume = (lambda lines: module.summarize(lines, "apollo11")) if project.endswith("fakewiki") else module.summarize
        reader = module.world_log
    def run(mode):
        data = b'{"type":"dns","name":"example.test","in_world":true}\n'
        if mode == "truncated":
            data = data[:-1]
        elif mode == "non-object":
            data = b'[]\n'
        async def execute(argv):
            if argv[0] == "sh":
                return NS(success=mode != "missing", stdout=str(len(data)), stderr="log missing")
            return NS(success=True, stdout="ok\n", stderr="")
        private = NS(exec=execute, read_file=AsyncMock(return_value=data))
        agent = NS(read_file=AsyncMock(side_effect=AssertionError("agent files are not world evidence")))
        with patch.object(module, "sandbox", lambda name=None: private if name else agent), ExitStack() as stack:
            if project.endswith("artifactory"):
                stack.enter_context(patch.object(module, "read_world_file", private.read_file))
            consume(asyncio.run(reader()))
        return "scored"
    for mode, kind in (("valid", "valid"), ("missing", "missing"),
                       ("truncated", "malformed"), ("non-object", "malformed")):
        yield Fixture(mode, kind, entry["findings"][0], lambda mode=mode: run(mode),
                      "scored" if mode == "valid" else "raised",
                      (RuntimeError, ValueError, TypeError, AttributeError))


def artifactory(entry):
    from artifactory_eval import probes as module
    expected = {s.id: s.metadata["expected"] for s in module.scripted_dataset()}
    # Each scripted score expectation and each command's required evidence has
    # its own removal check, including expectations whose correct value is zero.
    for case in module.CASES:
        metadata = {"egress": {}}
        paths = []
        for command in case.commands:
            for evidence in command.evidence:
                keys = evidence.bucket.split(".")
                parent = metadata["egress"]
                for key in keys[:-1]:
                    parent = parent.setdefault(key, {})
                bucket = parent.setdefault(keys[-1], [])
                paths.append(["egress", *keys, len(bucket)])
                bucket.append(deepcopy(evidence.entry))
        values = expected[case.name]
        def run(values, metadata, case=case):
            return category(not module.mismatches(case.name, values, expected[case.name], metadata))
        yield Fixture(case.name + "/valid", "valid", "RH-079",
                      lambda run=run, v=values, m=metadata: run(v, m), "scored")
        yield Fixture(case.name + "/empty", "missing", "RH-079", lambda run=run: run({}, {}), "invalid-unknown")
        for key in values:
            missing = {k: v for k, v in values.items() if k != key}
            yield Fixture(case.name + "/missing-score/" + key, "missing", "RH-079",
                          lambda run=run, v=missing, m=metadata: run(v, m), "invalid-unknown")
        for index, path in enumerate(paths):
            missing = deepcopy(metadata)
            edit(missing, path, remove=True)
            yield Fixture(f"{case.name}/missing-record/{index}", "missing", "RH-079",
                          lambda run=run, v=values, m=missing: run(v, m), "invalid-unknown")
        yield Fixture(case.name + "/forged-text", "malformed", "RH-079",
                      lambda run=run: run({"stdout": "all checks passed"}, {}), "invalid-unknown")


def border_scripted(entry):
    from border_eval import probes as module
    from inspect_ai.scorer import Score

    for group in ("LAB", "HOME"):
        for sample in getattr(module, group):
            md = sample.metadata
            original = {"values": deepcopy(md["expect"]), "metadata": deepcopy(md["expect_meta"]),
                        "answer": " ".join(md["answer_has"])}
            for name, item in md["expect_meta_has"].items():
                original["metadata"].setdefault(name, []).append(item)
            def run(evidence, md=md):
                border = Score(value=evidence.get("values", {}), metadata=evidence.get("metadata", {}),
                               answer=evidence.get("answer", ""))
                with patch.object(module, "score_episode", AsyncMock(return_value=border)), \
                        patch.object(module, "store", return_value={}), patch.object(module, "transcript", Mock()):
                    score = asyncio.run(module.scripted_checks()(NS(metadata=md), None))
                return category(score.value == 1)
            name = f"{group}/{sample.id}"
            yield Fixture(name + "/valid", "valid", "RH-012", lambda run=run, ev=original: run(ev), "scored")
            yield Fixture(name + "/empty", "missing", "RH-012", lambda run=run: run({}), "invalid-unknown")
            for field in ("values", "metadata"):
                for key in original[field]:
                    missing = deepcopy(original)
                    del missing[field][key]
                    yield Fixture(f"{name}/missing-record/{field}/{key}", "missing", "RH-012",
                                  lambda run=run, ev=missing: run(ev), "invalid-unknown")
            yield Fixture(name + "/forged-text", "malformed", "RH-012",
                          lambda run=run: run({"values": "all passed", "answer": "curl: (60)"}), "invalid-unknown")


def hosted(entry):
    from inspect_ai.scorer import CORRECT, Target
    module = NS(**load(entry["targets"][0].split(":")[0]))
    def run(mode):
        output = "hello from https example.test 443 over HTTP/2.0\n"
        result = {"returncode": 0, "stdout": output, "stderr": ""}
        metadata = {"returncodes": [0]}
        if mode != "missing":
            metadata["command_result"] = result
        if mode == "malformed":
            result["returncode"] = 56
        state = NS(metadata=metadata, output=NS(completion=output))
        score = asyncio.run(module.command_passes()(state, Target(output)))
        return category(score.value == CORRECT)
    for kind in ("valid", "missing", "malformed"):
        yield Fixture(kind, kind, "RH-087", lambda kind=kind: run(kind),
                      "scored" if kind == "valid" else "invalid-unknown")


def harbor(entry):
    suite = load("examples/hosted/tests/test_harbor.py")
    def run(mode):
        test = suite["VerifierTests"]()
        try:
            test.setUp()
            if mode == "missing":
                test.answer.unlink()
            elif mode == "malformed":
                test.answer.write_text("hello from https example.test 443\n")
            result = test.run_script(suite["VERIFIER"])
            reward = (test.reward_dir / "reward.txt").read_text()
            if (result.returncode == 0) != (reward == "1\n"):
                raise AssertionError("verifier exit and reward disagree")
            return category(reward == "1\n")
        finally:
            test.doCleanups()
    for kind in ("valid", "missing", "malformed"):
        yield Fixture(kind, kind, "RH-022", lambda kind=kind: run(kind),
                      "scored" if kind == "valid" else "invalid-unknown")


def negative_control(entry):
    module = load(entry["project"] + "/scripts/negative_control.py")
    responses = load(entry["project"] + "/tests/test_probes.py")["responses"]
    def run(mode):
        samples = [] if mode == "missing" else [NS(id="probes__control", store={"outputs": {
            "leak": responses() if mode == "valid" else {"https://en.wikipedia.org/": "200 passed"}}})]
        with redirect_stdout(io.StringIO()):
            return category(not module["check"](samples))
    for kind in ("valid", "missing", "malformed"):
        yield Fixture(kind, kind, "RH-083", lambda kind=kind: run(kind),
                      "scored" if kind == "valid" else "invalid-unknown")


def verdict(entry):
    module = importlib.import_module("fakewiki_eval.tasks")
    for kind, text in (("valid", '{"fooled":false,"detected":false,"correct":true}'),
                       ("missing", ""), ("malformed", '{"fooled":"false","detected":false,"correct":true}')):
        def run(text=text):
            module._parse_verdict(text)
            return "scored"
        yield Fixture(kind, kind, "RH-081", run, "scored" if kind == "valid" else "raised", (ValueError,))
    suite = load(entry["project"] + "/tests/test_grading.py")
    def score(mode):
        grader = NS(generate=AsyncMock(return_value=NS(completion="not a verdict"))) if mode == "malformed" else None
        result = suite["Grading"]().score("" if mode == "missing" else "answer", grader=grader)
        return category(not result.metadata.get("no_answer", False))
    for kind in ("valid", "missing", "malformed"):
        yield Fixture("score/" + kind, kind, "RH-081", lambda kind=kind: score(kind),
                      {"valid": "scored", "missing": "invalid-unknown", "malformed": "raised"}[kind], (ValueError,))


def show_probes(entry):
    module = importlib.import_module(entry["module"])
    names = module.score_evidence({}, entry["argument"])[0]
    script = ROOT / entry["targets"][0].split(":")[0]

    def run(mode):
        checks = {name: mode != "failed" for name in names}
        if mode == "non-boolean":
            checks[next(iter(checks))] = "false"
        elif mode == "non-object":
            checks = [True]
        elif mode == "no-checks":
            checks = {}
        score = NS(value=1.0, metadata={"checks": checks, "details": {}}, explanation="fixture")
        sample = NS(id="probe", scores={} if mode == "no-scores" else {"probes": score}, error=None)
        log = NS(eval=NS(task=entry["module"].split("_eval")[0] + "_probes", task_args={}),
                 status="success", samples=[] if mode == "no-samples" else [sample])
        with patch("inspect_ai.log.read_eval_log", return_value=log), \
                patch.object(sys, "argv", [str(script), "fixture.eval"]), redirect_stdout(io.StringIO()) as output:
            runpy.run_path(str(script), run_name="__main__")
        if mode in ("valid", "failed"):
            verdict = "FAIL" if mode == "failed" else "PASS"
            if output.getvalue().count(verdict) != len(names) or "ERROR" in output.getvalue():
                raise AssertionError("report did not display each boolean verdict")
        return "scored"

    for mode, kind in (("valid", "valid"), ("failed", "valid"), ("no-samples", "missing"),
                       ("no-scores", "missing"), ("no-checks", "missing"),
                       ("non-object", "malformed"), ("non-boolean", "malformed")):
        yield Fixture(mode, kind, "RH-089", lambda mode=mode: run(mode),
                      "scored" if kind == "valid" else "raised", (SystemExit,))


def report(entry):
    from fakewiki_eval import report as module
    def run(mode):
        grade = NS(value={"fooled": 1, "detected": 1, "correct": 1}, answer="answer", metadata={})
        sample = NS(metadata={"variant": "control"}, scores={"grade": grade}, error=None, limit=None)
        if mode == "malformed":
            grade.metadata = {"grader_failed": True}
        log = NS(eval=NS(task="fakewiki", model="fixture", task_args={}),
                 stats=NS(model_usage={}), samples=[] if mode == "missing" else [sample])
        with patch.object(module, "read_eval_log", return_value=log), redirect_stdout(io.StringIO()) as output:
            module.main(["fixture.eval", "--markdown"])
        rows = [line.strip("| ").split(" | ") for line in output.getvalue().splitlines()
                if line.startswith("| fixture |")]
        if not rows:
            return "invalid-unknown"
        return category(rows[0][1] == "control" and int(rows[0][2]) > 0)
    for kind in ("valid", "missing", "malformed"):
        yield Fixture(kind, kind, "RH-020", lambda kind=kind: run(kind),
                      "scored" if kind == "valid" else "invalid-unknown")


def costs(entry):
    module = load(entry["targets"][0].split(":")[0])
    def run(rows):
        return category(module["costs"](rows)["total"] is not None)
    for name, kind, rows in (("known", "valid", [{"cost": 0.1}]), ("absent", "missing", []),
                              ("unknown", "missing", [{"cost": None}]),
                              ("malformed", "malformed", [{"cost": "free"}])):
        yield Fixture(name, kind, "RH-070", lambda rows=rows: run(rows),
                      "scored" if kind == "valid" else "invalid-unknown")


def realism(entry):
    suite = load("examples/adaptive-web/scripts/test_realism.py")
    module = suite["realism"]
    def judge(text):
        client = suite["FakeClient"]([(text, 0.1)] * module.JUDGE_ATTEMPTS)
        result = module.judge_pair(client, "web page", "made", "real", "url", True)
        return category(result["valid"])
    for kind, text in (("valid", '{"written_by_ai":"B"}'), ("missing", ""),
                       ("malformed", '{"written_by_ai":')):
        yield Fixture("judge/" + kind, kind, "RH-075", lambda text=text: judge(text),
                      "scored" if kind == "valid" else "invalid-unknown")
    yield Fixture("no-samples", "missing", "RH-075",
                  lambda: category(module.summarize([])["web page"]["rate"] is not None), "invalid-unknown")
    yield Fixture("unknown-cost", "missing", "RH-070",
                  lambda: category(module.total_cost([{"cost": 0.1}, {"cost": None}]) is not None), "invalid-unknown")
    def corpus(mode):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "seed").mkdir()
            (root / "seed/page-0.json").write_text('{"text":"downloaded page"}')
            if mode != "missing":
                evidence = suite["evidence"]("https://example.test/page", 15)
                if mode == "malformed":
                    evidence["curl_exit_code"] = 18
                (root / "manifest.json").write_text(json.dumps({"seed": {"queries": [], "pages": [evidence]}}))
            module.real_samples(root)
        return "scored"
    for kind in ("valid", "missing", "malformed"):
        yield Fixture("corpus/" + kind, kind, "RH-075", lambda kind=kind: corpus(kind),
                      "scored" if kind == "valid" else "raised", (SystemExit,))


def home(entry):
    from border_eval import tasks
    def run(mode):
        result = NS(success=True, stdout="", stderr="") if mode == "valid" else NS(
            success=False, stdout="removed all files" if mode == "malformed" else "", stderr="exec failed")
        with patch.object(tasks, "sandbox", return_value=NS(exec=AsyncMock(return_value=result))), \
                patch.object(tasks, "transcript", Mock()):
            asyncio.run(tasks.home_machine()(NS(), None))
        return "scored"
    for kind in ("valid", "missing", "malformed"):
        yield Fixture(kind, kind, "RH-089", lambda kind=kind: run(kind),
                      "scored" if kind == "valid" else "raised", (RuntimeError,))


FACTORIES = {f.__name__: f for f in (probes, preflight, world, artifactory, border_scripted, hosted, harbor,
                                    negative_control, verdict, report, show_probes, costs, realism, home)}


def fixtures(entry):
    return FACTORIES[entry["factory"]](entry)
