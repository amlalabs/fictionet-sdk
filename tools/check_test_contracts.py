"""Check that registered regression tests ran and passed in CI test reports.

tests/check_contracts.json lists the regression tests that reward-hack fixes
landed. Each entry names a suite, the case id as the suite's report spells it,
the source file, the finding id and the reason the test matters.

  check SUITE=REPORT...  Fails unless every registered case of each named suite
                         appears exactly once in its report and passed. A case
                         that is missing, skipped, failed, errored or passed only
                         after a retry fails, and so does an absent, unreadable
                         or empty report. Unregistered cases do not matter.
  run --report PATH -s DIR [-p PATTERN]
                         Runs unittest discovery like `python -m unittest
                         discover` and writes a JSON report of each case's
                         outcome, since unittest writes none.
  validate               Checks the registry alone (also the default).

Case ids: `classname::name` from JUnit XML (nextest, pytest --junitxml), and
unittest's `TestCase.id()` from this tool's JSON report.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import unittest
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "tests" / "check_contracts.json"
# Each suite's report format: nextest's JUnit for the Rust tests, pytest's JUnit
# for the Inspect package, and this tool's unittest report for the rest.
SUITES = {"rust": "junit", "inspect": "junit", "demos": "unittest", "k8s": "unittest"}
ENTRY_KEYS = {"suite", "case", "source", "finding", "reason"}
FINDING = re.compile(r"RH-\d{3}")
UNITTEST_FORMAT = "fictionet-unittest-report"
# JUnit children that carry no outcome. Any other child means the case did not
# simply pass: failure, error, skipped, nextest's flakyFailure/flakyError (passed
# on a retry) and rerunFailure/rerunError, or anything this tool does not know.
JUNIT_NEUTRAL = {"system-out", "system-err", "properties"}
OUTCOMES = ("passed", "skipped", "expected-failure", "unexpected-success", "failed", "errored")


class ContractError(Exception):
    """The registry or a report could not be validated."""


def load_registry(path: Path = REGISTRY, root: Path = ROOT) -> list[dict]:
    """Returns the registry's entries, or raises ContractError naming every problem."""
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise ContractError(f"{path}: cannot read the registry: {e}") from e
    if not isinstance(data, dict) or set(data) - {"about", "cases"} or not isinstance(data.get("cases"), list):
        raise ContractError(f"{path}: expected an object with a 'cases' array")
    entries = data["cases"]
    if not entries:
        raise ContractError(f"{path}: the registry has no cases")
    errors = []
    seen = set()
    for i, entry in enumerate(entries):
        where = f"{path}: cases[{i}]"
        if not isinstance(entry, dict):
            errors.append(f"{where}: expected an object")
            continue
        if set(entry) != ENTRY_KEYS:
            errors.append(f"{where}: keys must be exactly {sorted(ENTRY_KEYS)}, got {sorted(entry)}")
            continue
        if not all(isinstance(entry[k], str) and entry[k].strip() for k in ENTRY_KEYS):
            errors.append(f"{where}: every field must be a non-empty string")
            continue
        where = f"{where} ({entry['case']})"
        if entry["suite"] not in SUITES:
            errors.append(f"{where}: unknown suite {entry['suite']!r}; known: {sorted(SUITES)}")
        if not FINDING.fullmatch(entry["finding"]):
            errors.append(f"{where}: finding must be an id like RH-033, got {entry['finding']!r}")
        key = (entry["suite"], entry["case"])
        if key in seen:
            errors.append(f"{where}: registered twice in suite {entry['suite']}")
        seen.add(key)
        source = root / entry["source"]
        if not source.is_file():
            errors.append(f"{where}: source {entry['source']} does not exist")
        elif not re.search(rf"\b{re.escape(function_name(entry))}\b", source.read_text()):
            errors.append(f"{where}: {function_name(entry)} does not appear in {entry['source']}")
    if errors:
        raise ContractError("\n".join(errors))
    return entries


def function_name(entry: dict) -> str:
    """The function or method name in a case id, without pytest parameters."""
    case = entry["case"].split("[", 1)[0]
    separator = "::" if SUITES.get(entry["suite"]) == "junit" else "."
    return case.rsplit(separator, 1)[-1]


def read_junit(path: Path) -> list[tuple[str, str, str]]:
    """Returns (case id, outcome, detail) for every testcase in a JUnit XML report."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as e:
        raise ContractError(f"{path}: cannot read the JUnit report: {e}") from e
    cases = []
    for case in root.iter("testcase"):
        classname, name = case.get("classname"), case.get("name")
        if not classname or not name:
            raise ContractError(f"{path}: a testcase lacks its classname or name")
        outcomes = [child.tag for child in case if child.tag not in JUNIT_NEUTRAL]
        detail = "; ".join(
            f"{child.tag}: {child.get('message') or (child.text or '').strip()[:200]}"
            for child in case if child.tag not in JUNIT_NEUTRAL
        )
        cases.append((f"{classname}::{name}", "passed" if not outcomes else ",".join(outcomes), detail))
    return cases


def read_unittest(path: Path) -> list[tuple[str, str, str]]:
    """Returns (case id, outcome, detail) for every case in a report written by `run`."""
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError) as e:
        raise ContractError(f"{path}: cannot read the unittest report: {e}") from e
    if not isinstance(data, dict) or data.get("format") != UNITTEST_FORMAT or not isinstance(data.get("cases"), list):
        raise ContractError(f"{path}: not a {UNITTEST_FORMAT} report")
    cases = []
    for case in data["cases"]:
        if (not isinstance(case, dict) or not isinstance(case.get("id"), str)
                or case.get("outcome") not in OUTCOMES or not isinstance(case.get("detail"), str)):
            raise ContractError(f"{path}: malformed case {case!r}")
        cases.append((case["id"], case["outcome"], case["detail"]))
    return cases


def check(entries: list[dict], suite: str, report: Path) -> list[str]:
    """Returns one message per registered case of `suite` that did not pass once."""
    if suite not in SUITES:
        raise ContractError(f"unknown suite {suite!r}; known: {sorted(SUITES)}")
    registered = [entry for entry in entries if entry["suite"] == suite]
    if not registered:
        raise ContractError(f"suite {suite!r} has no registered cases")
    if not report.is_file():
        raise ContractError(f"{suite}: report {report} does not exist")
    cases = read_junit(report) if SUITES[suite] == "junit" else read_unittest(report)
    if not cases:
        raise ContractError(f"{suite}: report {report} has no test cases")
    by_id: dict[str, list[tuple[str, str]]] = {}
    for case, outcome, detail in cases:
        by_id.setdefault(case, []).append((outcome, detail))
    errors = []
    for entry in registered:
        found = by_id.get(entry["case"], [])
        if not found:
            problem = "missing from the report"
        elif len(found) > 1:
            problem = f"reported {len(found)} times"
        elif found[0][0] != "passed":
            problem = f"{found[0][0]}" + (f" ({found[0][1]})" if found[0][1] else "")
        else:
            continue
        errors.append(f"{suite}: {entry['case']}: {problem}; {entry['finding']}: {entry['reason']}")
    return errors


class ReportResult(unittest.TextTestResult):
    """A unittest result that also keeps each case's worst outcome."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.outcomes: dict[str, tuple[str, str]] = {}

    def record(self, test, outcome, detail=""):
        # A subtest's outcome belongs to the test method that holds it.
        test = getattr(test, "test_case", test)
        previous = self.outcomes.get(test.id())
        if previous is None or OUTCOMES.index(outcome) > OUTCOMES.index(previous[0]):
            self.outcomes[test.id()] = (outcome, detail)

    def addSuccess(self, test):
        super().addSuccess(test)
        self.record(test, "passed")

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.record(test, "failed", self.failures[-1][1].strip().splitlines()[-1])

    def addError(self, test, err):
        super().addError(test, err)
        self.record(test, "errored", self.errors[-1][1].strip().splitlines()[-1])

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.record(test, "skipped", reason)

    def addExpectedFailure(self, test, err):
        super().addExpectedFailure(test, err)
        self.record(test, "expected-failure")

    def addUnexpectedSuccess(self, test):
        super().addUnexpectedSuccess(test)
        self.record(test, "unexpected-success")

    def addSubTest(self, test, subtest, err):
        super().addSubTest(test, subtest, err)
        if err is not None:
            failed = issubclass(err[0], test.failureException)
            self.record(test, "failed" if failed else "errored", f"{subtest.id()}: {err[1]}")


def run(report: Path, start: str, pattern: str, top: str | None) -> int:
    """Runs unittest discovery, writes the JSON report, and returns the exit status."""
    suite = unittest.TestLoader().discover(start, pattern, top)
    result = unittest.TextTestRunner(resultclass=ReportResult).run(suite)
    cases = [{"id": case, "outcome": outcome, "detail": detail}
             for case, (outcome, detail) in sorted(result.outcomes.items())]
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps({"format": UNITTEST_FORMAT, "cases": cases}, indent=1) + "\n")
    if result.testsRun == 0:
        print(f"no tests found in {start} matching {pattern}", file=sys.stderr)
        return 1
    return 0 if result.wasSuccessful() else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--registry", type=Path, default=REGISTRY)
    commands = parser.add_subparsers(dest="command")
    check_parser = commands.add_parser("check", help="check registered cases against reports")
    check_parser.add_argument("reports", nargs="+", metavar="SUITE=REPORT")
    run_parser = commands.add_parser("run", help="run unittest discovery and write a report")
    run_parser.add_argument("--report", type=Path, required=True)
    run_parser.add_argument("-s", "--start-directory", required=True)
    run_parser.add_argument("-p", "--pattern", default="test*.py")
    run_parser.add_argument("-t", "--top-level-directory")
    commands.add_parser("validate", help="check the registry alone")
    args = parser.parse_args(argv)

    if args.command == "run":
        return run(args.report, args.start_directory, args.pattern, args.top_level_directory)
    try:
        entries = load_registry(args.registry)
        if args.command != "check":
            print(f"{len(entries)} registered regression tests")
            return 0
        reports = {}
        for item in args.reports:
            suite, sep, report = item.partition("=")
            if not sep or not report:
                raise ContractError(f"expected SUITE=REPORT, got {item!r}")
            if suite in reports:
                raise ContractError(f"suite {suite!r} is named twice")
            reports[suite] = Path(report)
        errors = []
        for suite, report in reports.items():
            errors += check(entries, suite, report)
    except ContractError as e:
        print(e, file=sys.stderr)
        return 1
    for error in errors:
        print(error, file=sys.stderr)
    if errors:
        return 1
    for suite in reports:
        count = sum(entry["suite"] == suite for entry in entries)
        print(f"{suite}: all {count} registered regression tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
