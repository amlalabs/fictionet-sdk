"""Reject reports that do not show every registered regression test passing once."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

import check_test_contracts as checker

TOOL = Path(checker.__file__).resolve()
PASSED = '<testcase classname="fictionet::flood" name="{name}" time="1.0"/>'


def junit(*cases):
    return f'<testsuites><testsuite name="fictionet::flood">{"".join(cases)}</testsuite></testsuites>'


class Fixture(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "tests").mkdir()
        (self.root / "tests/flood.rs").write_text("#[test]\nfn floods() {}\n#[test]\nfn joins() {}\n")
        (self.root / "tests/test_demo.py").write_text("def test_refuses(self):\n    pass\n")

    def entry(self, **fields):
        entry = {"suite": "rust", "case": "fictionet::flood::floods", "source": "tests/flood.rs",
                 "finding": "RH-105", "reason": "Every sender keeps sending."}
        entry.update(fields)
        return entry

    def registry(self, *entries):
        path = self.root / "contracts.json"
        path.write_text(json.dumps({"cases": list(entries)}))
        return checker.load_registry(path, self.root)

    def report(self, text, name="junit.xml"):
        path = self.root / name
        path.write_text(text)
        return path

    def errors(self, report, entries=None, suite="rust"):
        entries = entries or self.registry(self.entry(), self.entry(case="fictionet::flood::joins"))
        return checker.check(entries, suite, report)


class Registry(Fixture):
    def test_the_real_registry_parses_and_names_existing_sources(self):
        entries = checker.load_registry()
        self.assertTrue(entries)
        self.assertEqual({entry["suite"] for entry in entries}, set(checker.SUITES))
        for entry in entries:
            self.assertTrue((checker.ROOT / entry["source"]).is_file(), entry)

    def test_entry_lacking_a_finding_is_rejected(self):
        entry = self.entry()
        del entry["finding"]
        with self.assertRaisesRegex(checker.ContractError, "keys must be exactly"):
            self.registry(entry)

    def test_empty_reason_or_malformed_finding_is_rejected(self):
        for fields, message in (({"reason": " "}, "non-empty"), ({"finding": "none"}, "finding must be")):
            with self.subTest(fields=fields), self.assertRaisesRegex(checker.ContractError, message):
                self.registry(self.entry(**fields))

    def test_unknown_suite_is_rejected(self):
        with self.assertRaisesRegex(checker.ContractError, "unknown suite 'cargo'"):
            self.registry(self.entry(suite="cargo"))

    def test_duplicate_entry_is_rejected(self):
        with self.assertRaisesRegex(checker.ContractError, "registered twice"):
            self.registry(self.entry(), self.entry())

    def test_missing_source_or_name_is_rejected(self):
        with self.assertRaisesRegex(checker.ContractError, "does not exist"):
            self.registry(self.entry(source="tests/gone.rs"))
        with self.assertRaisesRegex(checker.ContractError, "renamed does not appear"):
            self.registry(self.entry(case="fictionet::flood::renamed"))

    def test_empty_registry_is_rejected(self):
        with self.assertRaisesRegex(checker.ContractError, "no cases"):
            self.registry()


class JUnit(Fixture):
    def test_all_passed_is_accepted(self):
        report = self.report(junit(PASSED.format(name="floods"), PASSED.format(name="joins"),
                                   PASSED.format(name="unregistered")))
        self.assertEqual(self.errors(report), [])

    def test_missing_case_is_rejected(self):
        [error] = self.errors(self.report(junit(PASSED.format(name="floods"))))
        self.assertIn("fictionet::flood::joins: missing from the report; RH-105", error)

    def test_skipped_failed_errored_and_retried_cases_are_rejected(self):
        for child, outcome in (('<skipped message="ignored"/>', "skipped"),
                               ('<failure message="assertion failed"/>', "failure"),
                               ('<error message="panicked"/>', "error"),
                               ('<flakyFailure message="first attempt failed"/>', "flakyFailure"),
                               ('<flakyError message="first attempt crashed"/>', "flakyError"),
                               ("<rerunFailure/><failure/>", "rerunFailure,failure"),
                               ("<unknown/>", "unknown")):
            with self.subTest(outcome=outcome):
                report = self.report(junit(
                    PASSED.format(name="floods"),
                    f'<testcase classname="fictionet::flood" name="joins">{child}</testcase>'))
                [error] = self.errors(report)
                self.assertIn(f"fictionet::flood::joins: {outcome}", error)

    def test_output_alone_is_still_a_pass(self):
        report = self.report(junit(
            PASSED.format(name="floods"),
            '<testcase classname="fictionet::flood" name="joins"><system-out>sent</system-out></testcase>'))
        self.assertEqual(self.errors(report), [])

    def test_duplicated_case_is_rejected(self):
        report = self.report(junit(PASSED.format(name="floods"), PASSED.format(name="joins"),
                                   PASSED.format(name="joins")))
        [error] = self.errors(report)
        self.assertIn("joins: reported 2 times", error)

    def test_empty_absent_and_malformed_reports_are_rejected(self):
        for text, message in (("<testsuites/>", "no test cases"), ("<testsuites>", "cannot read"),
                              ('<testsuites><testcase name="joins"/></testsuites>', "lacks")):
            with self.subTest(text=text), self.assertRaisesRegex(checker.ContractError, message):
                self.errors(self.report(text))
        with self.assertRaisesRegex(checker.ContractError, "does not exist"):
            self.errors(self.root / "absent.xml")

    def test_suite_without_registered_cases_is_rejected(self):
        with self.assertRaisesRegex(checker.ContractError, "no registered cases"):
            self.errors(self.report(junit(PASSED.format(name="floods"))), suite="inspect")


class UnittestReports(Fixture):
    def entries(self):
        return self.registry(self.entry(suite="demos", case="test_demo.Failures.test_refuses",
                                        source="tests/test_demo.py", finding="RH-067"))

    def unittest_report(self, *cases):
        text = json.dumps({"format": checker.UNITTEST_FORMAT, "cases": [
            {"id": case, "outcome": outcome, "detail": ""} for case, outcome in cases]})
        return self.report(text, "demos.json")

    def test_passed_is_accepted_and_other_outcomes_rejected(self):
        case = "test_demo.Failures.test_refuses"
        self.assertEqual(self.errors(self.unittest_report((case, "passed")), self.entries(), "demos"), [])
        for outcome in ("skipped", "failed", "errored", "expected-failure", "unexpected-success"):
            with self.subTest(outcome=outcome):
                [error] = self.errors(self.unittest_report((case, outcome)), self.entries(), "demos")
                self.assertIn(f"test_refuses: {outcome}", error)

    def test_empty_and_malformed_reports_are_rejected(self):
        for text, message in ((json.dumps({"format": checker.UNITTEST_FORMAT, "cases": []}), "no test cases"),
                              (json.dumps({"cases": []}), "not a"),
                              (json.dumps({"format": checker.UNITTEST_FORMAT,
                                           "cases": [{"id": "x", "outcome": "ok", "detail": ""}]}), "malformed")):
            with self.subTest(text=text), self.assertRaisesRegex(checker.ContractError, message):
                self.errors(self.report(text, "demos.json"), self.entries(), "demos")


class Run(Fixture):
    def run_tool(self, source):
        tests = self.root / "suite"
        tests.mkdir()
        (tests / "test_fixture.py").write_text(textwrap.dedent(source))
        report = self.root / "out" / "report.json"
        result = subprocess.run([sys.executable, TOOL, "run", "--report", report, "-s", tests, "-p", "test_*.py"],
                                capture_output=True, text=True)
        cases = {}
        if report.exists():
            cases = {case["id"]: case["outcome"] for case in json.loads(report.read_text())["cases"]}
        return result.returncode, cases

    def test_outcomes_are_recorded_and_failures_exit_nonzero(self):
        status, cases = self.run_tool("""
            import unittest

            class Cases(unittest.TestCase):
                def test_passes(self):
                    pass

                def test_fails(self):
                    self.assertEqual(1, 2)

                def test_errors(self):
                    raise RuntimeError("broken")

                def test_subtest_fails(self):
                    for i in range(2):
                        with self.subTest(i=i):
                            self.assertEqual(i, 0)

                @unittest.skip("needs a tool")
                def test_skipped(self):
                    pass

                @unittest.expectedFailure
                def test_unexpected_success(self):
                    pass
            """)
        self.assertEqual(status, 1)
        self.assertEqual(cases, {
            "test_fixture.Cases.test_passes": "passed",
            "test_fixture.Cases.test_fails": "failed",
            "test_fixture.Cases.test_errors": "errored",
            "test_fixture.Cases.test_subtest_fails": "failed",
            "test_fixture.Cases.test_skipped": "skipped",
            "test_fixture.Cases.test_unexpected_success": "unexpected-success",
        })

    def test_a_skipped_subtest_marks_its_test_skipped(self):
        status, cases = self.run_tool("""
            import unittest

            class Cases(unittest.TestCase):
                def test_partly_skipped(self):
                    with self.subTest(part=1):
                        self.skipTest("needs a tool")
            """)
        self.assertEqual(status, 0)
        self.assertEqual(cases, {"test_fixture.Cases.test_partly_skipped": "skipped"})

    def test_passing_suite_exits_zero(self):
        status, cases = self.run_tool("""
            import unittest

            class Cases(unittest.TestCase):
                def test_passes(self):
                    pass
            """)
        self.assertEqual((status, cases), (0, {"test_fixture.Cases.test_passes": "passed"}))

    def test_import_error_and_no_tests_exit_nonzero(self):
        status, cases = self.run_tool("import missing_module_for_contract_test\n")
        self.assertEqual(status, 1)
        self.assertEqual(set(cases.values()), {"errored"})
        (self.root / "suite/test_fixture.py").write_text("")
        result = subprocess.run([sys.executable, TOOL, "run", "--report", self.root / "empty.json",
                                 "-s", self.root / "suite", "-p", "test_*.py"], capture_output=True)
        self.assertEqual(result.returncode, 1)


class CommandLine(Fixture):
    def test_check_exit_status(self):
        path = self.root / "contracts.json"
        path.write_text(json.dumps({"cases": [self.entry(source=str(self.root / "tests/flood.rs"))]}))
        passed = self.report(junit(PASSED.format(name="floods")))
        failed = self.report(junit(), "empty.xml")
        for reports, status in (([f"rust={passed}"], 0), ([f"rust={failed}"], 1),
                                ([f"rust={passed}", f"rust={passed}"], 1), ([str(passed)], 1)):
            with self.subTest(reports=reports):
                result = subprocess.run([sys.executable, TOOL, "--registry", path, "check", *reports],
                                        capture_output=True)
                self.assertEqual(result.returncode, status, result.stderr)


if __name__ == "__main__":
    unittest.main()
