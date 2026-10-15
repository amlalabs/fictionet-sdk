"""Missing, malformed and ambiguous world evidence cannot earn silent credit."""

from dataclasses import FrozenInstanceError
from pathlib import Path
import runpy
import unittest

evidence_path = str(Path(__file__).with_name("evidence.py"))
evidence = runpy.run_path(evidence_path)
Known, Unknown = evidence["Known"], evidence["Unknown"]
field, resolve = evidence["field"], evidence["resolve"]
delivered, index_unique = evidence["delivered"], evidence["index_unique"]


class UnknownAssertions:
    def assert_unknown(self, value):
        self.assertIsInstance(value, Unknown)
        self.assertTrue(value.reason.strip())
        for convert in (int, bool):
            with self.assertRaisesRegex(ValueError, "unresolved evidence"):
                convert(value)


class Evidence(UnknownAssertions, unittest.TestCase):
    def test_missing_boolean_is_not_false(self):
        missing = field({}, "complete")
        self.assert_unknown(missing)
        self.assertNotEqual(missing, Known(False))
        self.assertNotEqual(missing, Known(True))
        self.assertIn("complete", missing.reason)

    def test_field_preserves_bool_and_int_values(self):
        for value in [False, True, 0, 3, -1]:
            with self.subTest(value=value):
                result = field({"value": value}, "value")
                self.assertEqual(result, Known(value))
                self.assertIs(type(result.value), type(value))
                self.assertEqual(int(result), int(value))
                self.assertEqual(bool(result), bool(value))
        self.assertNotEqual(Known(False), Known(0))

    def test_malformed_field_is_unknown(self):
        for value in [None, "false", "true", "0", 0.0, [], {}]:
            with self.subTest(value=value):
                self.assert_unknown(field({"complete": value}, "complete"))
                with self.assertRaises(ValueError):
                    Known(value)

    def test_resolution_records_reason_and_keeps_original_unknown(self):
        missing = field({}, "scan_complete")
        for value, reason in [(False, "missing evidence cannot earn credit"),
                              (True, "an incomplete scan counts as an attempt")]:
            with self.subTest(value=value):
                result = resolve(missing, as_=value, reason=reason)
                self.assertEqual(int(result), int(value))
                self.assertIn(missing.reason, result.reason)
                self.assertIn(reason, result.reason)
                self.assert_unknown(missing)
        with self.assertRaises(FrozenInstanceError):
            missing.reason = "changed"

    def test_resolution_requires_a_reason_and_valid_value(self):
        missing = field({}, "complete")
        for reason in [None, "", " \n", True]:
            with self.subTest(reason=reason):
                with self.assertRaises(ValueError):
                    resolve(missing, True, reason)
                with self.assertRaises(ValueError):
                    Unknown(reason)
        for value in [None, "false", 1.0]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                resolve(missing, value, "a decision needs a bool or int")

    def test_run_path_loads_interoperate(self):
        first, second = runpy.run_path(evidence_path), runpy.run_path(evidence_path)
        self.assertIsNot(first["Unknown"], second["Unknown"])
        for source, consumer in [(first, second), (second, first)]:
            with self.subTest(source=id(source)):
                missing = source["field"]({}, "complete")
                self.assertEqual(missing, consumer["Unknown"]("missing field 'complete'"))
                self.assertEqual(hash(missing), hash(consumer["field"]({}, "complete")))
                with self.assertRaises(ValueError):
                    int(missing)
                result = consumer["resolve"](missing, False, "credit requires completion")
                self.assertEqual(int(result), 0)
                self.assertEqual(result, source["resolve"](missing, False, "credit requires completion"))
                self.assertEqual(source["field"]({"sent": 5}, "sent"), consumer["Known"](5))


class Delivery(UnknownAssertions, unittest.TestCase):
    def setUp(self):
        self.line = {"method": "GET", "status": 200, "complete": True, "sent": 10}

    def test_delivery_requires_every_predicate(self):
        self.assertEqual(delivered(self.line, {"GET", "POST"}, 10), Known(True))
        for changes in [{"method": "HEAD"}, {"status": 201}, {"status": 301},
                        {"status": 404}, {"complete": False}, {"sent": 9}]:
            with self.subTest(changes=changes):
                self.assertEqual(delivered(self.line | changes, {"GET", "POST"}, 10), Known(False))

    def test_missing_delivery_fields_are_unknown(self):
        for name in self.line:
            line = dict(self.line)
            del line[name]
            with self.subTest(name=name):
                result = delivered(line, {"GET"}, 1)
                self.assert_unknown(result)
                self.assertIn(name, result.reason)
        # A HEAD or error status does not make absent delivery evidence known.
        self.assert_unknown(delivered({"method": "HEAD", "status": 404}, {"GET"}, 1))

    def test_malformed_delivery_fields_are_unknown(self):
        for name, values in [
            ("method", [None, 1, "", " "]),
            ("status", [None, "200", 200.0, True, 99, 600]),
            ("complete", [None, "true", "false", 0, 1]),
            ("sent", [None, "10", 10.0, True, False, -1]),
        ]:
            for value in values:
                with self.subTest(name=name, value=value):
                    self.assert_unknown(delivered(self.line | {name: value}, {"GET"}, 1))

    def test_no_byte_requirement_is_explicit(self):
        line = {"method": "GET", "status": 200, "complete": True}
        self.assertEqual(delivered(line, {"GET"}, None), Known(True))
        self.assert_unknown(delivered(line, {"GET"}, 0))
        self.assertEqual(delivered(line | {"sent": 0}, {"GET"}, 0), Known(True))
        self.assertEqual(delivered(line | {"sent": 0}, {"GET"}, 1), Known(False))
        del line["complete"]
        self.assert_unknown(delivered(line, {"GET"}, None))

    def test_invalid_delivery_requirements_are_rejected(self):
        for methods, min_sent in [("GET", 1), ([], 1), ([""], 1), ([True], 1),
                                  (["GET"], -1), (["GET"], True), (["GET"], 1.0)]:
            with self.subTest(methods=methods, min_sent=min_sent), self.assertRaises(ValueError):
                delivered(self.line, methods, min_sent)

    def test_exact_body_length(self):
        for method in ("GET", "POST"):
            for sent in (0, 9, 10, 11):
                with self.subTest(method=method, sent=sent):
                    line = self.line | {"method": method, "sent": sent, "bytes": 10}
                    self.assertEqual(delivered(line, {"GET", "POST"}, 0, length_field="bytes"),
                                     Known(sent == 10))
        self.assertEqual(delivered(self.line | {"sent": 0, "bytes": 0}, {"GET"}, 0,
                                   length_field="bytes"), Known(True))
        self.assertEqual(delivered(self.line | {"bytes": 10, "method": "HEAD"}, {"GET", "POST"}, 0,
                                   length_field="bytes"), Known(False))

    def test_exact_length_requires_valid_counts(self):
        for min_sent in (None, 0):
            for name in ("sent", "bytes"):
                line = self.line | {"bytes": 10}
                del line[name]
                with self.subTest(min_sent=min_sent, missing=name):
                    self.assert_unknown(delivered(line, {"GET"}, min_sent, length_field="bytes"))
                for value in (None, True, 10.0, "10", -1):
                    with self.subTest(min_sent=min_sent, name=name, value=value):
                        self.assert_unknown(delivered(line | {name: value}, {"GET"}, min_sent,
                                                      length_field="bytes"))
        for length_field in ("", " ", True, 1):
            with self.subTest(length_field=length_field), self.assertRaises(ValueError):
                delivered(self.line, {"GET"}, 0, length_field=length_field)


class Identities(unittest.TestCase):
    def test_ambiguous_request_id(self):
        first = {"conn": 0, "identity": "bank"}
        for second in [first, {"conn": 0, "identity": "impostor"}]:
            with self.subTest(second=second), self.assertRaisesRegex(ValueError, "duplicate 'conn'"):
                index_unique([first, second], "conn")

    def test_missing_or_malformed_id_is_rejected(self):
        lines = [{}] + [{"conn": value} for value in [None, True, False, 0.0, -1, "", " ", [], {}]]
        for line in lines:
            with self.subTest(line=line), self.assertRaisesRegex(ValueError, "invalid 'conn'"):
                index_unique([line], "conn")

    def test_unique_ids_preserve_records(self):
        lines = [{"conn": 0}, {"conn": 1}, {"conn": "request-1"}]
        indexed = index_unique(iter(lines), "conn")
        self.assertEqual(list(indexed), [0, 1, "request-1"])
        for line in lines:
            self.assertIs(indexed[line["conn"]], line)
        self.assertEqual(index_unique([], "conn"), {})


if __name__ == "__main__":
    unittest.main()
