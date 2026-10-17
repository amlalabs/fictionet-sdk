"""Model inputs and outcomes keep unavailable evidence out of valid results."""

import runpy
from types import SimpleNamespace as NS
import unittest

from inspect_fictionet._common import outcomes as module

outcomes_path = module.__file__
outcomes = vars(module)
message_exposure = outcomes["message_exposure"]
termination = outcomes["termination"]
judgment = outcomes["judgment"]
KEYS = ("fooled", "detected", "correct")
VALUES = dict.fromkeys(KEYS, 1)


def message(identity, role="tool", text="evidence", **kwargs):
    return NS(id=identity, role=role, text=text, tool_calls=None, error=None, **kwargs)


def model(inputs, **kwargs):
    return NS(**dict(event="model", input=inputs, error=None, pending=None,
                     output=NS(stop_reason="stop")) | kwargs)


class Exposure(unittest.TestCase):
    def test_trailing_unconsumed_tool(self):
        early, trailing = message("early"), message("trailing")
        messages = [early, message("call", "assistant"), trailing]
        result = message_exposure(messages, [model([early])])
        self.assertEqual({i for i, item in result.items() if item.status == "seen"}, {0})
        self.assertEqual(result[2].status, "not_seen")
        self.assertTrue(result[2].reason)

    def test_pending_or_errored_generate_is_unknown(self):
        tool = message("tool")
        for change in [{"pending": True}, {"error": "provider failed"}]:
            with self.subTest(change=change):
                event = model([tool], **change)
                result = message_exposure([tool], [event])[0]
                self.assertEqual(result.status, "unknown")
                self.assertTrue(result.reason)
                # A later failed call cannot undo earlier proven consumption.
                self.assertEqual(message_exposure([tool], [model([tool]), event])[0].status, "seen")

    def test_message_without_id_is_unknown(self):
        for tool in [NS(role="tool", text="evidence"), message(None), message("")]:
            with self.subTest(tool=tool):
                self.assertEqual(message_exposure([tool], [model([tool])])[0].status, "unknown")

    def test_absent_events_are_unknown_and_empty_events_are_not_seen(self):
        tool = message("tool")
        self.assertEqual(message_exposure([tool])[0].status, "unknown")
        self.assertEqual(message_exposure([tool], [NS(event="info")])[0].status, "not_seen")
        self.assertEqual(message_exposure([tool], [])[0].status, "not_seen")

    def test_input_ids_survive_history_rewrites_and_tool_errors(self):
        tool = message("tool")
        tool.error = NS(message="curl: (60) certificate verify failed")
        # The input is a different object, and the submitted reply was removed.
        recorded = message("tool")
        result = message_exposure([message("unrelated", "assistant"), tool], [model([recorded])])
        self.assertEqual(result[0].status, "not_seen")
        self.assertEqual(result[1].status, "seen")

    def test_missing_model_provenance_is_unknown(self):
        tool = message("tool")
        for field in ["input", "error", "pending"]:
            event = model([tool])
            delattr(event, field)
            with self.subTest(field=field):
                self.assertEqual(message_exposure([tool], [event])[0].status, "unknown")
        for inputs in [None, "tool", [message(None)]]:
            with self.subTest(inputs=inputs):
                self.assertEqual(message_exposure([tool], [model(inputs)])[0].status, "unknown")
        self.assertEqual(message_exposure([tool], [NS()])[0].status, "unknown")

    def test_condensed_model_inputs_are_unknown(self):
        messages = [message("first"), message("second")]
        event = model([], input_refs=[(0, 2)])
        result = message_exposure(messages, [event])
        self.assertEqual([item.status for item in result.values()], ["unknown", "unknown"])
        self.assertTrue(all(item.reason for item in result.values()))
        result = message_exposure(messages, [model([messages[0]]), event])
        self.assertEqual([item.status for item in result.values()], ["seen", "unknown"])

    def test_empty_model_inputs_are_unknown(self):
        tool = message("tool")
        for event in [model([]), model([], input_refs=[])]:
            with self.subTest(event=event):
                self.assertEqual(message_exposure([tool], [event])[0].status, "unknown")

    def test_input_refs_leave_unlisted_messages_unknown(self):
        first, second = message("first"), message("second")
        event = model([first], input_refs=[(0, 2)])
        result = message_exposure([first, second], [event])
        self.assertEqual([item.status for item in result.values()], ["seen", "unknown"])

    def test_duplicate_message_ids_are_ambiguous(self):
        first, second = message("same"), message("same", text="different")
        result = message_exposure([first, second], [model([first])])
        self.assertEqual([item.status for item in result.values()], ["unknown", "unknown"])
        self.assertEqual(message_exposure([first], [model([first, second])])[0].status, "unknown")


class Termination(unittest.TestCase):
    def setUp(self):
        self.messages = [message("answer", "assistant", "I cannot do that.")]
        self.output = NS(stop_reason="stop", completion="I cannot do that.")
        self.events = [model([message("prompt", "user")])]

    def test_limit_event_terminates(self):
        event = NS(event="sample_limit", type="message", message="message limit exceeded")
        result = termination(self.messages, self.output, [event])
        self.assertEqual(result.status, "limit")
        self.assertEqual(result.limit_type, "message")
        self.assertEqual(result.reason, "message limit exceeded")

    def test_content_filter_terminates(self):
        self.output.stop_reason = "content_filter"
        result = termination(self.messages, self.output, [])
        self.assertEqual(result.status, "filtered")
        self.assertIn("content_filter", result.reason)
        self.output.completion = ""
        self.output.error = "provider moderation refused the input"
        result = termination(self.messages, self.output, [])
        self.assertEqual(result.status, "filtered")
        self.assertIn(self.output.error, result.reason)

    def test_model_length_terminates(self):
        self.output.stop_reason = "model_length"
        self.assertEqual(termination(self.messages, self.output, []).status, "model_length")

    def test_trailing_tool_or_unanswered_calls_have_no_final_reply(self):
        call = message("call", "assistant")
        call.tool_calls = [NS(id="call1")]
        for last in [message("tool"), call]:
            with self.subTest(last=last):
                result = termination([*self.messages, last], self.output, [])
                self.assertEqual(result.status, "no_final_reply")

    def test_normal_refusal_is_completed(self):
        self.assertEqual(termination(self.messages, self.output, self.events).status, "completed")

    def test_no_recorded_model_call_is_unknown(self):
        for events in [[], [NS(event="info")]]:
            with self.subTest(events=events):
                result = termination(self.messages, self.output, events)
                self.assertEqual(result.status, "unknown")
                self.assertTrue(result.reason)
                self.assertEqual(result.reason, "no model call was recorded")

    def test_missing_inputs_are_not_completed(self):
        for messages, output, events, reason in [
            (None, self.output, [], "final message is missing"),
            ([], self.output, [], "final message is missing"),
            (self.messages, None, self.events, "final output or event sequence is missing"),
            (self.messages, self.output, None, "final output or event sequence is missing"),
        ]:
            with self.subTest(messages=messages, output=output, events=events):
                result = termination(messages, output, events)
                self.assertEqual(result.status, "unknown")
                self.assertEqual(result.reason, reason)
        for reason in [None, "unknown", "max_tokens", "tool_calls"]:
            with self.subTest(reason=reason):
                self.output.stop_reason = reason
                result = termination(self.messages, self.output, self.events)
                self.assertEqual(result.status, "unknown")
                self.assertEqual(result.reason, f"no confirmed final assistant stop: {reason!r}")

    def test_empty_completion_has_no_final_reply(self):
        for completion in [None, "", " \n"]:
            with self.subTest(completion=completion):
                self.output.completion = completion
                self.assertEqual(termination(self.messages, self.output, []).status, "no_final_reply")

    def test_pending_or_errored_call_cannot_complete_stale_output(self):
        for change, reason in [({"pending": True}, "model call is pending"),
                               ({"error": "cancelled"}, "model call failed: cancelled")]:
            with self.subTest(change=change):
                result = termination(self.messages, self.output, [model(self.messages, **change)])
                self.assertEqual(result.status, "unknown")
                self.assertEqual(result.reason, reason)

    def test_empty_output_choices_are_unknown(self):
        class EmptyOutput(NS):
            @property
            def stop_reason(self):
                return self.choices[0].stop_reason

        for completion in [self.output.completion, ""]:
            with self.subTest(completion=completion):
                output = EmptyOutput(choices=[], completion=completion)
                result = termination(self.messages, output, self.events)
                self.assertEqual(result.status, "unknown")
                self.assertEqual(result.reason, "no confirmed final assistant stop: None")

    def test_malformed_tool_calls_cannot_complete(self):
        for calls in [0, "", {}]:
            with self.subTest(calls=calls):
                self.messages[-1].tool_calls = calls
                result = termination(self.messages, self.output, self.events)
                self.assertEqual(result.status, "unknown")
                self.assertEqual(result.reason, "no confirmed final assistant stop: 'stop'")


class Judgment(unittest.TestCase):
    def test_legacy_grader_failure(self):
        result = judgment("answer", dict.fromkeys(KEYS, 0), keys=KEYS,
                          metadata={"grader_failed": True})
        self.assertEqual(result.status, "grader_failed")
        self.assertIsNone(result.values)
        self.assertIsNone(result.attempts)
        self.assertIsNone(result.raw)

    def test_failure_preserves_reason_attempts_and_raw(self):
        result = judgment("answer", keys=KEYS, metadata={
            "grader_failed": True, "grader_attempts": 3,
            "grader_raw": "not JSON\n", "grader_error": "verdict did not parse",
        })
        self.assertEqual(result.status, "grader_failed")
        self.assertEqual(result.reason, "verdict did not parse")
        self.assertEqual(result.attempts, 3)
        self.assertEqual(result.raw, "not JSON\n")

    def test_empty_answer(self):
        for answer in [None, "", " \n\t"]:
            with self.subTest(answer=answer):
                result = judgment(answer, VALUES, keys=KEYS)
                self.assertEqual(result.status, "no_answer")
                self.assertIsNone(result.values)
        result = judgment(None, metadata={"grader_attempts": 0})
        self.assertEqual(result.status, "no_answer")
        self.assertEqual(result.attempts, 0)

    def test_valid_grade_preserves_values_and_attempts(self):
        values = {"fooled": False, "detected": 1, "correct": 0.0}
        result = judgment("answer", values, keys=KEYS,
                          metadata={"grader_attempts": 2, "grader_raw": "verdict"})
        self.assertEqual(result.status, "graded")
        self.assertEqual(result.values, values)
        self.assertEqual(result.attempts, 2)
        self.assertEqual(result.raw, "verdict")
        values["fooled"] = True
        self.assertIs(result.values["fooled"], False)

    def test_unrecognised_score_is_unknown(self):
        for values in [None, {}, [], 0, {"fooled": 1}, VALUES | {"extra": 1},
                       VALUES | {"fooled": "false"}, VALUES | {"fooled": None},
                       VALUES | {"fooled": float("nan")}, VALUES | {"fooled": 2}]:
            with self.subTest(values=values):
                result = judgment("answer", values, keys=KEYS)
                self.assertEqual(result.status, "unknown")
                self.assertIsNone(result.values)
                self.assertTrue(result.reason)
        self.assertEqual(judgment("answer", VALUES).status, "unknown")
        self.assertEqual(judgment(123, VALUES, keys=KEYS).status, "unknown")

    def test_malformed_metadata_cannot_validate_a_grade(self):
        for metadata in [[], {"grader_failed": "false"}, {"grader_attempts": -1},
                         {"grader_attempts": True}, {"grader_raw": []},
                         {"grader_failed": False, "grader_error": "invalid verdict"}]:
            with self.subTest(metadata=metadata):
                self.assertEqual(judgment("answer", VALUES, keys=KEYS,
                                          metadata=metadata).status, "unknown")

    def test_bare_interpreter_run_path_loads(self):
        other = runpy.run_path(outcomes_path)
        self.assertEqual(other["judgment"](None).status, "no_answer")
        self.assertEqual(other["judgment"]("answer", VALUES, keys=KEYS).status, "graded")


if __name__ == "__main__":
    unittest.main()
