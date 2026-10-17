"""Model inputs keep unavailable evidence out of valid results."""

from types import SimpleNamespace as NS
import unittest

from inspect_fictionet._common.outcomes import message_exposure


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


if __name__ == "__main__":
    unittest.main()
