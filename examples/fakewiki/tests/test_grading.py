import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from fakewiki_eval import tasks


@pytest.mark.parametrize("value", ['"false"', '0', 'null', '[]', '{}'])
def test_verdict_requires_booleans(value):
    with pytest.raises(ValueError, match="booleans"):
        tasks._parse_verdict('{"fooled":' + value + ',"detected":false,"correct":true}')


def test_boolean_false_stays_false():
    assert tasks._parse_verdict('{"fooled":false,"detected":false,"correct":true}') == {
        "fooled": False, "detected": False, "correct": True, "explanation": "",
    }


def test_schema_failures_retry_then_raise(monkeypatch):
    grader = SimpleNamespace(generate=AsyncMock(return_value=SimpleNamespace(
        completion='{"fooled":"false","detected":false,"correct":true}')))
    monkeypatch.setattr(tasks, "get_model", lambda *a, **k: grader)
    monkeypatch.setattr(tasks, "world_log", AsyncMock(return_value=[]))
    monkeypatch.setattr(tasks, "summarize", lambda *a: {})
    monkeypatch.setattr(tasks, "planted_text_seen", lambda *a: {})
    monkeypatch.setattr(tasks, "store", lambda: {})
    monkeypatch.setattr(tasks, "transcript", lambda: SimpleNamespace(info=lambda *a, **k: None))
    state = SimpleNamespace(metadata={"topic": "test", "true_claim": "yes", "false_claim": "no"},
                            output=SimpleNamespace(completion="answer"), messages=[], input_text="question")
    with pytest.raises(ValueError, match="grader failed after three attempts"):
        asyncio.run(tasks.fakewiki_scorer("test")(state, None))
    assert grader.generate.await_count == 3


def test_report_excludes_failed_grades_from_rates(monkeypatch, capsys):
    from fakewiki_eval import report
    valid = SimpleNamespace(metadata={"variant": "control"}, error=None, limit=None, scores={
        "grade": SimpleNamespace(value={"fooled": 1, "detected": 1, "correct": 1}, metadata={}, answer="yes"),
    })
    failed = SimpleNamespace(metadata={"variant": "control"}, error=None, limit=None, scores={
        "grade": SimpleNamespace(value={"fooled": 0, "detected": 0, "correct": 0},
                                  metadata={"grader_failed": True}, answer="yes"),
    })
    error = SimpleNamespace(metadata={"variant": "control"}, scores=None,
                            error=SimpleNamespace(message="grader failed after three attempts"))
    log = SimpleNamespace(eval=SimpleNamespace(task="fakewiki", model="test", task_args={}),
                          stats=SimpleNamespace(model_usage={}), samples=[valid, failed, error])
    monkeypatch.setattr(report, "read_eval_log", lambda _: log)
    report.main(["sample.eval", "--markdown"])
    lines = capsys.readouterr().out.splitlines()
    assert "| test | control | 1 | 1.00 | 1.00 | 1.00 |" in lines[2]
    assert lines[2].endswith("| 0 | 2 | 1 |")
