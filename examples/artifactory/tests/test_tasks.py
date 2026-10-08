"""Task construction and private-world reads work without starting Docker."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from artifactory_eval import tasks
from artifactory_eval.probes import CASES, mismatches, scripted_dataset
from artifactory_eval.world import SCORES, WorldLogError


def test_dataset_ids_seeds_and_variants() -> None:
    samples = tasks.dataset(tasks.VARIANTS, 2)
    assert [s.id for s in samples] == [f"{v}-{i:02d}" for v in tasks.VARIANTS for i in (1, 2)]
    assert len({s.metadata["seed"] for s in samples}) == 8
    for sample in samples:
        assert len(sample.metadata["seed"].encode()) >= 16
        assert sample.metadata["variant"] in tasks.VARIANTS
        assert sample.input == tasks.PROMPT
    assert samples[0].metadata == {"variant": "normal", "seed": "artifactory-normal-0001"}


@pytest.mark.parametrize("value", ["", "normal,", "unknown", "normal,normal", [], ["missing", ""]])
def test_variant_errors(value: str | list[str]) -> None:
    with pytest.raises(ValueError):
        tasks.split(value)


def test_trim_variants_and_reject_zero_samples() -> None:
    assert tasks.split(" normal, peer ") == ["normal", "peer"]
    with pytest.raises(ValueError):
        tasks.dataset(["normal"], 0)


def test_scripted_expectations_cover_every_score() -> None:
    samples = scripted_dataset()
    assert len(samples) == len(CASES) == 9
    assert len({s.id for s in samples}) == 9
    assert set().union(*(set(case.ones) for case in CASES)) == set(SCORES)
    for sample in samples:
        assert set(sample.metadata["expected"]) == set(SCORES)
        assert len(sample.metadata["seed"]) >= 16


def test_script_checks_zeros_and_required_metadata() -> None:
    expected = {name: int(name == "left_repository") for name in SCORES}
    assert mismatches("missing_egress", expected, expected, {})
    metadata = {"refused_served_ports": [{"dst": "10.20.0.15", "ports": 22}]}
    assert mismatches("missing_egress", expected, expected, metadata) == []
    assert mismatches("missing_egress", {**expected, "attempted_write": 1}, expected, metadata)
    assert mismatches("missing_write", expected, expected, {})
    assert mismatches("peer_reply", expected, expected, {})


def test_sandbox_options_pass_through(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {}

    def build(world: str, **kwargs: object) -> str:
        captured.update(world=world, **kwargs)
        return "sandbox"

    monkeypatch.setattr(tasks, "fictionet_sandbox", build)
    assert tasks.world_sandbox("w", "a", "t", "k8s") == "sandbox"
    assert captured == {
        "world": "w", "agent_image": "a", "attach_image": "t", "backend": "k8s",
        "world_ca": "/run/ca/ca.pem",
        "world_healthcheck": ["test", "-f", "/run/fictionet/ready"],
        "world_env": {
            "ARTIFACTORY_VARIANT": "${SAMPLE_METADATA_VARIANT:-}",
            "ARTIFACTORY_SEED": "${SAMPLE_METADATA_SEED:-}",
        },
    }


@pytest.mark.parametrize("key", ["variant", "seed"])
def test_setup_rejects_wrong_world_without_agent_exec(key: str, monkeypatch: pytest.MonkeyPatch) -> None:
    metadata = {"variant": "normal", "seed": "artifactory-normal-0001"}
    reader = AsyncMock(return_value=json.dumps({**metadata, key: "wrong"}))
    monkeypatch.setattr(tasks, "read_world_file", reader)
    monkeypatch.setattr(tasks, "sandbox", lambda *args: pytest.fail("setup used sandbox exec"))
    with pytest.raises(WorldLogError, match=key):
        asyncio.run(tasks.setup()(SimpleNamespace(metadata=metadata), None))
    reader.assert_awaited_once_with(tasks.STATE)


def test_setup_accepts_exact_parameters(monkeypatch: pytest.MonkeyPatch) -> None:
    metadata = {"variant": "normal", "seed": "artifactory-normal-0001"}
    monkeypatch.setattr(tasks, "read_world_file", AsyncMock(return_value=json.dumps(metadata)))
    state = SimpleNamespace(metadata=metadata)
    assert asyncio.run(tasks.setup()(state, None)) is state


@pytest.mark.parametrize("data,valid", [(b'{"type":"attached"}\n', True), (b'{"type":"attached"}', False), (b'{"type":"lost","count":1}\n', False)])
def test_settling_and_checked_log_read(data: bytes, valid: bool, monkeypatch: pytest.MonkeyPatch) -> None:
    world = SimpleNamespace(exec=AsyncMock(side_effect=[
        SimpleNamespace(success=True, stdout=str(n)) for n in (0, len(data), len(data))
    ]))
    agent = object()
    monkeypatch.setattr(tasks, "sandbox", lambda name=None: world if name == "world" else agent)
    reader = AsyncMock(return_value=data)
    monkeypatch.setattr(tasks, "read_world_file", reader)
    monkeypatch.setattr(tasks.asyncio, "sleep", AsyncMock())
    if valid:
        assert asyncio.run(tasks.settled_log()) == [{"type": "attached"}]
    else:
        with pytest.raises(WorldLogError):
            asyncio.run(tasks.settled_log())
    assert world.exec.await_count == 3
    reader.assert_awaited_once_with(tasks.LOG, text=False)


def test_world_alias_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    agent = object()
    monkeypatch.setattr(tasks, "sandbox", lambda name=None: agent)
    with pytest.raises(WorldLogError, match="separate"):
        asyncio.run(tasks.settled_log())


def test_stat_failure_is_not_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    world = SimpleNamespace(exec=AsyncMock(return_value=SimpleNamespace(success=False, stderr="denied")))
    monkeypatch.setattr(tasks, "sandbox", lambda name=None: world if name == "world" else object())
    with pytest.raises(WorldLogError, match="denied"):
        asyncio.run(tasks.settled_log())


def test_growth_during_read_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    world = SimpleNamespace(exec=AsyncMock(return_value=SimpleNamespace(success=True, stdout="0")))
    monkeypatch.setattr(tasks, "sandbox", lambda name=None: world if name == "world" else object())
    monkeypatch.setattr(tasks.asyncio, "sleep", AsyncMock())
    monkeypatch.setattr(tasks, "read_world_file", AsyncMock(return_value=b'{"type":"dns"}\n'))
    with pytest.raises(WorldLogError, match="changed"):
        asyncio.run(tasks.settled_log())
