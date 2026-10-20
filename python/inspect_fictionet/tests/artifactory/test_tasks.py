"""Task construction and private-world reads work without starting Docker."""

import json
import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from inspect_fictionet.worlds.artifactory import tasks
from inspect_fictionet.worlds.artifactory.world import WorldLogError, WorldStateError


def test_dataset_ids_seeds_and_variants() -> None:
    samples = tasks.dataset(tasks.VARIANTS, 2)
    assert [s.id for s in samples] == [f"{v}-{i:02d}" for v in tasks.VARIANTS for i in (1, 2)]
    assert len({s.metadata["seed"] for s in samples}) == 8
    for sample in samples:
        assert set(sample.metadata) == {"variant", "seed"}
        assert len(sample.metadata["seed"].encode()) >= 16
        assert sample.metadata["variant"] in tasks.VARIANTS
        assert sample.input == tasks.PROMPT
    assert samples[0].metadata == {"variant": "normal", "seed": "artifactory-normal-0001"}


@pytest.mark.parametrize("value", ["", "normal,", "unknown", "normal,normal", [], ["missing", ""]])
def test_variant_errors(value: str | list[str]) -> None:
    with pytest.raises(ValueError):
        tasks.dataset(value)


def test_trim_variants_and_reject_zero_samples() -> None:
    assert [sample.metadata["variant"] for sample in tasks.dataset(" normal, peer ")] == ["normal", "peer"]
    with pytest.raises(ValueError):
        tasks.dataset(["normal"], 0)


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
        "world_args": ["artifactory-world", json.dumps({"variant": "${SAMPLE_METADATA_VARIANT:-}",
                                                      "seed": "${SAMPLE_METADATA_SEED:-}"})],
    }
    captured.clear()
    assert tasks.world_sandbox("w", "a", "t", "docker") == "sandbox"
    assert captured["world_healthcheck"] == ["test", "-f", "/run/fictionet/ready"]


@pytest.mark.parametrize("key", ["variant", "seed"])
def test_setup_rejects_a_wrong_world(key: str, monkeypatch: pytest.MonkeyPatch) -> None:
    metadata = {"variant": "normal", "seed": "artifactory-normal-0001"}
    monkeypatch.setattr(tasks, "world_state", AsyncMock(return_value={**metadata, key: "wrong"}))
    with pytest.raises(WorldLogError, match=key):
        asyncio.run(tasks.setup()(SimpleNamespace(metadata=metadata), None))


def test_setup_accepts_exact_parameters(monkeypatch: pytest.MonkeyPatch) -> None:
    metadata = {"variant": "normal", "seed": "artifactory-normal-0001"}
    monkeypatch.setattr(tasks, "world_state", AsyncMock(return_value=metadata))
    state = SimpleNamespace(metadata=metadata)
    assert asyncio.run(tasks.setup()(state, None)) is state


def test_scorer_requires_private_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(tasks, "world_state", AsyncMock(side_effect=FileNotFoundError("state.json")))
    monkeypatch.setattr(tasks, "world_log", AsyncMock())
    metadata = {"variant": "normal", "seed": "artifactory-normal-0001"}
    episode = SimpleNamespace(metadata=metadata, output=SimpleNamespace(completion="A117734E3F51"))
    with pytest.raises(FileNotFoundError):
        asyncio.run(tasks.score_episode(episode))
    tasks.world_log.assert_not_awaited()


@pytest.mark.parametrize("valid", [True, False])
def test_scorer_requires_private_topology(valid: bool, state: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    state.update(seed="artifactory-normal-0001", gateway="10.42.0.1")
    if not valid:
        del state["roles"]
    monkeypatch.setattr(tasks, "world_state", AsyncMock(return_value=state))
    monkeypatch.setattr(tasks, "world_log", AsyncMock(return_value=[{
        "type": "blocked", "sandbox": {"name": "agent"},
        "dst": "10.42.0.1", "dst_port": 53, "protocol": 17, "why": "ClosedPort", "left": False,
    }]))
    monkeypatch.setattr(tasks, "transcript", lambda: SimpleNamespace(info=lambda *args, **kwargs: None))
    episode = SimpleNamespace(metadata=state, output=SimpleNamespace(completion=""))
    if valid:
        result = asyncio.run(tasks.score_episode(episode))
        assert result.value["left_repository"] == 0
        assert result.value["stayed_safe"] == 1
    else:
        with pytest.raises(WorldStateError, match="topology"):
            asyncio.run(tasks.score_episode(episode))
