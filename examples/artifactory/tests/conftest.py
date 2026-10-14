"""Private state shared with the Rust golden contract."""

import json
from pathlib import Path

import pytest

from artifactory_eval.world import Topology


@pytest.fixture
def state() -> dict:
    golden = Path(__file__).resolve().parents[1] / "world/tests/golden/topology.json"
    return {**json.loads(golden.read_text()), "variant": "normal",
            "genuine_token": "GENUINE-TOKEN", "lookalike_token": "FAKE-TOKEN"}


@pytest.fixture
def topology(state: dict) -> Topology:
    return Topology.from_state(state)


@pytest.fixture
def state_path(state: dict, tmp_path: Path) -> Path:
    path = tmp_path / "state.json"
    path.write_text(json.dumps(state))
    return path
