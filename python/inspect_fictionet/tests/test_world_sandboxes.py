"""World sandboxes preserve their network and private data configuration."""

import json
import subprocess
from pathlib import Path

import pytest
import yaml

from inspect_fictionet import fictionet_sandbox


def test_sandbox_isolates_agent_from_world(tmp_path):
    sandbox = fictionet_sandbox("world", cache_dir=tmp_path)
    config = yaml.safe_load(Path(sandbox.config).read_text())
    world, attach, agent = (config["services"][key] for key in ("world", "attach", "default"))
    assert world["network_mode"] == "none"
    assert attach["network_mode"] == "none"
    assert agent["network_mode"] == "service:attach"
    assert "NET_RAW" in agent["cap_drop"]
    assert agent["security_opt"] == ["no-new-privileges:true"]
    assert "unix:/run/relay/relay.sock" in attach["command"]
    assert not any(mount["target"] in ("/run/relay", "/var/lib/fictionet") for mount in agent.get("volumes", []))


@pytest.mark.parametrize("options", [
    {"world_network": "host"},
    {"world_mounts": {"/tmp/pages": "/run/relay"}},
    {"world_mounts": {"/tmp/pages": "/data/../run/relay"}},
    {"world_mounts": {"relative": "/pages"}},
    {"disable_ipv6": True, "ip_addr_v6": "fd00::2/64"},
])
def test_invalid_world_options(options, tmp_path):
    with pytest.raises(ValueError):
        fictionet_sandbox("world", cache_dir=tmp_path, **options)


@pytest.mark.parametrize("host_value", [None, "host replacement"])
def test_compose_preserves_literal_inputs(tmp_path, monkeypatch, host_value):
    variable = "FICTIONET_COMPOSE_LITERAL"
    if host_value is None:
        monkeypatch.delenv(variable, raising=False)
    else:
        monkeypatch.setenv(variable, host_value)
    values = [f"${variable}", f"${{{variable}:-fallback}}", "literal$$pair", "trailing$"]
    environment = {f"VALUE_{index}": value for index, value in enumerate(values)}
    command = ["sh", "-c", f'printf %s "${variable}"']
    source = str(tmp_path / f"${variable}")
    target = f"/data/${variable}"
    sandbox = fictionet_sandbox(
        "world", cache_dir=tmp_path / "cache", world_args=values,
        world_env=environment, agent_env=environment, agent_command=command,
        world_healthcheck=command, world_mounts={source: target},
    )
    result = subprocess.run(
        ["docker", "compose", "--env-file", "/dev/null", "-f", str(sandbox.config),
         "config", "--format", "json"],
        capture_output=True, text=True, check=True,
    )
    # Compose re-escapes dollars when printing its resolved model for reuse.
    services = json.loads(result.stdout.replace("$$", "$"))["services"]
    world, agent = services["world"], services["default"]
    assert world["command"] == values
    assert agent["command"] == command
    assert world["environment"] == environment
    assert environment.items() <= agent["environment"].items()
    assert world["healthcheck"]["test"][1:] == command
    mounts = {mount["source"]: mount["target"] for mount in world["volumes"]}
    assert mounts[source] == target


