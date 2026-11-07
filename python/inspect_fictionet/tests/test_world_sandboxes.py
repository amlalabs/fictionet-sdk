"""World sandboxes preserve their network and private data configuration."""

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


