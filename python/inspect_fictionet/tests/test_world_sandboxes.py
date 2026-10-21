"""World tasks preserve their network and private data configuration."""

import importlib
from pathlib import Path

import pytest
import yaml

from inspect_fictionet import fictionet_sandbox


@pytest.mark.parametrize("name", ["border", "fakewiki", "web", "artifactory"])
def test_tasks_use_isolated_shared_sandbox(name, monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    tasks = importlib.import_module(f"inspect_fictionet.worlds.{name}.tasks")
    task = getattr(tasks, name)()
    config = yaml.safe_load(Path(task.sandbox.config).read_text())
    world, attach, agent = (config["services"][key] for key in ("world", "attach", "default"))
    assert world["network_mode"] == ("bridge" if name == "web" else "none")
    assert attach["network_mode"] == "none"
    assert agent["network_mode"] == "service:attach"
    assert "NET_RAW" in agent["cap_drop"]
    assert agent["security_opt"] == ["no-new-privileges:true"]
    assert "unix:/run/relay/relay.sock" in attach["command"]
    assert not any(mount["target"] in ("/run/relay", "/var/lib/fictionet") for mount in agent.get("volumes", []))
    assert task.dataset


def test_border_home_configuration(monkeypatch, tmp_path):
    from inspect_fictionet.worlds.border.world import world_sandbox

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    config = yaml.safe_load(Path(world_sandbox("home").config).read_text())["services"]
    assert config["world"]["image"] == "fictionet-border-world:home"
    assert config["default"]["image"] == "fictionet-border-home:dev"
    assert config["attach"]["hostname"] == "rw-desktop"
    assert "--ip-addr=192.168.1.23/24" in config["attach"]["command"]
    assert "--dns=192.168.1.1" in config["attach"]["command"]
    assert config["attach"]["sysctls"] == {
        f"net.ipv6.conf.{name}.disable_ipv6": 1 for name in ("all", "default", "lo")
    }


def test_web_model_access_and_store_are_world_only(monkeypatch, tmp_path):
    from inspect_fictionet.worlds.web.world import world_sandbox

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    monkeypatch.setenv("OPENROUTER_API_KEY", "private-key")
    spec = world_sandbox(generator="openrouter", store_dir=tmp_path / "pages")
    text = Path(spec.config).read_text()
    config = yaml.safe_load(text)["services"]
    assert "private-key" not in text
    assert config["world"]["network_mode"] == "bridge"
    assert config["world"]["environment"]["OPENROUTER_API_KEY"] == "${OPENROUTER_API_KEY:-}"
    assert {"type": "bind", "source": str(tmp_path / "pages"), "target": "/var/lib/web"} in config["world"]["volumes"]
    assert config["attach"]["network_mode"] == "none"
    assert config["default"]["network_mode"] == "service:attach"
    assert "OPENROUTER_API_KEY" not in config["default"]["environment"]
    assert all(mount["type"] == "volume" and mount["read_only"] for mount in config["default"]["volumes"])


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


@pytest.mark.parametrize("generator", ["stub", "replay", "openrouter", "anthropic"])
def test_web_world_has_outbound_networking_with_every_generator(generator, monkeypatch, tmp_path):
    from inspect_fictionet.worlds.web.world import world_sandbox

    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    config = yaml.safe_load(Path(world_sandbox(generator=generator).config).read_text())["services"]
    assert config["world"]["network_mode"] == "bridge"
    assert config["attach"]["network_mode"] == "none"
    assert config["default"]["network_mode"] == "service:attach"
