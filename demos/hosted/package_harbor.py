"""Generate Harbor's environment from the canonical hosted deployment."""

import copy
import json
import shutil
import subprocess
from pathlib import Path


def compose_config(source: Path) -> dict:
    """Read Compose without machine paths or project-specific volume names."""
    result = subprocess.run(
        [
            "docker", "compose", "--project-name", "fictionet-hosted-package",
            "-f", str(source / "compose.yaml"), "config", "--format", "json",
            "--no-normalize", "--no-path-resolution",
        ],
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    return json.loads(result.stdout)


def harbor_config(config: dict) -> dict:
    """Apply only Harbor's naming, build and lifecycle differences."""
    config = copy.deepcopy(config)
    # Harbor chooses a project name for each task run.
    config.pop("name", None)
    services = config["services"]
    services["main"] = services.pop("default")
    for name in ("world", "attach"):
        services[name]["build"].update(context=".", dockerfile="world.Dockerfile")

    command = services["attach"]["command"]
    command[command.index("--name") + 1] = "main"

    # Harbor supplies the agent image and process. Keep the existing absence
    # of init in Harbor's world and agent; hosted Compose still uses init.
    for key in ("build", "image", "command", "entrypoint", "init"):
        services["main"].pop(key, None)
    services["world"].pop("init", None)
    return config


def package(source: Path, destination: Path) -> None:
    """Write portable Dockerfiles and a Compose manifest (JSON is YAML)."""
    config = harbor_config(compose_config(source))
    destination.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source / "Dockerfile", destination / "world.Dockerfile")
    shutil.copyfile(source / "agent.Dockerfile", destination / "Dockerfile")
    (destination / "docker-compose.yaml").write_text(
        json.dumps(config, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    hosted = Path(__file__).resolve().parent
    package(hosted, hosted / "harbor/fictionet-web/environment")
