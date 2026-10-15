import copy
import importlib.util
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


HOSTED = Path(__file__).resolve().parents[1]
FILES = ("Dockerfile", "world.Dockerfile", "docker-compose.yaml")
spec = importlib.util.spec_from_file_location("package_harbor", HOSTED / "package_harbor.py")
packaging = importlib.util.module_from_spec(spec)
spec.loader.exec_module(packaging)


class PackagingTests(unittest.TestCase):
    def test_generation_is_deterministic_and_relocatable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "relocated-hosted"
            source.mkdir()
            for name in ("Dockerfile", "agent.Dockerfile", "compose.yaml"):
                shutil.copyfile(HOSTED / name, source / name)
            first, second = root / "first", root / "second"
            packaging.package(HOSTED, first)
            packaging.package(source, second)
            for name in FILES:
                with self.subTest(file=name):
                    self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
            packaging.package(source, second)
            for name in FILES:
                self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
            self.assertEqual((first / "Dockerfile").read_bytes(), (HOSTED / "agent.Dockerfile").read_bytes())
            self.assertEqual((first / "world.Dockerfile").read_bytes(), (HOSTED / "Dockerfile").read_bytes())

    def test_topology_and_harbor_differences(self):
        hosted = packaging.compose_config(HOSTED)
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            packaging.package(HOSTED, destination)
            harbor = json.loads((destination / "docker-compose.yaml").read_text())
        self.assertNotIn("name", harbor)
        self.assertEqual(harbor["volumes"], hosted["volumes"])
        self.assertEqual(set(harbor["volumes"]), {"sock", "ca"})
        services = harbor["services"]
        self.assertEqual(set(services), {"world", "attach", "main"})
        for name in ("world", "attach"):
            build = dict(hosted["services"][name]["build"], context=".", dockerfile="world.Dockerfile")
            self.assertEqual(services[name]["build"], build)
            self.assertEqual(services[name]["network_mode"], "none")
            for key in ("image", "volumes", "healthcheck"):
                self.assertEqual(services[name][key], hosted["services"][name][key])
        self.assertEqual(services["world"]["command"], hosted["services"]["world"]["command"])
        command = services["attach"]["command"].copy()
        name_index = command.index("--name") + 1
        self.assertEqual(command[name_index], "main")
        command[name_index] = hosted["services"]["attach"]["command"][name_index]
        self.assertEqual(command, hosted["services"]["attach"]["command"])
        self.assertEqual(services["attach"]["cap_add"], ["NET_ADMIN"])
        self.assertEqual(services["attach"]["devices"], hosted["services"]["attach"]["devices"])
        self.assertEqual(services["attach"]["depends_on"], hosted["services"]["attach"]["depends_on"])
        self.assertEqual(services["attach"]["depends_on"]["world"]["condition"], "service_healthy")
        self.assertEqual(services["main"]["network_mode"], "service:attach")
        for key in ("volumes", "depends_on"):
            self.assertEqual(services["main"][key], hosted["services"]["default"][key])
        self.assertEqual(services["main"]["depends_on"]["attach"]["condition"], "service_healthy")
        agent_keys = ("build", "image", "command", "entrypoint", "init")
        for key in agent_keys:
            self.assertNotIn(key, services["main"])
        self.assertNotIn("init", services["world"])
        self.assertTrue(hosted["services"]["world"]["init"])
        self.assertTrue(hosted["services"]["default"]["init"])

        # Undo the explicit deltas: everything else must match the hosted
        # config, including fields a different Compose release may emit.
        restored = copy.deepcopy(harbor)
        if "name" in hosted:
            restored["name"] = hosted["name"]
        restored_services = restored["services"]
        restored_services["default"] = restored_services.pop("main")
        for name in ("world", "attach"):
            restored_services[name]["build"] = hosted["services"][name]["build"]
        restored_services["attach"]["command"] = command
        restored_services["world"]["init"] = hosted["services"]["world"]["init"]
        for key in agent_keys:
            if key in hosted["services"]["default"]:
                restored_services["default"][key] = hosted["services"]["default"][key]
        self.assertEqual(restored, hosted)

    def test_compose_accepts_package_with_framework_agent(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory)
            packaging.package(HOSTED, destination)
            # Harbor supplies main's build/image and process when it merges
            # this environment with its framework Compose file.
            framework = destination / "framework.json"
            framework.write_text(json.dumps({"services": {"main": {
                "build": {"context": ".", "dockerfile": "Dockerfile"},
                "image": "harbor-agent:test", "command": ["sleep", "infinity"],
            }}}))
            for project in ("first-task", "second-task"):
                result = subprocess.run(
                    [
                        "docker", "compose", "-p", project,
                        "-f", str(framework),
                        "-f", str(destination / "docker-compose.yaml"),
                        "config", "--format", "json",
                    ],
                    check=True, stdout=subprocess.PIPE, text=True,
                )
                config = json.loads(result.stdout)
                main = config["services"]["main"]
                self.assertEqual(main["image"], "harbor-agent:test")
                self.assertEqual(main["command"], ["sleep", "infinity"])
                self.assertEqual(main["network_mode"], "service:attach")
                for name in ("ca", "sock"):
                    self.assertEqual(config["volumes"][name]["name"], f"{project}_{name}")
                for service in config["services"].values():
                    build = service["build"]
                    self.assertEqual(Path(build["context"]), destination)
                    self.assertTrue((destination / build["dockerfile"]).is_file())

    def test_canonical_changes_propagate(self):
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "environment"
            packaging.package(HOSTED, destination)
            source = Path(directory) / "hosted"
            source.mkdir()
            for name in ("Dockerfile", "agent.Dockerfile"):
                (source / name).write_bytes((HOSTED / name).read_bytes() + b"\nENV PACKAGING_TEST=1\n")
            config = packaging.compose_config(HOSTED)
            config["services"]["world"]["environment"] = {"WORLD_OPTION": "changed"}
            config["services"]["world"]["healthcheck"]["retries"] = 17
            config["services"]["world"]["build"]["args"] = {"BUILD_OPTION": "changed"}
            command = config["services"]["attach"]["command"]
            command[command.index("--ip-addr") + 1] = "10.0.0.3/24"
            config["services"]["default"]["volumes"] = ["ca:/run/changed-ca:ro"]
            (source / "compose.yaml").write_text(json.dumps(config))
            hosted = packaging.compose_config(source)
            packaging.package(source, destination)
            generated = json.loads((destination / "docker-compose.yaml").read_text())
            services = generated["services"]
            self.assertEqual(services["world"]["environment"], {"WORLD_OPTION": "changed"})
            self.assertEqual(services["world"]["healthcheck"]["retries"], 17)
            self.assertEqual(services["world"]["build"]["args"], {"BUILD_OPTION": "changed"})
            self.assertIn("10.0.0.3/24", services["attach"]["command"])
            self.assertEqual(services["main"]["volumes"], hosted["services"]["default"]["volumes"])
            self.assertEqual((destination / "Dockerfile").read_bytes(), (source / "agent.Dockerfile").read_bytes())
            self.assertEqual((destination / "world.Dockerfile").read_bytes(), (source / "Dockerfile").read_bytes())


if __name__ == "__main__":
    unittest.main()
