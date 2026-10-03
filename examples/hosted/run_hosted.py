"""Runs this example on one hosted sandbox with Docker inside it, checks it,
and deletes the sandbox.

    python run_hosted.py daytona   # needs DAYTONA_API_KEY and `pip install daytona`
    python run_hosted.py e2b       # needs E2B_API_KEY and `pip install e2b`

Run ./build.sh first. The script uploads this directory's Dockerfiles,
compose file, check.sh and bin/, runs `docker compose up --build --wait`
inside the sandbox, then check.sh. It prints how long each step took.

Daytona: the sandbox is made from the `docker:28.3.3-dind` image, which
Daytona runs with full capabilities, and dockerd is started by hand.
E2B: a template `fictionet-dind` (Ubuntu 24.04 with Docker) is built once,
and later runs reuse it. Delete it from the E2B dashboard when done.
"""

import shlex
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
FILES = ["Dockerfile", "agent.Dockerfile", "compose.yaml", "check.sh", "bin/fictionet", "bin/web_world"]
t0 = time.time()


def log(*args):
    print(f"[{time.time() - t0:5.1f}s]", *args, flush=True)


def daytona():
    from daytona import CreateSandboxFromImageParams, Daytona, FileUpload, Image, Resources

    client = Daytona()
    sandbox = client.create(
        CreateSandboxFromImageParams(
            image=Image.base("docker:28.3.3-dind"),
            resources=Resources(cpu=2, memory=4, disk=8),
            auto_stop_interval=15,
            auto_delete_interval=60,
        ),
        timeout=600,
    )
    log("created sandbox", sandbox.id)

    def run(cmd, timeout=600):
        r = sandbox.process.exec(f"sh -c {shlex.quote(cmd)}", timeout=timeout)
        return r.exit_code, r.result

    try:
        run("dockerd-entrypoint.sh dockerd > /var/log/dockerd.log 2>&1 &", timeout=10)
        wait_for_docker(run, "docker info")
        sandbox.fs.upload_files(
            [FileUpload(source=str(HERE / f), destination=f"/root/hosted/{f}") for f in FILES]
        )
        up_and_check(run, "cd /root/hosted &&", "")
    finally:
        client.delete(sandbox)
        log("deleted sandbox", sandbox.id)


def e2b():
    from e2b import CommandExitException, Sandbox, Template

    template = (
        Template()
        .from_ubuntu_image("24.04")
        .run_cmd(
            "sudo apt-get update && sudo DEBIAN_FRONTEND=noninteractive "
            "apt-get install -y --no-install-recommends docker.io docker-compose-v2 iproute2"
        )
    )
    Template.build(template, "fictionet-dind", cpu_count=2, memory_mb=4096)
    log("template fictionet-dind ready")
    sandbox = Sandbox.create("fictionet-dind", timeout=900)
    log("created sandbox", sandbox.sandbox_id)

    def run(cmd, timeout=600):
        try:
            r = sandbox.commands.run(cmd, timeout=timeout)
            return r.exit_code, r.stdout + r.stderr
        except CommandExitException as e:
            return e.exit_code, e.stdout + e.stderr

    try:
        # dockerd may already be running, started by the image's init.
        run("sudo docker info >/dev/null 2>&1 || (sudo sh -c 'dockerd > /var/log/dockerd.log 2>&1 &')", timeout=10)
        wait_for_docker(run, "sudo docker info")
        for f in FILES:
            sandbox.files.write(f"/home/user/hosted/{f}", (HERE / f).read_bytes())
        up_and_check(run, "cd /home/user/hosted &&", "sudo")
    finally:
        sandbox.kill()
        log("deleted sandbox", sandbox.sandbox_id)


def wait_for_docker(run, cmd):
    for _ in range(60):
        if run(f"{cmd} >/dev/null 2>&1", timeout=10)[0] == 0:
            log("dockerd ready")
            return
        time.sleep(1)
    sys.exit("dockerd did not start")


def up_and_check(run, cd, sudo):
    code, out = run(f"{cd} {sudo} docker compose up -d --build --wait 2>&1 | tail -5")
    log("docker compose up:", out.strip().splitlines()[-1] if out.strip() else "")
    code, out = run(f"{cd} {sudo} sh ./check.sh", timeout=300)
    print(out.rstrip())
    log("check.sh exit status", code)
    run(f"{cd} {sudo} docker compose down -v", timeout=120)
    if code != 0:
        sys.exit(1)


if __name__ == "__main__":
    {"daytona": daytona, "e2b": e2b}[sys.argv[1]]()
