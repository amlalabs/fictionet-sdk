use crate::images;
use crate::process::{Checks, Cleanup, Result, capture, cmd, poll, run as execute};
use std::process::Command;
use std::time::Duration;

mod proxy;
mod tun;

const CLUSTER: &str = "fictionet-k8s-test";
const CONTEXT: &str = "kind-fictionet-k8s-test";

struct Kube {
    namespace: &'static str,
    pod: &'static str,
    container: &'static str,
}

impl Kube {
    fn command(&self, args: &[&str]) -> Command {
        let mut command = kubectl(&["-n", self.namespace]);
        command.args(args);
        command
    }

    fn agent(&self, args: &[&str]) -> Command {
        let mut command = self.command(&["exec", self.pod, "-c", self.container, "--"]);
        command.args(args);
        command
    }

    fn field(&self, path: &str) -> Result<String> {
        capture(&mut self.command(&["get", "pod", self.pod, "-o", &format!("jsonpath={path}")]))
    }

    fn logs(&self, container: &str) -> Command {
        self.command(&["logs", self.pod, "-c", container])
    }

    fn restart(&self, checks: &mut Checks) -> Result {
        let mut state = String::new();
        poll(Duration::from_secs(60), Duration::from_secs(1), || {
            let count =
                self.field("{.status.initContainerStatuses[?(@.name==\"attach\")].restartCount}")?;
            let ready =
                self.field("{.status.initContainerStatuses[?(@.name==\"attach\")].ready}")?;
            state = format!("{count} {ready}");
            Ok(count.parse::<u64>()? >= 1 && ready == "true")
        })?;
        checks.require("attach restarted and is ready", state == "1 true", &state);
        Ok(())
    }

    fn stop_attach(&self) -> Result {
        let node = format!("{CLUSTER}-control-plane");
        let id = capture(&mut cmd(
            "docker",
            &[
                "exec",
                &node,
                "crictl",
                "ps",
                "--name",
                "attach",
                "--label",
                &format!("io.kubernetes.pod.name={}", self.pod),
                "-q",
            ],
        ))?;
        if id.trim().is_empty() || id.split_whitespace().count() != 1 {
            return Err(format!("expected one attach container, got {id}").into());
        }
        execute(&mut cmd(
            "docker",
            &[
                "exec",
                &node,
                "crictl",
                "--timeout",
                "30s",
                "stop",
                "-t",
                "0",
                id.trim(),
            ],
        ))
    }
}

fn kubectl(args: &[&str]) -> Command {
    let mut command = cmd("kubectl", &["--context", CONTEXT]);
    command.args(args);
    command
}

fn helm(args: &[&str]) -> Command {
    let mut command = cmd("helm", &["--kube-context", CONTEXT]);
    command.args(args);
    command
}

pub fn run(args: &[String]) -> Result {
    let mode = match args {
        [] => "all",
        [mode] if matches!(mode.as_str(), "tun" | "proxy") => mode,
        _ => return Err("usage: cargo xtask k8s [tun|proxy]".into()),
    };
    images::build("deploy/Dockerfile", "attach", "fictionet-attach:dev")?;
    images::build("deploy/Dockerfile", "agent", "fictionet-agent:dev")?;
    let mut images = vec!["fictionet-attach:dev", "fictionet-agent:dev"];
    if mode != "proxy" {
        images::build("deploy/Dockerfile", "web-world", "fictionet-web-world:dev")?;
        images.push("fictionet-web-world:dev");
    }
    if mode != "tun" {
        images::build(
            "tests/docker/web/Dockerfile",
            "fixture",
            "fictionet-web-fixture:dev",
        )?;
        images.push("fictionet-web-fixture:dev");
    }
    let mut cleanup = Cleanup::default();
    let clusters = capture(&mut cmd("kind", &["get", "clusters"]))?;
    if !clusters.lines().any(|line| line == CLUSTER) {
        cleanup.push(cmd("kind", &["delete", "cluster", "--name", CLUSTER]));
        execute(&mut cmd(
            "kind",
            &["create", "cluster", "--name", CLUSTER, "--wait", "120s"],
        ))?;
    }
    let result = (|| {
        execute(cmd("kind", &["load", "docker-image", "--name", CLUSTER]).args(&images))?;
        if mode != "proxy" {
            tun::run()?;
        }
        if mode != "tun" {
            proxy::run()?;
        }
        Ok(())
    })();
    cleanup.finish(result)
}
