use crate::process::{Checks, Cleanup, Result, capture, cmd, poll, run as execute, token};
use std::process::Command;
use std::time::Duration;

mod proxy;
mod web;

pub struct Compose {
    file: String,
    project: Option<String>,
    env: Vec<(String, String)>,
}

impl Compose {
    pub fn new(file: &str) -> Self {
        Self {
            file: file.into(),
            project: None,
            env: Vec::new(),
        }
    }

    pub fn project(mut self, project: &str) -> Self {
        self.project = Some(project.into());
        self
    }
    pub fn env(mut self, key: &str, value: &str) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn command(&self, args: &[&str]) -> Command {
        let mut command = cmd("docker", &["compose", "-f", &self.file]);
        if let Some(project) = &self.project {
            command.args(["-p", project]);
        }
        command
            .envs(self.env.iter().map(|(key, value)| (key, value)))
            .args(args);
        command
    }

    pub fn agent(&self, args: &[&str]) -> Command {
        let mut command = self.command(&["exec", "-T", "agent"]);
        command.args(args);
        command
    }

    pub fn down(&self) -> Command {
        self.command(&["down", "-v", "--remove-orphans", "--timeout", "2"])
    }
    pub fn logs(&self, service: &str) -> Result<String> {
        capture(&mut self.command(&["logs", "--no-log-prefix", service]))
    }
}

pub fn run(args: &[String]) -> Result {
    let [suite] = args else {
        return Err("usage: cargo xtask docker <ping|tcpudp|proxy|web>".into());
    };
    if suite == "tcpudp" {
        return tcpudp();
    }
    if !matches!(suite.as_str(), "ping" | "proxy" | "web") {
        return Err(format!("unknown Docker suite: {suite}").into());
    }
    let compose =
        Compose::new(&format!("tests/docker/{suite}/compose.yaml")).env("RELAY_TOKEN", &token(16)?);
    execute(&mut compose.down())?;
    let mut cleanup = Cleanup::default();
    cleanup.push(compose.down());
    let result = (|| {
        execute(&mut compose.command(&["build", "--quiet"]))?;
        execute(&mut compose.command(&["up", "-d", "--wait"]))?;
        match suite.as_str() {
            "ping" => ping(&compose),
            "proxy" => proxy::run(&compose),
            "web" => web::run(&compose),
            _ => unreachable!(),
        }
    })();
    cleanup.finish(result)
}

fn tcpudp() -> Result {
    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "release".into());
    execute(&mut cmd(
        "docker",
        &[
            "build",
            "-t",
            "fictionet-tcpudp-test",
            "--build-arg",
            &format!("PROFILE={profile}"),
            "-f",
            "tests/docker/tcpudp/Dockerfile",
            ".",
        ],
    ))?;
    let name = format!("fictionet-tcpudp-test-{}", std::process::id());
    let mut command = cmd(
        "docker",
        &[
            "run",
            "--rm",
            "--name",
            &name,
            "--cap-add",
            "NET_ADMIN",
            "--device",
            "/dev/net/tun",
            "--sysctl",
            "net.ipv6.conf.all.disable_ipv6=0",
        ],
    );
    for key in ["FICTIONET_TRACE", "FICTIONET_ONLY_LOSS"] {
        if std::env::var(key).is_ok_and(|v| !v.is_empty()) {
            command.args(["-e", &format!("{key}=1")]);
        }
    }
    execute(command.args([
        "fictionet-tcpudp-test",
        "/test",
        "tun_linux::",
        "--nocapture",
    ]))
}

fn world_says(compose: &Compose, text: &str) -> Result<bool> {
    poll(Duration::from_secs(10), Duration::from_millis(200), || {
        Ok(compose.logs("world")?.contains(text))
    })
}

fn attachment_count(compose: &Compose) -> Result<usize> {
    Ok(compose
        .logs("world")?
        .lines()
        .filter(|line| {
            *line == "attached abc mtu 1500" || line.starts_with("attached abc mtu 1500 ")
        })
        .count())
}

fn ping(compose: &Compose) -> Result {
    let mut checks = Checks::default();
    checks.ok(
        "ping 10.0.0.1",
        "",
        &mut compose.agent(&["ping", "-c", "3", "-W", "2", "10.0.0.1"]),
    )?;
    checks.ok(
        "ping fd00::1",
        "",
        &mut compose.agent(&["ping", "-6", "-c", "3", "-W", "2", "fd00::1"]),
    )?;
    let resolv = capture(&mut compose.agent(&["cat", "/etc/resolv.conf"]))?;
    checks.require(
        "agent resolv.conf lists 10.0.0.1",
        resolv.lines().any(|line| line == "nameserver 10.0.0.1"),
        &resolv,
    );
    checks.fails(
        "agent cannot run ip addr add",
        "Operation not permitted",
        &mut compose.agent(&["ip", "addr", "add", "10.0.0.9/24", "dev", "tun0"]),
    )?;
    let attach = |prefix: &[&str], name: &str| {
        let mut command = compose.command(prefix);
        command.args([
            "attach",
            "fictionet",
            "attach",
            "--name",
            name,
            "--world",
            "unix:/run/fictionet/world.sock",
            "--type",
            "tun",
            "--no-ip-addr",
            "--no-gateway",
            "--no-dns",
            "--no-ip-addr-v6",
            "--no-gateway-v6",
            "--no-dns-v6",
        ]);
        command
    };
    checks.output(
        "taken name refused",
        "abc is already attached",
        &attach(&["run", "--rm", "--no-deps", "-T"], "abc").output()?,
        Some(3),
    )?;
    let id = capture(&mut attach(&["run", "-d", "--no-deps"], "term"))?;
    let id = id.trim();
    let mut cleanup = Cleanup::default();
    cleanup.push(cmd("docker", &["rm", "-f", id]));
    if world_says(compose, "attached term")? {
        execute(&mut cmd("docker", &["kill", "--signal", "TERM", id]))?;
        let code = capture(&mut cmd("docker", &["wait", id]))?;
        checks.require(
            "SIGTERM detaches",
            world_says(compose, "detached term")?,
            format!("attach exited {}", code.trim()),
        );
    } else {
        checks.require("second attach attached", false, compose.logs("world")?);
    }
    cleanup.finish(Ok(()))?;
    execute(&mut compose.command(&["kill", "-s", "SIGKILL", "attach"]))?;
    checks.require(
        "SIGKILL detaches abc",
        world_says(compose, "detached abc")?,
        compose.logs("world")?,
    );
    let before = attachment_count(compose)?;
    execute(&mut compose.command(&["start", "attach"]))?;
    let attached = poll(Duration::from_secs(10), Duration::from_millis(200), || {
        Ok(attachment_count(compose)? > before)
    })?;
    checks.require(
        "attach attached again after restart",
        attached,
        compose.logs("world")?,
    );
    if attached {
        execute(&mut compose.command(&["kill", "-s", "SIGKILL", "world"]))?;
        let id = capture(&mut compose.command(&["ps", "-aq", "attach"]))?;
        let code = capture(&mut cmd("docker", &["wait", id.trim()]))?;
        let logs = compose.logs("attach")?;
        checks.require(
            "world gone: attach exited 0 and removed tun0",
            code.trim() == "0" && logs.contains("the world closed the connection; tun0 removed"),
            format!("exit {code}: {logs}"),
        );
    }
    println!(
        "world log:\n{}\nattach log:\n{}",
        compose.logs("world")?,
        compose.logs("attach")?
    );
    checks.finish()
}
