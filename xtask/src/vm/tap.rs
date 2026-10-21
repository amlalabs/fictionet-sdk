use super::*;
use crate::process::{Checks, poll_interruptible as poll};
use base64::Engine;
use regex::Regex;

pub(super) fn directory() -> PathBuf {
    crate::root().join(".vm")
}

pub(super) fn prepared() -> PathBuf {
    directory().join(format!("prepared-{DEBIAN_BUILD}.qcow2"))
}

pub(super) fn prepare_image(base: &Path, out: &Path, packages: &str, size: &str) -> Result {
    if out.exists() {
        return Ok(());
    }
    let work = directory().join(format!("prep-{}", token(6)?));
    private_dir(&work)?;
    fs::write(
        work.join("user-data"),
        format!(
            "#cloud-config\npackage_update: true\npackages: [{packages}]\nruncmd:\n  - [sh, -c, 'echo FICTIONET-PREP-DONE > /dev/ttyS0']\npower_state: {{mode: poweroff, condition: true}}\n"
        ),
    )?;
    fs::write(
        work.join("meta-data"),
        format!("instance-id: prep-{}\nlocal-hostname: prep\n", token(6)?),
    )?;
    iso(
        &work.join("seed.iso"),
        "cidata",
        &[work.join("user-data"), work.join("meta-data")],
    )?;
    overlay(base, &work.join("disk.qcow2"), Some(size))?;
    execute(qemu(1800).args([
        "-m",
        "2G",
        "-smp",
        "2",
        "-serial",
        &format!("file:{}", work.join("console.log").display()),
        "-drive",
        &format!("file={},if=virtio", work.join("disk.qcow2").display()),
        "-drive",
        &format!(
            "file={},if=virtio,media=cdrom,readonly=on",
            work.join("seed.iso").display()
        ),
        "-nic",
        "user,model=virtio-net-pci",
    ]))?;
    if !fs::read_to_string(work.join("console.log"))?.contains("FICTIONET-PREP-DONE") {
        return Err(format!(
            "image preparation failed; see {}",
            work.join("console.log").display()
        )
        .into());
    }
    fs::rename(work.join("disk.qcow2"), out)?;
    remove(&work)
}

pub(super) fn fetch_guest() -> Result {
    let base = fetch_base(&directory())?;
    prepare_image(
        &base,
        &prepared(),
        "bind9-dnsutils, curl, iputils-ping",
        "4G",
    )
}

pub(super) fn qemu(seconds: u64) -> Command {
    cmd(
        "timeout",
        &[
            &seconds.to_string(),
            "qemu-system-x86_64",
            "-enable-kvm",
            "-cpu",
            "host",
            "-display",
            "none",
            "-no-reboot",
        ],
    )
}

pub(super) fn wait_file(path: &Path, child: &mut ChildGuard, log: &Path) -> Result {
    wait_for(path, Path::exists, child, log)
}

pub(super) fn wait_ca(path: &Path, world: &mut ChildGuard, log: &Path) -> Result {
    wait_for(
        path,
        |path| {
            fs::read_to_string(path).is_ok_and(|text| text.contains("-----END CERTIFICATE-----"))
        },
        world,
        log,
    )
}

fn wait_for(
    path: &Path,
    ready: impl Fn(&Path) -> bool,
    child: &mut ChildGuard,
    log: &Path,
) -> Result {
    if poll(Duration::from_secs(10), Duration::from_millis(100), || {
        if let Some(status) = child.0.try_wait()? {
            return Err(format!(
                "process exited with {status}: {}",
                fs::read_to_string(log).unwrap_or_default()
            )
            .into());
        }
        Ok(ready(path))
    })? {
        Ok(())
    } else {
        Err(format!(
            "timed out waiting for {}: {}",
            path.display(),
            fs::read_to_string(log).unwrap_or_default()
        )
        .into())
    }
}

pub(super) struct GuestScript {
    pub script: String,
    expected: Vec<(String, u8)>,
}

impl GuestScript {
    fn new() -> Self {
        Self { script: r#"#!/bin/bash
ip() { command ip -color=never "$@"; }
show() {
    local name="$1" status t0 t1
    shift
    printf '$ %s\n' "$*"
    t0=$(date +%s%N)
    if "$@" 2>&1; then status=0; else status=$?; fi
    t1=$(date +%s%N)
    printf '\n[exit %d]\n[took %d ms]\n=== guest result %s %d %d\n' "$status" "$(((t1-t0)/1000000))" "$name" "$status" "$(((t1-t0)/1000000))"
}
echo '=== guest begin'
"#.into(), expected: Vec::new() }
    }
    fn command(&mut self, name: &str, status: u8, command: &str) {
        self.script.push_str(&format!("show {name} {command}\n"));
        self.expected.push((name.into(), status));
    }
    pub fn web() -> Self {
        let mut guest = Self::new();
        for (name, command) in [
            ("links", "ip -br link"),
            ("address", "ip -br addr"),
            ("route", "ip route"),
            ("dns_config", "cat /etc/resolv.conf"),
            ("dns", "dig +short example.test"),
            (
                "https",
                "curl -sS --cacert /root/ca.pem https://example.test/",
            ),
            (
                "download",
                "curl -sS --cacert /root/ca.pem -o /dev/null -w 'size %{size_download} time %{time_total}\\n' https://example.test/big",
            ),
            ("ping", "ping -c 3 10.0.0.1"),
        ] {
            guest.command(name, 0, command);
        }
        guest.command("nxdomain", 6, "curl -sS --max-time 10 http://nowhere.test/");
        guest.command("unreachable", 7, "curl -sS --max-time 10 http://192.0.2.1/");
        guest.script.push_str("echo '=== guest end'\n");
        guest
    }
    fn dual() -> Self {
        let mut guest = Self::new();
        guest.script.push_str("for i in $(seq 40); do ip -6 addr show dev ens3 | grep -q 'fd00::2/128' && break; sleep 0.5; done\n");
        guest.command("address", 0, "ip -br addr show dev ens3");
        guest.command("route", 0, "ip -6 route");
        guest.command("ipv4", 0, "ping -c 3 10.0.0.1");
        guest.command("ipv6", 0, "ping -c 3 fd00::1");
        guest.command("ipv6_world", 0, "ping -c 3 2001:db8::99");
        guest.script.push_str("echo '=== guest end'\n");
        guest
    }
    pub fn validate(&self, text: &str, success: bool) -> Result {
        let mut errors = Vec::new();
        if !success {
            errors.push("emulator failed or timed out".into());
        }
        let lines: Vec<_> = text.lines().map(str::trim_end).collect();
        if !lines.contains(&"=== guest end") {
            errors.push("the guest did not reach the end of its script".into());
        }
        for (name, status) in &self.expected {
            let record = format!("=== guest result {name} {status} ");
            if !lines.iter().any(|line| line.starts_with(&record)) {
                errors.push(format!("{name}: no result with status {status}"));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("\n").into())
        }
    }
}

pub(super) fn web_checks(checks: &mut Checks, text: &str, route: bool) -> Result {
    let address = if route {
        r"(?m)(inet 10\.0\.0\.2/24|ens3 +UP +10\.0\.0\.2/24)"
    } else {
        r"UP +10\.0\.0\.2/24"
    };
    for (name, pattern) in [
        ("DHCP address", address),
        ("DNS answer", r"(?m)^203\.0\.113\.10$"),
        ("HTTPS response", r"(?m)^hello from https example\.test 443"),
        ("16 MiB download", r"(?m)^size 16777216 "),
        ("gateway ping", "3 packets transmitted, 3 received"),
    ] {
        checks.require(name, Regex::new(pattern)?.is_match(text), text);
    }
    if route {
        checks.require(
            "default route",
            Regex::new(r"(?m)^default via 10\.0\.0\.1 dev ens3")?.is_match(text),
            text,
        );
    }
    for (name, pattern) in [
        ("nxdomain", "Could not resolve host: nowhere.test"),
        ("unreachable", "Failed to connect to 192.0.2.1"),
    ] {
        let ms = Regex::new(&format!(r"(?m)^=== guest result {name} [0-9]+ ([0-9]+)$"))?
            .captures(text)
            .and_then(|m| m[1].parse::<u64>().ok());
        checks.require(
            &format!("{name} fails in less than 2000 ms"),
            text.contains(pattern) && ms.is_some_and(|ms| ms < 2000),
            text,
        );
    }
    Ok(())
}

pub(super) fn attach_ended(
    checks: &mut Checks,
    attach: &mut ChildGuard,
    log: &Path,
    message: &str,
) -> Result {
    let ended = poll(Duration::from_secs(5), Duration::from_millis(100), || {
        Ok(attach.0.try_wait()?.is_some())
    })?;
    let success = ended && attach.0.wait()?.success();
    let text = fs::read_to_string(log)?;
    println!("{text}");
    checks.require(
        "attach exits cleanly after detaching",
        success && text.contains(message),
        &text,
    );
    Ok(())
}

pub(super) fn build(release: bool) -> Result<PathBuf> {
    let target = crate::root().join("target");
    let mut command = cmd(
        "cargo",
        &[
            "build",
            "--locked",
            "--features",
            "web-proxy,tokio",
            "--bin",
            "fictionet",
            "--example",
            "web_fixture",
            "--example",
            "ping_world",
        ],
    );
    command.env("CARGO_TARGET_DIR", &target);
    if release {
        command.arg("--release");
    }
    execute(&mut command)?;
    Ok(target.join(if release { "release" } else { "debug" }))
}

pub fn run(fetch: bool) -> Result {
    let _lock = lock()?;
    check_host()?;
    private_dir(&directory())?;
    if fetch {
        fetch_guest()?;
    }
    if !prepared().is_file() {
        return Err("no prepared image; run cargo xtask vm --fetch".into());
    }
    let target = build(false)?;
    let work = directory().join(format!("tap-{}", token(6)?));
    private_dir(&work)?;
    let result = (|| {
        let mut checks = Checks::default();
        let ipv6_route =
            Regex::new(r"(?m)^default (nhid [0-9]+ )?via fe80::7683:c2ff:fe9a:47d1 dev ens3")?;
        for dual in [false, true] {
            let name = if dual { "dual" } else { "web" };
            let world_log = work.join("world.log");
            let mut world_cmd = Command::new(target.join(if dual {
                "examples/ping_world"
            } else {
                "examples/web_fixture"
            }));
            world_cmd.arg(work.join("world.sock"));
            if !dual {
                world_cmd.arg(work.join("ca.pem"));
            }
            let mut world = background(&mut world_cmd, &world_log)?;
            let ready = work.join("ready");
            remove(&ready)?;
            let mut attach_cmd = Command::new(target.join("fictionet"));
            attach_cmd
                .args([
                    "attach",
                    "--world",
                    &format!("unix:{}", work.join("world.sock").display()),
                    "--name",
                    "agent",
                    "--type",
                    "tap",
                    "--vm",
                    &format!("qemu:{}", work.join("vm.sock").display()),
                    "--ready-file",
                ])
                .arg(&ready)
                .args([
                    "--world-wait",
                    "10",
                    "--ip-addr",
                    "10.0.0.2/24",
                    "--gateway",
                    "10.0.0.1",
                    "--dns",
                    "10.0.0.1",
                ]);
            if dual {
                attach_cmd.args([
                    "--ip-addr-v6",
                    "fd00::2/64",
                    "--gateway-v6",
                    "fd00::1",
                    "--dns-v6",
                    "fd00::1",
                ]);
            } else {
                attach_cmd.arg("--no-ip-addr-v6");
            }
            let attach_log = work.join("attach.log");
            let mut attach = background(&mut attach_cmd, &attach_log)?;
            wait_file(&ready, &mut attach, &attach_log)?;
            if !dual {
                wait_ca(&work.join("ca.pem"), &mut world, &world_log)?;
            }
            let guest = if dual {
                GuestScript::dual()
            } else {
                GuestScript::web()
            };
            let seed = work.join(name);
            private_dir(&seed)?;
            let script =
                guest
                    .script
                    .replacen("#!/bin/bash\n", "#!/bin/bash\nexec > /dev/ttyS1 2>&1\n", 1)
                    + "poweroff\n";
            let encode = |data: &[u8]| base64::engine::general_purpose::STANDARD.encode(data);
            fs::write(
                seed.join("user-data"),
                format!(
                    "#cloud-config\nwrite_files:\n  - path: /root/ca.pem\n    encoding: b64\n    content: {}\n  - path: /root/check.sh\n    permissions: '0755'\n    encoding: b64\n    content: {}\nruncmd:\n  - [/root/check.sh]\n",
                    encode(&fs::read(work.join("ca.pem"))?),
                    encode(script.as_bytes())
                ),
            )?;
            fs::write(
                seed.join("meta-data"),
                format!("instance-id: {name}-{}\nlocal-hostname: agent\n", token(6)?),
            )?;
            let mut files = vec![seed.join("user-data"), seed.join("meta-data")];
            if dual {
                fs::write(
                    seed.join("network-config"),
                    "network:\n  version: 2\n  ethernets:\n    ens3:\n      dhcp4: true\n      dhcp6: true\n",
                )?;
                files.push(seed.join("network-config"));
            }
            iso(&seed.join("seed.iso"), "cidata", &files)?;
            overlay(&prepared(), &seed.join("disk.qcow2"), None)?;
            let output = qemu(300)
                .args([
                    "-m",
                    "1G",
                    "-smp",
                    "2",
                    "-serial",
                    &format!("file:{}", seed.join("console.log").display()),
                    "-serial",
                    &format!("file:{}", seed.join("out.txt").display()),
                    "-drive",
                    &format!("file={},if=virtio", seed.join("disk.qcow2").display()),
                    "-drive",
                    &format!(
                        "file={},if=virtio,media=cdrom,readonly=on",
                        seed.join("seed.iso").display()
                    ),
                    "-netdev",
                    &format!(
                        "stream,id=n0,server=off,addr.type=unix,addr.path={}",
                        work.join("vm.sock").display()
                    ),
                    "-device",
                    "virtio-net-pci,netdev=n0",
                ])
                .output()?;
            let raw = fs::read_to_string(seed.join("out.txt")).unwrap_or_default();
            let text = raw.replace('\r', "");
            println!("{text}");
            let validated = guest.validate(&raw, output.status.success());
            checks.require(
                "QEMU and guest completed",
                validated.is_ok(),
                format!(
                    "{validated:?}\n{}\n{}",
                    crate::process::combined(&output),
                    fs::read_to_string(seed.join("console.log")).unwrap_or_default()
                ),
            );
            attach_ended(
                &mut checks,
                &mut attach,
                &attach_log,
                "QEMU closed the connection; agent detached",
            )?;
            if dual {
                checks.require("DHCPv6 address", text.contains("fd00::2/128"), &text);
                checks.require("IPv6 default route", ipv6_route.is_match(&text), &text);
                checks.require(
                    "three successful IPv4 and IPv6 pings",
                    text.matches("3 packets transmitted, 3 received").count() == 3,
                    &text,
                );
            } else {
                web_checks(&mut checks, &text, true)?;
            }
        }
        checks.finish()
    })();
    if result.is_ok() {
        remove(&work)?;
    } else {
        eprintln!("VM logs are in {}", work.display());
    }
    result
}
