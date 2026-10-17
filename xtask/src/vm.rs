use crate::process::{ChildGuard, Result, capture, cmd, input, poll, run as execute, token};
use std::fs::{self, File, OpenOptions};
use std::io::{IsTerminal, Read, Write};
use std::net::TcpListener;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

mod nested;
mod tap;

const DEBIAN_BUILD: &str = "20261001-2618";
const DEBIAN_SHA512: &str = "f46f0671a6e5bdec5291ab8972bae2f10e5408c2f64a74078f11efc2f06a436a9d0313ed50e0472542eeabf780e9f7c792ac0a314c6c20507fcd9fd81b468c3d";
pub const KIND_NODE: &str =
    "kindest/node:v1.37.0@sha256:a1ed56cfb0e7b93589bdf97c8cd566405a265939e3620fc4f5de89adff580ae5";
const KIND_VERSION: &str = "v0.33.0";
const KUBECTL_VERSION: &str = "v1.37.1";
const HELM_VERSION: &str = "v4.3.0";
const UV_VERSION: &str = "0.12.22";

pub fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

pub fn private_dir(path: &Path) -> Result {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn remove(path: &Path) -> Result {
    if path.is_dir() {
        fs::remove_dir_all(path)?;
    } else if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn check_host() -> Result {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .map_err(|e| format!("/dev/kvm is not usable: {e}; see vm/README.md"))?;
    Ok(())
}

fn debian_name() -> String {
    format!("debian-13-genericcloud-amd64-{DEBIAN_BUILD}.qcow2")
}

fn fetch_base(dir: &Path) -> Result<PathBuf> {
    let name = debian_name();
    let path = dir.join(&name);
    let url = format!("https://cloud.debian.org/images/cloud/trixie/{DEBIAN_BUILD}/{name}");
    download(&url, &path, "sha512sum", DEBIAN_SHA512)?;
    Ok(path)
}

fn download(url: &str, path: &Path, algorithm: &str, hash: &str) -> Result {
    if path.is_file() {
        return Ok(());
    }
    private_dir(path.parent().ok_or("download needs a directory")?)?;
    let part = path.with_extension("part");
    execute(
        cmd("curl", &["-fSL", "--progress-bar", "-o"])
            .arg(&part)
            .arg(url),
    )?;
    let actual = capture(cmd(algorithm, &[]).arg(&part))?;
    if actual.split_whitespace().next() != Some(hash) {
        remove(&part)?;
        return Err(format!("{}: {algorithm} mismatch", path.display()).into());
    }
    fs::rename(part, path)?;
    Ok(())
}

fn iso(output: &Path, label: &str, files: &[PathBuf]) -> Result {
    execute(
        cmd("genisoimage", &["-quiet", "-output"])
            .arg(output)
            .args(["-volid", label, "-joliet", "-rock"])
            .args(files),
    )
}

fn overlay(base: &Path, out: &Path, size: Option<&str>) -> Result {
    let mut command = cmd(
        "qemu-img",
        &["create", "-q", "-f", "qcow2", "-F", "qcow2", "-b"],
    );
    command.arg(base).arg(out);
    if let Some(size) = size {
        command.arg(size);
    }
    execute(&mut command)
}

fn logged(command: &mut Command, path: &Path) -> Result {
    let file = File::create(path)?;
    let mut child = ChildGuard(
        command
            .stdout(Stdio::piped())
            .stderr(file.try_clone()?)
            .spawn()?,
    );
    let mut output = child.0.stdout.take().ok_or("missing child stdout")?;
    let mut log = file;
    let mut bytes = [0; 8192];
    loop {
        let n = output.read(&mut bytes)?;
        if n == 0 {
            break;
        }
        log.write_all(&bytes[..n])?;
        std::io::stdout().write_all(&bytes[..n])?;
    }
    let status = child.0.wait()?;
    if !status.success() {
        return Err(format!("command exited with {status}; see {}", path.display()).into());
    }
    Ok(())
}

pub fn background(command: &mut Command, path: &Path) -> Result<ChildGuard> {
    let log = File::create(path)?;
    Ok(ChildGuard(
        command.stdout(log.try_clone()?).stderr(log).spawn()?,
    ))
}

fn port(preferred: u16) -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", preferred))
        .or_else(|_| TcpListener::bind(("127.0.0.1", 0)))?;
    Ok(listener.local_addr()?.port())
}

pub struct Vm {
    dir: PathBuf,
}

impl Vm {
    fn new() -> Self {
        Self {
            dir: crate::root().join(".vm"),
        }
    }
    fn path(&self, path: &str) -> PathBuf {
        self.dir.join(path)
    }
    pub fn read(&self, path: &str) -> Result<String> {
        Ok(fs::read_to_string(self.path(path))?.trim().into())
    }
    fn pid(&self) -> Option<String> {
        let pid = self.read("run/qemu.pid").ok()?;
        if !pid.bytes().all(|c| c.is_ascii_digit()) || pid.is_empty() {
            return None;
        }
        let command = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
        command
            .split(|b| *b == 0)
            .any(|arg| arg == self.path("run/qemu.pid").as_os_str().as_encoded_bytes())
            .then_some(pid)
    }
    fn require_running(&self) -> Result {
        if self.pid().is_none() {
            return Err("the VM is not running; start it with cargo xtask vm up".into());
        }
        Ok(())
    }
    pub fn ssh(&self) -> Result<Command> {
        let mut command = cmd(
            "ssh",
            &["-F", "/dev/null", "-p", &self.read("run/ssh-port")?, "-i"],
        );
        command.arg(self.path("ssh/id_ed25519"));
        for option in [
            "IdentitiesOnly=yes",
            "BatchMode=yes",
            "LogLevel=ERROR",
            "ForwardAgent=no",
            "ForwardX11=no",
            "ClearAllForwardings=yes",
            "HostKeyAlias=fictionet-vm",
            "StrictHostKeyChecking=accept-new",
            "ControlMaster=auto",
            "ControlPersist=120",
            "ServerAliveInterval=10",
            "ServerAliveCountMax=3",
        ] {
            command.args(["-o", option]);
        }
        command.args([
            "-o",
            &format!(
                "UserKnownHostsFile=\"{}\"",
                self.path("ssh/known_hosts").display()
            ),
            "-o",
            &format!("ControlPath=\"{}\"", self.path("run/ssh.sock").display()),
        ]);
        Ok(command)
    }
    fn remote(&self, text: &str) -> Result<Command> {
        let mut command = self.ssh()?;
        command.args(["root@127.0.0.1", text]);
        Ok(command)
    }
    fn boot(&self, disk: &Path, mode: &str, seed: Option<&Path>) -> Result {
        private_dir(&self.path("run"))?;
        let cache = self.path("cache.qcow2");
        if !cache.is_file() {
            execute(
                cmd("qemu-img", &["create", "-q", "-f", "qcow2"])
                    .arg(&cache)
                    .arg("80G"),
            )?;
        }
        let check = cmd("qemu-img", &["check", "-q", "-r", "leaks"])
            .arg(&cache)
            .output()?;
        if !check.status.success() {
            return Err(format!(
                "cache disk check failed: {}",
                crate::process::combined(&check)
            )
            .into());
        }
        let ssh_port = port(2222)?;
        let dashboard_port = port(7878)?;
        fs::write(self.path("run/ssh-port"), ssh_port.to_string())?;
        fs::write(self.path("run/dashboard-port"), dashboard_port.to_string())?;
        let mem = std::env::var("VM_MEM").unwrap_or_else(|_| "5G".into());
        let mut command = cmd("qemu-system-x86_64", &[]);
        if std::env::var("VM_SCOPE").as_deref() != Ok("0") {
            if cmd("systemd-run", &["--user", "--scope", "-q", "true"])
                .output()
                .is_ok_and(|o| o.status.success())
            {
                let memory = mem.to_uppercase();
                let mib = if let Some(gib) = memory.strip_suffix('G') {
                    gib.parse::<u64>()?
                        .checked_mul(1024)
                        .ok_or("VM_MEM too large")?
                } else {
                    memory.trim_end_matches('M').parse::<u64>()?
                };
                // A fresh scope name for each boot: on the first run, the
                // scope that prepared the image is still loaded when the
                // prepared image boots, and systemd refuses a loaded name.
                command = cmd(
                    "systemd-run",
                    &[
                        "--user",
                        "--scope",
                        "-q",
                        "--unit",
                        &format!("fictionet-vm-{}", token(4)?),
                        "-p",
                        &format!(
                            "MemoryMax={}M",
                            mib.checked_add(1024).ok_or("VM_MEM too large")?
                        ),
                        "-p",
                        "MemorySwapMax=0",
                        "qemu-system-x86_64",
                    ],
                );
            } else {
                eprintln!(
                    "No systemd user session; QEMU runs without the memory cap (VM_SCOPE=0 silences this)."
                );
            }
        }
        command.args(["-name", "fictionet-vm", "-machine", "q35,accel=kvm", "-cpu", "host", "-smp", &std::env::var("VM_CPUS").unwrap_or_else(|_| "4".into()), "-m", &mem,
            "-nodefaults", "-display", "none", "-vga", "std", "-serial", &format!("file:{}", self.path("run/console.log").display()),
            "-drive", &format!("if=none,id=root,file={},format=qcow2,cache={mode},discard=unmap", disk.display()), "-device", "virtio-blk-pci,drive=root,bootindex=0",
            "-drive", &format!("if=none,id=cache,file={},format=qcow2,cache=writeback,discard=unmap", cache.display()), "-device", "virtio-blk-pci,drive=cache,serial=fncache",
            "-netdev", &format!("user,id=net0,hostfwd=tcp:127.0.0.1:{ssh_port}-:22,hostfwd=tcp:127.0.0.1:{dashboard_port}-:7878"), "-device", "virtio-net-pci,netdev=net0,mac=52:54:00:f1:c7:01", "-device", "virtio-rng-pci", "-pidfile"])
            .arg(self.path("run/qemu.pid")).arg("-daemonize");
        if let Some(seed) = seed {
            command.args([
                "-drive",
                &format!("if=virtio,file={},format=raw,readonly=on", seed.display()),
            ]);
        }
        execute(&mut command)
    }
    fn wait_ssh(&self, seconds: u64) -> Result {
        let ready = poll(
            Duration::from_secs(seconds),
            Duration::from_millis(200),
            || {
                crate::process::interrupted()?;
                if self.pid().is_none() {
                    return Err("QEMU exited while booting".into());
                }
                Ok(self
                    .ssh()?
                    .args(["-o", "ConnectTimeout=1", "root@127.0.0.1", "true"])
                    .output()?
                    .status
                    .success())
            },
        );
        if !matches!(ready, Ok(true)) {
            eprintln!(
                "{}",
                fs::read_to_string(self.path("run/console.log")).unwrap_or_default()
            );
            self.stop()?;
            ready?;
            return Err(format!("the VM did not answer SSH within {seconds} s").into());
        }
        Ok(())
    }
    fn stop(&self) -> Result {
        if let Some(pid) = self.pid() {
            let mut asked = ChildGuard(
                self.ssh()?
                    .args([
                        "-o",
                        "ConnectTimeout=5",
                        "root@127.0.0.1",
                        "systemctl poweroff",
                    ])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()?,
            );
            if !poll(Duration::from_secs(60), Duration::from_millis(200), || {
                Ok(self.pid().is_none())
            })? {
                execute(&mut cmd("kill", &[&pid]))?;
                if !poll(Duration::from_secs(10), Duration::from_millis(200), || {
                    Ok(self.pid().is_none())
                })? {
                    execute(&mut cmd("kill", &["-9", &pid]))?;
                }
            }
            let _ = asked.0.try_wait()?;
        }
        if self.path("run/ssh.sock").exists() {
            let _ = cmd(
                "ssh",
                &[
                    "-F",
                    "/dev/null",
                    "-O",
                    "exit",
                    "-o",
                    &format!("ControlPath=\"{}\"", self.path("run/ssh.sock").display()),
                    "x",
                ],
            )
            .output()?;
        }
        remove(&self.path("run/qemu.pid"))
    }
    fn prepare(&self) -> Result<PathBuf> {
        check_host()?;
        private_dir(&self.dir)?;
        let base = fetch_base(&self.path("images"))?;
        private_dir(&self.path("ssh"))?;
        if !self.path("ssh/id_ed25519").exists() {
            execute(
                cmd(
                    "ssh-keygen",
                    &["-q", "-t", "ed25519", "-N", "", "-C", "fictionet-vm", "-f"],
                )
                .arg(self.path("ssh/id_ed25519")),
            )?;
        }
        let versions = format!(
            "KIND_VERSION={} KUBECTL_VERSION={} HELM_VERSION={} UV_VERSION={}",
            quote(KIND_VERSION),
            quote(KUBECTL_VERSION),
            quote(HELM_VERSION),
            quote(UV_VERSION)
        );
        let mut data =
            format!("{DEBIAN_BUILD}\n{DEBIAN_SHA512}\n{versions}\n{KIND_NODE}\n").into_bytes();
        for path in [
            crate::root().join("vm/guest/provision.sh"),
            crate::root().join("rust-toolchain.toml"),
            self.path("ssh/id_ed25519.pub"),
        ] {
            data.extend(fs::read(path)?);
        }
        let mut hash = ChildGuard(
            cmd("sha256sum", &[])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()?,
        );
        hash.0
            .stdin
            .take()
            .ok_or("missing hash stdin")?
            .write_all(&data)?;
        let mut digest = String::new();
        hash.0
            .stdout
            .take()
            .ok_or("missing hash stdout")?
            .read_to_string(&mut digest)?;
        if !hash.0.wait()?.success() {
            return Err("sha256sum failed".into());
        }
        let prepared = self.path(&format!(
            "images/prepared-{}.qcow2",
            digest.get(..12).ok_or("invalid sha256sum output")?
        ));
        if prepared.exists() {
            return Ok(prepared);
        }
        let start = Instant::now();
        eprintln!("Preparing the VM image (packages, Docker, kind and Rust)");
        let part = prepared.with_extension("part");
        self.remove_prepared("part")?;
        overlay(
            Path::new(base.file_name().ok_or("missing image name")?),
            &part,
            Some("24G"),
        )?;
        let seed = self.path("run/seed");
        private_dir(&seed)?;
        fs::write(
            seed.join("meta-data"),
            "instance-id: fictionet-prepare\nlocal-hostname: fictionet-vm\n",
        )?;
        fs::write(
            seed.join("user-data"),
            format!(
                "#cloud-config\nhostname: fictionet-vm\ndisable_root: false\nssh_pwauth: false\nssh_authorized_keys:\n  - {}\n",
                self.read("ssh/id_ed25519.pub")?
            ),
        )?;
        iso(
            &self.path("run/seed.iso"),
            "cidata",
            &[seed.join("user-data"), seed.join("meta-data")],
        )?;
        remove(&self.path("ssh/known_hosts"))?;
        let result = (|| {
            self.boot(&part, "writeback", Some(&self.path("run/seed.iso")))?;
            self.wait_ssh(300)?;
            execute(&mut self.remote("mkdir -p /root/provision/guest")?)?;
            input(
                &mut self.remote("cat > /root/provision/guest/provision.sh")?,
                &fs::read(crate::root().join("vm/guest/provision.sh"))?,
            )?;
            input(
                &mut self.remote("cat > /root/provision/rust-toolchain.toml")?,
                &fs::read(crate::root().join("rust-toolchain.toml"))?,
            )?;
            logged(
                &mut self.remote(&format!(
                    "{versions} bash /root/provision/guest/provision.sh"
                ))?,
                &self.path("prepare.log"),
            )?;
            if !fs::read_to_string(self.path("prepare.log"))?
                .lines()
                .any(|l| l == "prepared")
            {
                return Err("preparing failed; see .vm/prepare.log".into());
            }
            Ok(())
        })();
        let stopped = self.stop();
        result.and(stopped)?;
        remove(&self.path("run"))?;
        self.remove_prepared("qcow2")?;
        fs::rename(part, &prepared)?;
        remove(&self.path("ssh/known_hosts"))?;
        eprintln!(
            "Prepared the image in {:.1} s",
            start.elapsed().as_secs_f64()
        );
        Ok(prepared)
    }
    fn remove_prepared(&self, extension: &str) -> Result {
        for entry in fs::read_dir(self.path("images"))? {
            let path = entry?.path();
            if path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .starts_with("prepared-")
                && path.extension().is_some_and(|e| e == extension)
            {
                remove(&path)?;
            }
        }
        Ok(())
    }
    fn up(&self) -> Result {
        if self.pid().is_some() {
            eprintln!("Using the running VM");
            return Ok(());
        }
        let prepared = self.prepare()?;
        let start = Instant::now();
        remove(&self.path("run"))?;
        private_dir(&self.path("run"))?;
        let backing =
            Path::new("../images").join(prepared.file_name().ok_or("missing prepared name")?);
        overlay(&backing, &self.path("run/disk.qcow2"), None)?;
        self.boot(&self.path("run/disk.qcow2"), "unsafe", None)?;
        self.wait_ssh(180)?;
        execute(&mut self.remote("set -e; docker ps -aq | xargs -r docker rm -f >/dev/null; kind get clusters | xargs -r -n1 kind delete cluster --name")?)?;
        fs::write(
            self.path("run/boot-seconds"),
            format!("{:.1}", start.elapsed().as_secs_f64()),
        )?;
        eprintln!(
            "The VM is up in {:.1} s: SSH on 127.0.0.1:{}, dashboard on 127.0.0.1:{}",
            start.elapsed().as_secs_f64(),
            self.read("run/ssh-port")?,
            self.read("run/dashboard-port")?
        );
        Ok(())
    }
    fn down(&self) -> Result {
        self.stop()?;
        remove(&self.path("run"))?;
        eprintln!("The VM is down, and its overlay is deleted");
        Ok(())
    }
    pub fn sync(&self) -> Result {
        self.require_running()?;
        let files = cmd(
            "git",
            &[
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
                "--",
                ".",
                ":(exclude)fuzz/corpus",
            ],
        )
        .output()?;
        if !files.status.success() {
            return Err(
                format!("git ls-files failed: {}", crate::process::combined(&files)).into(),
            );
        }
        let mut names = Vec::new();
        for path in files.stdout.split(|b| *b == 0).filter(|p| !p.is_empty()) {
            if crate::root()
                .join(std::ffi::OsStr::from_bytes(path))
                .symlink_metadata()
                .is_ok()
            {
                names.extend(path);
                names.push(0);
            }
        }
        let archive = self.path("source.tar.gz");
        input(
            cmd("tar", &["--null", "-T", "-", "-czf"]).arg(&archive),
            &names,
        )?;
        let result = execute(
            self.remote("rm -rf /src && mkdir /src && tar -xzf - -C /src")?
                .stdin(File::open(&archive)?),
        );
        remove(&archive)?;
        result
    }
    pub fn build(&self, targets: &[String]) -> Result {
        execute(&mut self.remote(&format!(
                "bash /src/vm/guest/build.sh {}",
                targets
                    .iter()
                    .map(|s| quote(s))
                    .collect::<Vec<_>>()
                    .join(" ")
            ))?)
    }
}

pub fn with_vm(action: impl FnOnce(&Vm) -> Result) -> Result {
    let _lock = lock()?;
    let vm = Vm::new();
    let booted = vm.pid().is_none();
    let result = vm.up().and_then(|()| action(&vm));
    if booted && std::env::var("VM_KEEP").as_deref() != Ok("1") {
        let stopped = vm.down();
        result.and(stopped)
    } else {
        if booted {
            eprintln!("The VM is still running (VM_KEEP=1). Stop it with cargo xtask vm down.");
        }
        result
    }
}

fn lock() -> Result<File> {
    let lock = File::open(crate::root().join("xtask/src/vm.rs"))?;
    lock.lock()?;
    Ok(lock)
}

pub fn run(args: &[String]) -> Result {
    match args {
        [] => return tap::run(false),
        [fetch] if fetch == "--fetch" => return tap::run(true),
        [nested] if nested == "nested" => return nested::run(false),
        [nested, fetch] if nested == "nested" && fetch == "--fetch" => return nested::run(true),
        [guest] if guest == "nested-guest" => return nested::guest(),
        [test, name] if test == "test" => {
            return with_vm(|vm| {
                vm.sync()?;
                logged(
                    &mut vm.remote(&format!(
                        "KIND_NODE_IMAGE={} bash /src/vm/guest/test.sh {}",
                        quote(KIND_NODE),
                        quote(name)
                    ))?,
                    &vm.path(&format!("test-{name}.log")),
                )
            });
        }
        [help] if matches!(help.as_str(), "--help" | "-h") => {
            println!(
                "cargo xtask vm [--fetch | nested [--fetch] | prepare | up | down | clean | status | sync | build [sdk|border|fakewiki|adaptive-web] | test <name> | ssh [command]]"
            );
            return Ok(());
        }
        _ => {}
    }
    let (command, rest) = args.split_first().ok_or("missing VM command")?;
    if !matches!(
        command.as_str(),
        "up" | "down" | "clean" | "prepare" | "sync" | "status" | "build" | "ssh"
    ) || (!rest.is_empty() && !matches!(command.as_str(), "build" | "ssh"))
    {
        return Err("invalid VM arguments; use cargo xtask vm --help".into());
    }
    let _lock = if matches!(command.as_str(), "status" | "ssh") {
        None
    } else {
        Some(lock()?)
    };
    let vm = Vm::new();
    match command.as_str() {
        "up" => vm.up(),
        "down" => vm.down(),
        "clean" => {
            vm.down()?;
            remove(&vm.dir)
        }
        "prepare" => {
            if vm.pid().is_some() {
                return Err("stop the VM before preparing its image".into());
            }
            vm.prepare().map(|_| ())
        }
        "sync" => vm.sync(),
        "build" => {
            vm.sync()?;
            vm.build(rest)
        }
        "ssh" => {
            vm.require_running()?;
            let mut ssh = vm.ssh()?;
            if rest.is_empty()
                || (std::io::stdin().is_terminal() && std::io::stdout().is_terminal())
            {
                ssh.arg("-t");
            }
            ssh.arg("root@127.0.0.1");
            if !rest.is_empty() {
                ssh.arg(rest.join(" "));
            }
            execute(&mut ssh)
        }
        "status" => {
            if let Some(pid) = vm.pid() {
                println!(
                    "running: pid {pid}, SSH on 127.0.0.1:{}, dashboard on 127.0.0.1:{}",
                    vm.read("run/ssh-port")?,
                    vm.read("run/dashboard-port")?
                );
            } else {
                println!("not running");
            }
            if vm.dir.exists() {
                execute(cmd("du", &["-sh", "--apparent-size"]).arg(&vm.dir))?;
                execute(cmd("du", &["-sh"]).arg(&vm.dir))?;
            }
            Ok(())
        }
        _ => unreachable!(),
    }
}
