//! Ubuntu comparison over QEMU userspace Ethernet links.

use crate::Result;
use fictionet::relay::{self, Hello, Message, unix};
use fictionet::stdlib::network::ethernet::frame::{self, Frame};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const IMAGE: &str = "noble-server-cloudimg-amd64.img";
const SOURCE: &str = "https://cloud-images.ubuntu.com/noble/current";
const SERVER_MAC: [u8; 6] = [0x52, 0x54, 0, 0x20, 0, 0x10];
const CLIENT_MAC: [u8; 6] = [0x52, 0x54, 0, 0x20, 0, 0x11];

struct Process(Child);

fn own_child(command: &mut Command) {
    let parent = std::process::id() as libc::pid_t;
    // SAFETY: these child operations allocate nothing and are async-signal-safe.
    unsafe {
        command.pre_exec(move || {
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent {
                libc::_exit(1);
            }
            Ok(())
        });
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn checked(command: &mut Command) -> Result<Vec<u8>> {
    let output = command.output()?;
    if !output.status.success() {
        return Err(format!("{command:?}: {}", String::from_utf8_lossy(&output.stderr)).into());
    }
    Ok(output.stdout)
}

pub async fn run(args: &[String]) -> Result {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("missing workspace")?
        .join("target/honeypot-diff");
    fs::create_dir_all(root.join("share"))?;
    let root = root.canonicalize()?;
    match args.first().map(String::as_str) {
        Some("prepare") if args.len() == 1 => prepare(&root).await,
        Some("run") if (2..=3).contains(&args.len()) => {
            let label = &args[1];
            if label.is_empty()
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err("run name must contain only letters, digits and hyphens".into());
            }
            let binary = args
                .get(2)
                .map(PathBuf::from)
                .unwrap_or_else(|| root.parent().unwrap().join("debug/honeypot"));
            compare(&root, label, &binary.canonicalize()?)
        }
        _ => Err("usage: cargo xtask honeypot-diff prepare | run NAME [HONEYPOT_BINARY]".into()),
    }
}

async fn download(root: &Path) -> Result {
    let client = reqwest::Client::new();
    let sums = client
        .get(format!("{SOURCE}/SHA256SUMS"))
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    let hash = sums
        .lines()
        .find_map(|line| {
            let (hash, name) = line.split_once(char::is_whitespace)?;
            (name.trim().trim_start_matches('*') == IMAGE).then_some(hash)
        })
        .ok_or("Ubuntu image checksum missing")?;
    if !root.join(IMAGE).exists() {
        println!("Downloading official Ubuntu image into {}", root.display());
        let mut response = client
            .get(format!("{SOURCE}/{IMAGE}"))
            .send()
            .await?
            .error_for_status()?;
        let partial = root.join("ubuntu.partial");
        let mut file = File::create(&partial)?;
        while let Some(chunk) = response.chunk().await? {
            file.write_all(&chunk)?;
        }
        fs::rename(partial, root.join(IMAGE))?;
    }
    let actual = checked(Command::new("sha256sum").arg(root.join(IMAGE)))?;
    if !String::from_utf8(actual)?.starts_with(&format!("{hash} ")) {
        return Err("Ubuntu checksum differs; remove the cached image and prepare again".into());
    }
    fs::write(root.join("SHA256SUMS"), sums)?;
    Ok(())
}

fn overlay(base: &Path, disk: &Path) -> Result {
    checked(
        Command::new("qemu-img")
            .args(["create", "-f", "qcow2", "-F", "qcow2", "-b"])
            .arg(base)
            .arg(disk),
    )?;
    checked(Command::new("qemu-img").arg("resize").arg(disk).arg("16G"))?;
    Ok(())
}

fn seed(
    root: &Path,
    name: &str,
    probe: bool,
    comparison: bool,
    commands: Vec<Vec<String>>,
) -> Result<PathBuf> {
    let directory = root.join(format!("seed-{name}"));
    fs::create_dir_all(&directory)?;
    let data = serde_json::json!({
        "hostname": if probe { "comparison-probe" } else { "ubuntu-reference" },
        "manage_etc_hosts": true,
        "runcmd": commands
    });
    fs::write(
        directory.join("user-data"),
        format!("#cloud-config\n{}\n", serde_json::to_string_pretty(&data)?),
    )?;
    fs::write(
        directory.join("meta-data"),
        format!("instance-id: {name}\n"),
    )?;
    let mut interfaces = serde_json::json!({
        "wan": {"match": {"macaddress": "52:54:00:10:00:01"}, "set-name": "wan", "dhcp4": true},
        "reference": {"match": {"macaddress": if probe {"52:54:00:10:00:11"} else {"52:54:00:10:00:10"}},
            "set-name": "reference", "addresses": [if probe {"192.0.2.1/24"} else {"192.0.2.10/24"}], "optional": true}
    });
    if !comparison {
        interfaces.as_object_mut().unwrap().remove("reference");
    }
    if probe && comparison {
        interfaces["imitation"] = serde_json::json!({"match": {"macaddress": "52:54:00:20:00:11"},
            "set-name": "imitation", "addresses": ["198.51.100.1/24"], "optional": true});
    }
    fs::write(
        directory.join("network-config"),
        serde_json::to_vec_pretty(&serde_json::json!({"version": 2, "ethernets": interfaces}))?,
    )?;
    let iso = root.join(format!("seed-{name}.iso"));
    checked(
        Command::new("genisoimage")
            .args(["-quiet", "-output"])
            .arg(&iso)
            .args(["-volid", "cidata", "-joliet", "-rock"])
            .arg(directory.join("user-data"))
            .arg(directory.join("meta-data"))
            .arg(directory.join("network-config")),
    )?;
    Ok(iso)
}

fn command(words: &[&str]) -> Vec<String> {
    words.iter().map(|s| (*s).to_owned()).collect()
}

fn mount_commands() -> Vec<Vec<String>> {
    vec![
        command(&["mkdir", "-p", "/mnt/comparison"]),
        command(&[
            "mount",
            "-t",
            "9p",
            "-o",
            "trans=virtio,version=9p2000.L",
            "comparison",
            "/mnt/comparison",
        ]),
    ]
}

fn launch(
    root: &Path,
    disk: &Path,
    seed: &Path,
    log: &Path,
    networks: &[(&str, String, &str)],
) -> Result<Process> {
    let file = File::create(log)?;
    let mut cmd = Command::new("qemu-system-x86_64");
    own_child(&mut cmd);
    // The caller runs cargo xtask in its MemoryMax systemd scope; children
    // inherit it. No guest NIC is backed by a host network device.
    cmd.args([
        "-enable-kvm",
        "-cpu",
        "host",
        "-smp",
        "2",
        "-m",
        "2048",
        "-display",
        "none",
        "-no-reboot",
        "-monitor",
        "none",
        "-serial",
        "stdio",
        "-smbios",
        "type=1,manufacturer=QEMU",
    ])
    .arg("-drive")
    .arg(format!("file={},if=virtio,format=qcow2", disk.display()))
    .arg("-drive")
    .arg(format!("file={},media=cdrom,format=raw", seed.display()))
    .arg("-virtfs")
    .arg(format!(
        "local,path={},mount_tag=comparison,security_model=none",
        root.join("share").display()
    ))
    .args([
        "-netdev",
        "user,id=wan",
        "-device",
        "virtio-net-pci,netdev=wan,mac=52:54:00:10:00:01",
    ]);
    for (id, backend, mac) in networks {
        cmd.arg("-netdev")
            .arg(format!("{backend},id={id}"))
            .arg("-device")
            .arg(format!("virtio-net-pci,netdev={id},mac={mac}"));
    }
    Ok(Process(
        cmd.stdin(Stdio::null())
            .stdout(file.try_clone()?)
            .stderr(file)
            .spawn()?,
    ))
}

fn finish(guest: &mut Process, timeout: Duration) -> Result {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = guest.0.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(format!("QEMU exited: {status}").into())
            };
        }
        if Instant::now() >= deadline {
            return Err("guest deadline expired; inspect its serial log".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

async fn prepare(root: &Path) -> Result {
    download(root).await?;
    for (name, probe) in [("ubuntu", false), ("probe", true)] {
        let disk = root.join(format!("{name}.qcow2"));
        let ready = root.join("share").join(format!("{name}-prepared"));
        if disk.exists() && ready.exists() {
            continue;
        }
        if disk.exists() {
            fs::remove_file(&disk)?;
        }
        if ready.exists() {
            fs::remove_file(&ready)?;
        }
        overlay(&root.join(IMAGE), &disk)?;
        let mut commands = mount_commands();
        commands.push(command(&["sh", "-ec", &format!(
            "export DEBIAN_FRONTEND=noninteractive; apt-get update; apt-get -y dist-upgrade; apt-get install -y linux-generic openssh-server nginx nmap curl; printf '1\\n' > /proc/sys/net/mptcp/enabled; dpkg-query -W linux-generic openssh-server nginx nmap > /mnt/comparison/{name}-packages.txt; touch /mnt/comparison/{name}-prepared"
        )]));
        commands.push(command(&["poweroff"]));
        let iso = seed(root, &format!("prepare-{name}"), probe, false, commands)?;
        let log = root.join(format!("{name}-prepare.log"));
        println!("Updating {name} guest; progress: {}", log.display());
        let mut guest = launch(root, &disk, &iso, &log, &[])?;
        finish(&mut guest, Duration::from_secs(1800))?;
        if !ready.exists() {
            return Err(format!("{name} provisioning failed; inspect {}", log.display()).into());
        }
    }
    Ok(())
}

fn guest_executable(root: &Path) -> Result {
    let source = std::env::current_exe()?;
    let share = root.join("share");
    checked(
        Command::new("objcopy")
            .arg("--strip-debug")
            .arg(&source)
            .arg(share.join("xtask")),
    )?;
    let libraries = share.join("lib");
    fs::create_dir_all(&libraries)?;
    let deps = String::from_utf8(checked(Command::new("ldd").arg(&source))?)?;
    for word in deps.split_whitespace().filter(|s| s.starts_with('/')) {
        let path = Path::new(word);
        fs::copy(
            path,
            libraries.join(path.file_name().ok_or("library filename missing")?),
        )?;
    }
    Ok(())
}

fn compare(root: &Path, label: &str, binary: &Path) -> Result {
    for name in ["ubuntu", "probe"] {
        if !root.join("share").join(format!("{name}-prepared")).exists() {
            return Err("run cargo xtask honeypot-diff prepare first".into());
        }
    }
    guest_executable(root)?;
    let result = root.join("share").join(label);
    fs::create_dir(&result)?;
    let guest_result = format!("/mnt/comparison/{label}");
    let socket = root.join("world.sock");
    let log = File::create(result.join("honeypot-stdout.log"))?;
    let mut server_command = Command::new(binary);
    own_child(&mut server_command);
    let mut honeypot = Process(
        server_command
            .args([
                "--world",
                &format!("unix:{}", socket.display()),
                "--address",
                "198.51.100.10",
                "--log",
            ])
            .arg(result.join("honeypot.jsonl"))
            .arg("--pcap")
            .arg(result.join("honeypot.pcapng"))
            .stdout(log.try_clone()?)
            .stderr(log)
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    let world = loop {
        if let Ok(fd) = unix::connect(&socket) {
            break fd;
        }
        if honeypot.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err("honeypot did not listen".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    unix::set_timeout(
        world.as_raw_fd(),
        libc::SO_RCVTIMEO,
        Some(relay::HANDSHAKE_TIMEOUT),
    )?;
    unix::set_timeout(
        world.as_raw_fd(),
        libc::SO_SNDTIMEO,
        Some(relay::HANDSHAKE_TIMEOUT),
    )?;
    unix::send(
        world.as_raw_fd(),
        &Message::Hello(Hello {
            version: relay::VERSION,
            mtu: 1500,
            kind: "qemu".into(),
            name: "internet".into(),
        })
        .encode(),
        false,
    )?;
    let mut buffer = [0; 65536];
    let n = unix::recv(world.as_raw_fd(), &mut buffer, false)?;
    if relay::decode(&buffer[..n])? != Message::Accept {
        return Err("honeypot refused comparison attachment".into());
    }
    let link = TcpListener::bind("127.0.0.1:0")?;
    let reference_port = TcpListener::bind("127.0.0.1:0")?;
    let reference_address = reference_port.local_addr()?;
    drop(reference_port);
    let mut commands = mount_commands();
    commands.push(command(&["mkdir", "-p", "/run/sshd"]));
    commands.push(command(&[
        "sh",
        "-ec",
        &format!("cat /boot/config-$(uname -r) > {guest_result}/ubuntu-kernel-config.txt; ss -ltnp > {guest_result}/listeners.txt; systemctl cat ssh.socket > {guest_result}/ssh-socket.txt"),
    ]));
    commands.push(command(&["sh", "-ec", &format!(
        "uname -r > {guest_result}/ubuntu-kernel.txt; case $(uname -r) in 6.8.*) ;; *) exit 1;; esac; printf '1\\n' > /proc/sys/net/mptcp/enabled; cat /proc/sys/net/mptcp/enabled > {guest_result}/mptcp-enabled.txt; /usr/sbin/sshd -T > {guest_result}/sshd-config.txt; nginx -T > {guest_result}/nginx-config.txt 2>&1; dpkg-query -W linux-generic openssh-server nginx > {guest_result}/ubuntu-packages.txt; touch {guest_result}/ubuntu-ready"
    )]));
    let iso = seed(root, &format!("{label}-ubuntu"), false, true, commands)?;
    let disk = root.join(format!("{label}-ubuntu.qcow2"));
    overlay(&root.join("ubuntu.qcow2"), &disk)?;
    let mut ubuntu = launch(
        root,
        &disk,
        &iso,
        &result.join("ubuntu-serial.log"),
        &[(
            "reference",
            format!("socket,listen={reference_address}"),
            "52:54:00:10:00:10",
        )],
    )?;
    let deadline = Instant::now() + Duration::from_secs(180);
    while !result.join("ubuntu-ready").exists() {
        if ubuntu.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err("Ubuntu did not become ready; inspect ubuntu-serial.log".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let mut commands = mount_commands();
    commands.push(command(&["touch", "/run/fictionet-comparison-guest"]));
    commands.push(command(&["sh", "-c", &format!(
        "/mnt/comparison/lib/ld-linux-x86-64.so.2 --library-path /mnt/comparison/lib /mnt/comparison/xtask honeypot-probe {guest_result} > {guest_result}/probe.log 2>&1; echo $? > {guest_result}/probe-status; poweroff"
    )]));
    let iso = seed(root, &format!("{label}-probe"), true, true, commands)?;
    let disk = root.join(format!("{label}-probe.qcow2"));
    overlay(&root.join("probe.qcow2"), &disk)?;
    let mut probe = launch(
        root,
        &disk,
        &iso,
        &result.join("probe-serial.log"),
        &[
            (
                "reference",
                format!("socket,connect={reference_address}"),
                "52:54:00:10:00:11",
            ),
            (
                "imitation",
                format!("socket,connect={}", link.local_addr()?),
                "52:54:00:20:00:11",
            ),
        ],
    )?;
    link.set_nonblocking(true)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let stream = loop {
        match link.accept() {
            Ok((stream, _)) => break stream,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        if probe.0.try_wait()?.is_some() || Instant::now() >= deadline {
            return Err("probe Ethernet did not connect".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    println!("Guest probes running; results: {}", result.display());
    let deadline = Instant::now() + Duration::from_secs(600);
    forward(&mut probe, stream, world.as_raw_fd(), deadline)?;
    if fs::read_to_string(result.join("probe-status"))?.trim() != "0" {
        return Err("guest probes failed; inspect probe.log".into());
    }
    println!("Comparison complete: {}", result.display());
    Ok(())
}

fn send_frame(stream: &mut TcpStream, bytes: &[u8]) -> Result {
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}

fn forward(
    probe: &mut Process,
    mut stream: TcpStream,
    world: std::os::fd::RawFd,
    deadline: Instant,
) -> Result {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let mut buffer = [0; 65536];
    loop {
        if probe.0.try_wait()?.is_some() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("probe guest deadline expired".into());
        }
        let mut fds = [
            libc::pollfd {
                fd: stream.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: world,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: both descriptors are owned for this loop and fds is writable.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), 2, 100) };
        if ready < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        if fds[1].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0 {
            return Err("honeypot attachment disconnected".into());
        }
        if fds[0].revents & libc::POLLIN != 0 {
            let mut length = [0; 4];
            if let Err(error) = stream.read_exact(&mut length) {
                if error.kind() == std::io::ErrorKind::UnexpectedEof {
                    return finish(probe, Duration::from_secs(30));
                }
                return Err(error.into());
            }
            let length = u32::from_be_bytes(length) as usize;
            if !(14..=buffer.len()).contains(&length) {
                return Err("invalid QEMU frame length".into());
            }
            stream.read_exact(&mut buffer[..length])?;
            let Some(frame) = Frame::parse(&buffer[..length]) else {
                continue;
            };
            if frame.ethertype == frame::IPV4 {
                unix::send(world, &Message::Packet(frame.payload).encode(), false)?;
            } else if frame.ethertype == frame::ARP
                && frame.payload.len() >= 28
                && frame.payload[6..8] == [0, 1]
                && frame.payload[24..28] == [198, 51, 100, 10]
            {
                let mut arp = frame.payload[..28].to_vec();
                arp[6..8].copy_from_slice(&2u16.to_be_bytes());
                arp[18..24].copy_from_slice(&frame.payload[8..14]);
                arp[24..28].copy_from_slice(&frame.payload[14..18]);
                arp[8..14].copy_from_slice(&SERVER_MAC);
                arp[14..18].copy_from_slice(&[198, 51, 100, 10]);
                send_frame(
                    &mut stream,
                    &frame::frame(frame.src, SERVER_MAC, frame::ARP, &arp),
                )?;
            }
        }
        if fds[1].revents & libc::POLLIN != 0 {
            let n = unix::recv(world, &mut buffer, false)?;
            if n == 0 {
                return Err("honeypot attachment closed".into());
            }
            if let Message::Packet(packet) = relay::decode(&buffer[..n])? {
                send_frame(
                    &mut stream,
                    &frame::frame(CLIENT_MAC, SERVER_MAC, frame::IPV4, packet),
                )?;
            }
        }
    }
}
