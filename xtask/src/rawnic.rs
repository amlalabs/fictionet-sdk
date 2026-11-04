//! Isolated QEMU transport validation.
use crate::Result;
use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Guest(Child);
impl Drop for Guest {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn output(command: &mut Command) -> Result<Vec<u8>> {
    let result = command.output()?;
    if !result.status.success() {
        return Err(format!(
            "command failed: {command:?}: {}",
            String::from_utf8_lossy(&result.stderr)
        )
        .into());
    }
    Ok(result.stdout)
}

fn entry(archive: &mut Vec<u8>, name: &str, mode: u32, bytes: &[u8]) {
    node(archive, name, mode, bytes, (0, 0));
}

fn node(archive: &mut Vec<u8>, name: &str, mode: u32, bytes: &[u8], device: (u32, u32)) {
    let header = format!(
        "070701{:08x}{mode:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}",
        0,
        0,
        0,
        1,
        0,
        bytes.len(),
        0,
        0,
        device.0,
        device.1,
        name.len() + 1,
        0
    );
    archive.extend(header.as_bytes());
    archive.extend(name.as_bytes());
    archive.push(0);
    while !archive.len().is_multiple_of(4) {
        archive.push(0);
    }
    archive.extend(bytes);
    while !archive.len().is_multiple_of(4) {
        archive.push(0);
    }
}

fn executable(archive: &mut Vec<u8>, source: &Path, destination: &str) -> Result {
    entry(archive, destination, 0o100755, &fs::read(source)?);
    let deps = output(Command::new("ldd").arg(source))?;
    for word in String::from_utf8(deps)?
        .split_whitespace()
        .filter(|word| word.starts_with('/'))
    {
        let path = Path::new(word);
        entry(
            archive,
            word.trim_start_matches('/'),
            0o100755,
            &fs::read(path)?,
        );
    }
    Ok(())
}

#[path = "rawnic_frames.rs"]
mod frames;

pub fn run(directory: PathBuf) -> Result {
    fs::create_dir_all(&directory)?;
    let directory = fs::canonicalize(directory)?;
    output(Command::new("cargo").args([
        "build",
        "-p",
        "xtask",
        "--features",
        "rawnic",
        "--bin",
        "rawnic-guest",
    ]))?;
    let metadata: serde_json::Value =
        serde_json::from_slice(&output(Command::new("cargo").args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
        ]))?)?;
    let target = PathBuf::from(
        metadata["target_directory"]
            .as_str()
            .ok_or("missing cargo target directory")?,
    );
    let mut test_binaries = Vec::new();
    for (package, features) in [
        ("fictionet-host", "virtio-net"),
        ("honeypot-world", "raw-virtio"),
    ] {
        let test_build = output(Command::new("cargo").args([
            "test",
            "-p",
            package,
            "--no-default-features",
            "--features",
            features,
            "--lib",
            "--tests",
            "--no-run",
            "--message-format=json",
        ]))?;
        for value in String::from_utf8(test_build)?
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        {
            if value["profile"]["test"].as_bool() == Some(true)
                && let Some(path) = value["executable"].as_str()
            {
                test_binaries.push(PathBuf::from(path));
            }
        }
    }
    if test_binaries.is_empty() {
        return Err("cargo did not produce guest test binaries".into());
    }
    let mut archive = Vec::new();
    for dir in [
        "dev", "proc", "sys", "lib", "lib64", "usr", "usr/lib", "modules", "tests",
    ] {
        entry(&mut archive, dir, 0o40755, &[]);
    }
    node(&mut archive, "dev/console", 0o020600, &[], (5, 1));
    executable(&mut archive, &target.join("debug/rawnic-guest"), "init")?;
    for (index, binary) in test_binaries.iter().enumerate() {
        executable(&mut archive, binary, &format!("tests/{index}"))?;
    }
    let mut modules = Vec::new();
    for module in ["vfio-pci", "vfio_iommu_type1"] {
        let dependencies = output(Command::new("modprobe").args(["--show-depends", module]))?;
        for line in String::from_utf8(dependencies)?.lines() {
            let path = line
                .strip_prefix("insmod ")
                .ok_or("unexpected module dependency")?
                .split_whitespace()
                .next()
                .ok_or("missing module path")?;
            if !modules.contains(&path.to_owned()) {
                modules.push(path.to_owned());
            }
        }
    }
    for (index, module) in modules.iter().enumerate() {
        let bytes = if module.ends_with(".zst") {
            output(Command::new("zstd").args(["-dc", module]))?
        } else {
            fs::read(module)?
        };
        entry(&mut archive, &format!("modules/{index}"), 0o100644, &bytes);
    }
    entry(&mut archive, "TRAILER!!!", 0, &[]);
    let initrd = directory.join("guest.cpio");
    fs::write(&initrd, archive)?;
    let listener = TcpListener::bind("127.0.0.1:0")?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let log = directory.join("serial.log");
    fs::write(&log, [])?;
    let mut command = Command::new("qemu-system-x86_64");
    command.args([
        "-machine",
        "q35,accel=tcg",
        "-cpu",
        "max",
        "-m",
        "2G",
        "-smp",
        "2",
        "-display",
        "none",
        "-no-reboot",
        "-monitor",
        "none",
        "-serial",
    ]);
    command.arg(format!("file:{}", log.display()));
    command.args(["-smbios", "type=1,manufacturer=QEMU"]);
    command
        .args(["-kernel", "/boot/vmlinuz-linux", "-initrd"])
        .arg(initrd);
    command.args([
        "-append",
        "console=ttyS0 panic=-1 intel_iommu=on iommu.strict=1 fictionet.rawnic=1 rdinit=/init",
        "-device",
        "intel-iommu,intremap=on,caching-mode=on",
        "-netdev",
    ]);
    command.arg(format!("socket,id=frames,connect={address}"));
    command.args([
        "-device", "virtio-net-pci,netdev=frames,disable-legacy=on,iommu_platform=on,addr=03.0,mac=52:54:00:12:34:56",
        "-nic", "none",
    ]);
    let mut child = Guest(
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?,
    );

    let result = (|| -> Result {
        let deadline = Instant::now() + Duration::from_secs(120);
        let mut stream: TcpStream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error.into()),
            }
            if child.0.try_wait()?.is_some() || Instant::now() > deadline {
                return Err("QEMU did not connect its frame socket".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        stream.set_nodelay(true)?;
        loop {
            if fs::read_to_string(&log)?.contains("RAWNIC READY") {
                break;
            }
            if child.0.try_wait()?.is_some() || Instant::now() > deadline {
                return Err("guest did not initialize VFIO; inspect serial.log".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        for (index, frame) in frames::fixtures().into_iter().enumerate() {
            stream.write_all(&(frame.len() as u32).to_be_bytes())?;
            stream.write_all(&frame)?;
            let mut size = [0; 4];
            stream.read_exact(&mut size)?;
            let size = u32::from_be_bytes(size) as usize;
            if size > 65536 {
                return Err("invalid QEMU frame length".into());
            }
            let mut echoed = vec![0; size];
            stream.read_exact(&mut echoed)?;
            if echoed != frame {
                return Err("guest frame differs from byte-exact input".into());
            }
            println!(
                "Frame {}: {} bytes preserved through guest world",
                index + 1,
                frame.len()
            );
        }
        stream.write_all(&60u32.to_be_bytes())?;
        let mut acknowledgment = [0x5a; 60];
        acknowledgment[..6].copy_from_slice(&[0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        stream.write_all(&acknowledgment)?;
        loop {
            if fs::read_to_string(&log)?.contains("HONEYPOT READY") {
                break;
            }
            if child.0.try_wait()?.is_some() || Instant::now() > deadline {
                return Err("guest did not start honeypot; inspect serial.log".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        for (index, frame) in frames::fixtures().into_iter().enumerate() {
            stream.write_all(&(frame.len() as u32).to_be_bytes())?;
            stream.write_all(&frame)?;
            if index == 0 {
                let mut size = [0; 4];
                stream.read_exact(&mut size)?;
                let size = u32::from_be_bytes(size) as usize;
                if !(54..=2036).contains(&size) {
                    return Err("invalid honeypot response length".into());
                }
                let mut answer = vec![0; size];
                stream.read_exact(&mut answer)?;
                use fictionet::stdlib::network::{ip, tcp};
                let header = ip::Header::parse_whole(&answer[14..])
                    .ok_or("honeypot response is not valid IP")?;
                let segment = header.payload(&answer[14..]);
                if answer[..6] != frame[6..12]
                    || answer[6..12] != frame[..6]
                    || answer[12..14] != [8, 0]
                    || header.protocol != 6
                    || segment.len() < 20
                    || segment[13] != 0x12
                    || segment[..4] != [0, 80, 0x12, 0x34]
                    || segment[8..12] != 1u32.to_be_bytes()
                    || ip::transport_checksum(header.src, header.dst, header.protocol, segment) != 0
                    || !tcp::options(segment)?.iter().any(|option| {
                        matches!(option,
                        tcp::TcpOption::Unknown { kind: 30, data }
                            if data.len() == 10 && data[..2] == [1, 1])
                    })
                {
                    return Err("honeypot did not return an MPTCP SYN-ACK".into());
                }
                println!("Honeypot answered raw MPTCP SYN with a valid Ethernet SYN-ACK");
            }
        }
        stream.write_all(&60u32.to_be_bytes())?;
        stream.write_all(&acknowledgment)?;
        loop {
            if let Some(status) = child.0.try_wait()? {
                if !status.success() || !fs::read_to_string(&log)?.contains("RAWNIC PASS") {
                    return Err("guest validation failed; inspect serial.log".into());
                }
                break;
            }
            if Instant::now() > deadline {
                return Err("guest validation timed out".into());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    })();
    println!("QEMU serial log: {}", log.display());
    result
}
