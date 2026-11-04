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

pub fn fixtures() -> Vec<Vec<u8>> {
    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = bytes
            .chunks(2)
            .map(|chunk| u16::from_be_bytes([chunk[0], *chunk.get(1).unwrap_or(&0)]) as u32)
            .sum::<u32>();
        while sum > 65535 {
            sum = (sum & 65535) + (sum >> 16);
        }
        !(sum as u16)
    }
    fn tcp(options: &[u8], flags: u8) -> Vec<u8> {
        let mut frame = vec![0u8; 54 + options.len()];
        frame[..6].copy_from_slice(&[0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        frame[6..12].copy_from_slice(&[0x52, 0x54, 0, 0xab, 0xcd, 0xef]);
        frame[12..14].copy_from_slice(&[8, 0]);
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&((40 + options.len()) as u16).to_be_bytes());
        frame[22] = 64;
        frame[23] = 6;
        frame[26..30].copy_from_slice(&[192, 0, 2, 1]);
        frame[30..34].copy_from_slice(&[192, 0, 2, 2]);
        frame[34..38].copy_from_slice(&[0x12, 0x34, 0, 80]);
        frame[46] = ((20 + options.len()) / 4) as u8 * 16;
        frame[47] = flags;
        frame[48..50].copy_from_slice(&4096u16.to_be_bytes());
        frame[54..].copy_from_slice(options);
        let ip_checksum = checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
        let mut pseudo = frame[26..34].to_vec();
        pseudo.extend([0, 6]);
        pseudo.extend(((20 + options.len()) as u16).to_be_bytes());
        pseudo.extend(&frame[34..]);
        frame[50..52].copy_from_slice(&checksum(&pseudo).to_be_bytes());
        frame.resize(frame.len().max(60), 0);
        frame
    }
    let capable = tcp(&[30, 4, 1, 1], 2);
    let dss = tcp(&[30, 8, 0x20, 1, 0x12, 0x34, 0x56, 0x78], 16);
    let mut vlan = capable.clone();
    vlan.splice(12..12, [0x81, 0, 0, 42]);
    let mut malformed = capable.clone();
    malformed[14] = 0x4f;
    malformed[24] ^= 0xff;
    malformed[50] ^= 0xff;
    let unknown = vec![0xff; 61];
    let mut maximum = vec![0xa5; 1514];
    maximum[..6].copy_from_slice(&capable[..6]);
    maximum[12..14].copy_from_slice(&[0x88, 0xb5]);
    vec![capable, dss, vlan, malformed, unknown, maximum]
}

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
    let test_build = output(Command::new("cargo").args([
        "test",
        "-p",
        "fictionet-host",
        "--no-default-features",
        "--features",
        "virtio-net",
        "--lib",
        "--no-run",
        "--message-format=json",
    ]))?;
    let test_binary = String::from_utf8(test_build)?
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .find_map(|value| {
            (value["profile"]["test"].as_bool() == Some(true))
                .then(|| value["executable"].as_str().map(PathBuf::from))
                .flatten()
        })
        .ok_or("cargo did not produce guest unit test binary")?;
    let mut archive = Vec::new();
    for dir in [
        "dev", "proc", "sys", "lib", "lib64", "usr", "usr/lib", "modules",
    ] {
        entry(&mut archive, dir, 0o40755, &[]);
    }
    node(&mut archive, "dev/console", 0o020600, &[], (5, 1));
    executable(&mut archive, &target.join("debug/rawnic-guest"), "init")?;
    executable(&mut archive, &test_binary, "driver-tests")?;
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
        "1G",
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
        for (index, frame) in fixtures().into_iter().enumerate() {
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
