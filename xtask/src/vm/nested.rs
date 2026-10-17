use super::*;
use crate::process::{Checks, Cleanup};
use serde_json::Value;

const FC_VERSION: &str = "v1.17.0";
const CH_VERSION: &str = "v53.0";
const KERNEL: &str = "vmlinux-6.1.155";

fn l1() -> PathBuf {
    tap::directory().join(format!("prepared-l1-{DEBIAN_BUILD}.qcow2"))
}
fn assets() -> PathBuf {
    tap::directory().join("assets/iso")
}
fn l2() -> PathBuf {
    assets().join(format!("l2-root-{DEBIAN_BUILD}.qcow2"))
}

fn fetch() -> Result {
    tap::fetch_guest()?;
    tap::prepare_image(
        &tap::prepared(),
        &l1(),
        "qemu-system-x86, qemu-utils",
        "16G",
    )?;
    private_dir(&assets())?;
    let archive = tap::directory().join(format!("assets/firecracker-{FC_VERSION}-x86_64.tgz"));
    download(
        &format!(
            "https://github.com/firecracker-microvm/firecracker/releases/download/{FC_VERSION}/firecracker-{FC_VERSION}-x86_64.tgz"
        ),
        &archive,
        "sha256sum",
        "06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558",
    )?;
    let fc = format!("firecracker-{FC_VERSION}-x86_64");
    if !assets().join(&fc).exists() {
        execute(
            cmd("tar", &["xzf"])
                .arg(&archive)
                .arg("-C")
                .arg(assets())
                .args([
                    "--strip-components=1",
                    &format!("release-{FC_VERSION}-x86_64/{fc}"),
                ]),
        )?;
    }
    let ch = assets().join(format!("cloud-hypervisor-static-{CH_VERSION}"));
    download(
        &format!(
            "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/{CH_VERSION}/cloud-hypervisor-static"
        ),
        &ch,
        "sha256sum",
        "448af3d4e59b22c2987f7df94c213ad40fb53a10d437e42b5ee6c4fce7c29ecc",
    )?;
    fs::set_permissions(ch, fs::Permissions::from_mode(0o755))?;
    download(
        &format!("https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/{KERNEL}"),
        &assets().join(KERNEL),
        "sha256sum",
        "e20e46d0c36c55c0d1014eb20576171b3f3d922260d9f792017aeff53af3d4f2",
    )?;
    if !l2().exists() {
        let raw = tap::directory().join("full.raw");
        let root = tap::directory().join("root.raw");
        execute(
            cmd("qemu-img", &["convert", "-O", "raw"])
                .arg(tap::prepared())
                .arg(&raw),
        )?;
        let table: Value = serde_json::from_str(&capture(cmd("sfdisk", &["-J"]).arg(&raw))?)?;
        let partition = table["partitiontable"]["partitions"]
            .as_array()
            .ok_or("missing partition table")?
            .iter()
            .max_by_key(|p| p["size"].as_u64())
            .ok_or("no partitions")?;
        let start = partition["start"]
            .as_u64()
            .ok_or("invalid partition start")?;
        let size = partition["size"].as_u64().ok_or("invalid partition size")?;
        execute(&mut cmd(
            "dd",
            &[
                &format!("if={}", raw.display()),
                &format!("of={}", root.display()),
                "bs=512",
                &format!("skip={start}"),
                &format!("count={size}"),
                "conv=sparse",
                "status=none",
            ],
        ))?;
        let part = l2().with_extension("part");
        execute(
            cmd("qemu-img", &["convert", "-O", "qcow2"])
                .arg(&root)
                .arg(&part),
        )?;
        fs::rename(part, l2())?;
        remove(&raw)?;
        remove(&root)?;
    }
    Ok(())
}

pub fn run(fetch_images: bool) -> Result {
    let _lock = lock()?;
    check_host()?;
    let nested = [
        "/sys/module/kvm_amd/parameters/nested",
        "/sys/module/kvm_intel/parameters/nested",
    ]
    .iter()
    .any(|p| fs::read_to_string(p).is_ok_and(|s| matches!(s.trim(), "1" | "Y")));
    if !nested {
        return Err("nested virtualization is off (kvm_amd or kvm_intel nested=1)".into());
    }
    if fetch_images {
        fetch()?;
    }
    let fc = assets().join(format!("firecracker-{FC_VERSION}-x86_64"));
    let ch = assets().join(format!("cloud-hypervisor-static-{CH_VERSION}"));
    for path in [l1(), assets().join(KERNEL), fc.clone(), ch.clone(), l2()] {
        if !path.exists() {
            return Err(format!(
                "{} is missing; run cargo xtask vm nested --fetch",
                path.display()
            )
            .into());
        }
    }
    let target = tap::build(true)?;
    execute(
        cmd("cargo", &["build", "--release", "--locked", "-p", "xtask"])
            .env("CARGO_TARGET_DIR", crate::root().join("target")),
    )?;
    let work = tap::directory().join(format!("nested-{}", token(6)?));
    private_dir(&work)?;
    let result = (|| {
        let assets_iso = tap::directory().join(format!(
            "assets/assets-{DEBIAN_BUILD}-{FC_VERSION}-{CH_VERSION}-{KERNEL}.iso"
        ));
        if !assets_iso.exists() {
            let part = assets_iso.with_extension("part");
            execute(cmd("genisoimage", &["-quiet", "-output"]).arg(&part).args([
                "-volid",
                "FNASSETS",
                "-rock",
                "-graft-points",
                &format!("vmlinux={}", assets().join(KERNEL).display()),
                &format!("firecracker={}", fc.display()),
                &format!("cloud-hypervisor={}", ch.display()),
                &format!("l2-root.qcow2={}", l2().display()),
            ]))?;
            fs::rename(part, &assets_iso)?;
        }
        execute(
            cmd("genisoimage", &["-quiet", "-output"])
                .arg(work.join("run.iso"))
                .args([
                    "-volid",
                    "FNRUN",
                    "-rock",
                    "-graft-points",
                    &format!("fictionet={}", target.join("fictionet").display()),
                    &format!(
                        "web_fixture={}",
                        target.join("examples/web_fixture").display()
                    ),
                    &format!("xtask={}", target.join("xtask").display()),
                ]),
        )?;
        fs::write(
            work.join("user-data"),
            "#cloud-config\nruncmd:\n  - [sh, -c, 'mkdir -p /mnt/assets /mnt/run && mount -o ro LABEL=FNASSETS /mnt/assets && mount -o ro LABEL=FNRUN /mnt/run && FICTIONET_ROOT=/mnt/run /mnt/run/xtask vm nested-guest > /dev/ttyS1 2>&1; poweroff']\n",
        )?;
        fs::write(
            work.join("meta-data"),
            format!("instance-id: nested-{}\nlocal-hostname: l1\n", token(6)?),
        )?;
        iso(
            &work.join("seed.iso"),
            "cidata",
            &[work.join("user-data"), work.join("meta-data")],
        )?;
        overlay(&l1(), &work.join("l1.qcow2"), None)?;
        let mut qemu = tap::qemu(1200);
        qemu.args([
            "-m",
            "5G",
            "-smp",
            "4",
            "-serial",
            &format!("file:{}", work.join("console.log").display()),
            "-serial",
            &format!("file:{}", work.join("out.txt").display()),
            "-nic",
            "none",
        ]);
        for (disk, readonly) in [
            (work.join("l1.qcow2"), false),
            (work.join("seed.iso"), true),
            (assets_iso, true),
            (work.join("run.iso"), true),
        ] {
            qemu.args([
                "-drive",
                &format!(
                    "file={},if=virtio{}",
                    disk.display(),
                    if readonly {
                        ",media=cdrom,readonly=on"
                    } else {
                        ""
                    }
                ),
            ]);
        }
        let start = Instant::now();
        let output = qemu.output()?;
        let text = fs::read_to_string(work.join("out.txt"))
            .unwrap_or_default()
            .replace('\r', "");
        println!("L1 ran for {:.1} s\n{text}", start.elapsed().as_secs_f64());
        if !output.status.success()
            || !text.lines().any(|s| s == "=== L1 done")
            || text.lines().any(|s| s.starts_with("FAIL: "))
            || !text.lines().any(|s| s.starts_with("PASS: "))
        {
            return Err(format!(
                "nested VM checks failed: {}\n{}",
                crate::process::combined(&output),
                fs::read_to_string(work.join("console.log")).unwrap_or_default()
            )
            .into());
        }
        Ok(())
    })();
    if result.is_ok() {
        remove(&work)?;
    } else {
        eprintln!("VM logs are in {}", work.display());
    }
    result
}

pub fn guest() -> Result {
    if !cmd("modprobe", &["kvm_amd"]).output()?.status.success() {
        execute(&mut cmd("modprobe", &["kvm_intel"]))?;
    }
    check_host()?;
    for module in ["tun", "sch_ingress", "cls_matchall", "act_mirred"] {
        execute(&mut cmd("modprobe", &[module]))?;
    }
    let work = Path::new("/var/lib/fictionet-test");
    private_dir(work)?;
    private_dir(Path::new("/run/fictionet"))?;
    let mut world = background(
        &mut cmd(
            "/mnt/run/web_fixture",
            &["/run/fictionet/world.sock", "/run/fictionet/ca.pem"],
        ),
        &work.join("world.log"),
    )?;
    tap::wait_file(
        Path::new("/run/fictionet/world.sock"),
        &mut world,
        &work.join("world.log"),
    )?;
    tap::wait_ca(
        Path::new("/run/fictionet/ca.pem"),
        &mut world,
        &work.join("world.log"),
    )?;
    let template = work.join("template.ext4");
    execute(
        cmd(
            "qemu-img",
            &["convert", "-O", "raw", "/mnt/assets/l2-root.qcow2"],
        )
        .arg(&template),
    )?;
    fs::create_dir_all("/mnt/l2")?;
    execute(cmd("mount", &["-o", "loop"]).arg(&template).arg("/mnt/l2"))?;
    let mut mount = Cleanup::default();
    mount.push(cmd("umount", &["/mnt/l2"]));
    fs::write("/mnt/l2/etc/cloud/cloud-init.disabled", "")?;
    for entry in fs::read_dir("/mnt/l2/etc/netplan")? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "yaml") {
            remove(&path)?;
        }
    }
    fs::write(
        "/mnt/l2/etc/fstab",
        "/dev/vda / ext4 rw,discard,errors=remount-ro 0 1\n",
    )?;
    fs::write(
        "/mnt/l2/etc/systemd/network/10-fictionet.network",
        "[Match]\nType=ether\n\n[Network]\nDHCP=ipv4\nIPv6AcceptRA=no\n",
    )?;
    let guest = tap::GuestScript::web();
    let script = guest.script.replacen(
        "#!/bin/bash\n",
        "#!/bin/bash\nexec > /root/out.txt 2>&1\n",
        1,
    ) + "sync\nif grep -q fn.halt=reboot /proc/cmdline; then systemctl reboot; else systemctl poweroff; fi\n";
    fs::write("/mnt/l2/root/check.sh", script)?;
    fs::set_permissions("/mnt/l2/root/check.sh", fs::Permissions::from_mode(0o755))?;
    fs::copy("/run/fictionet/ca.pem", "/mnt/l2/root/ca.pem")?;
    fs::write(
        "/mnt/l2/etc/systemd/system/fictionet-check.service",
        "[Unit]\nDescription=Fictionet checks\nWants=network-online.target\nAfter=network-online.target\n\n[Service]\nType=oneshot\nExecStart=/root/check.sh\n\n[Install]\nWantedBy=multi-user.target\n",
    )?;
    execute(&mut cmd(
        "ln",
        &[
            "-sf",
            "/etc/systemd/system/fictionet-check.service",
            "/mnt/l2/etc/systemd/system/multi-user.target.wants/",
        ],
    ))?;
    mount.finish(Ok(()))?;
    let mut checks = Checks::default();
    for vmm in ["qemu", "firecracker", "cloud-hypervisor"] {
        println!("=== {vmm}: attach --vm tap:tap0");
        execute(&mut cmd("ip", &["netns", "add", "vm1"]))?;
        let mut cleanup = Cleanup::default();
        cleanup.push(cmd("ip", &["netns", "del", "vm1"]));
        execute(&mut cmd(
            "ip",
            &["-n", "vm1", "tuntap", "add", "dev", "tap0", "mode", "tap"],
        ))?;
        let disk = work.join(format!("{vmm}.ext4"));
        execute(cmd("cp", &["--sparse=always"]).arg(&template).arg(&disk))?;
        let ready = Path::new("/run/fictionet/agent.ready");
        remove(ready)?;
        let log = work.join(format!("{vmm}-attach.log"));
        let mut attach = background(
            &mut cmd(
                "/mnt/run/fictionet",
                &[
                    "attach",
                    "--world",
                    "unix:/run/fictionet/world.sock",
                    "--name",
                    "agent",
                    "--type",
                    "tap",
                    "--vm",
                    "tap:tap0",
                    "--netns",
                    "/run/netns/vm1",
                    "--ip-addr",
                    "10.0.0.2/24",
                    "--gateway",
                    "10.0.0.1",
                    "--dns",
                    "10.0.0.1",
                    "--no-ip-addr-v6",
                    "--ready-file",
                    "/run/fictionet/agent.ready",
                ],
            ),
            &log,
        )?;
        tap::wait_file(ready, &mut attach, &log)?;
        execute(&mut cmd("ip", &["-n", "vm1", "-br", "link"]))?;
        execute(&mut cmd(
            "tc",
            &["-n", "vm1", "filter", "show", "dev", "tap0", "ingress"],
        ))?;
        let second = cmd(
            "timeout",
            &[
                "10",
                "/mnt/run/fictionet",
                "attach",
                "--world",
                "unix:/run/fictionet/world.sock",
                "--name",
                "agent2",
                "--type",
                "tap",
                "--vm",
                "tap:tap0",
                "--netns",
                "/run/netns/vm1",
                "--no-ip-addr",
                "--no-ip-addr-v6",
                "--ready-file",
                "/run/fictionet/agent.ready",
            ],
        )
        .output()?;
        checks.require(
            "a second attach is refused and leaves the first alone",
            second.status.code() == Some(1)
                && crate::process::combined(&second).contains("another attach is using tap0")
                && ready.exists()
                && capture(&mut cmd(
                    "tc",
                    &["-n", "vm1", "filter", "show", "dev", "tap0", "ingress"],
                ))?
                .contains("mirred"),
            crate::process::combined(&second),
        );
        let console = work.join(format!("{vmm}-console.log"));
        let mut emulator = cmd("timeout", &["300", "ip", "netns", "exec", "vm1"]);
        match vmm {
            "qemu" => {
                emulator.args([
                    "qemu-system-x86_64",
                    "-enable-kvm",
                    "-cpu",
                    "host",
                    "-m",
                    "512M",
                    "-smp",
                    "1",
                    "-nodefaults",
                    "-display",
                    "none",
                    "-no-reboot",
                    "-kernel",
                    "/mnt/assets/vmlinux",
                    "-append",
                    "console=ttyS0 reboot=k panic=1 root=/dev/vda rw",
                    "-drive",
                    &format!("file={},if=virtio,format=raw", disk.display()),
                    "-netdev",
                    "tap,id=n0,ifname=tap0,script=no,downscript=no",
                    "-device",
                    "virtio-net-pci,netdev=n0,mac=52:54:00:12:34:56",
                    "-serial",
                    &format!("file:{}", console.display()),
                ]);
            }
            "firecracker" => {
                let config = serde_json::json!({"boot-source": {"kernel_image_path": "/mnt/assets/vmlinux", "boot_args": "console=ttyS0 reboot=k panic=1 fn.halt=reboot"}, "drives": [{"drive_id": "root", "path_on_host": disk, "is_root_device": true, "is_read_only": false}], "network-interfaces": [{"iface_id": "eth0", "host_dev_name": "tap0", "guest_mac": "52:54:00:12:34:56"}], "machine-config": {"vcpu_count": 1, "mem_size_mib": 512}});
                fs::write(work.join("vm.json"), serde_json::to_vec(&config)?)?;
                emulator
                    .args(["/mnt/assets/firecracker", "--no-api", "--config-file"])
                    .arg(work.join("vm.json"))
                    .args(["--log-path", "/dev/null"]);
            }
            _ => {
                emulator.args([
                    "/mnt/assets/cloud-hypervisor",
                    "--kernel",
                    "/mnt/assets/vmlinux",
                    "--cmdline",
                    "console=ttyS0 reboot=k panic=1 root=/dev/vda rw",
                    "--disk",
                    &format!("path={}", disk.display()),
                    "--net",
                    "tap=tap0,mac=52:54:00:12:34:56",
                    "--cpus",
                    "boot=1",
                    "--memory",
                    "size=512M",
                    "--serial",
                    &format!("file={}", console.display()),
                    "--console",
                    "off",
                ]);
            }
        }
        let output = emulator.output()?;
        execute(cmd("mount", &["-o", "loop,ro"]).arg(&disk).arg("/mnt/l2"))?;
        let mut mount = Cleanup::default();
        mount.push(cmd("umount", &["/mnt/l2"]));
        let raw = fs::read_to_string("/mnt/l2/root/out.txt").unwrap_or_default();
        let text = raw.replace('\r', "");
        mount.finish(Ok(()))?;
        fs::write(work.join(format!("{vmm}-out.txt")), &text)?;
        println!("{text}");
        let validated = guest.validate(&raw, output.status.success());
        checks.require(
            "emulator and guest completed",
            validated.is_ok(),
            format!(
                "{validated:?}\n{}\n{}",
                crate::process::combined(&output),
                fs::read_to_string(&console).unwrap_or_default()
            ),
        );
        tap::web_checks(&mut checks, &text, false)?;
        execute(&mut cmd("ip", &["-n", "vm1", "link", "del", "tap0"]))?;
        tap::attach_ended(
            &mut checks,
            &mut attach,
            &log,
            "tap0 was removed; agent detached",
        )?;
        let links = capture(&mut cmd(
            "ip",
            &["-n", "vm1", "-o", "link", "show", "type", "tun"],
        ))?;
        checks.require(
            "attach removes its TAP device",
            links.trim().is_empty(),
            links,
        );
        drop(attach);
        cleanup.finish(Ok(()))?;
        remove(&disk)?;
    }
    checks.finish()?;
    println!("=== L1 done");
    Ok(())
}
