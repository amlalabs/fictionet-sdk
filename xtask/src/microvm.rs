//! `cargo xtask microvm`: the guest assets of the self-contained demo, the
//! demo binary that embeds them, and a run of it.
//!
//! The demo boots its guest with `msb_krun`, which takes the kernel from the
//! program itself. Three assets go into `demos/assets`, zstd-compressed:
//!
//! - `kernel.zst`: the kernel microsandbox pairs with `msb_krun`, built
//!   from its libkrunfw fork, flattened as libkrunfw flattens it.
//! - `agentd.zst`: microsandbox's guest agent, a static Linux binary.
//! - `rootfs.ext4.zst`: an ext4 image of `curlimages/curl`, pulled by
//!   digest.
//!
//! Every download is checked against the hash pinned here.

use crate::process::{Result, capture, cmd, run as execute};
use crate::vm::{download, private_dir};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// The libkrunfw fork microsandbox builds its kernel from: the commit its
/// `vendor/libkrunfw` submodule names at microsandbox `e526683`. Its patch
/// 0035 gives an x86 guest the poweroff that `msb_krun` waits for.
const KRUNFW_COMMIT: &str = "70ff1e821a7b513adb391aef6ad538f6ce148c17";
const KRUNFW_SHA256: &str = "fd7a66aabab4dae6bfab46c363bc05511b45da881fe88930f6b21c8bfd0097d8";
/// The kernel release that commit's Makefile names, and its checksum from
/// kernel.org's signed `sha256sums.asc`.
const LINUX: &str = "linux-6.12.113";
const LINUX_SHA256: &str = "413f7d9fcbbd85c980987b8ccb6fb247e9cabd9b5fdcc292e2dc1d55f428b63d";
/// The build stamps libkrunfw's Makefile sets, so the kernel names the
/// same build as libkrunfw's.
const KBUILD: &[&str] = &[
    "KBUILD_BUILD_TIMESTAMP=Fri Jul 24 13:01:52 WAT 2026",
    "KBUILD_BUILD_USER=root",
    "KBUILD_BUILD_HOST=libkrunfw",
    "KBUILD_BUILD_VERSION=1",
];

/// The guest agent, at the release whose client the demo links.
const AGENTD: &str = "microsandbox-agentd@0.7.8";
const GUEST_TARGET: &str = "x86_64-unknown-linux-gnu";

/// `curlimages/curl:8.23.0` for linux/amd64: curl, and busybox with its
/// `udhcpc` DHCP client and the script that applies a lease.
const IMAGE_REPOSITORY: &str = "curlimages/curl";
const IMAGE_MANIFEST: &str =
    "sha256:0ed5beeda77dc30495d1c586b7126437fc6438a6a76e29d9fedd0c436596e8fa";

pub fn run(args: &[String]) -> Result {
    match args {
        [] => {
            assets()?;
            build()?;
            demo()
        }
        [step] if step == "assets" => assets(),
        [step] if step == "build" => {
            assets()?;
            build()
        }
        _ => Err("usage: cargo xtask microvm [assets | build]".into()),
    }
}

/// Where downloads and build trees go: `<target>/microvm`.
fn work() -> Result<PathBuf> {
    let metadata: serde_json::Value = serde_json::from_str(&capture(&mut cmd(
        "cargo",
        &["metadata", "--locked", "--no-deps", "--format-version", "1"],
    ))?)?;
    let target = metadata["target_directory"]
        .as_str()
        .ok_or("cargo metadata gave no target directory")?;
    let dir = Path::new(target).join("microvm");
    private_dir(&dir)?;
    Ok(dir)
}

fn assets_dir() -> Result<PathBuf> {
    let dir = crate::root().join("demos/assets");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn assets() -> Result {
    let work = work()?;
    let out = assets_dir()?;
    kernel(&work, &out)?;
    agentd(&work, &out)?;
    rootfs(&work, &out)
}

/// Builds the kernel as libkrunfw's Makefile does, then flattens its
/// loadable segments as libkrunfw's `bin2cbundle.py` does. The asset holds
/// the guest load address and entry point, each a little-endian u64, then
/// the flat image.
fn kernel(work: &Path, out: &Path) -> Result {
    let asset = out.join("kernel.zst");
    // The commit names the kernel release and its patches, so a new pin
    // builds in a tree of its own.
    let dir = work.join(format!("kernel-{}", &KRUNFW_COMMIT[..12]));
    private_dir(&dir)?;
    let krunfw_tar = dir.join(format!("libkrunfw-{KRUNFW_COMMIT}.tar.gz"));
    download(
        &format!("https://github.com/superradcompany/libkrunfw/archive/{KRUNFW_COMMIT}.tar.gz"),
        &krunfw_tar,
        "sha256sum",
        KRUNFW_SHA256,
    )?;
    let linux_tar = dir.join(format!("{LINUX}.tar.gz"));
    download(
        &format!("https://cdn.kernel.org/pub/linux/kernel/v6.x/{LINUX}.tar.gz"),
        &linux_tar,
        "sha256sum",
        LINUX_SHA256,
    )?;
    let krunfw = dir.join("libkrunfw");
    let source = dir.join(LINUX);
    let vmlinux = source.join("vmlinux");
    if !vmlinux.is_file() {
        for tree in [&krunfw, &source] {
            if tree.exists() {
                fs::remove_dir_all(tree)?;
            }
        }
        fs::create_dir_all(&krunfw)?;
        execute(
            cmd("tar", &["-xzf"])
                .arg(&krunfw_tar)
                .arg("-C")
                .arg(&krunfw)
                .arg("--strip-components=1"),
        )?;
        execute(cmd("tar", &["-xzf"]).arg(&linux_tar).arg("-C").arg(&dir))?;
        let mut patches: Vec<PathBuf> = fs::read_dir(krunfw.join("patches"))?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<std::io::Result<_>>()?;
        patches.retain(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with('0') && n.ends_with(".patch"))
        });
        patches.sort();
        for patch in &patches {
            execute(
                cmd("patch", &["-f", "-s", "-p1", "-d"])
                    .arg(&source)
                    .stdin(fs::File::open(patch)?),
            )?;
        }
        fs::copy(
            krunfw.join("config-libkrunfw_x86_64"),
            source.join(".config"),
        )?;
        execute(cmd("make", &["-s", "olddefconfig"]).current_dir(&source))?;
        let jobs = format!("-j{}", jobs());
        execute(
            cmd("make", &["-s", &jobs, "vmlinux"])
                .args(KBUILD)
                .current_dir(&source),
        )?;
    }
    if asset.is_file() && newer(&asset, &vmlinux)? {
        return Ok(());
    }
    let elf = fs::read(&vmlinux)?;
    let (load, entry, image) = flatten(&elf)?;
    let mut bytes = Vec::with_capacity(16 + image.len());
    bytes.extend_from_slice(&load.to_le_bytes());
    bytes.extend_from_slice(&entry.to_le_bytes());
    bytes.extend_from_slice(&image);
    compress(&bytes, &asset)?;
    println!(
        "kernel: {} MiB flat, loads at {load:#x}, enters at {entry:#x}",
        image.len() >> 20
    );
    Ok(())
}

/// How many jobs `make` runs: cargo's limit if one is set, else every CPU.
fn jobs() -> usize {
    std::env::var("CARGO_BUILD_JOBS")
        .ok()
        .and_then(|j| j.parse().ok())
        .unwrap_or_else(|| std::thread::available_parallelism().map_or(4, |n| n.get()))
}

/// The loadable segments of an x86-64 `vmlinux`, laid out by physical
/// address from the first one, with zeros in the gaps: the load address
/// (the first segment's virtual address in the low 28 bits), the ELF entry
/// point, and the bytes.
fn flatten(elf: &[u8]) -> Result<(u64, u64, Vec<u8>)> {
    let u16_at = |at: usize| -> Result<u16> {
        Ok(u16::from_le_bytes(
            elf.get(at..at + 2)
                .ok_or("vmlinux is cut short")?
                .try_into()?,
        ))
    };
    let u32_at = |at: usize| -> Result<u32> {
        Ok(u32::from_le_bytes(
            elf.get(at..at + 4)
                .ok_or("vmlinux is cut short")?
                .try_into()?,
        ))
    };
    let u64_at = |at: usize| -> Result<u64> {
        Ok(u64::from_le_bytes(
            elf.get(at..at + 8)
                .ok_or("vmlinux is cut short")?
                .try_into()?,
        ))
    };
    if elf.get(..5) != Some(b"\x7fELF\x02") {
        return Err("vmlinux is not a 64-bit ELF file".into());
    }
    let entry = u64_at(0x18)?;
    let phoff = u64_at(0x20)? as usize;
    let phentsize = u16_at(0x36)? as usize;
    let phnum = u16_at(0x38)? as usize;
    let mut image = Vec::new();
    let mut load = None;
    for i in 0..phnum {
        let ph = phoff + i * phentsize;
        const PT_LOAD: u32 = 1;
        if u32_at(ph)? != PT_LOAD {
            continue;
        }
        let offset = u64_at(ph + 8)? as usize;
        let vaddr = u64_at(ph + 16)?;
        let paddr = u64_at(ph + 24)?;
        let filesz = u64_at(ph + 32)? as usize;
        let base = *load.get_or_insert(vaddr & 0xfff_ffff);
        let at = paddr
            .checked_sub(base)
            .ok_or("a segment loads below the first")? as usize;
        if at < image.len() {
            return Err("vmlinux segments overlap".into());
        }
        image.resize(at, 0);
        image.extend_from_slice(
            elf.get(offset..offset + filesz)
                .ok_or("a segment runs past the end of vmlinux")?,
        );
    }
    let load = load.ok_or("vmlinux has no loadable segment")?;
    Ok((load, entry, image))
}

/// Builds microsandbox's agent from its crates.io release as a static
/// binary, which runs on any guest userland.
fn agentd(work: &Path, out: &Path) -> Result {
    let asset = out.join("agentd.zst");
    let root = work.join(AGENTD.replace('@', "-"));
    let binary = root.join("bin/agentd");
    if !binary.is_file() {
        let rustflags =
            format!("target.{GUEST_TARGET}.rustflags=[\"-C\", \"target-feature=+crt-static\"]");
        execute(
            cmd(
                "cargo",
                &["install", "--locked", "--quiet", "--target", GUEST_TARGET],
            )
            .args([
                "--config",
                &rustflags,
                "--config",
                "profile.release.strip=true",
            ])
            .arg("--root")
            .arg(&root)
            .arg("--target-dir")
            .arg(work.join("agentd-build"))
            .arg(AGENTD),
        )?;
    }
    if asset.is_file() && newer(&asset, &binary)? {
        return Ok(());
    }
    compress(&fs::read(&binary)?, &asset)
}

/// The root filesystem: an ext4 image of the pinned image, made once.
fn rootfs(work: &Path, out: &Path) -> Result {
    let asset = out.join("rootfs.ext4.zst");
    let dir = work.join(format!("image-{}", &IMAGE_MANIFEST[7..19]));
    private_dir(&dir)?;
    let image = dir.join("rootfs.ext4");
    if !image.is_file() {
        ext4(&dir, &image)?;
    }
    if asset.is_file() && newer(&asset, &image)? {
        return Ok(());
    }
    compress(&fs::read(&image)?, &asset)
}

/// Pulls the image's one layer by digest and makes an ext4 image of it
/// with `mke2fs -d`, which keeps the owners and modes the layer's tar
/// headers give. The image gets room to spare for the guest's writes.
fn ext4(dir: &Path, image: &Path) -> Result {
    let token: serde_json::Value = serde_json::from_str(&capture(&mut cmd(
        "curl",
        &[
            "-fsS",
            &format!(
                "https://auth.docker.io/token?service=registry.docker.io&scope=repository:{IMAGE_REPOSITORY}:pull"
            ),
        ],
    ))?)?;
    let token = token["token"].as_str().ok_or("no registry token")?;
    let auth = format!("Authorization: Bearer {token}");
    // `kind` is the registry's word for the object: manifests or blobs.
    let fetch = |kind: &str, digest: &str, path: &Path, accept: &str| -> Result {
        if path.is_file() {
            return Ok(());
        }
        let part = path.with_extension("part");
        execute(
            cmd(
                "curl",
                &[
                    "-fsSL",
                    "-H",
                    &auth,
                    "-H",
                    &format!("Accept: {accept}"),
                    "-o",
                ],
            )
            .arg(&part)
            .arg(format!(
                "https://registry-1.docker.io/v2/{IMAGE_REPOSITORY}/{kind}/{digest}"
            )),
        )?;
        let sum = capture(cmd("sha256sum", &[]).arg(&part))?;
        let want = digest
            .strip_prefix("sha256:")
            .ok_or("not a sha256 digest")?;
        if sum.split_whitespace().next() != Some(want) {
            fs::remove_file(&part)?;
            return Err(format!("{digest}: sha256 mismatch").into());
        }
        fs::rename(part, path)?;
        Ok(())
    };
    let manifest_path = dir.join("manifest.json");
    fetch(
        "manifests",
        IMAGE_MANIFEST,
        &manifest_path,
        "application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json",
    )?;
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(&manifest_path)?)?;
    let layers = manifest["layers"]
        .as_array()
        .ok_or("the manifest lists no layers")?;
    // One layer needs no whiteouts applied; a multi-layer image would.
    let [layer] = layers.as_slice() else {
        return Err(format!(
            "{IMAGE_REPOSITORY} has {} layers; expected one",
            layers.len()
        )
        .into());
    };
    let digest = layer["digest"].as_str().ok_or("a layer has no digest")?;
    let blob = dir.join("layer.tar.gz");
    fetch("blobs", digest, &blob, "*/*")?;
    let tar = dir.join("layer.tar");
    let mut gunzip = cmd("gzip", &["-dc"]);
    gunzip.stdin(fs::File::open(&blob)?);
    gunzip.stdout(fs::File::create(&tar)?);
    execute(&mut gunzip)?;
    let mib = (fs::metadata(&tar)?.len() >> 20) * 2 + 64;
    let part = image.with_extension("part");
    if part.exists() {
        fs::remove_file(&part)?;
    }
    execute(
        cmd(
            "mke2fs",
            &[
                "-q",
                "-t",
                "ext4",
                "-E",
                "root_owner=0:0",
                "-L",
                "rootfs",
                "-d",
            ],
        )
        .arg(&tar)
        .arg(&part)
        .arg(format!("{mib}M")),
    )?;
    fs::rename(part, image)?;
    Ok(())
}

fn compress(bytes: &[u8], path: &Path) -> Result {
    let part = path.with_extension("part");
    let mut encoder = zstd::Encoder::new(fs::File::create(&part)?, 19)?;
    encoder.multithread(jobs() as u32)?;
    encoder.write_all(bytes)?;
    encoder.finish()?.sync_all()?;
    fs::rename(&part, path)?;
    Ok(())
}

/// Whether `a` was modified after `b`.
fn newer(a: &Path, b: &Path) -> Result<bool> {
    Ok(fs::metadata(a)?.modified()? > fs::metadata(b)?.modified()?)
}

fn build() -> Result {
    execute(&mut cmd(
        "cargo",
        &["build", "--locked", "--release", "-p", "fictionet-demo"],
    ))
}

/// Runs the demo, then checks that it left nothing behind: no process of
/// its executable, and none of the private directories its VMs use.
fn demo() -> Result {
    let work = work()?;
    let binary = work
        .parent()
        .ok_or("the target directory has no parent")?
        .join("release/fictionet-demo");
    let before = vm_dirs()?;
    execute(&mut std::process::Command::new(&binary))?;
    let running: Vec<String> = fs::read_dir("/proc")?
        .filter_map(|entry| entry.ok())
        .filter(|entry| fs::read_link(entry.path().join("exe")).is_ok_and(|exe| exe == binary))
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    if !running.is_empty() {
        return Err(format!("the demo left processes running: {}", running.join(", ")).into());
    }
    let left: Vec<PathBuf> = vm_dirs()?
        .into_iter()
        .filter(|d| !before.contains(d))
        .collect();
    if !left.is_empty() {
        return Err(format!("the demo left its VM storage behind: {left:?}").into());
    }
    println!("nothing left behind: no demo process, no VM storage");
    Ok(())
}

/// The private directories VMs keep their storage in.
fn vm_dirs() -> Result<Vec<PathBuf>> {
    Ok(fs::read_dir(std::env::temp_dir())?
        .filter_map(|entry| entry.ok())
        .filter(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .starts_with("fictionet-vm-")
        })
        .map(|entry| entry.path())
        .collect())
}
