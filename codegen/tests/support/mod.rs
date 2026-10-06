use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

static NEXT: AtomicUsize = AtomicUsize::new(0);
pub struct Scratch(pub PathBuf);
impl Scratch {
    pub fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "fictionet-layout-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

pub fn rustfmt_available() -> bool {
    Command::new("rustfmt").arg("--version").output().is_ok()
}
pub fn check_rustfmt(files: &[PathBuf]) {
    for chunk in files.chunks(32) {
        let result = Command::new("rustfmt")
            .args(["--edition", "2024", "--check"])
            .args(chunk)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
    }
}

pub fn compile_and_run(files: &[PathBuf], scratch: &Scratch) {
    let deps = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let sdk = std::fs::read_dir(&deps)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("libfictionet-")
        })
        .filter(|p| p.extension().is_some_and(|e| e == "rlib"))
        .max_by_key(|p| p.metadata().unwrap().modified().unwrap())
        .unwrap();
    let compiler = if Command::new("clippy-driver")
        .arg("--version")
        .output()
        .is_ok()
    {
        "clippy-driver".into()
    } else {
        std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into())
    };
    for (batch, chunk) in files.chunks(8).enumerate() {
        let harness = scratch.0.join(format!("compiled_{batch}.rs"));
        let mut source = String::from("#![allow(dead_code)]\n");
        for (i, path) in chunk.iter().enumerate() {
            source.push_str(&format!("#[path = {:?}]\nmod example{i};\n", path));
        }
        std::fs::write(&harness, source).unwrap();
        let executable = scratch
            .0
            .join(format!("compiled_{batch}{}", std::env::consts::EXE_SUFFIX));
        let output = Command::new(&compiler)
            .args(["--edition", "2024", "--test", "-Dwarnings"])
            .arg(&harness)
            .arg("--extern")
            .arg(format!("fictionet={}", sdk.display()))
            .arg("-L")
            .arg(format!("dependency={}", deps.display()))
            .arg("-o")
            .arg(&executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "batch {batch}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output = Command::new(executable).output().unwrap();
        assert!(
            output.status.success(),
            "batch {batch}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
