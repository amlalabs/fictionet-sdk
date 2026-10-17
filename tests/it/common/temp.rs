use std::path::PathBuf;

/// A new directory of this test's own. Unix socket paths must be short,
/// so it is under the system's temp dir, not a long target dir.
pub fn dir() -> PathBuf {
    let n = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("fn-{}-{n}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// The path of a world socket in a new directory.
pub fn socket() -> String {
    dir().join("world.sock").to_str().unwrap().to_owned()
}
