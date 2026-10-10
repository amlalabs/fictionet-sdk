use std::sync::atomic::{AtomicU64, Ordering};

static SOCKETS: AtomicU64 = AtomicU64::new(0);

/// Returns a world socket path in the system temporary directory.
pub(super) fn socket_path(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("fictionet-bench-sockets");
    std::fs::create_dir_all(&dir).unwrap();
    let n = SOCKETS.fetch_add(1, Ordering::Relaxed);
    let path = dir.join(format!("{tag}-{}-{n}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    path
}
