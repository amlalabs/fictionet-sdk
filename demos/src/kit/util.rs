use std::path::{Path, PathBuf};

/// A private run directory, removed when dropped.
pub(crate) struct RunDir(PathBuf);

impl RunDir {
    pub(crate) fn new(parent: &Path, name: &str) -> std::io::Result<RunDir> {
        use std::os::unix::fs::DirBuilderExt;
        if name.is_empty()
            || !name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
        {
            return Err(std::io::Error::other("invalid run directory name"));
        }
        let mut bytes = [0u8; 8];
        fictionet::random_bytes(&mut bytes)?;
        let path = parent.join(format!("{name}-{}", u64::from_ne_bytes(bytes)));
        std::fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(RunDir(path))
    }
    pub(crate) fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for RunDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Generates a random version four UUID.
pub fn random_uuid() -> String {
    let mut b = [0u8; 16];
    fictionet::random_bytes(&mut b).expect("the system random source");
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}\
            {:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}
