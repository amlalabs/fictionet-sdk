//! Prepared images: an asset decompressed into a file of the VM's private
//! storage.

use std::fs::OpenOptions;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Decompresses a zstd `asset` into a new file at `path` with `mode`. Runs
/// of zeros become holes, so a mostly empty disk image takes little space.
/// Returns the file's length.
pub(crate) fn extract(asset: &[u8], path: &Path, mode: u32) -> io::Result<u64> {
    const BLOCK: usize = 64 << 10;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)?;
    let mut decoder = zstd::Decoder::new(asset)?;
    let mut block = vec![0u8; BLOCK];
    let mut len = 0u64;
    loop {
        let mut filled = 0;
        while filled < BLOCK {
            match decoder.read(&mut block[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        if filled == 0 {
            break;
        }
        if block[..filled].iter().all(|&b| b == 0) {
            file.seek(SeekFrom::Current(filled as i64))?;
        } else {
            file.write_all(&block[..filled])?;
        }
        len += filled as u64;
    }
    file.set_len(len)?;
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn zeros_become_holes_and_the_bytes_come_back() {
        let mut image = vec![0u8; 8 << 20];
        image[100..105].copy_from_slice(b"first");
        let tail = image.len() - 3;
        image[tail..].copy_from_slice(b"end");
        let asset = zstd::encode_all(&image[..], 3).unwrap();
        let dir = std::env::temp_dir().join(format!("fictionet-image-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("disk");
        let _ = std::fs::remove_file(&path);
        assert_eq!(extract(&asset, &path, 0o600).unwrap(), image.len() as u64);
        let meta = std::fs::metadata(&path).unwrap();
        let back = std::fs::read(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(back == image, "the extracted bytes differ");
        assert_eq!(meta.mode() & 0o777, 0o600);
        // Two 64 KiB blocks hold data, with room for the file system to
        // allocate around them; the rest are holes.
        assert!(
            meta.blocks() * 512 <= 256 << 10,
            "{} bytes on disk",
            meta.blocks() * 512
        );
    }

    #[test]
    fn an_existing_file_is_not_overwritten() {
        let dir =
            std::env::temp_dir().join(format!("fictionet-image-exists-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("disk");
        std::fs::write(&path, b"keep").unwrap();
        let asset = zstd::encode_all(&b"new"[..], 3).unwrap();
        let err = extract(&asset, &path, 0o600).unwrap_err();
        let kept = std::fs::read(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(kept, b"keep");
    }
}
