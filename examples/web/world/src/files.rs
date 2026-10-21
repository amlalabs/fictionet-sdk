//! The files worlds on one store share: the store's lock and the JSON
//! Lines files they append to. A world reads what the others appended,
//! then writes, while it holds `store.lock`.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Opens the lock of the store at `root`, creating it.
pub(crate) fn store_lock(root: &Path) -> io::Result<File> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(root.join("store.lock"))
}

/// A file's lock, held until dropped.
pub(crate) struct FileLock(File);

impl FileLock {
    /// Waits for `file`'s lock.
    pub(crate) fn take(file: &File) -> io::Result<Self> {
        let file = file.try_clone()?;
        file.lock()?;
        Ok(Self(file))
    }

    /// `file`'s lock, or `None` while someone else holds it.
    pub(crate) fn try_take(file: &File) -> io::Result<Option<Self>> {
        let file = file.try_clone()?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self(file))),
            Err(std::fs::TryLockError::WouldBlock) => Ok(None),
            Err(std::fs::TryLockError::Error(e)) => Err(e),
        }
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        // Closing a clone does not release the lock; the others share it.
        let _ = self.0.unlock();
    }
}

/// A JSON Lines file worlds on one store append to. Each world reads on
/// from where it stopped.
pub(crate) struct Appended {
    /// The file, to read from `read` on.
    file: File,
    /// Where lines are appended: the file itself, but for tests.
    writer: Box<dyn Write + Send>,
    path: PathBuf,
    /// The bytes and lines applied so far.
    read: u64,
    lines: usize,
}

impl Appended {
    /// Opens `path` to read and append, creating it.
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(path)
            .map_err(|e| {
                io::Error::new(e.kind(), format!("cannot read {}: {e}", path.display()))
            })?;
        Ok(Self {
            writer: Box::new(file.try_clone()?),
            file,
            path: path.to_owned(),
            read: 0,
            lines: 0,
        })
    }

    /// Appends to `writer` instead of the file.
    #[cfg(test)]
    pub(crate) fn set_writer(&mut self, writer: Box<dyn Write + Send>) {
        self.writer = writer;
    }

    /// Reads the lines after the ones applied so far and hands them to
    /// `apply` in order. Without the store's lock (`held` false) a line
    /// still being written waits for the next read. While it is held, every
    /// line is finished, and one without its newline is an error. If a line
    /// is not a `T`, none is applied. If `apply` refuses one, nothing counts
    /// as read, so the next read tries the same lines again.
    pub(crate) fn read_on<T: DeserializeOwned>(
        &mut self,
        held: bool,
        mut apply: impl FnMut(T) -> Result<(), String>,
    ) -> io::Result<()> {
        let mut text = Vec::new();
        self.file.seek(SeekFrom::Start(self.read))?;
        self.file.read_to_end(&mut text)?;
        let complete = text
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |end| end + 1);
        let entries = text[..complete]
            .split_inclusive(|&b| b == b'\n')
            .enumerate()
            .map(|(i, line)| serde_json::from_slice::<T>(line).map_err(|e| self.bad(i, e)))
            .collect::<io::Result<Vec<_>>>()?;
        let count = entries.len();
        if held && complete < text.len() {
            return Err(self.bad(count, "the line is unfinished"));
        }
        for (i, entry) in entries.into_iter().enumerate() {
            apply(entry).map_err(|why| self.bad(i, why))?;
        }
        self.read += complete as u64;
        self.lines += count;
        Ok(())
    }

    /// Appends `value` as a line, which counts as read. The caller holds
    /// the store's lock.
    pub(crate) fn append(&mut self, value: &impl Serialize) -> io::Result<()> {
        let mut line = serde_json::to_vec(value).map_err(io::Error::other)?;
        line.push(b'\n');
        self.writer.write_all(&line)?;
        self.read += line.len() as u64;
        self.lines += 1;
        Ok(())
    }

    /// An error about the `i`th line after those applied so far.
    fn bad(&self, i: usize, why: impl std::fmt::Display) -> io::Error {
        let line = self.lines + 1 + i;
        let why = format!("{}: line {line}: {why}", self.path.display());
        io::Error::new(io::ErrorKind::InvalidData, why)
    }
}
