//! Size-capped rotating log writer
//!
//! Provides a `RotatingWriter` that implements `std::io::Write + Send`.
//! When the current log file exceeds `MAX_LOG_SIZE`, it is renamed to `.old`
//! and a new file is opened. This bounds total disk usage to ~2× `MAX_LOG_SIZE`.
//!
//! Logging must never kill the signer — all I/O errors are silently swallowed.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Maximum size of the active log file before rotation (512 KB).
const MAX_LOG_SIZE: u64 = 512 * 1024;

struct Inner {
    file: File,
    bytes_written: u64,
    path: PathBuf,
    old_path: PathBuf,
}

/// A thread-safe, size-capped rotating log writer.
///
/// Wraps a file in a `Mutex` and tracks bytes written. When the file exceeds
/// [`MAX_LOG_SIZE`], it is rotated: current → `.old`, then a fresh file is opened.
pub struct RotatingWriter {
    inner: Mutex<Inner>,
}

impl RotatingWriter {
    /// Open (or create) the log file at `path`, seeding the byte counter from
    /// its current size on disk.
    pub fn new(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let bytes_written = file.metadata().map(|m| m.len()).unwrap_or(0);
        let old_path = path.with_extension("log.old");
        Ok(Self {
            inner: Mutex::new(Inner {
                file,
                bytes_written,
                path: path.to_path_buf(),
                old_path,
            }),
        })
    }

    #[cfg(test)]
    fn with_max_size(path: &Path, max_size: u64) -> io::Result<RotatingWriterTest> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let bytes_written = file.metadata().map(|m| m.len()).unwrap_or(0);
        let old_path = path.with_extension("log.old");
        Ok(RotatingWriterTest {
            inner: Mutex::new(Inner {
                file,
                bytes_written,
                path: path.to_path_buf(),
                old_path,
            }),
            max_size,
        })
    }
}

impl Write for RotatingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Ok(mut inner) = self.inner.lock() else {
            // Mutex poisoned — silently drop the write
            return Ok(buf.len());
        };
        Ok(write_with_rotation(&mut inner, buf, MAX_LOG_SIZE))
    }

    fn flush(&mut self) -> io::Result<()> {
        let Ok(mut inner) = self.inner.lock() else {
            return Ok(());
        };
        inner.file.flush()
    }
}

/// Perform the write, rotating if the size threshold would be exceeded.
fn write_with_rotation(inner: &mut Inner, buf: &[u8], max_size: u64) -> usize {
    if inner.bytes_written + buf.len() as u64 > max_size {
        // Attempt rotation — if anything fails, silently continue with the current file
        let _ = rotate(inner);
    }
    match inner.file.write(buf) {
        Ok(n) => {
            inner.bytes_written += n as u64;
            n
        }
        Err(_) => {
            // Logging must never kill the signer
            buf.len()
        }
    }
}

/// Rotate: close current file, rename to `.old`, open fresh file, reset counter.
fn rotate(inner: &mut Inner) -> io::Result<()> {
    inner.file.flush()?;
    fs::rename(&inner.path, &inner.old_path)?;
    inner.file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&inner.path)?;
    inner.bytes_written = 0;
    Ok(())
}

// ---------- test-only variant with configurable max_size ----------

#[cfg(test)]
struct RotatingWriterTest {
    inner: Mutex<Inner>,
    max_size: u64,
}

#[cfg(test)]
impl Write for RotatingWriterTest {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let Ok(mut inner) = self.inner.lock() else {
            return Ok(buf.len());
        };
        Ok(write_with_rotation(&mut inner, buf, self.max_size))
    }

    fn flush(&mut self) -> io::Result<()> {
        let Ok(mut inner) = self.inner.lock() else {
            return Ok(());
        };
        inner.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    fn log_path(dir: &TempDir) -> PathBuf {
        dir.path().join("signer.log")
    }

    fn old_path(dir: &TempDir) -> PathBuf {
        dir.path().join("signer.log.old")
    }

    #[test]
    fn below_threshold_file_grows() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let mut w = RotatingWriter::with_max_size(&path, 100).unwrap();
        w.write_all(b"hello").unwrap();
        w.flush().unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "hello");
        assert!(!old_path(&dir).exists());
    }

    #[test]
    fn above_threshold_rotates() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let mut w = RotatingWriter::with_max_size(&path, 10).unwrap();

        // Write 8 bytes — below threshold
        w.write_all(b"aaaaaaaa").unwrap();
        w.flush().unwrap();
        assert!(!old_path(&dir).exists());

        // Write 5 more bytes — triggers rotation (8 + 5 > 10)
        w.write_all(b"bbbbb").unwrap();
        w.flush().unwrap();

        // Old file has the first write, current file has the second
        assert_eq!(fs::read_to_string(old_path(&dir)).unwrap(), "aaaaaaaa");
        assert_eq!(fs::read_to_string(&path).unwrap(), "bbbbb");
    }

    #[test]
    fn multiple_rotations() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let mut w = RotatingWriter::with_max_size(&path, 10).unwrap();

        // First rotation
        w.write_all(b"1111111111").unwrap(); // exactly 10
        w.write_all(b"222").unwrap(); // triggers rotation
        w.flush().unwrap();
        assert_eq!(fs::read_to_string(old_path(&dir)).unwrap(), "1111111111");
        assert_eq!(fs::read_to_string(&path).unwrap(), "222");

        // Second rotation — .old is overwritten
        w.write_all(b"33333333").unwrap(); // 3 + 8 = 11 > 10 → rotate
        w.flush().unwrap();
        assert_eq!(fs::read_to_string(old_path(&dir)).unwrap(), "222");
        assert_eq!(fs::read_to_string(&path).unwrap(), "33333333");
    }

    #[test]
    fn write_after_rotate_continues() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);
        let mut w = RotatingWriter::with_max_size(&path, 5).unwrap();

        w.write_all(b"aaa").unwrap();
        w.write_all(b"bbb").unwrap(); // triggers rotation
        w.write_all(b"c").unwrap(); // write after rotation
        w.flush().unwrap();

        assert_eq!(fs::read_to_string(&path).unwrap(), "bbbc");
    }

    #[test]
    fn seeds_counter_from_existing_file() {
        let dir = TempDir::new().unwrap();
        let path = log_path(&dir);

        // Pre-populate the file with 8 bytes
        fs::write(&path, "existing!").unwrap(); // 9 bytes

        let mut w = RotatingWriter::with_max_size(&path, 15).unwrap();
        // 9 + 7 = 16 > 15 → should rotate
        w.write_all(b"newdata").unwrap();
        w.flush().unwrap();

        assert_eq!(fs::read_to_string(old_path(&dir)).unwrap(), "existing!");
        assert_eq!(fs::read_to_string(&path).unwrap(), "newdata");
    }
}
