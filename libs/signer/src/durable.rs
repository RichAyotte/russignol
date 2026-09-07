//! Writes that survive a power cut mid-write.
//!
//! Every file the device writes to its keys partition is read back by a boot
//! that may follow a power cut at any instant, and a half-written key file is
//! one no later boot can repair while that partition is mounted read-only.

use log::debug;
use std::fs;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

/// Write `data` to `target` through a `.tmp` sibling and a rename.
///
/// The file is fsynced before the rename so its contents survive a crash; the
/// rename itself is what makes the replacement atomic. The parent-directory
/// fsync after it is best-effort, some Linux mounts rejecting it.
///
/// # Errors
///
/// Returns an error if `target` names no file, or if creating, writing,
/// syncing or renaming the temporary fails.
pub fn atomic_write(target: &Path, data: &[u8]) -> io::Result<()> {
    let mut tmp = PathBuf::from(target);
    let tmp_filename = match target.file_name() {
        Some(name) => {
            let mut s = name.to_os_string();
            s.push(".tmp");
            s
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("atomic_write target has no filename: {}", target.display()),
            ));
        }
    };
    tmp.set_file_name(tmp_filename);

    {
        let mut file = fs::File::create(&tmp)?;
        file.write_all(data)?;
        file.sync_all()?;
    }

    fs::rename(&tmp, target)?;

    if let Some(parent) = target.parent() {
        match fs::File::open(parent) {
            Ok(dir) => {
                if let Err(e) = dir.sync_all() {
                    debug!(
                        "Best-effort parent fsync failed for {}: {e}",
                        parent.display()
                    );
                }
            }
            Err(e) => debug!(
                "Best-effort parent open failed for {}: {e}",
                parent.display()
            ),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn atomic_write_creates_file() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("foo");
        atomic_write(&target, b"hello").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"hello");
        assert!(!dir.path().join("foo.tmp").exists(), ".tmp leftover");
    }

    #[test]
    fn atomic_write_overwrites_existing() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("foo");
        fs::write(&target, b"old").unwrap();
        atomic_write(&target, b"new").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
    }

    #[test]
    fn atomic_write_overwrites_stale_tmp() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("foo");
        let tmp = dir.path().join("foo.tmp");
        fs::write(&tmp, b"garbage").unwrap();
        atomic_write(&target, b"new").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
    }

    /// A rename onto a directory fails, and the write leaves the target as it
    /// was rather than as anything partial.
    #[test]
    fn a_write_that_cannot_land_leaves_the_target_alone() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("occupied");
        fs::create_dir(&target).unwrap();

        assert!(atomic_write(&target, b"new").is_err());
        assert!(target.is_dir(), "the target was replaced");
    }
}
