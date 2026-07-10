//! First-boot rootfs integrity check.
//!
//! The host records the SHA-256 of the image's rootfs partition in the flash
//! manifest; this module re-hashes `/dev/mmcblk0p2` and compares. The check
//! detects accidental corruption only — the SD card is attacker-mutable and
//! the Pi has no secure boot, so it makes no authenticity claim. It runs on
//! first boot only: that is the one boot where the signer is root (to mount
//! the boot partition and read the raw rootfs device) and the partition still
//! matches the manifest byte-for-byte on every image. The comparison is also
//! only meaningful while the rootfs is mounted read-only — a read-write mount
//! (dev images) changes the partition's bytes by design — so a read-write
//! rootfs skips the check.

use crate::constants::{BOOT_MOUNT, ROOTFS_PARTITION};
use crate::util::{BootMountMode, mount_boot_partition, unmount_boot_partition};
use russignol_flash_manifest::{FlashManifest, MANIFEST_FILENAME};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Outcome of the rootfs integrity check
pub enum RootfsCheck {
    /// The rootfs partition matches the hash recorded at flash time
    Verified,
    /// The rootfs partition does not match — the card is likely corrupted
    Mismatch { expected: String, actual: String },
    /// No comparison was possible; the reason says why
    Skipped(String),
}

/// Whether the rootfs (the `/` mount) is mounted read-only, from the content
/// of `/proc/mounts`. The last `/` entry wins — later mounts shadow earlier
/// ones.
fn rootfs_mounted_readonly(proc_mounts: &str) -> bool {
    proc_mounts
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let [_device, mount_point, _fstype] = [fields.next()?, fields.next()?, fields.next()?];
            let options = fields.next()?;
            (mount_point == "/").then(|| options.split(',').any(|option| option == "ro"))
        })
        .next_back()
        .unwrap_or(false)
}

/// The rootfs hash recorded in the flash manifest, if the manifest parses and
/// carries one
fn expected_rootfs_hash(manifest_json: &str) -> Option<String> {
    serde_json::from_str::<FlashManifest>(manifest_json)
        .ok()
        .and_then(|manifest| manifest.rootfs_sha256)
}

/// SHA-256 (hex) of a file or block device, streaming. `progress` receives
/// the running percentage.
///
/// # Errors
///
/// Fails when the path cannot be opened or read.
fn sha256_hex_of(path: &Path, mut progress: impl FnMut(u8)) -> Result<String, String> {
    let display = path.display();
    let mut file =
        std::fs::File::open(path).map_err(|e| format!("failed to open {display}: {e}"))?;
    // Regular-file metadata reports a block device's length as 0; seeking to
    // the end works for both.
    let total = file
        .seek(SeekFrom::End(0))
        .map_err(|e| format!("failed to size {display}: {e}"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|e| format!("failed to rewind {display}: {e}"))?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    let mut done: u64 = 0;
    let mut last_percent = u8::MAX;
    loop {
        let n = file
            .read(&mut buf)
            .map_err(|e| format!("failed to read {display}: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        done += n as u64;
        if let Some(ratio) = (done * 100).checked_div(total) {
            let percent = u8::try_from(ratio.min(100)).expect("<= 100");
            if percent != last_percent {
                last_percent = percent;
                progress(percent);
            }
        }
    }
    Ok(hex::encode(hasher.finalize()))
}

/// Run the full check: gate on a read-only rootfs, read the manifest's
/// recorded hash from the boot partition, and compare it against a fresh hash
/// of the rootfs partition. `progress` receives the hashing percentage.
pub fn verify_rootfs(progress: impl FnMut(u8)) -> RootfsCheck {
    let mounts = match std::fs::read_to_string("/proc/mounts") {
        Ok(mounts) => mounts,
        Err(e) => return RootfsCheck::Skipped(format!("cannot read /proc/mounts: {e}")),
    };
    if !rootfs_mounted_readonly(&mounts) {
        return RootfsCheck::Skipped(
            "rootfs is mounted read-write; its bytes are expected to change".to_string(),
        );
    }

    let expected = match staged_manifest_hash() {
        Ok(Some(hash)) => hash,
        Ok(None) => {
            return RootfsCheck::Skipped("flash manifest records no rootfs hash".to_string());
        }
        Err(e) => return RootfsCheck::Skipped(e),
    };

    let actual = match sha256_hex_of(Path::new(ROOTFS_PARTITION), progress) {
        Ok(hash) => hash,
        Err(e) => return RootfsCheck::Skipped(format!("cannot hash {ROOTFS_PARTITION}: {e}")),
    };

    if actual.eq_ignore_ascii_case(&expected) {
        RootfsCheck::Verified
    } else {
        RootfsCheck::Mismatch { expected, actual }
    }
}

/// Read the manifest's rootfs hash from the boot partition, mounting and
/// unmounting around the read. A missing manifest is `Ok(None)` — cards
/// flashed by older hosts have no manifest hash to compare against.
fn staged_manifest_hash() -> Result<Option<String>, String> {
    mount_boot_partition(BootMountMode::ReadOnly)?;
    let content = std::fs::read_to_string(Path::new(BOOT_MOUNT).join(MANIFEST_FILENAME));
    let _ = unmount_boot_partition();
    match content {
        Ok(json) => Ok(expected_rootfs_hash(&json)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read the flash manifest: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn readonly_rootfs_is_detected() {
        let mounts = "/dev/root / f2fs ro,relatime,fsync_mode=strict 0 0\n\
                      /dev/mmcblk0p3 /keys f2fs rw,relatime 0 0\n";
        assert!(rootfs_mounted_readonly(mounts));
    }

    #[test]
    fn readwrite_rootfs_is_not_readonly() {
        let mounts = "/dev/root / f2fs rw,relatime,fsync_mode=strict 0 0\n";
        assert!(!rootfs_mounted_readonly(mounts));
    }

    /// `errors=remount-ro` contains the substring "ro" but the mount is rw —
    /// option matching must be exact.
    #[test]
    fn remount_ro_option_does_not_read_as_readonly() {
        let mounts = "/dev/root / f2fs rw,relatime,errors=remount-ro 0 0\n";
        assert!(!rootfs_mounted_readonly(mounts));
    }

    #[test]
    fn missing_root_entry_is_not_readonly() {
        let mounts = "/dev/mmcblk0p3 /keys f2fs rw,relatime 0 0\n";
        assert!(!rootfs_mounted_readonly(mounts));
    }

    /// Later mounts shadow earlier ones, so the last `/` entry decides
    #[test]
    fn last_root_entry_wins() {
        let mounts = "rootfs / rootfs rw 0 0\n\
                      /dev/root / f2fs ro,relatime 0 0\n";
        assert!(rootfs_mounted_readonly(mounts));
    }

    #[test]
    fn manifest_with_rootfs_hash_yields_it() {
        let json = r#"{
            "card_id": "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8",
            "flashed_at": "2026-03-06T12:34:56Z",
            "host_version": "0.25.0",
            "image_sha256": "abc123",
            "rootfs_sha256": "def456"
        }"#;
        assert_eq!(expected_rootfs_hash(json), Some("def456".to_string()));
    }

    #[test]
    fn manifest_without_rootfs_hash_yields_none() {
        let json = r#"{
            "card_id": "a1b2c3d4e5f6a7b8a1b2c3d4e5f6a7b8",
            "flashed_at": "2026-03-06T12:34:56Z",
            "host_version": "0.20.0",
            "image_sha256": "abc123"
        }"#;
        assert_eq!(expected_rootfs_hash(json), None);
    }

    #[test]
    fn unparseable_manifest_yields_none() {
        assert_eq!(expected_rootfs_hash("not json"), None);
    }

    #[test]
    fn sha256_hex_of_hashes_a_file_with_full_progress() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        std::io::Write::write_all(&mut file, b"hello world").unwrap();

        let mut last_percent = 0u8;
        let hash = sha256_hex_of(file.path(), |p| last_percent = p).unwrap();

        // sha256("hello world")
        assert_eq!(
            hash,
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert_eq!(last_percent, 100);
    }

    #[test]
    fn sha256_hex_of_missing_path_is_an_error() {
        assert!(sha256_hex_of(Path::new("/nonexistent/device"), |_| {}).is_err());
    }
}
