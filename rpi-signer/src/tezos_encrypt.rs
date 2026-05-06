//! Encryption utilities for Tezos signer secret keys
//!
//! This module handles both encryption (during first-boot setup) and
//! decryption (during normal operation) of secret keys.
//! Core encryption logic is in russignol-crypto; this module provides
//! file I/O for the signer process plus the device-side migration that
//! re-encrypts legacy v1 blobs to v2 across two boots (verify-then-promote).

use log::{debug, info, warn};
use russignol_crypto::BlobFormat;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub use russignol_crypto::SECRET_KEYS_ENC_PATH;

pub const KEYS_MOUNT: &str = "/keys";

/// Staged v2 blob produced from a v1 unlock; promoted to canonical only
/// after a different boot's PIN unlock successfully decrypts it.
const SECRET_KEYS_ENC_V2_PENDING: &str = "/keys/secret_keys.enc.v2.pending";

/// Records the `boot_id` at the moment the staged v2 blob was written so we
/// can tell on a later unlock whether we've actually rebooted since staging.
const SECRET_KEYS_ENC_V2_BOOT_ID: &str = "/keys/secret_keys.enc.v2.boot_id";

/// Linux's per-boot UUID; rotates on every boot independent of the clock,
/// which is what we need on a Pi without an RTC.
const PROC_BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

/// Decrypt secret keys, transparently driving the v1→v2 migration state
/// machine on the device.
///
/// # Errors
///
/// Returns an error if the canonical blob is missing, the PIN is wrong, or
/// `/proc/sys/kernel/random/boot_id` cannot be read.
pub fn decrypt_secret_keys(password: &[u8]) -> io::Result<String> {
    let boot_id = current_boot_id()?;
    migrate_and_decrypt(
        password,
        Path::new(SECRET_KEYS_ENC_PATH),
        Path::new(SECRET_KEYS_ENC_V2_PENDING),
        Path::new(SECRET_KEYS_ENC_V2_BOOT_ID),
        &boot_id,
    )
}

/// Encrypt secret keys JSON and atomically write to `/keys/secret_keys.enc`.
///
/// # Errors
///
/// Returns an error if encryption or any file I/O step fails.
pub fn encrypt_secret_keys(password: &[u8], secret_keys_json: &str) -> io::Result<()> {
    let encrypted = russignol_crypto::encrypt(password, secret_keys_json)?;
    atomic_write(Path::new(SECRET_KEYS_ENC_PATH), &encrypted)?;
    info!("Encrypted secret keys written to {SECRET_KEYS_ENC_PATH}");
    Ok(())
}

/// Drive the migration state machine.
///
/// The decision table is documented in the upgrade plan; the short version:
/// a v1 unlock stages a v2 blob alongside (recording the current `boot_id`),
/// and the staged blob only replaces v1 after a *different* boot decrypts it
/// successfully with the user's PIN. v1 stays on disk until that verify
/// succeeds, so a corrupt v2 producer cannot brick the device.
fn migrate_and_decrypt(
    password: &[u8],
    canonical_path: &Path,
    pending_path: &Path,
    boot_id_path: &Path,
    current_boot_id: &str,
) -> io::Result<String> {
    let canonical = fs::read(canonical_path).map_err(|e| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Failed to read encrypted secret keys {}: {e}",
                canonical_path.display()
            ),
        )
    })?;

    let staged_boot_id = read_trimmed(boot_id_path).ok();
    let rebooted_since_staging = staged_boot_id
        .as_deref()
        .is_some_and(|prior| prior != current_boot_id);
    let pending_present = pending_path.exists();

    if pending_present && rebooted_since_staging {
        let pending = fs::read(pending_path)?;
        match russignol_crypto::decrypt(password, &pending) {
            Ok(plaintext) => {
                fs::rename(pending_path, canonical_path)?;
                let _ = fs::remove_file(boot_id_path);
                info!(
                    "Promoted staged v2 blob to {} after successful verification",
                    canonical_path.display()
                );
                return Ok(plaintext);
            }
            Err(pending_err) => {
                let canonical_result = russignol_crypto::decrypt_with_format(password, &canonical);
                match canonical_result {
                    Ok((plaintext, _)) => {
                        let _ = fs::remove_file(pending_path);
                        let _ = fs::remove_file(boot_id_path);
                        warn!(
                            "Staged v2 failed verification ({pending_err}); reverted to v1 at {}",
                            canonical_path.display()
                        );
                        return Ok(plaintext);
                    }
                    Err(canonical_err) => {
                        return Err(canonical_err);
                    }
                }
            }
        }
    }

    let (plaintext, format) = russignol_crypto::decrypt_with_format(password, &canonical)?;

    if format == BlobFormat::V1Legacy && !pending_present {
        match russignol_crypto::encrypt(password, &plaintext) {
            Ok(staged) => {
                if let Err(stage_err) =
                    stage_v2(&staged, pending_path, boot_id_path, current_boot_id)
                {
                    warn!(
                        "Failed to stage v2 blob alongside {}: {stage_err}",
                        canonical_path.display()
                    );
                } else {
                    info!(
                        "Staged v2 blob at {} (boot_id={current_boot_id}); will promote on next boot",
                        pending_path.display()
                    );
                }
            }
            Err(err) => {
                warn!("Failed to re-encrypt v1 blob to v2 for staging: {err}");
            }
        }
    }

    Ok(plaintext)
}

/// Read `/proc/sys/kernel/random/boot_id`, trimmed of trailing whitespace.
///
/// # Errors
///
/// Returns an error if the proc file cannot be read (e.g. on a non-Linux
/// host); callers surface this before attempting any decrypt.
fn current_boot_id() -> io::Result<String> {
    read_trimmed(Path::new(PROC_BOOT_ID))
}

fn read_trimmed(path: &Path) -> io::Result<String> {
    let raw = fs::read_to_string(path)?;
    Ok(raw.trim().to_owned())
}

fn stage_v2(
    blob: &[u8],
    pending_path: &Path,
    boot_id_path: &Path,
    current_boot_id: &str,
) -> io::Result<()> {
    atomic_write(pending_path, blob)?;
    atomic_write(boot_id_path, current_boot_id.as_bytes())?;
    Ok(())
}

/// Write `data` to `target` via a `.tmp` sibling and rename, fsyncing the
/// file before rename so the new contents survive a crash. The parent
/// directory fsync is best-effort (some Linux mounts reject it); the
/// rename itself is the atomicity guarantee.
fn atomic_write(target: &Path, data: &[u8]) -> io::Result<()> {
    use std::io::Write as _;

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

/// Set proper permissions and ownership on key files
///
/// During first boot, files are created as root. This function:
/// 1. Changes ownership to russignol (so files are readable after privilege drop)
/// 2. Sets mode 400 (read-only by owner)
pub fn set_key_permissions() -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    // russignol user UID/GID (from /etc/passwd)
    const RUSSIGNOL_UID: u32 = 1000;
    const RUSSIGNOL_GID: u32 = 1000;

    let key_files = [
        Path::new(SECRET_KEYS_ENC_PATH),
        &Path::new(KEYS_MOUNT).join("public_keys"),
        &Path::new(KEYS_MOUNT).join("public_key_hashs"),
        &Path::new(KEYS_MOUNT).join("chain_info.json"),
    ];

    for path in key_files {
        if path.exists() {
            // Set ownership to russignol user (required for reading after privilege drop)
            let result = unsafe {
                let c_path = std::ffi::CString::new(path.to_str().unwrap_or("")).map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid path: {e}"))
                })?;
                libc::chown(c_path.as_ptr(), RUSSIGNOL_UID, RUSSIGNOL_GID)
            };
            if result != 0 {
                warn!(
                    "Failed to chown {}: {}",
                    path.display(),
                    io::Error::last_os_error()
                );
            } else {
                info!("Set {} owner to russignol", path.display());
            }

            // Set mode 400 (read-only by owner)
            let mut perms = fs::metadata(path)?.permissions();
            perms.set_mode(0o400);
            fs::set_permissions(path, perms)?;
            info!("Set {} to mode 400 (read-only)", path.display());
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const LEGACY_V1_FIXTURE: &[u8] =
        include_bytes!("../../libs/crypto/tests/fixtures/legacy_v1.bin");
    const LEGACY_V1_PIN: &[u8] = b"123456";
    const LEGACY_V1_PLAINTEXT: &str = r#"{"consensus":"edsk_fixture"}"#;

    struct Layout {
        _dir: TempDir,
        canonical: PathBuf,
        pending: PathBuf,
        boot_id: PathBuf,
    }

    impl Layout {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let canonical = dir.path().join("secret_keys.enc");
            let pending = dir.path().join("secret_keys.enc.v2.pending");
            let boot_id = dir.path().join("secret_keys.enc.v2.boot_id");
            Self {
                _dir: dir,
                canonical,
                pending,
                boot_id,
            }
        }
    }

    // ---- atomic_write -------------------------------------------------

    #[test]
    fn test_atomic_write_creates_file() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("foo");
        atomic_write(&target, b"hello").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"hello");
        assert!(!dir.path().join("foo.tmp").exists(), ".tmp leftover");
    }

    #[test]
    fn test_atomic_write_overwrites_existing() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("foo");
        fs::write(&target, b"old").unwrap();
        atomic_write(&target, b"new").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
    }

    #[test]
    fn test_atomic_write_overwrites_stale_tmp() {
        let dir = TempDir::new().unwrap();
        let target = dir.path().join("foo");
        let tmp = dir.path().join("foo.tmp");
        fs::write(&tmp, b"garbage").unwrap();
        atomic_write(&target, b"new").unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"new");
    }

    // ---- migrate_and_decrypt -----------------------------------------

    #[test]
    fn test_migrate_v2_canonical_no_action() {
        let l = Layout::new();
        let plaintext = "fresh-v2-secret";
        let v2 = russignol_crypto::encrypt(LEGACY_V1_PIN, plaintext).unwrap();
        fs::write(&l.canonical, &v2).unwrap();

        let result =
            migrate_and_decrypt(LEGACY_V1_PIN, &l.canonical, &l.pending, &l.boot_id, "boot1")
                .unwrap();

        assert_eq!(result, plaintext);
        assert_eq!(fs::read(&l.canonical).unwrap(), v2);
        assert!(!l.pending.exists());
        assert!(!l.boot_id.exists());
    }

    #[test]
    fn test_migrate_v1_canonical_stages_pending() {
        let l = Layout::new();
        fs::write(&l.canonical, LEGACY_V1_FIXTURE).unwrap();

        let result =
            migrate_and_decrypt(LEGACY_V1_PIN, &l.canonical, &l.pending, &l.boot_id, "boot1")
                .unwrap();

        assert_eq!(result, LEGACY_V1_PLAINTEXT);
        assert_eq!(fs::read(&l.canonical).unwrap(), LEGACY_V1_FIXTURE);
        assert!(l.pending.exists(), "pending v2 should be staged");
        let staged = fs::read(&l.pending).unwrap();
        assert_eq!(staged[0], 0x02, "staged blob must be v2");
        assert_eq!(read_trimmed(&l.boot_id).unwrap(), "boot1");
    }

    #[test]
    fn test_migrate_v1_with_pending_same_boot_no_action() {
        let l = Layout::new();
        fs::write(&l.canonical, LEGACY_V1_FIXTURE).unwrap();
        let staged = russignol_crypto::encrypt(LEGACY_V1_PIN, LEGACY_V1_PLAINTEXT).unwrap();
        fs::write(&l.pending, &staged).unwrap();
        fs::write(&l.boot_id, "boot1\n").unwrap();

        let result =
            migrate_and_decrypt(LEGACY_V1_PIN, &l.canonical, &l.pending, &l.boot_id, "boot1")
                .unwrap();

        assert_eq!(result, LEGACY_V1_PLAINTEXT);
        assert_eq!(fs::read(&l.canonical).unwrap(), LEGACY_V1_FIXTURE);
        assert_eq!(fs::read(&l.pending).unwrap(), staged);
        assert_eq!(read_trimmed(&l.boot_id).unwrap(), "boot1");
    }

    #[test]
    fn test_migrate_v1_with_pending_post_reboot_good_v2_promotes() {
        let l = Layout::new();
        fs::write(&l.canonical, LEGACY_V1_FIXTURE).unwrap();
        let staged = russignol_crypto::encrypt(LEGACY_V1_PIN, LEGACY_V1_PLAINTEXT).unwrap();
        fs::write(&l.pending, &staged).unwrap();
        fs::write(&l.boot_id, "boot1\n").unwrap();

        let result =
            migrate_and_decrypt(LEGACY_V1_PIN, &l.canonical, &l.pending, &l.boot_id, "boot2")
                .unwrap();

        assert_eq!(result, LEGACY_V1_PLAINTEXT);
        assert_eq!(
            fs::read(&l.canonical).unwrap(),
            staged,
            "canonical must be the formerly-pending v2 bytes"
        );
        assert!(!l.pending.exists());
        assert!(!l.boot_id.exists());
    }

    #[test]
    fn test_migrate_v1_with_pending_post_reboot_bad_v2_keeps_v1() {
        let l = Layout::new();
        fs::write(&l.canonical, LEGACY_V1_FIXTURE).unwrap();
        let bad_pending = vec![0x02u8; 100];
        fs::write(&l.pending, &bad_pending).unwrap();
        fs::write(&l.boot_id, "boot1\n").unwrap();

        let result =
            migrate_and_decrypt(LEGACY_V1_PIN, &l.canonical, &l.pending, &l.boot_id, "boot2")
                .unwrap();

        assert_eq!(result, LEGACY_V1_PLAINTEXT);
        assert_eq!(fs::read(&l.canonical).unwrap(), LEGACY_V1_FIXTURE);
        assert!(!l.pending.exists());
        assert!(!l.boot_id.exists());
    }

    #[test]
    fn test_migrate_v1_with_pending_post_reboot_wrong_pin_keeps_both() {
        let l = Layout::new();
        fs::write(&l.canonical, LEGACY_V1_FIXTURE).unwrap();
        let staged = russignol_crypto::encrypt(LEGACY_V1_PIN, LEGACY_V1_PLAINTEXT).unwrap();
        fs::write(&l.pending, &staged).unwrap();
        fs::write(&l.boot_id, "boot1\n").unwrap();

        let result = migrate_and_decrypt(b"wrong", &l.canonical, &l.pending, &l.boot_id, "boot2");

        assert!(result.is_err());
        assert_eq!(fs::read(&l.canonical).unwrap(), LEGACY_V1_FIXTURE);
        assert_eq!(fs::read(&l.pending).unwrap(), staged);
        assert_eq!(read_trimmed(&l.boot_id).unwrap(), "boot1");
    }

    #[test]
    fn test_migrate_no_pending_wrong_pin_returns_error() {
        let l = Layout::new();
        fs::write(&l.canonical, LEGACY_V1_FIXTURE).unwrap();

        let result = migrate_and_decrypt(b"wrong", &l.canonical, &l.pending, &l.boot_id, "boot1");

        assert!(result.is_err());
        assert_eq!(fs::read(&l.canonical).unwrap(), LEGACY_V1_FIXTURE);
        assert!(!l.pending.exists());
        assert!(!l.boot_id.exists());
    }

    #[test]
    fn test_migrate_missing_boot_id_sidecar_treats_as_same_boot() {
        let l = Layout::new();
        fs::write(&l.canonical, LEGACY_V1_FIXTURE).unwrap();
        let stale_pending = b"stale-pending-bytes".to_vec();
        fs::write(&l.pending, &stale_pending).unwrap();

        let result =
            migrate_and_decrypt(LEGACY_V1_PIN, &l.canonical, &l.pending, &l.boot_id, "boot2")
                .unwrap();

        assert_eq!(result, LEGACY_V1_PLAINTEXT);
        assert_eq!(fs::read(&l.canonical).unwrap(), LEGACY_V1_FIXTURE);
        assert_eq!(fs::read(&l.pending).unwrap(), stale_pending);
    }
}
