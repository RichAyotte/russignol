//! Encryption utilities for Tezos signer secret keys.
//!
//! Core encryption is in russignol-crypto; this module owns file I/O and the
//! device-side migration that converts a v1 blob (or a v2 blob still living
//! at the v1 path) into a v2 blob at the v2 path.
//!
//! # State machine
//!
//! Two filenames carry all state. Their presence/absence on disk decides what
//! `migrate_and_decrypt` does on this boot:
//!
//! | `secret_keys.enc` (v1 path) | `secret_keys.enc.v2` (v2 path) | this-boot action                                                          |
//! |-----------------------------|--------------------------------|----------------------------------------------------------------------------|
//! | absent                      | absent                         | error — setup is responsible for the first-boot path                       |
//! | present                     | absent                         | unlock v1, write v2, **reboot** so verify reads from flash                  |
//! | present                     | present                        | verify v2 with PIN; on success unlink v1 in-process; on PIN-decrypts-v1-not-v2 unlink v2 |
//! | absent                      | present                        | steady state — unlock v2                                                   |
//!
//! v1 is never destroyed until v2 has been read back from flash and decrypted
//! with the user's PIN, so a corrupt v2 producer cannot brick the device.

use log::{debug, info, warn};
use russignol_crypto::BlobFormat;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub use russignol_crypto::{SECRET_KEYS_ENC_PATH, SECRET_KEYS_ENC_V2_PATH};

pub const KEYS_MOUNT: &str = "/keys";

/// Reboot-loop guard: counts how many `StagedV2` events have happened
/// without a steady-state v2 unlock in between. Reset when a boot finds
/// only the v2 file (steady state) or successfully promotes; threshold
/// halts migration and surfaces `MigrationDisabled`.
const MIGRATION_ATTEMPTS_PATH: &str = "/keys/.migration_attempts";

/// One reboot per migration; allow three retry cycles before halting.
const MIGRATION_ATTEMPT_THRESHOLD: u32 = 4;

/// Surfaced to the caller so the UI can show the user what happened on
/// this boot. `None` means "steady-state unlock" — the device is fully on
/// its target format and nothing migration-related happened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MigrationEvent {
    /// v1 only on disk: a v2 blob was written alongside; reboot expected
    /// so the next boot can verify the v2 from flash before unlinking v1.
    StagedV2,
    /// Both files were present, v2 verified with the PIN, v1 was unlinked
    /// in-process. No reboot needed.
    PromotedV2,
    /// Both files were present, v2 failed PIN decrypt but v1 succeeded;
    /// v2 was unlinked. The device stays on v1 and the next boot will
    /// re-stage.
    RevertedFromCorruptV2 { reason: String },
    /// v1 unlock succeeded but writing the v2 file failed (e.g. EROFS).
    /// Plaintext is intact; nothing was changed on disk.
    StagingFailed { reason: String },
    /// Retry budget exhausted. Migration is skipped this boot; v1 is
    /// decrypted with its native format and the user must take action.
    MigrationDisabled { attempts: u32 },
}

/// Plaintext plus an optional migration event the app event loop dispatches
/// on (countdown page + reboot, error page, or normal unlock).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptOutcome {
    pub plaintext: String,
    pub migration: Option<MigrationEvent>,
}

/// Decrypt secret keys, transparently driving the v1→v2 migration state
/// machine on the device.
///
/// `on_stage_start` fires once on the v1-only path between the v1 unlock and
/// the v2 re-encrypt — both scrypt steps are slow (~9s each on the target
/// hardware), and the UI uses this hook to swap the progress page so the bar
/// tracks the second phase instead of pinning at 100%. The hook does not
/// fire on the verify-and-promote path or on a steady-state unlock.
///
/// # Errors
///
/// Returns an error if both key files are missing, or if the supplied PIN
/// fails to decrypt whichever file(s) the state machine consults.
pub fn decrypt_secret_keys(
    password: &[u8],
    on_stage_start: impl FnOnce(),
) -> io::Result<DecryptOutcome> {
    migrate_and_decrypt(
        password,
        Path::new(SECRET_KEYS_ENC_PATH),
        Path::new(SECRET_KEYS_ENC_V2_PATH),
        Path::new(MIGRATION_ATTEMPTS_PATH),
        on_stage_start,
    )
}

/// Encrypt secret keys JSON and atomically write to the v2 path. Used by
/// fresh first-boot setup; new devices skip the migration machinery entirely.
///
/// # Errors
///
/// Returns an error if encryption or any file I/O step fails.
pub fn encrypt_secret_keys(password: &[u8], secret_keys_json: &str) -> io::Result<()> {
    let encrypted = russignol_crypto::encrypt(password, secret_keys_json)?;
    atomic_write(Path::new(SECRET_KEYS_ENC_V2_PATH), &encrypted)?;
    info!("Encrypted secret keys written to {SECRET_KEYS_ENC_V2_PATH}");
    Ok(())
}

fn migrate_and_decrypt(
    password: &[u8],
    v1_path: &Path,
    v2_path: &Path,
    counter_path: &Path,
    on_stage_start: impl FnOnce(),
) -> io::Result<DecryptOutcome> {
    let v1_present = v1_path.exists();
    let v2_present = v2_path.exists();

    match (v1_present, v2_present) {
        (false, false) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "No encrypted secret keys at {} or {}",
                v1_path.display(),
                v2_path.display()
            ),
        )),

        (false, true) => {
            let v2 = fs::read(v2_path)?;
            let plaintext = russignol_crypto::decrypt(password, &v2)?;
            let _ = clear_counter(counter_path);
            Ok(DecryptOutcome {
                plaintext,
                migration: None,
            })
        }

        (true, false) => stage_v1_to_v2(password, v1_path, v2_path, counter_path, on_stage_start),

        (true, true) => verify_v2_or_revert(password, v1_path, v2_path, counter_path),
    }
}

fn stage_v1_to_v2(
    password: &[u8],
    v1_path: &Path,
    v2_path: &Path,
    counter_path: &Path,
    on_stage_start: impl FnOnce(),
) -> io::Result<DecryptOutcome> {
    let v1 = fs::read(v1_path)?;
    let attempts = read_counter(counter_path);

    if attempts >= MIGRATION_ATTEMPT_THRESHOLD {
        let (plaintext, _) = russignol_crypto::decrypt_with_format(password, &v1)?;
        warn!(
            "Migration disabled after {attempts} attempts; v1 decrypted natively, no further migration this boot"
        );
        return Ok(DecryptOutcome {
            plaintext,
            migration: Some(MigrationEvent::MigrationDisabled { attempts }),
        });
    }

    let (plaintext, format) = russignol_crypto::decrypt_with_format(password, &v1)?;

    if !matches!(format, BlobFormat::V1Legacy) {
        return Err(io::Error::other("v1-named file contains non-v1 format"));
    }

    on_stage_start();

    let stage_result = match russignol_crypto::encrypt(password, &plaintext) {
        Ok(v2_blob) => atomic_write(v2_path, &v2_blob),
        Err(err) => Err(io::Error::other(format!("re-encrypt failed: {err}"))),
    };

    match stage_result {
        Ok(()) => match increment_counter(counter_path, attempts) {
            Ok(new_attempts) => {
                info!(
                    "Staged v2 at {} (attempt {new_attempts}); will verify next boot",
                    v2_path.display()
                );
                Ok(DecryptOutcome {
                    plaintext,
                    migration: Some(MigrationEvent::StagedV2),
                })
            }
            Err(e) => Ok(DecryptOutcome {
                plaintext,
                migration: Some(MigrationEvent::StagingFailed {
                    reason: format!("counter persist: {e}"),
                }),
            }),
        },
        Err(stage_err) => Ok(DecryptOutcome {
            plaintext,
            migration: Some(MigrationEvent::StagingFailed {
                reason: format!("{stage_err}"),
            }),
        }),
    }
}

fn verify_v2_or_revert(
    password: &[u8],
    v1_path: &Path,
    v2_path: &Path,
    counter_path: &Path,
) -> io::Result<DecryptOutcome> {
    let attempts = read_counter(counter_path);

    if attempts >= MIGRATION_ATTEMPT_THRESHOLD {
        let v1 = fs::read(v1_path)?;
        let (plaintext, _) = russignol_crypto::decrypt_with_format(password, &v1)?;
        warn!(
            "Migration disabled after {attempts} attempts; v1 decrypted natively, v2 left in place"
        );
        return Ok(DecryptOutcome {
            plaintext,
            migration: Some(MigrationEvent::MigrationDisabled { attempts }),
        });
    }

    let v2 = fs::read(v2_path)?;
    match russignol_crypto::decrypt(password, &v2) {
        Ok(plaintext) => {
            fs::remove_file(v1_path)?;
            let _ = clear_counter(counter_path);
            info!(
                "Promoted v2 at {} after successful verification; v1 unlinked",
                v2_path.display()
            );
            Ok(DecryptOutcome {
                plaintext,
                migration: Some(MigrationEvent::PromotedV2),
            })
        }
        Err(v2_err) => {
            let v1 = fs::read(v1_path)?;
            match russignol_crypto::decrypt_with_format(password, &v1) {
                Ok((plaintext, _)) => {
                    let _ = fs::remove_file(v2_path);
                    let reason = format!("{v2_err}");
                    warn!(
                        "v2 at {} failed verification ({reason}); reverted, v1 remains",
                        v2_path.display()
                    );
                    Ok(DecryptOutcome {
                        plaintext,
                        migration: Some(MigrationEvent::RevertedFromCorruptV2 { reason }),
                    })
                }
                Err(v1_err) => Err(v1_err),
            }
        }
    }
}

fn read_counter(path: &Path) -> u32 {
    fs::read_to_string(path)
        .ok()
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

fn increment_counter(path: &Path, current: u32) -> io::Result<u32> {
    let next = current.saturating_add(1);
    atomic_write(path, next.to_string().as_bytes())?;
    Ok(next)
}

fn clear_counter(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
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

/// Set ownership to russignol and mode 0400 on every key file present on
/// the keys partition. Migration boots run the signer as root; this readies
/// the files so the russignol-uid signer can read them after privilege drop.
///
/// # Errors
///
/// Returns an error if reading or setting permissions fails on a present
/// file. Missing files are skipped.
pub fn set_key_permissions() -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;

    const RUSSIGNOL_UID: u32 = 1000;
    const RUSSIGNOL_GID: u32 = 1000;

    let key_files = [
        Path::new(SECRET_KEYS_ENC_PATH),
        Path::new(SECRET_KEYS_ENC_V2_PATH),
        &Path::new(KEYS_MOUNT).join("public_keys"),
        &Path::new(KEYS_MOUNT).join("public_key_hashs"),
        &Path::new(KEYS_MOUNT).join("chain_info.json"),
    ];

    for path in key_files {
        if path.exists() {
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
        v1_path: PathBuf,
        v2_path: PathBuf,
        counter: PathBuf,
    }

    impl Layout {
        fn new() -> Self {
            let dir = TempDir::new().unwrap();
            let v1_path = dir.path().join("secret_keys.enc");
            let v2_path = dir.path().join("secret_keys.enc.v2");
            let counter = dir.path().join(".migration_attempts");
            Self {
                _dir: dir,
                v1_path,
                v2_path,
                counter,
            }
        }

        fn run(&self, password: &[u8]) -> io::Result<DecryptOutcome> {
            migrate_and_decrypt(password, &self.v1_path, &self.v2_path, &self.counter, || {})
        }
    }

    // ---- atomic_write -------------------------------------------------

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

    // ---- migrate_and_decrypt: filename state machine -----------------

    #[test]
    fn migrate_v2_only_unlocks_and_clears_counter() {
        let l = Layout::new();
        let plaintext = "post-promote-secret";
        let v2 = russignol_crypto::encrypt(LEGACY_V1_PIN, plaintext).unwrap();
        fs::write(&l.v2_path, &v2).unwrap();
        fs::write(&l.counter, "2").unwrap();

        let outcome = l.run(LEGACY_V1_PIN).unwrap();

        assert_eq!(outcome.plaintext, plaintext);
        assert_eq!(outcome.migration, None);
        assert_eq!(fs::read(&l.v2_path).unwrap(), v2);
        assert!(!l.v1_path.exists());
        assert!(
            !l.counter.exists(),
            "steady-state v2 unlock must clear the counter"
        );
    }

    #[test]
    fn migrate_v1_only_v1_format_stages_v2() {
        let l = Layout::new();
        fs::write(&l.v1_path, LEGACY_V1_FIXTURE).unwrap();

        let outcome = l.run(LEGACY_V1_PIN).unwrap();

        assert_eq!(outcome.plaintext, LEGACY_V1_PLAINTEXT);
        assert_eq!(outcome.migration, Some(MigrationEvent::StagedV2));
        assert_eq!(
            fs::read(&l.v1_path).unwrap(),
            LEGACY_V1_FIXTURE,
            "v1 must remain on disk until verified"
        );
        assert!(l.v2_path.exists(), "v2 must be staged");
        assert_eq!(fs::read(&l.v2_path).unwrap()[0], 0x02, "staged blob is v2");
        assert_eq!(read_counter(&l.counter), 1);
    }

    #[test]
    fn migrate_v1_only_v2_format_errors() {
        let l = Layout::new();
        let plaintext = "in-place-upgrade-secret";
        let v2 = russignol_crypto::encrypt(LEGACY_V1_PIN, plaintext).unwrap();
        fs::write(&l.v1_path, &v2).unwrap();

        let result = l.run(LEGACY_V1_PIN);

        assert!(result.is_err());
        assert!(!l.v2_path.exists(), "no v2 staged when format mismatches");
        assert_eq!(read_counter(&l.counter), 0);
    }

    #[test]
    fn migrate_both_present_good_v2_promotes() {
        let l = Layout::new();
        fs::write(&l.v1_path, LEGACY_V1_FIXTURE).unwrap();
        let v2 = russignol_crypto::encrypt(LEGACY_V1_PIN, LEGACY_V1_PLAINTEXT).unwrap();
        fs::write(&l.v2_path, &v2).unwrap();
        fs::write(&l.counter, "1").unwrap();

        let outcome = l.run(LEGACY_V1_PIN).unwrap();

        assert_eq!(outcome.plaintext, LEGACY_V1_PLAINTEXT);
        assert_eq!(outcome.migration, Some(MigrationEvent::PromotedV2));
        assert!(!l.v1_path.exists(), "v1 unlinked after verify");
        assert_eq!(fs::read(&l.v2_path).unwrap(), v2, "v2 unchanged");
        assert!(!l.counter.exists(), "promotion clears the counter");
    }

    #[test]
    fn migrate_both_present_bad_v2_reverts_to_v1() {
        let l = Layout::new();
        fs::write(&l.v1_path, LEGACY_V1_FIXTURE).unwrap();
        let bad_v2 = vec![0x02u8; 100];
        fs::write(&l.v2_path, &bad_v2).unwrap();
        fs::write(&l.counter, "1").unwrap();

        let outcome = l.run(LEGACY_V1_PIN).unwrap();

        assert_eq!(outcome.plaintext, LEGACY_V1_PLAINTEXT);
        assert!(matches!(
            outcome.migration,
            Some(MigrationEvent::RevertedFromCorruptV2 { .. })
        ));
        assert!(!l.v2_path.exists(), "corrupt v2 unlinked");
        assert_eq!(fs::read(&l.v1_path).unwrap(), LEGACY_V1_FIXTURE);
        assert_eq!(
            read_counter(&l.counter),
            1,
            "revert does not advance counter"
        );
    }

    #[test]
    fn migrate_both_present_wrong_pin_keeps_both_files() {
        let l = Layout::new();
        fs::write(&l.v1_path, LEGACY_V1_FIXTURE).unwrap();
        let v2 = russignol_crypto::encrypt(LEGACY_V1_PIN, LEGACY_V1_PLAINTEXT).unwrap();
        fs::write(&l.v2_path, &v2).unwrap();

        let result = l.run(b"wrong");

        assert!(result.is_err());
        assert_eq!(fs::read(&l.v1_path).unwrap(), LEGACY_V1_FIXTURE);
        assert_eq!(fs::read(&l.v2_path).unwrap(), v2);
    }

    #[test]
    fn migrate_v1_only_wrong_pin_keeps_v1() {
        let l = Layout::new();
        fs::write(&l.v1_path, LEGACY_V1_FIXTURE).unwrap();

        let result = l.run(b"wrong");

        assert!(result.is_err());
        assert_eq!(fs::read(&l.v1_path).unwrap(), LEGACY_V1_FIXTURE);
        assert!(!l.v2_path.exists());
    }

    #[test]
    fn migrate_staging_failure_returns_staging_failed() {
        let l = Layout::new();
        fs::write(&l.v1_path, LEGACY_V1_FIXTURE).unwrap();
        let unwritable_v2 = l.v1_path.parent().unwrap().join("does/not/exist/v2");

        let outcome =
            migrate_and_decrypt(LEGACY_V1_PIN, &l.v1_path, &unwritable_v2, &l.counter, || {})
                .unwrap();

        assert_eq!(outcome.plaintext, LEGACY_V1_PLAINTEXT);
        assert!(matches!(
            outcome.migration,
            Some(MigrationEvent::StagingFailed { .. })
        ));
        assert_eq!(read_counter(&l.counter), 0, "failed staging keeps counter");
        assert!(!unwritable_v2.exists());
    }

    #[test]
    fn migrate_counter_persist_failure_returns_staging_failed() {
        let l = Layout::new();
        fs::write(&l.v1_path, LEGACY_V1_FIXTURE).unwrap();
        let unwritable_counter = l.v1_path.parent().unwrap().join("does/not/exist/counter");

        let outcome = migrate_and_decrypt(
            LEGACY_V1_PIN,
            &l.v1_path,
            &l.v2_path,
            &unwritable_counter,
            || {},
        )
        .unwrap();

        assert_eq!(outcome.plaintext, LEGACY_V1_PLAINTEXT);
        assert!(matches!(
            outcome.migration,
            Some(MigrationEvent::StagingFailed { .. })
        ));
        assert_eq!(
            fs::read(&l.v1_path).unwrap(),
            LEGACY_V1_FIXTURE,
            "v1 unchanged"
        );
        assert!(l.v2_path.exists(), "v2 staging itself succeeded");
        assert_eq!(read_counter(&unwritable_counter), 0);
    }

    #[test]
    fn migrate_threshold_disables_migration_v1_only() {
        let l = Layout::new();
        fs::write(&l.v1_path, LEGACY_V1_FIXTURE).unwrap();
        fs::write(&l.counter, MIGRATION_ATTEMPT_THRESHOLD.to_string()).unwrap();

        let outcome = l.run(LEGACY_V1_PIN).unwrap();

        assert_eq!(outcome.plaintext, LEGACY_V1_PLAINTEXT);
        assert_eq!(
            outcome.migration,
            Some(MigrationEvent::MigrationDisabled {
                attempts: MIGRATION_ATTEMPT_THRESHOLD
            })
        );
        assert_eq!(fs::read(&l.v1_path).unwrap(), LEGACY_V1_FIXTURE);
        assert!(!l.v2_path.exists(), "no staging when migration disabled");
        assert_eq!(read_counter(&l.counter), MIGRATION_ATTEMPT_THRESHOLD);
    }

    #[test]
    fn migrate_threshold_disables_migration_both_present() {
        let l = Layout::new();
        fs::write(&l.v1_path, LEGACY_V1_FIXTURE).unwrap();
        let v2 = russignol_crypto::encrypt(LEGACY_V1_PIN, LEGACY_V1_PLAINTEXT).unwrap();
        fs::write(&l.v2_path, &v2).unwrap();
        fs::write(&l.counter, MIGRATION_ATTEMPT_THRESHOLD.to_string()).unwrap();

        let outcome = l.run(LEGACY_V1_PIN).unwrap();

        assert_eq!(outcome.plaintext, LEGACY_V1_PLAINTEXT);
        assert_eq!(
            outcome.migration,
            Some(MigrationEvent::MigrationDisabled {
                attempts: MIGRATION_ATTEMPT_THRESHOLD
            })
        );
        assert_eq!(fs::read(&l.v1_path).unwrap(), LEGACY_V1_FIXTURE);
        assert_eq!(fs::read(&l.v2_path).unwrap(), v2);
        assert_eq!(read_counter(&l.counter), MIGRATION_ATTEMPT_THRESHOLD);
    }

    #[test]
    fn migrate_no_keys_returns_not_found() {
        let l = Layout::new();
        let result = l.run(LEGACY_V1_PIN);
        let err = result.expect_err("missing keys must error");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
