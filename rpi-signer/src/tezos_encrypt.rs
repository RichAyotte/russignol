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

use log::{error, info, warn};
use russignol_crypto::BlobFormat;
use russignol_signer_lib::durable::atomic_write;
use std::fs;
use std::io;
use std::path::Path;

use crate::secret::Secret;

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
    MigrationDisabled { attempts: Attempts },
}

/// What a card's staging-attempt record says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Attempts {
    /// The record says this many staging attempts have happened.
    Counted(u32),
    /// The record is present and will not read as a number. How many is
    /// unknown, and unknown is not zero: reading it as zero hands the
    /// migration a fresh budget on every boot, which is the reboot loop the
    /// budget exists to stop.
    Unreadable,
}

impl Attempts {
    /// Whether the staging budget is spent.
    const fn exhausted(self) -> bool {
        match self {
            Self::Counted(n) => n >= MIGRATION_ATTEMPT_THRESHOLD,
            Self::Unreadable => true,
        }
    }
}

impl std::fmt::Display for Attempts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Counted(n) => write!(f, "{n} attempts"),
            Self::Unreadable => f.write_str("an unreadable attempt record"),
        }
    }
}

/// Plaintext plus an optional migration event the app event loop dispatches
/// on (countdown page + reboot, error page, or normal unlock).
///
/// `plaintext` is private so a stray `{:?}` cannot widen redaction:
/// `Secret<String>` zeroizes on drop and renders as `<redacted>`, but the
/// outer struct's derived `Debug` only forwards through that wrapper.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecryptOutcome {
    plaintext: Secret<String>,
    pub migration: Option<MigrationEvent>,
}

impl DecryptOutcome {
    pub fn into_parts(self) -> (Secret<String>, Option<MigrationEvent>) {
        (self.plaintext, self.migration)
    }
}

/// Decrypt secret keys, transparently driving the v1→v2 migration state
/// machine on the device.
///
/// `on_stage_start` fires once on the v1-only path between the v1 unlock and
/// the v2 re-encrypt — both scrypt steps are slow, and the UI uses this hook
/// to swap the progress page so the bar tracks the second phase instead of
/// pinning at 100%. The hook does not fire on the verify-and-promote path or
/// on a steady-state unlock.
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
            let plaintext = Secret::from_zeroizing(russignol_crypto::decrypt(password, &v2)?);
            // The counter is read only on the arms where the v1 blob exists, so
            // once the blob is gone nothing reads what this unlink leaves.
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

    if attempts.exhausted() {
        let (plaintext, _) = russignol_crypto::decrypt_with_format(password, &v1)?;
        let plaintext = Secret::from_zeroizing(plaintext);
        warn!(
            "Migration disabled after {attempts}; v1 decrypted natively, no further migration this boot"
        );
        return Ok(DecryptOutcome {
            plaintext,
            migration: Some(MigrationEvent::MigrationDisabled { attempts }),
        });
    }

    let (plaintext, format) = russignol_crypto::decrypt_with_format(password, &v1)?;
    let plaintext = Secret::from_zeroizing(plaintext);

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

    if attempts.exhausted() {
        let v1 = fs::read(v1_path)?;
        let (plaintext, _) = russignol_crypto::decrypt_with_format(password, &v1)?;
        let plaintext = Secret::from_zeroizing(plaintext);
        warn!("Migration disabled after {attempts}; v1 decrypted natively, v2 left in place");
        return Ok(DecryptOutcome {
            plaintext,
            migration: Some(MigrationEvent::MigrationDisabled { attempts }),
        });
    }

    let v2 = fs::read(v2_path)?;
    match russignol_crypto::decrypt(password, &v2) {
        Ok(plaintext) => {
            let plaintext = Secret::from_zeroizing(plaintext);
            fs::remove_file(v1_path)?;
            if let Err(e) = clear_counter(counter_path) {
                error!(
                    "Attempt record at {} outlived the promote it counted: {e}",
                    counter_path.display()
                );
            }
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
                    let plaintext = Secret::from_zeroizing(plaintext);
                    // A revert that cannot unlink has not reverted: both files
                    // remain and the next boot verifies the same corrupt blob,
                    // so what the operator is shown says so.
                    let reason = match fs::remove_file(v2_path) {
                        Ok(()) => format!("{v2_err}"),
                        Err(e) => format!("{v2_err}; the corrupt blob remains ({e})"),
                    };
                    warn!(
                        "v2 at {} failed verification ({reason}); v1 remains",
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

/// What the card's attempt record says, with no record at all reading as no
/// attempts. Every other way of not getting a number is [`Attempts::Unreadable`],
/// which stops the migration rather than restarting its budget.
fn read_counter(path: &Path) -> Attempts {
    match fs::read_to_string(path) {
        Ok(raw) => raw
            .trim()
            .parse::<u32>()
            .map_or(Attempts::Unreadable, Attempts::Counted),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Attempts::Counted(0),
        Err(e) => {
            error!("Attempt record at {} will not read: {e}", path.display());
            Attempts::Unreadable
        }
    }
}

fn increment_counter(path: &Path, current: Attempts) -> io::Result<u32> {
    let next = match current {
        Attempts::Counted(n) => n.saturating_add(1),
        // Behind exhausted(), so unreachable; the threshold is the honest
        // answer if it ever is reached, an unreadable record being no evidence
        // of a low count.
        Attempts::Unreadable => MIGRATION_ATTEMPT_THRESHOLD,
    };
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
    use std::path::PathBuf;
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

    // ---- migrate_and_decrypt: filename state machine -----------------

    /// An unreadable attempt record is not a record of no attempts. Reading it
    /// as zero hands the migration a fresh budget on every boot, which is the
    /// reboot loop the budget exists to stop.
    #[test]
    fn an_unreadable_attempt_record_stops_the_migration() {
        let l = Layout::new();
        let plaintext = "legacy-secret";
        let v1 = LEGACY_V1_FIXTURE.to_vec();
        fs::write(&l.v1_path, &v1).unwrap();
        let v2 = russignol_crypto::encrypt(b"999999", plaintext).unwrap();
        fs::write(&l.v2_path, &v2).unwrap();
        fs::write(&l.counter, "not a number").unwrap();

        let outcome = l.run(LEGACY_V1_PIN).unwrap();

        assert!(
            matches!(
                outcome.migration,
                Some(MigrationEvent::MigrationDisabled { .. })
            ),
            "an unreadable record must stop the migration: {:?}",
            outcome.migration
        );
        assert!(l.v1_path.exists(), "v1 must remain");
        assert!(l.v2_path.exists(), "v2 must be left where it is");
    }

    /// A revert that cannot unlink the corrupt v2 blob has not reverted: both
    /// files remain and the next boot verifies the same corrupt blob again, so
    /// the operator is told rather than shown a revert that did not happen.
    #[test]
    fn a_revert_that_cannot_unlink_says_so() {
        use std::os::unix::fs::PermissionsExt;

        let l = Layout::new();
        fs::write(&l.v1_path, LEGACY_V1_FIXTURE).unwrap();
        let v2 = russignol_crypto::encrypt(b"999999", "wrong-pin-blob").unwrap();
        fs::write(&l.v2_path, &v2).unwrap();
        let dir = l.v1_path.parent().expect("the layout has a directory");
        let mode = fs::metadata(dir).unwrap().permissions().mode();
        fs::set_permissions(dir, fs::Permissions::from_mode(0o555)).unwrap();

        let outcome = l.run(LEGACY_V1_PIN);

        fs::set_permissions(dir, fs::Permissions::from_mode(mode)).unwrap();
        let outcome = outcome.unwrap();
        let Some(MigrationEvent::RevertedFromCorruptV2 { reason }) = outcome.migration else {
            panic!("expected a revert, got {:?}", outcome.migration)
        };
        assert!(
            reason.contains("remains"),
            "the reason must say the blob is still there: {reason}"
        );
        assert!(l.v2_path.exists(), "the unlink could not have succeeded");
    }

    #[test]
    fn migrate_v2_only_unlocks_and_clears_counter() {
        let l = Layout::new();
        let plaintext = "post-promote-secret";
        let v2 = russignol_crypto::encrypt(LEGACY_V1_PIN, plaintext).unwrap();
        fs::write(&l.v2_path, &v2).unwrap();
        fs::write(&l.counter, "2").unwrap();

        let outcome = l.run(LEGACY_V1_PIN).unwrap();

        assert_eq!(outcome.plaintext.as_str(), plaintext);
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

        assert_eq!(outcome.plaintext.as_str(), LEGACY_V1_PLAINTEXT);
        assert_eq!(outcome.migration, Some(MigrationEvent::StagedV2));
        assert_eq!(
            fs::read(&l.v1_path).unwrap(),
            LEGACY_V1_FIXTURE,
            "v1 must remain on disk until verified"
        );
        assert!(l.v2_path.exists(), "v2 must be staged");
        assert_eq!(fs::read(&l.v2_path).unwrap()[0], 0x02, "staged blob is v2");
        assert_eq!(read_counter(&l.counter), Attempts::Counted(1));
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
        assert_eq!(read_counter(&l.counter), Attempts::Counted(0));
    }

    #[test]
    fn migrate_both_present_good_v2_promotes() {
        let l = Layout::new();
        fs::write(&l.v1_path, LEGACY_V1_FIXTURE).unwrap();
        let v2 = russignol_crypto::encrypt(LEGACY_V1_PIN, LEGACY_V1_PLAINTEXT).unwrap();
        fs::write(&l.v2_path, &v2).unwrap();
        fs::write(&l.counter, "1").unwrap();

        let outcome = l.run(LEGACY_V1_PIN).unwrap();

        assert_eq!(outcome.plaintext.as_str(), LEGACY_V1_PLAINTEXT);
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

        assert_eq!(outcome.plaintext.as_str(), LEGACY_V1_PLAINTEXT);
        assert!(matches!(
            outcome.migration,
            Some(MigrationEvent::RevertedFromCorruptV2 { .. })
        ));
        assert!(!l.v2_path.exists(), "corrupt v2 unlinked");
        assert_eq!(fs::read(&l.v1_path).unwrap(), LEGACY_V1_FIXTURE);
        assert_eq!(
            read_counter(&l.counter),
            Attempts::Counted(1),
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

        assert_eq!(outcome.plaintext.as_str(), LEGACY_V1_PLAINTEXT);
        assert!(matches!(
            outcome.migration,
            Some(MigrationEvent::StagingFailed { .. })
        ));
        assert_eq!(
            read_counter(&l.counter),
            Attempts::Counted(0),
            "failed staging keeps counter"
        );
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

        assert_eq!(outcome.plaintext.as_str(), LEGACY_V1_PLAINTEXT);
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
        assert_eq!(read_counter(&unwritable_counter), Attempts::Counted(0));
    }

    #[test]
    fn migrate_threshold_disables_migration_v1_only() {
        let l = Layout::new();
        fs::write(&l.v1_path, LEGACY_V1_FIXTURE).unwrap();
        fs::write(&l.counter, MIGRATION_ATTEMPT_THRESHOLD.to_string()).unwrap();

        let outcome = l.run(LEGACY_V1_PIN).unwrap();

        assert_eq!(outcome.plaintext.as_str(), LEGACY_V1_PLAINTEXT);
        assert_eq!(
            outcome.migration,
            Some(MigrationEvent::MigrationDisabled {
                attempts: Attempts::Counted(MIGRATION_ATTEMPT_THRESHOLD)
            })
        );
        assert_eq!(fs::read(&l.v1_path).unwrap(), LEGACY_V1_FIXTURE);
        assert!(!l.v2_path.exists(), "no staging when migration disabled");
        assert_eq!(
            read_counter(&l.counter),
            Attempts::Counted(MIGRATION_ATTEMPT_THRESHOLD)
        );
    }

    #[test]
    fn migrate_threshold_disables_migration_both_present() {
        let l = Layout::new();
        fs::write(&l.v1_path, LEGACY_V1_FIXTURE).unwrap();
        let v2 = russignol_crypto::encrypt(LEGACY_V1_PIN, LEGACY_V1_PLAINTEXT).unwrap();
        fs::write(&l.v2_path, &v2).unwrap();
        fs::write(&l.counter, MIGRATION_ATTEMPT_THRESHOLD.to_string()).unwrap();

        let outcome = l.run(LEGACY_V1_PIN).unwrap();

        assert_eq!(outcome.plaintext.as_str(), LEGACY_V1_PLAINTEXT);
        assert_eq!(
            outcome.migration,
            Some(MigrationEvent::MigrationDisabled {
                attempts: Attempts::Counted(MIGRATION_ATTEMPT_THRESHOLD)
            })
        );
        assert_eq!(fs::read(&l.v1_path).unwrap(), LEGACY_V1_FIXTURE);
        assert_eq!(fs::read(&l.v2_path).unwrap(), v2);
        assert_eq!(
            read_counter(&l.counter),
            Attempts::Counted(MIGRATION_ATTEMPT_THRESHOLD)
        );
    }

    #[test]
    fn migrate_no_keys_returns_not_found() {
        let l = Layout::new();
        let result = l.run(LEGACY_V1_PIN);
        let err = result.expect_err("missing keys must error");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
