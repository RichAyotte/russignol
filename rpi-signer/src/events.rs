use embedded_graphics::prelude::Point;
use russignol_signer_lib::ChainId;
use std::time::Duration;

use crate::secret::Secret;
use crate::tezos_encrypt::MigrationEvent;

/// Outcome of the pre-keygen watermark-config presence check, carried by
/// [`AppEvent::WatermarkConfigChecked`]. The setup gate maps it to a
/// proceed-to-keygen vs block decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigPresence {
    /// A valid, node-staged config is present on the boot partition.
    Present,
    /// No config is staged.
    Missing,
    /// A config is staged but failed validation.
    Invalid,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AppEvent {
    // === First-boot setup events ===
    StartSetup,                 // User tapped "Begin" to start first-boot setup
    StorageSetupComplete,       // Storage partitions created and formatted successfully
    StorageSetupFailed(String), // Storage setup failed with error message
    StorageProgress {
        message: String,
        percent: u8,
    }, // Progress update during storage setup
    WatermarkConfigChecked(ConfigPresence), // Result of the pre-keygen config-presence check
    FirstPinEntered(Secret<Vec<u8>>), // First PIN entered during creation
    PinMismatch,                // PINs don't match during confirmation
    KeyGenSuccess(Secret<String>), // Key generation completed, carries secret_keys JSON
    KeyGenFailed(String),       // Key generation failed with error message

    // === Normal operation events ===
    EnterPin,
    InvalidPinEntered,
    PinVerified {
        json: Secret<String>,
        migration: Option<MigrationEvent>,
    }, // PIN verified successfully, carries decrypted secret_keys JSON + migration outcome
    /// Fired by the PIN-verify thread between the v1 unlock and the v2
    /// re-encrypt so the UI can swap in a fresh progress page (the
    /// "Verifying PIN..." bar has already capped at 100% by this point).
    PinVerifyProgress {
        message: String,
        estimated_duration: Duration,
    },
    /// Fired by the migration error notice's OK button; carries the
    /// already-decrypted secret keys forward to the normal unlock path.
    AcknowledgeMigrationNotice {
        json: Secret<String>,
    },
    PinVerificationFailed,         // PIN verification failed (wrong PIN)
    DeviceLocked,                  // Too many failed PIN attempts, device locked
    KeysDecrypted(Secret<String>), // Keys decrypted, carries secret_keys JSON for signer
    /// A page repainting itself (e.g. PIN entry dots on each touch). Renders
    /// unless the screensaver is active — including on a modal page.
    DirtyDisplay,
    /// The signer's per-signature background callback. Renders the current page
    /// unless a modal is up, so a held-key signing burst never flashes a modal.
    SigningActivity,
    Touch(Point),
    PinEntered(Secret<Vec<u8>>),
    ActivateScreensaver,   // Trigger screensaver after inactivity
    DeactivateScreensaver, // Wake from screensaver on touch
    Shutdown,              // Signal to exit the application
    WatermarkError {
        pkh: String,
        chain_id: ChainId,
        error_message: String,
        /// For `LevelTooLow` errors: current watermark level
        current_level: Option<u32>,
        /// For `LevelTooLow` errors: requested signing level
        requested_level: Option<u32>,
    }, // Watermark error from signer
    WatermarkUpdateSuccess, // Signal that watermark update is complete
    LargeWatermarkGap {
        pkh: String,
        chain_id: ChainId,
        current_level: u32,
        requested_level: u32,
    }, // Large level gap detected, needs user confirmation
    WatermarkMissing {
        pkh: String,
        chain_id: ChainId,
        requested_level: u32,
    }, // Signing request hit a key with no watermark, offer on-device recovery
    UnknownKeyRequested {
        pkh: String,
    }, // Signing request named a key the device does not hold
    UnknownKeyDismissed,   // User acknowledged the unknown-key alert modal
    UpdateWatermarkToLevel {
        pkh: String,
        chain_id: ChainId,
        new_level: u32,
    }, // User confirmed updating watermark to new level
    DialogDismissed,       // User cancelled a dialog, return to menu
    ShowMenu,              // Show menu page
    ShowStatus,            // Show status page
    ShowSignatures,        // Show signatures/activity page
    ShowWatermarks,        // Show watermarks page
    ShowBlockchain,        // Show blockchain/chain info page
    ShowAbout,             // Show about page
    RequestShutdown,       // Show shutdown confirmation from menu
    FatalError {
        title: String,
        message: String,
    }, // Fatal error - show error page and halt
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `AppEvent`'s derived `Debug` must not surface the inner PIN bytes
    /// or decrypted JSON — `Secret<T>` provides the redaction; the derive
    /// only forwards.
    #[test]
    fn debug_redacts_pin_and_plaintext_payloads() {
        let dbg = format!("{:?}", AppEvent::PinEntered(Secret::new(vec![1, 2, 3, 4])));
        assert_eq!(
            dbg, "PinEntered(<redacted>)",
            "PIN payload not fully redacted: {dbg}"
        );
        for digit in ['1', '2', '3', '4'] {
            assert!(
                !dbg.contains(digit),
                "PIN digit {digit} leaked through Debug: {dbg}"
            );
        }

        let dbg = format!(
            "{:?}",
            AppEvent::KeysDecrypted(Secret::new(String::from("super-secret-json")))
        );
        assert_eq!(
            dbg, "KeysDecrypted(<redacted>)",
            "JSON payload not fully redacted: {dbg}"
        );
    }
}
