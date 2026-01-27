use embedded_graphics::prelude::Point;
use russignol_signer_lib::ChainId;

#[derive(Clone, Debug)]
pub enum AppEvent {
    // === First-boot setup events ===
    StartSetup,                 // User tapped "Begin" to start first-boot setup
    StorageSetupComplete,       // Storage partitions created and formatted successfully
    StorageSetupFailed(String), // Storage setup failed with error message
    StorageProgress {
        message: String,
        percent: u8,
    }, // Progress update during storage setup
    FirstPinEntered(Vec<u8>),   // First PIN entered during creation
    PinMismatch,                // PINs don't match during confirmation
    KeyGenSuccess(String),      // Key generation completed, carries secret_keys JSON
    KeyGenFailed(String),       // Key generation failed with error message

    // === Normal operation events ===
    EnterPin,
    InvalidPinEntered,
    PinVerified(String), // PIN verified successfully, carries decrypted secret_keys JSON
    PinVerificationFailed, // PIN verification failed (wrong PIN)
    DeviceLocked,        // Too many failed PIN attempts, device locked
    KeysDecrypted(String), // Keys decrypted, carries secret_keys JSON for signer
    DirtyDisplay,
    Touch(Point),
    PinEntered(Vec<u8>),
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
    UpdateWatermarkToLevel {
        pkh: String,
        chain_id: ChainId,
        new_level: u32,
    }, // User confirmed updating watermark to new level
    DialogDismissed,       // User cancelled a dialog, return to home
    ShowStatus,            // Show status page
    ShowSignatures,        // Show signatures page
    FatalError {
        title: String,
        message: String,
    }, // Fatal error - show error page and halt
}
