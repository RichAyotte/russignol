//! First-boot setup operations
//!
//! This module handles partition verification and directory creation for
//! first-boot setup. The signer runs as the russignol user (not root), so:
//! - Files created are already owned by russignol (no chown needed)
//! - Partition remount is handled by the init script on next boot
//!
//! Partition layout (created at first boot by storage module):
//! - Partition 3 (keys): 64MB F2FS, holds encrypted keys
//! - Partition 4 (data): 64MB F2FS, holds watermarks and logs

use std::path::Path;

use crate::util::run_command;

// Keys partition (p3) - created at first boot
pub const KEYS_PART: &str = "/dev/mmcblk0p3";
pub const KEYS_MOUNT: &str = "/keys";

// Data partition (p4) - created at first boot
pub const DATA_PART: &str = "/dev/mmcblk0p4";
pub const DATA_MOUNT: &str = "/data";

// Setup marker lives on keys partition (survives data partition corruption)
pub const SETUP_MARKER: &str = "/keys/.setup_complete";

// Path to check for existing keys (CRITICAL: never overwrite if this exists)
const SECRET_KEYS_ENC: &str = "/keys/secret_keys.enc";

/// Check if storage partitions need to be created (first boot on fresh image)
pub fn needs_storage_setup() -> bool {
    !Path::new("/sys/block/mmcblk0/mmcblk0p3").exists()
}

/// Check if this is a first boot (no setup marker exists)
/// Also returns true if partitions don't exist yet (needs storage setup first)
pub fn is_first_boot() -> bool {
    if needs_storage_setup() {
        return true; // Definitely first boot - partitions not created yet
    }
    !Path::new(SETUP_MARKER).exists()
}

/// Early partition verification - checks for critical error conditions
/// before showing the greeting page.
///
/// This catches the case where keys exist but the setup marker is missing
/// (e.g., marker was accidentally deleted). We must NOT run setup in this
/// case as it would destroy existing keys.
pub fn verify_partitions_early() -> Result<(), String> {
    // CRITICAL: If keys exist but marker doesn't, refuse to proceed
    if Path::new(SECRET_KEYS_ENC).exists() {
        return Err("ABORT: Existing keys detected but setup marker missing! \
             Setup cannot proceed - this would destroy your keys. \
             If you need to reset, reflash the device."
            .into());
    }
    Ok(())
}

fn is_partition_mounted(partition: &str) -> bool {
    std::fs::read_to_string("/proc/mounts")
        .map(|mounts| mounts.lines().any(|line| line.starts_with(partition)))
        .unwrap_or(false)
}

/// Verify partitions are ready for setup
pub fn verify_partitions() -> Result<(), String> {
    // Verify keys partition is mounted
    if !is_partition_mounted(KEYS_PART) {
        return Err("Keys partition not mounted - init script may have failed".into());
    }
    log::info!("Keys partition mounted at {KEYS_MOUNT}");

    // CRITICAL: Check if keys already exist - if so, REFUSE to proceed
    if Path::new(SECRET_KEYS_ENC).exists() {
        return Err("ABORT: Existing keys detected on keys partition! \
             Setup cannot proceed - this would risk data loss. \
             If you need to reset, reflash the device."
            .into());
    }

    // Check for setup marker
    if Path::new(SETUP_MARKER).exists() {
        return Err(
            "Setup already completed (marker exists on keys partition). \
             Remove marker manually if you need to re-run setup."
                .into(),
        );
    }

    // Verify data partition is mounted
    if !is_partition_mounted(DATA_PART) {
        return Err("Data partition not mounted - init script may have failed".into());
    }
    log::info!("Data partition mounted at {DATA_MOUNT}");

    log::info!("Partitions verified: ready for setup");
    Ok(())
}

/// Create required directories on data partition
pub fn create_directories() -> Result<(), String> {
    // Create watermarks directory on data partition
    let watermarks_dir = format!("{DATA_MOUNT}/watermarks");
    std::fs::create_dir_all(&watermarks_dir)
        .map_err(|e| format!("Failed to create {watermarks_dir}: {e}"))?;
    log::info!("Created watermarks directory: {watermarks_dir}");

    // Create logs directory on data partition
    let logs_dir = format!("{DATA_MOUNT}/logs");
    std::fs::create_dir_all(&logs_dir).map_err(|e| format!("Failed to create {logs_dir}: {e}"))?;
    log::info!("Created logs directory: {logs_dir}");

    // Change ownership to russignol user (we're still running as root at this point,
    // privileges are dropped later in main.rs after setup is complete)
    run_command(
        "chown",
        &["-R", "russignol:russignol", &watermarks_dir, &logs_dir],
    )?;
    log::info!("Changed ownership of data directories to russignol");

    // Verify data partition is writable
    let test_file = format!("{DATA_MOUNT}/.write_test");
    std::fs::write(&test_file, "test").map_err(|e| format!("{DATA_MOUNT} not writable: {e}"))?;
    std::fs::remove_file(&test_file).map_err(|e| format!("Failed to remove test file: {e}"))?;

    log::info!("Data partition verified: mounted and writable");
    Ok(())
}

/// Write the setup completion marker
pub fn write_setup_marker() -> Result<(), String> {
    std::fs::write(SETUP_MARKER, "1").map_err(|e| format!("Failed to write setup marker: {e}"))
}

/// Sync filesystem buffers
pub fn sync_disk() {
    log::info!("Syncing disk...");
    match std::process::Command::new("sync").output() {
        Ok(_) => log::info!("Disk synced."),
        Err(e) => log::error!("Failed to sync disk: {e}"),
    }
}
