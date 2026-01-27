//! Device-specific path constants for the rpi-signer
//!
//! This module centralizes all hardcoded paths used on the Raspberry Pi.
//! These paths are specific to the Buildroot-based embedded Linux environment.

/// Keys directory on the read-only keys partition
pub const KEYS_DIR: &str = "/keys";

/// Chain information file (created during first-boot setup)
pub const CHAIN_INFO_FILE: &str = "/keys/chain_info.json";

/// Watermark storage directory on the data partition
pub const WATERMARK_DIR: &str = "/data/watermarks";

/// Boot partition device path (first partition on SD card)
pub const BOOT_PARTITION: &str = "/dev/mmcblk0p1";

/// Boot partition mount point
///
/// This is intentionally a fixed path rather than using mktemp because:
/// - This runs on an embedded device with a controlled tmpfs environment
/// - The Buildroot system has predictable state at boot time
/// - Using a fixed path simplifies error recovery and debugging
pub const BOOT_MOUNT: &str = "/tmp/boot";
