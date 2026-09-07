//! Device-specific path constants for the rpi-signer
//!
//! This module centralizes all hardcoded paths used on the Raspberry Pi.
//! These paths are specific to the Buildroot-based embedded Linux environment.

/// Keys directory on the read-only keys partition
pub const KEYS_DIR: &str = "/keys";

/// Chain information file (created during first-boot setup)
pub const CHAIN_INFO_FILE: &str = "/keys/chain_info.json";

/// Boot partition device path (first partition on SD card)
pub const BOOT_PARTITION: &str = "/dev/mmcblk0p1";

/// Rootfs partition device path (second partition on SD card)
pub const ROOTFS_PARTITION: &str = "/dev/mmcblk0p2";

/// Log directory on the data partition
pub const LOG_DIR: &str = "/data/logs";

/// Log file path for the rotating log writer
pub const LOG_FILE: &str = "/data/logs/signer.log";

/// Boot partition mount point
///
/// This is intentionally a fixed path rather than using mktemp because:
/// - This runs on an embedded device with a controlled tmpfs environment
/// - The Buildroot system has predictable state at boot time
/// - Using a fixed path simplifies error recovery and debugging
pub const BOOT_MOUNT: &str = "/tmp/boot";

/// Environment variable through which the init hands the signer the flash
/// manifest it read from the boot partition (p1). The unprivileged runtime
/// signer cannot mount p1 itself, so the always-root init reads it once and
/// passes it here. A cross-language contract with the init scripts
/// (`rootfs-overlay-hardened/init`, `rootfs-overlay-dev/etc/init.d/S20russignol`),
/// like `EXIT_CODE_REBOOT`.
pub const FLASH_MANIFEST_ENV: &str = "RUSSIGNOL_FLASH_MANIFEST";

/// Environment variable through which the init hands the signer the boot
/// partition's failure to mount, as the sentence the signer halts on before it
/// draws the PIN page; empty where it mounted. The keys and data partitions
/// need no such record, `storage::check_boot_mounts` reading their state off
/// `/proc/mounts`, where a probe mount unmounted again leaves nothing. A
/// cross-language contract with the init scripts (`rootfs-overlay-hardened/init`,
/// `rootfs-overlay-dev/etc/init.d/S20russignol`), like `EXIT_CODE_REBOOT`.
pub const BOOT_FAULT_ENV: &str = "RUSSIGNOL_BOOT_FAULT";

/// Where an operator's request to provision one key waits for the boot that
/// carries it out.
///
/// On the data partition because nothing past unlock can write the keys
/// partition: both init scripts remount it read-only and start the signer
/// under an unprivileged uid, so a request staged while the device is signing
/// has nowhere else to go. Its presence is what makes the next boot a
/// privileged one, which is a cross-language contract with the init scripts
/// (`rootfs-overlay-hardened/init`,
/// `rootfs-overlay-dev/etc/init.d/S20russignol`), like `EXIT_CODE_REBOOT`.
pub const PROVISION_REQUEST_FILE: &str = "/data/provision-request";

/// One-time keys a tz6 key is generated over.
///
/// 2^24 epochs is 388 days at three signatures per six-second block, so a card
/// is rotated once a year with a month of slack. Generation walks every leaf
/// and costs 41 minutes on the device, paid once per rotation; per year of
/// signing that cost is the same at every span, a leaf being a signature. What
/// a wider span would buy is fewer years between the visits where somebody
/// stands at the device entering a PIN, and once a year is already the fewest
/// a rotation can be.
pub const XMSS_EPOCHS: std::ops::RangeInclusive<russignol_signer_lib::xmss::Epoch> =
    0..=((1 << 24) - 1);
