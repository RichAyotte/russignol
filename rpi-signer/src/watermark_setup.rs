//! Watermark configuration processing for first boot
//!
//! This module reads watermark configuration from the boot partition and
//! records the chain info plus the staged floor level. The level is applied as
//! an authenticated floor only after PIN unlock, when the per-key MAC key
//! exists; no watermark bytes are written here.
//!
//! The watermark config is a one-time use file that is deleted after processing.

use crate::constants::{BOOT_MOUNT, BOOT_PARTITION, CHAIN_INFO_FILE};
use crate::util::run_command;
use serde::Deserialize;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

/// Config file name on boot partition
const CONFIG_FILENAME: &str = "watermark-config.json";

/// russignol's uid/gid on the device; the signer runs under it after the
/// privilege drop and must be able to read what setup writes as root.
const RUSSIGNOL_UID: u32 = 1000;
const RUSSIGNOL_GID: u32 = 1000;

/// Watermark config file structure (matches host-utility output)
///
/// Note: This config does NOT include the PKH. The device reads its own
/// generated keys and creates watermarks for those.
#[derive(Debug, Deserialize)]
pub struct WatermarkConfig {
    pub chain: ChainInfo,
}

#[derive(Debug, Deserialize)]
pub struct ChainInfo {
    pub id: String,
    pub level: u32,
    pub name: String,
    pub blocks_per_cycle: u32,
}

/// Result of watermark processing
pub enum WatermarkResult {
    /// Config found and processed successfully
    Configured { chain_name: String, level: u32 },
    /// No config file found (watermarks not pre-configured)
    NotFound,
    /// Config found but had errors
    Error(String),
}

/// Process watermark configuration from boot partition
///
/// This function:
/// 1. Mounts the FAT32 boot partition
/// 2. Reads and validates watermark-config.json if present
/// 3. Records the chain info (the staged floor level is returned for the
///    post-unlock authenticated seed)
/// 4. Deletes the config file (one-time use)
/// 5. Unmounts the boot partition
pub fn process_watermark_config() -> WatermarkResult {
    log::info!("Checking for watermark configuration...");

    // Mount boot partition
    if let Err(e) = mount_boot_partition() {
        return WatermarkResult::Error(format!("Failed to mount boot partition: {e}"));
    }

    let config_path = Path::new(BOOT_MOUNT).join(CONFIG_FILENAME);

    // Check if config exists
    if !config_path.exists() {
        log::info!("No watermark config found on boot partition");
        let _ = unmount_boot_partition();
        return WatermarkResult::NotFound;
    }

    log::info!("Found watermark config: {}", config_path.display());

    // Read and parse config
    let result = process_config_file(&config_path);

    // Always unmount, even on error
    let _ = unmount_boot_partition();

    result
}

fn mount_boot_partition() -> Result<(), String> {
    fs::create_dir_all(BOOT_MOUNT).map_err(|e| format!("Failed to create mount point: {e}"))?;

    // Check if already mounted (e.g. from a previous attempt or manual SSH inspection)
    if is_mounted(BOOT_MOUNT) {
        log::info!("Boot partition already mounted at {BOOT_MOUNT}");
        return Ok(());
    }

    run_command(
        "/bin/mount",
        &["-t", "vfat", "-o", "rw", BOOT_PARTITION, BOOT_MOUNT],
    )?;
    log::debug!("Mounted {BOOT_PARTITION} to {BOOT_MOUNT}");
    Ok(())
}

/// Check if a path is a mount point by reading /proc/mounts
fn is_mounted(path: &str) -> bool {
    fs::read_to_string("/proc/mounts").is_ok_and(|contents| {
        contents
            .lines()
            .any(|line| line.split(' ').nth(1) == Some(path))
    })
}

fn unmount_boot_partition() -> Result<(), String> {
    let _ = Command::new("/bin/sync").output(); // Sync first, ignore result
    run_command("/bin/umount", &[BOOT_MOUNT])?;
    let _ = fs::remove_dir(BOOT_MOUNT); // Clean up mount point
    log::debug!("Unmounted {BOOT_MOUNT}");
    Ok(())
}

fn process_config_file(config_path: &Path) -> WatermarkResult {
    // Read config file
    let content = match fs::read_to_string(config_path) {
        Ok(c) => c,
        Err(e) => return WatermarkResult::Error(format!("Failed to read config: {e}")),
    };

    // Parse JSON
    let config: WatermarkConfig = match serde_json::from_str(&content) {
        Ok(c) => c,
        Err(e) => return WatermarkResult::Error(format!("Invalid JSON: {e}")),
    };

    // Validate config
    if let Err(e) = validate_config(&config) {
        return WatermarkResult::Error(e);
    }

    // Save chain info for status page display
    if let Err(e) = save_chain_info(&config) {
        return WatermarkResult::Error(e);
    }

    // Delete config file (one-time use)
    if let Err(e) = fs::remove_file(config_path) {
        log::warn!("Failed to delete config file: {e}");
        // Continue anyway - watermarks were created
    } else {
        log::info!("Deleted config file after processing");
    }

    WatermarkResult::Configured {
        chain_name: config.chain.name.clone(),
        level: config.chain.level,
    }
}

fn validate_config(config: &WatermarkConfig) -> Result<(), String> {
    // Chain ID format
    if !config.chain.id.starts_with("Net") {
        return Err("Invalid chain ID format (must start with 'Net')".into());
    }

    // Level bounds
    if config.chain.level == 0 {
        return Err("Level cannot be 0".into());
    }
    if config.chain.level > 100_000_000 {
        return Err(format!("Level suspiciously high ({})", config.chain.level));
    }

    log::info!(
        "Validated config: chain={}, level={}",
        config.chain.name,
        config.chain.level
    );
    Ok(())
}

/// Save chain info to /`keys/chain_info.json` for display on status page
///
/// This file is stored on the keys partition alongside the cryptographic keys.
fn save_chain_info(config: &WatermarkConfig) -> Result<(), String> {
    let chain_info = serde_json::json!({
        "id": config.chain.id,
        "name": config.chain.name,
        "blocks_per_cycle": config.chain.blocks_per_cycle
    });

    let json = serde_json::to_string_pretty(&chain_info)
        .map_err(|e| format!("Failed to serialize chain info: {e}"))?;

    fs::write(CHAIN_INFO_FILE, json).map_err(|e| format!("Failed to write chain info: {e}"))?;

    // This runs as root before the privilege drop; the signer later reads the
    // file as russignol (uid 1000). The staged-config recovery path has no
    // later chown step, so the writer must give russignol ownership itself
    // rather than rely on one — otherwise the file stays root-owned and the
    // signer cannot read the chain id it binds watermarks to.
    let path = Path::new(CHAIN_INFO_FILE);
    std::os::unix::fs::chown(path, Some(RUSSIGNOL_UID), Some(RUSSIGNOL_GID))
        .map_err(|e| format!("Failed to set chain info owner: {e}"))?;
    let mut perms = fs::metadata(path)
        .map_err(|e| format!("Failed to get chain info metadata: {e}"))?
        .permissions();
    perms.set_mode(0o400);
    fs::set_permissions(path, perms)
        .map_err(|e| format!("Failed to set chain info permissions: {e}"))?;

    log::info!(
        "Saved chain info: {} ({}) to {}",
        config.chain.name,
        config.chain.id,
        CHAIN_INFO_FILE
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_config_without_net_prefix() {
        let config = WatermarkConfig {
            chain: ChainInfo {
                id: "BadPrefix".into(),
                level: 1_000,
                name: "test".into(),
                blocks_per_cycle: 8_192,
            },
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn rejects_zero_level() {
        let config = WatermarkConfig {
            chain: ChainInfo {
                id: "NetXtest".into(),
                level: 0,
                name: "test".into(),
                blocks_per_cycle: 8_192,
            },
        };
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn accepts_valid_config() {
        let config = WatermarkConfig {
            chain: ChainInfo {
                id: "NetXtest".into(),
                level: 1_000,
                name: "test".into(),
                blocks_per_cycle: 8_192,
            },
        };
        assert!(validate_config(&config).is_ok());
    }
}
