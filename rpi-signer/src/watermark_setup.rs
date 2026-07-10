//! Watermark configuration processing for first boot
//!
//! This module reads watermark configuration from the boot partition and
//! records the chain info plus the staged floor level. The level is applied as
//! an authenticated floor only after PIN unlock, when the per-key MAC key
//! exists; no watermark bytes are written here.
//!
//! The watermark config is a one-time use file that is deleted after processing.

use crate::constants::{BOOT_MOUNT, CHAIN_INFO_FILE};
use crate::util::{BootMountMode, mount_boot_partition, unmount_boot_partition};
use serde::Deserialize;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

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

impl WatermarkConfig {
    /// The `Configured` result for this config — the chain name and staged
    /// floor level surfaced to the setup flow.
    fn configured(&self) -> WatermarkResult {
        WatermarkResult::Configured {
            chain_name: self.chain.name.clone(),
            level: self.chain.level,
        }
    }
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

    if let Err(e) = mount_boot_partition(BootMountMode::ReadWrite) {
        return WatermarkResult::Error(format!("Failed to mount boot partition: {e}"));
    }

    let config_path = Path::new(BOOT_MOUNT).join(CONFIG_FILENAME);
    let result = match read_and_validate_config(&config_path) {
        Ok(config) => consume_config(&config, &config_path),
        Err(result) => result,
    };

    // Always unmount, even on error.
    let _ = unmount_boot_partition();

    result
}

/// Validate the staged config without consuming it: mount the boot partition,
/// classify the config, unmount, and leave the file in place. The pre-keygen
/// gate uses this so a card is never provisioned with key material before a
/// valid watermark floor is staged; the consuming pass
/// ([`process_watermark_config`]) runs later, after keygen.
pub fn validate_watermark_config() -> WatermarkResult {
    log::info!("Validating watermark configuration (non-consuming)...");

    if let Err(e) = mount_boot_partition(BootMountMode::ReadOnly) {
        return WatermarkResult::Error(format!("Failed to mount boot partition: {e}"));
    }

    let config_path = Path::new(BOOT_MOUNT).join(CONFIG_FILENAME);
    let result = classify_config(&config_path);

    let _ = unmount_boot_partition();

    result
}

/// Read, parse, and validate the config at `config_path`. Returns the validated
/// config, or the `WatermarkResult` describing why it is unusable (`NotFound`
/// when absent, `Error` on read/parse/validation failure). No side effects; the
/// file is left untouched. Sole read-and-validate site — both the non-consuming
/// gate and the consuming path go through it, so they classify identically.
fn read_and_validate_config(config_path: &Path) -> Result<WatermarkConfig, WatermarkResult> {
    if !config_path.exists() {
        return Err(WatermarkResult::NotFound);
    }
    let content = fs::read_to_string(config_path)
        .map_err(|e| WatermarkResult::Error(format!("Failed to read config: {e}")))?;
    let config: WatermarkConfig = serde_json::from_str(&content)
        .map_err(|e| WatermarkResult::Error(format!("Invalid JSON: {e}")))?;
    validate_config(&config).map_err(WatermarkResult::Error)?;
    Ok(config)
}

/// Classify the config at `config_path` without consuming it: `NotFound` when
/// absent, `Configured` when valid, `Error` otherwise. No side effects — the
/// file is left in place.
fn classify_config(config_path: &Path) -> WatermarkResult {
    match read_and_validate_config(config_path) {
        Ok(config) => config.configured(),
        Err(result) => result,
    }
}

/// Record chain info and delete the one-time config, returning `Configured`.
/// Called only after [`read_and_validate_config`] accepts the file, so the
/// file is deleted only for a valid config.
fn consume_config(config: &WatermarkConfig, config_path: &Path) -> WatermarkResult {
    if let Err(e) = save_chain_info(config) {
        return WatermarkResult::Error(e);
    }

    if let Err(e) = fs::remove_file(config_path) {
        log::warn!("Failed to delete config file: {e}");
        // Continue anyway - chain info was recorded.
    } else {
        log::info!("Deleted config file after processing");
    }

    config.configured()
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
    use tempfile::tempdir;

    const VALID_CONFIG_JSON: &str =
        r#"{"chain":{"id":"NetXtest","level":1000,"name":"test","blocks_per_cycle":8192}}"#;
    const BAD_PREFIX_CONFIG_JSON: &str =
        r#"{"chain":{"id":"BadPrefix","level":1000,"name":"test","blocks_per_cycle":8192}}"#;

    #[test]
    fn classify_valid_config_is_configured_and_keeps_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);
        fs::write(&path, VALID_CONFIG_JSON).unwrap();
        let result = classify_config(&path);
        assert!(
            matches!(result, WatermarkResult::Configured { level, .. } if level == 1_000),
            "valid config must classify as Configured"
        );
        assert!(path.exists(), "classification must not consume the file");
    }

    #[test]
    fn classify_missing_config_is_not_found() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);
        assert!(matches!(classify_config(&path), WatermarkResult::NotFound));
    }

    #[test]
    fn classify_invalid_json_is_error_and_keeps_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);
        fs::write(&path, "not json").unwrap();
        assert!(matches!(classify_config(&path), WatermarkResult::Error(_)));
        assert!(
            path.exists(),
            "a failed classification must not consume the file"
        );
    }

    #[test]
    fn classify_invalid_config_is_error_and_keeps_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join(CONFIG_FILENAME);
        fs::write(&path, BAD_PREFIX_CONFIG_JSON).unwrap();
        assert!(matches!(classify_config(&path), WatermarkResult::Error(_)));
        assert!(path.exists());
    }

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
