//! Watermark configuration generation for first boot
//!
//! This module generates a JSON configuration file that can be placed on the
//! SD card's boot partition to initialize watermarks during first boot.
//!
//! Watermarks are required before the signer will accept any signing requests,
//! preventing attackers from setting artificially low initial watermarks.

use crate::blockchain;
use crate::config::RussignolConfig;
use crate::image;
use crate::system;
use crate::utils::{
    create_http_agent, format_with_separators, get_partition_path, http_get_json, info,
    mount_partition, resolve_tool, success, unmount_partition, warn_if_err, warning,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::network::MAINNET_CHAIN_NAME;

/// Config file name on boot partition
pub const CONFIG_FILENAME: &str = "watermark-config.json";

/// Watermark config file structure (read by signer during first boot)
///
/// Note: This config does NOT include the PKH. The device will use its own
/// generated keys when creating watermarks during first boot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WatermarkConfig {
    pub created: String,
    pub chain: ChainInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainInfo {
    pub id: String,
    pub level: u32,
    pub name: String,
    pub blocks_per_cycle: u32,
}

/// Block header response from RPC
#[derive(Debug, Deserialize)]
struct BlockHeader {
    chain_id: String,
    level: u32,
}

/// Network version response from /version RPC
#[derive(Debug, Deserialize)]
struct VersionResponse {
    network_version: NetworkVersion,
}

#[derive(Debug, Deserialize)]
struct NetworkVersion {
    chain_name: String,
}

/// Prefetch chain information from the node
///
/// This should be called early in the flash workflow to fail fast
/// if the node is unavailable, before prompting for SD card selection.
///
/// Uses `system::verify_octez_node()` for thorough validation (process running,
/// RPC responsive, sync status), then fetches the specific chain data needed.
pub fn prefetch_chain_info(config: &RussignolConfig) -> Result<ChainInfo> {
    info(&format!("Checking node: {}", config.rpc_endpoint));

    // Thorough node verification: process running, RPC responsive, synced
    system::verify_octez_node(config)?;

    // Fetch block header for chain_id and level
    let header = fetch_block_header(&config.rpc_endpoint)
        .with_context(|| format!("Failed to fetch block header from {}", config.rpc_endpoint))?;

    // Validate level
    if header.level == 0 {
        bail!("Node returned level 0 - node may not be synced");
    }
    if header.level > 1_000_000_000 {
        warning(&format!(
            "Level {} seems unusually high - verify your node is on the correct network",
            header.level
        ));
    }

    // Fetch blocks_per_cycle from protocol constants
    let blocks_per_cycle_i64 = blockchain::get_blocks_per_cycle(config)
        .ok_or_else(|| anyhow::anyhow!("Failed to fetch blocks_per_cycle from node"))?;
    let blocks_per_cycle = u32::try_from(blocks_per_cycle_i64)
        .map_err(|_| anyhow::anyhow!("Invalid blocks_per_cycle value: {blocks_per_cycle_i64}"))?;

    // Look up human-readable network name (optional, non-fatal if fails)
    let name = resolve_chain_name(&header.chain_id, lookup_human_name(&config.rpc_endpoint));

    success(&format!(
        "Node OK: {name} at level {}",
        format_with_separators(header.level)
    ));

    Ok(ChainInfo {
        id: header.chain_id,
        level: header.level,
        name,
        blocks_per_cycle,
    })
}

/// Write watermark config to SD card without user confirmation
///
/// Used after flashing when chain info has already been pre-fetched
/// and validated. No prompts are shown - config is written directly.
pub fn write_watermark_config(device: &Path, chain_info: &ChainInfo) -> Result<()> {
    // Check for required tools
    check_required_tools();

    // Mount boot partition
    let boot_partition = get_boot_partition_path(device);
    let mount_point = mount_partition(&boot_partition, "vfat", false)?;

    // Generate and write config
    let wm_config = watermark_config_for(chain_info);
    let config_path = mount_point.join(CONFIG_FILENAME);

    if let Err(e) = write_config_file(&config_path, &wm_config) {
        warn_if_err(
            unmount_partition(&mount_point, &boot_partition),
            "Failed to unmount after a failed watermark write",
        );
        return Err(e);
    }

    // Unmount
    unmount_partition(&mount_point, &boot_partition)?;

    Ok(())
}

/// Read watermark config from SD card boot partition
///
/// Used to verify that the config was written correctly after flashing.
pub fn read_watermark_config(device: &Path) -> Result<WatermarkConfig> {
    let boot_partition = get_boot_partition_path(device);
    let mount_point = mount_partition(&boot_partition, "vfat", true)?;

    let config_path = mount_point.join(CONFIG_FILENAME);
    let result = std::fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read {}", config_path.display()))
        .and_then(|content| {
            serde_json::from_str(&content).context("Failed to parse watermark config")
        });

    // Always unmount, even on error
    warn_if_err(
        unmount_partition(&mount_point, &boot_partition),
        "Failed to unmount after reading watermark config",
    );

    result
}

pub(crate) fn detect_and_verify_device(device: Option<PathBuf>) -> Result<PathBuf> {
    let device = if let Some(d) = device {
        if !d.exists() {
            bail!("Device not found: {}", d.display());
        }
        d
    } else {
        info("Detecting SD card...");
        let devices = image::detect_removable_devices()?;
        devices.into_iter().next().map(|d| d.path).ok_or_else(|| {
            anyhow::anyhow!(
                "No removable USB device found. Insert SD card and try again, or use --device."
            )
        })?
    };

    verify_block_device(&device)?;
    Ok(device)
}

// =============================================================================
// Helper functions
// =============================================================================

/// Check for required tools and warn about missing ones
fn check_required_tools() {
    #[cfg(target_os = "linux")]
    {
        // Check for udisksctl (preferred for unprivileged mounting)
        if resolve_tool("udisksctl").is_none() {
            warning(
                "udisksctl not found. Mounting will require sudo privileges.\n  \
                 Install with: sudo apt install udisks2  (Debian/Ubuntu)\n  \
                             sudo dnf install udisks2  (Fedora)",
            );
        }

        // Check for blkid (used for partition type verification)
        // Note: blkid is often in /sbin which may not be in PATH
        if resolve_tool("blkid").is_none() {
            warning(
                "blkid not found. Partition verification will be skipped.\n  \
                 Install with: sudo apt install util-linux  (Debian/Ubuntu)",
            );
        }
    }

    #[cfg(target_os = "macos")]
    {
        // macOS uses diskutil which is always available
    }
}

fn fetch_block_header(rpc_endpoint: &str) -> Result<BlockHeader> {
    let url = format!("{rpc_endpoint}/chains/main/blocks/head/header");
    let agent = create_http_agent(30);
    let json = http_get_json(&agent, &url)
        .with_context(|| format!("Failed to connect to node at {rpc_endpoint}"))?;
    serde_json::from_value(json).context("Failed to parse block header JSON")
}

/// Fetch `chain_name` from node's /version endpoint
fn fetch_chain_name(rpc_endpoint: &str) -> Result<String> {
    let url = format!("{rpc_endpoint}/version");
    let agent = create_http_agent(10);
    let json = http_get_json(&agent, &url)?;
    let version: VersionResponse = serde_json::from_value(json)?;
    Ok(version.network_version.chain_name)
}

/// Look up human-readable network name
///
/// Returns Some(name) if found, None otherwise.
/// For mainnet, returns "Mainnet" directly.
/// For testnets, queries teztnets.com.
fn lookup_human_name(rpc_endpoint: &str) -> Option<String> {
    // First get the chain_name from the node
    let chain_name = fetch_chain_name(rpc_endpoint).ok()?;

    // Check for mainnet (hardcoded - it's stable)
    if chain_name == MAINNET_CHAIN_NAME {
        return Some("Mainnet".to_string());
    }

    crate::network::human_name_for_chain(&chain_name, &crate::network::fetch_public_networks())
}

/// Resolve the display name for a chain: the human-readable network name when
/// known, otherwise the chain id itself.
fn resolve_chain_name(chain_id: &str, human_name: Option<String>) -> String {
    human_name.unwrap_or_else(|| chain_id.to_string())
}

/// Wrap a produced `ChainInfo` into the on-card config, stamping the write time.
/// The single place `ChainInfo` becomes a `WatermarkConfig`, shared by every
/// write path.
fn watermark_config_for(chain: &ChainInfo) -> WatermarkConfig {
    WatermarkConfig {
        created: chrono::Utc::now().to_rfc3339(),
        chain: chain.clone(),
    }
}

fn write_config_file(path: &Path, config: &WatermarkConfig) -> Result<()> {
    let json = serde_json::to_string_pretty(config).context("Failed to serialize config")?;
    std::fs::write(path, &json).with_context(|| format!("Failed to write {}", path.display()))?;
    Ok(())
}

// =============================================================================
// Platform-specific partition handling
// =============================================================================

fn get_boot_partition_path(device: &Path) -> PathBuf {
    get_partition_path(device, 1)
}

// =============================================================================
// Device verification
// =============================================================================

fn verify_block_device(device: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::FileTypeExt;
        let metadata = std::fs::metadata(device)
            .with_context(|| format!("Cannot access device {}", device.display()))?;
        if !metadata.file_type().is_block_device() {
            bail!("{} is not a block device", device.display());
        }
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS, just check the device exists and starts with /dev/disk
        if !device.to_string_lossy().starts_with("/dev/disk") {
            bail!("{} doesn't appear to be a disk device", device.display());
        }
    }

    Ok(())
}

/// Read the watermark config back off `device` and confirm it is non-empty.
///
/// The post-write check shared by the flash path and the disk check's boot-config
/// staging, so the two verify the write the same way and cannot drift.
pub fn read_back_and_verify(device: &Path) -> Result<WatermarkConfig> {
    let written = read_watermark_config(device).context("Failed to read back watermark config")?;
    if written.chain.name.is_empty() || written.chain.id.is_empty() {
        bail!(
            "Invalid chain info on the SD card (name '{}', id '{}'); the watermark config \
             is corrupted. Reflash the card or run 'russignol check disk'.",
            written.chain.name,
            written.chain.id
        );
    }
    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_chain_name_prefers_human_name() {
        assert_eq!(
            resolve_chain_name("NetXdQprcVkpaWU", Some("Mainnet".to_string())),
            "Mainnet"
        );
    }

    #[test]
    fn resolve_chain_name_falls_back_to_chain_id() {
        assert_eq!(
            resolve_chain_name("NetXe8DbhW9A1eS", None),
            "NetXe8DbhW9A1eS"
        );
    }

    #[test]
    fn test_config_serialization() {
        let chain = ChainInfo {
            id: "NetXdQprcVkpaWU".to_string(),
            level: 7_500_123,
            name: "Mainnet".to_string(),
            blocks_per_cycle: 24576,
        };
        let config = watermark_config_for(&chain);

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("\"id\": \"NetXdQprcVkpaWU\""));
        assert!(json.contains("\"name\": \"Mainnet\""));
        assert!(json.contains("\"level\": 7500123"));
        assert!(json.contains("\"blocks_per_cycle\": 24576"));
        assert!(json.contains("\"created\":"));
        // Config should NOT contain any PKH - device will use its own keys
        assert!(!json.contains("tz4"));
    }
}
