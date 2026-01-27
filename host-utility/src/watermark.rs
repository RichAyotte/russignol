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
    create_http_agent, create_orange_theme, format_with_separators, get_partition_path,
    http_get_json, info, print_title_bar, success, warning,
};
use anyhow::{Context, Result, bail};
use colored::Colorize;
use inquire::Confirm;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Mainnet chain name (only hardcoded network - testnets are looked up dynamically)
const MAINNET_CHAIN_NAME: &str = "TEZOS_MAINNET";

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

#[derive(Debug, Clone, Serialize, Deserialize)]
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

/// Teztnets.com network entry (only fields we need)
#[derive(Debug, Deserialize)]
struct TeztnetEntry {
    chain_name: String,
    human_name: String,
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
    let human_name = lookup_human_name(&config.rpc_endpoint);

    success(&format!(
        "Node OK: {} at level {}",
        human_name.as_deref().unwrap_or(&header.chain_id),
        format_with_separators(header.level)
    ));

    Ok(ChainInfo {
        id: header.chain_id.clone(),
        level: header.level,
        name: human_name.unwrap_or(header.chain_id),
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
    let mount_point = mount_boot_partition(&boot_partition)?;

    // Generate and write config
    let wm_config = WatermarkConfig {
        created: chrono::Utc::now().to_rfc3339(),
        chain: chain_info.clone(),
    };
    let config_path = mount_point.join(CONFIG_FILENAME);

    if let Err(e) = write_config_file(&config_path, &wm_config) {
        let _ = unmount_partition(&mount_point, &boot_partition);
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
    let mount_point = mount_boot_partition(&boot_partition)?;

    let config_path = mount_point.join(CONFIG_FILENAME);
    let result = std::fs::read_to_string(&config_path)
        .with_context(|| format!("Failed to read {}", config_path.display()))
        .and_then(|content| {
            serde_json::from_str(&content).context("Failed to parse watermark config")
        });

    // Always unmount, even on error
    let _ = unmount_partition(&mount_point, &boot_partition);

    result
}

/// Standalone watermark init command with strict verifications
pub fn cmd_watermark_init(
    device: Option<PathBuf>,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<()> {
    println!();
    print_title_bar("⚙ Initialize Watermarks");
    check_required_tools();

    let device = detect_and_verify_device(device)?;
    let boot_partition = get_boot_partition_path(&device);
    verify_boot_partition(&boot_partition)?;
    let mount_point = mount_boot_partition(&boot_partition)?;

    // All operations after mounting need cleanup on error
    let result = do_watermark_init(&device, &boot_partition, &mount_point, auto_confirm, config);

    // Always try to unmount
    if result.is_err() {
        let _ = unmount_partition(&mount_point, &boot_partition);
    }

    result
}

fn detect_and_verify_device(device: Option<PathBuf>) -> Result<PathBuf> {
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

fn do_watermark_init(
    device: &Path,
    boot_partition: &Path,
    mount_point: &Path,
    auto_confirm: bool,
    config: &RussignolConfig,
) -> Result<()> {
    if let Err(e) = verify_russignol_image(mount_point) {
        bail!(
            "SD card verification failed: {e}. This doesn't appear to be a valid russignol image."
        );
    }

    let (header, blocks_per_cycle, human_name) = fetch_and_validate_chain_info(config)?;

    display_watermark_summary(device, &header, human_name.as_ref(), blocks_per_cycle);

    validate_level_bounds(header.level)?;

    if !auto_confirm {
        let confirmed = Confirm::new("Write watermark configuration to this SD card?")
            .with_default(true)
            .with_render_config(create_orange_theme())
            .prompt()
            .context("Failed to get confirmation")?;

        if !confirmed {
            info("Watermark configuration cancelled");
            let _ = unmount_partition(mount_point, boot_partition);
            return Ok(());
        }
    }

    write_watermark_config_and_cleanup(
        mount_point,
        boot_partition,
        &header,
        human_name.as_deref(),
        blocks_per_cycle,
    )
}

fn fetch_and_validate_chain_info(
    config: &RussignolConfig,
) -> Result<(BlockHeader, u32, Option<String>)> {
    info(&format!("Querying node: {}", config.rpc_endpoint));

    let header = fetch_block_header(&config.rpc_endpoint)
        .map_err(|e| anyhow::anyhow!("Failed to query node: {e}. Is your node running?"))?;

    let blocks_per_cycle_i64 = blockchain::get_blocks_per_cycle(config)
        .ok_or_else(|| anyhow::anyhow!("Failed to fetch blocks_per_cycle from node"))?;
    let blocks_per_cycle = u32::try_from(blocks_per_cycle_i64)
        .map_err(|_| anyhow::anyhow!("Invalid blocks_per_cycle value: {blocks_per_cycle_i64}"))?;

    if !header.chain_id.starts_with("Net") {
        bail!(
            "Invalid chain ID format: {} (expected to start with 'Net')",
            header.chain_id
        );
    }

    let human_name = lookup_human_name(&config.rpc_endpoint);

    Ok((header, blocks_per_cycle, human_name))
}

fn display_watermark_summary(
    device: &Path,
    header: &BlockHeader,
    human_name: Option<&String>,
    blocks_per_cycle: u32,
) {
    println!();
    println!("  Device:      {}", device.display().to_string().cyan());
    println!("  Chain ID:    {}", header.chain_id.cyan());
    if let Some(name) = human_name {
        println!("  Network:     {}", name.cyan());
    }
    println!(
        "  Head Level:  {}",
        format_with_separators(header.level).cyan()
    );
    println!(
        "  Blocks/Cycle: {}",
        format_with_separators(blocks_per_cycle).cyan()
    );
    println!();
}

fn validate_level_bounds(level: u32) -> Result<()> {
    if level == 0 {
        bail!("Level 0 is invalid - node may not be synced");
    }
    if level > 1_000_000_000 {
        bail!("Level {level} exceeds maximum allowed. Verify your node is on the correct network.");
    }
    Ok(())
}

fn write_watermark_config_and_cleanup(
    mount_point: &Path,
    boot_partition: &Path,
    header: &BlockHeader,
    human_name: Option<&str>,
    blocks_per_cycle: u32,
) -> Result<()> {
    let wm_config =
        create_watermark_config(&header.chain_id, human_name, header.level, blocks_per_cycle);
    let config_path = mount_point.join(CONFIG_FILENAME);
    write_config_file(&config_path, &wm_config)?;

    unmount_partition(mount_point, boot_partition)?;

    println!();
    success("Watermark configuration written successfully!");
    println!();
    println!("  Next steps:");
    println!("  1. Safely eject the SD card");
    println!("  2. Insert into your russignol device");
    println!("  3. Boot the device - watermarks will be configured automatically");
    println!();

    Ok(())
}

// =============================================================================
// Helper functions
// =============================================================================

/// Check if a tool exists (checks common paths since /sbin may not be in PATH)
#[cfg(target_os = "linux")]
fn tool_exists(name: &str) -> bool {
    // Check PATH first via 'which'
    if Command::new("which")
        .arg(name)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return true;
    }

    // Check /sbin and /usr/sbin (not always in user's PATH)
    for dir in ["/sbin", "/usr/sbin"] {
        if Path::new(dir).join(name).exists() {
            return true;
        }
    }

    false
}

/// Check for required tools and warn about missing ones
fn check_required_tools() {
    #[cfg(target_os = "linux")]
    {
        // Check for udisksctl (preferred for unprivileged mounting)
        if !tool_exists("udisksctl") {
            warning(
                "udisksctl not found. Mounting will require sudo privileges.\n  \
                 Install with: sudo apt install udisks2  (Debian/Ubuntu)\n  \
                             sudo dnf install udisks2  (Fedora)",
            );
        }

        // Check for blkid (used for partition type verification)
        // Note: blkid is often in /sbin which may not be in PATH
        if !tool_exists("blkid") {
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

    // Query teztnets.com for testnets (short timeout - this is just cosmetic)
    let agent = create_http_agent(3);
    let json = http_get_json(&agent, "https://teztnets.com/teztnets.json").ok()?;
    let networks: HashMap<String, TeztnetEntry> = serde_json::from_value(json).ok()?;

    // Find matching chain_name
    networks
        .values()
        .find(|entry| entry.chain_name == chain_name)
        .map(|entry| entry.human_name.clone())
}

fn create_watermark_config(
    chain_id: &str,
    human_name: Option<&str>,
    level: u32,
    blocks_per_cycle: u32,
) -> WatermarkConfig {
    WatermarkConfig {
        created: chrono::Utc::now().to_rfc3339(),
        chain: ChainInfo {
            id: chain_id.to_string(),
            level,
            name: human_name.unwrap_or(chain_id).to_string(),
            blocks_per_cycle,
        },
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

/// Create a temporary mount point directory using mktemp
fn create_temp_mount_point() -> Result<PathBuf> {
    let output = Command::new("mktemp")
        .args(["-d", "-t", "russignol-boot.XXXXXX"])
        .output()
        .context("Failed to run mktemp")?;

    if !output.status.success() {
        bail!(
            "Failed to create temp directory: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    Ok(PathBuf::from(path))
}

fn mount_boot_partition(partition: &Path) -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        // Check if partition is already mounted (desktop may auto-mount after flash)
        let output = Command::new("findmnt")
            .args(["-n", "-o", "TARGET"])
            .arg(partition)
            .output();

        if let Ok(output) = output
            && output.status.success()
        {
            let mount_point = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !mount_point.is_empty() {
                info(&format!("Partition already mounted at {mount_point}"));
                return Ok(PathBuf::from(mount_point));
            }
        }

        // Try udisksctl first (works without sudo for removable media)
        let output = Command::new("udisksctl")
            .args(["mount", "-b"])
            .arg(partition)
            .output();

        if let Ok(output) = output
            && output.status.success()
        {
            // Parse mount point from output: "Mounted /dev/sdc1 at /run/media/user/BOOT."
            let stdout = String::from_utf8_lossy(&output.stdout);
            if let Some(mount_point) = stdout
                .split(" at ")
                .nth(1)
                .map(|s| s.trim().trim_end_matches('.'))
            {
                return Ok(PathBuf::from(mount_point));
            }
        }

        // Fall back to traditional mount (requires sudo)
        let mount_point = create_temp_mount_point()?;

        let output = Command::new("mount")
            .args(["-t", "vfat", "-o", "rw"])
            .arg(partition)
            .arg(&mount_point)
            .output()
            .context("Failed to run mount")?;

        if !output.status.success() {
            // Clean up temp directory on failure
            let _ = std::fs::remove_dir(&mount_point);
            bail!(
                "Failed to mount boot partition: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(mount_point)
    }

    #[cfg(target_os = "macos")]
    {
        let mount_point = create_temp_mount_point()?;

        let output = Command::new("mount")
            .args(["-t", "msdos"])
            .arg(partition)
            .arg(&mount_point)
            .output()
            .context("Failed to run mount")?;

        if !output.status.success() {
            // Clean up temp directory on failure
            let _ = std::fs::remove_dir(&mount_point);
            bail!(
                "Failed to mount boot partition: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        Ok(mount_point)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        bail!("Mounting not supported on this platform")
    }
}

fn unmount_partition(mount_point: &Path, partition: &Path) -> Result<()> {
    // Sync first
    let _ = Command::new("sync").output();

    #[cfg(target_os = "linux")]
    {
        // Try udisksctl first (matches how we mounted)
        let output = Command::new("udisksctl")
            .args(["unmount", "-b"])
            .arg(partition)
            .output();

        if let Ok(output) = output
            && output.status.success()
        {
            // udisksctl handles cleanup automatically
            return Ok(());
        }

        // Fall back to traditional umount (requires sudo)
        let output = Command::new("umount")
            .arg(mount_point)
            .output()
            .context("Failed to run umount")?;

        if !output.status.success() {
            bail!(
                "Failed to unmount: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Clean up mount point (only needed for traditional mount)
        let _ = std::fs::remove_dir(mount_point);

        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("umount")
            .arg(mount_point)
            .output()
            .context("Failed to run umount")?;

        if !output.status.success() {
            bail!(
                "Failed to unmount: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Clean up mount point
        let _ = std::fs::remove_dir(mount_point);

        return Ok(());
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (mount_point, partition);
        bail!("Unmounting not supported on this platform")
    }
}

// =============================================================================
// Strict verification helpers (for standalone command)
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

fn verify_boot_partition(partition: &Path) -> Result<()> {
    if !partition.exists() {
        bail!(
            "Boot partition {} not found. Is the SD card properly flashed?",
            partition.display()
        );
    }

    #[cfg(target_os = "linux")]
    {
        // Check partition type using blkid (use /sbin/blkid as it may not be in PATH)
        let output = Command::new("/sbin/blkid")
            .args(["-o", "value", "-s", "TYPE"])
            .arg(partition)
            .output();

        if let Ok(output) = output {
            let fs_type = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !fs_type.is_empty() && fs_type != "vfat" {
                bail!(
                    "Boot partition {} is {} (expected vfat/FAT32)",
                    partition.display(),
                    fs_type
                );
            }
        }
    }

    Ok(())
}

fn verify_russignol_image(mount_point: &Path) -> Result<()> {
    // Check for expected boot files that indicate this is a russignol image
    let expected_files = ["config.txt", "cmdline.txt"];

    for filename in &expected_files {
        let path = mount_point.join(filename);
        if !path.exists() {
            bail!("Missing expected file: {filename}");
        }
    }

    // Check cmdline.txt contains russignol-specific content
    let cmdline = std::fs::read_to_string(mount_point.join("cmdline.txt"))?;
    if !cmdline.contains("root=") {
        bail!("cmdline.txt doesn't appear to be a valid boot configuration");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_serialization_with_name() {
        let config = create_watermark_config("NetXdQprcVkpaWU", Some("Mainnet"), 7_500_123, 24576);

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("NetXdQprcVkpaWU"));
        assert!(json.contains("\"name\": \"Mainnet\""));
        assert!(json.contains("\"level\": 7500123"));
        assert!(json.contains("\"blocks_per_cycle\": 24576"));
        // Config should NOT contain any PKH - device will use its own keys
        assert!(!json.contains("tz4"));
    }

    #[test]
    fn test_config_serialization_without_name() {
        // When human_name is None, chain_id is used as the name
        let config = create_watermark_config("NetXe8DbhW9A1eS", None, 515_000, 8192);

        let json = serde_json::to_string_pretty(&config).unwrap();
        assert!(json.contains("\"id\": \"NetXe8DbhW9A1eS\""));
        assert!(json.contains("\"name\": \"NetXe8DbhW9A1eS\"")); // Falls back to chain_id
        assert!(json.contains("\"level\": 515000"));
        assert!(json.contains("\"blocks_per_cycle\": 8192"));
    }
}
