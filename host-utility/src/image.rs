//! SD card image download and flash functionality
//!
//! This module provides commands to download russignol SD card images
//! and flash them to removable storage devices.

use anyhow::{Context, Result, bail};
use clap::Subcommand;
use colored::Colorize;
use indicatif::{ProgressBar, ProgressStyle};
use inquire::{Select, Text};
use sha2::{Digest, Sha256};
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::config;
use crate::constants::ORANGE_256;
use crate::progress;
use crate::utils::{
    self, JsonValueExt, create_http_agent, create_orange_theme, format_with_separators,
    print_title_bar,
};
use crate::version;
use crate::watermark;

/// Download metadata resolved from URL or release info
struct DownloadInfo {
    url: String,
    checksum: Option<String>,
    compressed_size: Option<u64>,
    uncompressed_size: Option<u64>,
}

/// Image subcommands
#[derive(Subcommand, Debug)]
pub enum ImageCommands {
    /// Download the latest russignol SD card image
    Download {
        /// Custom URL to download image from (default: russignol.com)
        #[arg(long)]
        url: Option<String>,

        /// Output file path (default: russignol-<version>.img.xz in current directory)
        #[arg(long, short)]
        output: Option<PathBuf>,

        /// Skip checksum verification (not recommended)
        #[arg(long)]
        skip_verify: bool,
    },

    /// Flash an image to an SD card
    Flash {
        /// Path to the image file (.img.xz or .img)
        image: PathBuf,

        /// Target device (e.g., /dev/sdc). Auto-detects if not specified.
        #[arg(long, short)]
        device: Option<PathBuf>,

        /// Tezos node RPC endpoint (default: <http://localhost:8732>)
        #[arg(long)]
        endpoint: Option<String>,

        /// Skip all confirmation prompts (dangerous!)
        #[arg(long, short = 'y')]
        yes: bool,

        /// Restore keys and watermarks from an existing SD card (Linux only).
        /// Optionally specify the source device, or omit to auto-detect.
        #[arg(long, num_args = 0..=1, default_missing_value = "auto")]
        restore_keys: Option<PathBuf>,
    },

    /// Download and flash in one step
    DownloadAndFlash {
        /// Custom URL to download image from (default: russignol.com)
        #[arg(long)]
        url: Option<String>,

        /// Target device (e.g., /dev/sdc). Auto-detects if not specified.
        #[arg(long, short)]
        device: Option<PathBuf>,

        /// Tezos node RPC endpoint (default: <http://localhost:8732>)
        #[arg(long)]
        endpoint: Option<String>,

        /// Skip all confirmation prompts (dangerous!)
        #[arg(long, short = 'y')]
        yes: bool,

        /// Restore keys and watermarks from an existing SD card (Linux only).
        /// Optionally specify the source device, or omit to auto-detect.
        #[arg(long, num_args = 0..=1, default_missing_value = "auto")]
        restore_keys: Option<PathBuf>,
    },

    /// List available images
    List,
}

/// Represents a detected block device
#[derive(Debug, Clone)]
pub struct BlockDevice {
    pub name: String,
    pub path: PathBuf,
    pub transport: String,
    pub size: String,
    pub model: String,
}

impl BlockDevice {
    /// Create a minimal `BlockDevice` from a device path when lookup fails.
    pub fn from_path(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        Self {
            name: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            path,
            transport: "unknown".to_string(),
            size: "unknown".to_string(),
            model: "Unknown".to_string(),
        }
    }
}

impl std::fmt::Display for BlockDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} - {} ({}, {})",
            self.path.display(),
            self.model,
            self.size,
            self.transport.to_uppercase()
        )
    }
}

/// Main entry point for image commands
pub fn run_image_command(command: ImageCommands) -> Result<()> {
    match command {
        ImageCommands::Download {
            url,
            output,
            skip_verify,
        } => cmd_download(url, output, skip_verify),
        ImageCommands::Flash {
            image,
            device,
            endpoint,
            yes,
            restore_keys,
        } => cmd_flash(
            &image,
            device,
            endpoint.as_deref(),
            yes,
            restore_keys.as_deref(),
        ),
        ImageCommands::DownloadAndFlash {
            url,
            device,
            endpoint,
            yes,
            restore_keys,
        } => cmd_download_and_flash(
            url,
            device,
            endpoint.as_deref(),
            yes,
            restore_keys.as_deref(),
        ),
        ImageCommands::List => cmd_list(),
    }
}

// =============================================================================
// Command implementations
// =============================================================================

/// Check if the current user is in the 'disk' group (standard across Linux distros)
#[cfg(target_os = "linux")]
fn user_in_disk_group() -> bool {
    use nix::unistd::{Group, getgroups};

    // Get the disk group's GID
    let disk_gid = match Group::from_name("disk") {
        Ok(Some(group)) => group.gid,
        _ => return false,
    };

    // Check if user's supplementary groups include disk
    match getgroups() {
        Ok(groups) => groups.contains(&disk_gid),
        Err(_) => false,
    }
}

/// Check for required flash tools and bail if critical ones are missing
fn check_flash_tools() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mut missing = Vec::new();

        // Critical tools - can't proceed without these
        for tool in ["dd", "lsblk"] {
            if utils::resolve_tool(tool).is_none() {
                missing.push(tool);
            }
        }

        if !missing.is_empty() {
            bail!(
                "Required tools not found: {}.\n  \
                 Install with: sudo apt install coreutils util-linux  (Debian/Ubuntu)",
                missing.join(", ")
            );
        }

        // Check block device access: require 'disk' group membership
        let in_disk_group = user_in_disk_group();
        if !in_disk_group {
            bail!(
                "Not in 'disk' group - SD card write will fail.\n\n\
                 Options:\n  \
                 1. Add yourself to disk group:\n     \
                    sudo usermod -aG disk $USER\n     \
                    (then log out and back in)\n\n  \
                 2. Flash the SD card yourself using another tool\n     \
                    (e.g., Raspberry Pi Imager, dd with sudo)"
            );
        }

        // Check for udisksctl (needed for mounting boot partition during watermark config)
        if utils::resolve_tool("udisksctl").is_none() {
            utils::warning(
                "udisksctl not found. Mounting boot partition for watermark config may fail.\n  \
                 Install with: sudo apt install udisks2  (Debian/Ubuntu)\n  \
                             sudo dnf install udisks2  (Fedora)",
            );
        }

        // Check for blkid (used for partition type verification)
        // Note: blkid is often in /sbin which may not be in PATH
        if utils::resolve_tool("blkid").is_none() {
            utils::warning(
                "blkid not found. Partition verification will be skipped.\n  \
                 Install with: sudo apt install util-linux  (Debian/Ubuntu)",
            );
        }

        // Check for findmnt (used to detect already-mounted partitions)
        if utils::resolve_tool("findmnt").is_none() {
            utils::warning(
                "findmnt not found. Auto-mount detection will be skipped.\n  \
                 Install with: sudo apt install util-linux  (Debian/Ubuntu)",
            );
        }
    }

    #[cfg(target_os = "macos")]
    {
        // macOS uses diskutil which is always available
        // dd is also always available on macOS
    }

    Ok(())
}

/// Check node connectivity and fetch chain info for watermark configuration
///
/// Returns `Ok(Some(chain_info))` if node is available,
/// Ok(None) if no config exists and no endpoint provided (with warning),
/// or Err if node check fails.
///
/// If `endpoint_override` is provided, it will be used instead of the configured endpoint.
/// If no config exists but endpoint is provided, creates a minimal config using the endpoint.
fn check_node_for_watermarks(
    endpoint_override: Option<&str>,
) -> Result<Option<watermark::ChainInfo>> {
    let loaded_config = config::RussignolConfig::load().ok();

    // Determine effective config: use loaded config with endpoint override,
    // or create minimal config if endpoint provided without existing config
    let effective_config = match (&loaded_config, endpoint_override) {
        (Some(cfg), Some(endpoint)) => {
            // Have config, override endpoint
            let mut cfg_clone = cfg.clone();
            cfg_clone.rpc_endpoint = endpoint.to_string();
            Some(cfg_clone)
        }
        (Some(cfg), None) => {
            // Have config, use as-is
            Some(cfg.clone())
        }
        (None, Some(endpoint)) => {
            // No config but endpoint provided - create minimal config
            Some(config::RussignolConfig::minimal_with_endpoint(endpoint))
        }
        (None, None) => {
            // No config and no endpoint
            None
        }
    };

    if let Some(ref cfg) = effective_config {
        match watermark::prefetch_chain_info(cfg) {
            Ok(info) => Ok(Some(info)),
            Err(e) => {
                bail!("Node check failed: {e}. Ensure your node is running before flashing.");
            }
        }
    } else {
        utils::warning(
            "No russignol configuration found. Watermarks will not be configured.\n  \
             Run 'russignol config' first, or use 'russignol watermark init' after flashing.",
        );
        Ok(None)
    }
}

fn cmd_download(url: Option<String>, output: Option<PathBuf>, skip_verify: bool) -> Result<()> {
    println!();
    print_title_bar("📥 Download SD Card Image");

    let (download_url, expected_checksum, compressed_size) = if let Some(custom_url) = url {
        utils::info(&format!("Using custom URL: {custom_url}"));
        (custom_url, None, None)
    } else {
        // Fetch version info to get image details
        utils::info("Fetching latest version info...");
        let version_info = version::fetch_latest_version()
            .context("Failed to fetch version info from russignol.com")?;

        let image_info = version_info.images.get("pi-zero").context(
            "No pi-zero image found in version info. Use --url to specify a direct download URL.",
        )?;

        let url = version::get_image_download_url(&version_info, "pi-zero")?;
        utils::success(&format!(
            "Found image: {} ({})",
            image_info.filename,
            format_bytes(image_info.compressed_size_bytes)
        ));

        (
            url,
            Some(image_info.sha256.clone()),
            Some(image_info.compressed_size_bytes),
        )
    };

    // Determine output path
    let output_path = output.unwrap_or_else(|| {
        let filename = get_filename_from_url(&download_url);
        PathBuf::from(filename)
    });

    // Download with caching
    let checksum = if skip_verify {
        None
    } else {
        let cs = expected_checksum.as_deref().filter(|s| !s.is_empty());
        if cs.is_none() {
            bail!(
                "Checksum not available for this release.\n\
                 Use --skip-verify to download without verification (not recommended)."
            );
        }
        cs
    };
    let cached_path = download_with_cache(&download_url, checksum, compressed_size)?;

    // Copy to output location if different from cache
    if cached_path == output_path {
        utils::success(&format!("Image available at: {}", cached_path.display()));
    } else {
        std::fs::copy(&cached_path, &output_path)
            .with_context(|| format!("Failed to save image to {}", output_path.display()))?;
        utils::success(&format!("Image saved to: {}", output_path.display()));
    }
    println!();

    Ok(())
}

/// Shared restore-flash logic used by both `cmd_flash` and `cmd_download_and_flash`
fn run_restore_flash(
    restore_source: &Path,
    image: &Path,
    device: Option<PathBuf>,
    yes: bool,
    uncompressed_size: Option<u64>,
) -> Result<()> {
    use crate::restore_keys;

    restore_keys::check_restore_tools()?;

    let detected = detect_removable_devices().unwrap_or_default();
    let single_reader =
        restore_keys::is_single_reader_mode(restore_source, device.as_deref(), &detected);

    if single_reader {
        return restore_keys::run_single_reader_restore(
            restore_source,
            image,
            yes,
            uncompressed_size,
        );
    }

    // Dual reader: read source card first
    restore_keys::ensure_source_partitions_visible(restore_source)?;
    let spinner = progress::create_spinner("Reading source card...");
    let backup = restore_keys::read_source_card(restore_source)?;
    spinner.finish_and_clear();

    // Select/validate target device
    let target = if let Some(dev) = device {
        utils::info(&format!("Using specified device: {}", dev.display()));
        lookup_block_device(&dev).unwrap_or_else(|_| BlockDevice::from_path(dev))
    } else {
        let target = detected
            .into_iter()
            .find(|d| d.path != *restore_source)
            .context("No target device found. Use --device to specify the target SD card.")?;
        utils::info(&format!("Using target device: {}", target.path.display()));
        target
    };

    check_device_not_mounted(&target.path)?;
    check_device_has_media(&target.path)?;

    restore_keys::run_dual_reader_restore(&target, image, yes, uncompressed_size, &backup)
}

fn cmd_flash(
    image: &Path,
    device: Option<PathBuf>,
    endpoint: Option<&str>,
    yes: bool,
    restore_keys: Option<&Path>,
) -> Result<()> {
    // Check for required tools first
    check_flash_tools()?;

    // Early validation before any output
    if !image.exists() {
        bail!("Image file not found: {}", image.display());
    }
    if let Some(ref dev) = device
        && !dev.exists()
    {
        bail!("Device not found: {}", dev.display());
    }
    // Restore-keys path
    if let Some(restore_keys_arg) = restore_keys {
        println!();
        print_title_bar("💾 Flash SD Card (with key restore)");
        let restore_source = crate::restore_keys::resolve_restore_source(restore_keys_arg)?;
        return run_restore_flash(&restore_source, image, device, yes, None);
    }

    // Normal path
    println!();
    print_title_bar("💾 Flash SD Card");

    // Check node FIRST - fail fast if node is unavailable
    let chain_info = check_node_for_watermarks(endpoint)?;

    // Detect or use provided device
    let target_device = if let Some(dev) = device {
        utils::info(&format!("Using specified device: {}", dev.display()));
        // Create a basic BlockDevice for the specified path
        BlockDevice {
            name: dev
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            path: dev.clone(),
            transport: "unknown".to_string(),
            size: "unknown".to_string(),
            model: "User specified".to_string(),
        }
    } else {
        select_device()?
    };

    // Check if mounted and has media
    check_device_not_mounted(&target_device.path)?;
    check_device_has_media(&target_device.path)?;

    // Safety confirmation
    if !confirm_flash_operation(&target_device, yes)? {
        utils::info("Flash cancelled");
        println!();
        return Ok(());
    }

    // Perform the flash (no size hint for local files)
    flash_image_to_device(image, &target_device.path, None)?;

    // Re-read partition table so kernel sees new partitions
    reread_partition_table(&target_device.path);

    // Write and verify watermark config
    println!();
    if let Some(ref info) = chain_info {
        watermark::write_watermark_config(&target_device.path, info)
            .context("Failed to write watermark config")?;

        // Read back to verify and display actual written values
        let written = watermark::read_watermark_config(&target_device.path)
            .context("Failed to read back watermark config")?;

        // Validate chain info
        if written.chain.name.is_empty() || written.chain.id.is_empty() {
            bail!(
                "Invalid chain info written to SD card:\n  \
                 Name: '{}'\n  ID: '{}'\n\n\
                 The watermark config is corrupted. Please reflash the SD card.",
                written.chain.name,
                written.chain.id
            );
        }

        // Display verified values
        utils::success("Flash complete!");
        println!(
            "  Chain:       {} ({})",
            written.chain.name.cyan(),
            written.chain.id.cyan()
        );
        println!(
            "  Head Level:  {}",
            format_with_separators(written.chain.level).cyan()
        );
        println!();
        println!("  You can now insert the SD card into your Raspberry Pi Zero 2W.");
    } else {
        utils::success(
            "Flash complete! (no watermark config - run 'russignol watermark init' later)",
        );
        println!();
        println!("  You can now insert the SD card into your Raspberry Pi Zero 2W.");
    }

    Ok(())
}

/// Resolve download URL and metadata from custom URL or latest release
fn resolve_download_info(url: Option<String>) -> Result<DownloadInfo> {
    if let Some(custom_url) = url {
        utils::info(&format!("Using custom URL: {custom_url}"));
        Ok(DownloadInfo {
            url: custom_url,
            checksum: None,
            compressed_size: None,
            uncompressed_size: None,
        })
    } else {
        utils::info("Fetching latest version info...");
        let version_info = version::fetch_latest_version()
            .context("Failed to fetch version info from russignol.com")?;

        let image_info = version_info
            .images
            .get("pi-zero")
            .context("No pi-zero image found. Use --url to specify a direct download URL.")?;

        let url = version::get_image_download_url(&version_info, "pi-zero")?;
        utils::success(&format!(
            "Found image: {} ({})",
            image_info.filename,
            format_bytes(image_info.compressed_size_bytes)
        ));

        Ok(DownloadInfo {
            url,
            checksum: Some(image_info.sha256.clone()),
            compressed_size: Some(image_info.compressed_size_bytes),
            uncompressed_size: Some(image_info.size_bytes),
        })
    }
}

fn cmd_download_and_flash(
    url: Option<String>,
    device: Option<PathBuf>,
    endpoint: Option<&str>,
    yes: bool,
    restore_keys: Option<&Path>,
) -> Result<()> {
    // Check for required tools first
    check_flash_tools()?;

    // Early validation before any output
    if let Some(ref dev) = device
        && !dev.exists()
    {
        bail!("Device not found: {}", dev.display());
    }
    // Restore-keys path
    if let Some(restore_keys_arg) = restore_keys {
        println!();
        print_title_bar("📥💾 Download and Flash SD Card (with key restore)");

        let restore_source = crate::restore_keys::resolve_restore_source(restore_keys_arg)?;

        // Download first (can happen before touching cards)
        let dl = resolve_download_info(url)?;
        let checksum = dl.checksum.as_deref().filter(|s| !s.is_empty()).context(
            "Checksum not available for this release. Cannot safely flash without verification.",
        )?;
        let image_path = download_with_cache(&dl.url, Some(checksum), dl.compressed_size)?;

        return run_restore_flash(
            &restore_source,
            &image_path,
            device,
            yes,
            dl.uncompressed_size,
        );
    }

    // Normal path
    println!();
    print_title_bar("📥💾 Download and Flash SD Card");

    // Check node FIRST - fail fast if node is unavailable
    let chain_info = check_node_for_watermarks(endpoint)?;

    // Detect/select device
    let target_device = if let Some(dev) = device {
        utils::info(&format!("Using specified device: {}", dev.display()));
        BlockDevice {
            name: dev
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            path: dev.clone(),
            transport: "unknown".to_string(),
            size: "unknown".to_string(),
            model: "User specified".to_string(),
        }
    } else {
        select_device()?
    };

    // Check if mounted and has media
    check_device_not_mounted(&target_device.path)?;
    check_device_has_media(&target_device.path)?;

    // Get download info (uncompressed_size is used for progress bar during flash)
    let dl = resolve_download_info(url)?;

    // Safety confirmation BEFORE downloading
    if !confirm_flash_operation(&target_device, yes)? {
        utils::info("Flash cancelled");
        println!();
        return Ok(());
    }

    // Download with caching and resume support (checksum required for flash)
    let checksum = dl.checksum.as_deref().filter(|s| !s.is_empty()).context(
        "Checksum not available for this release. Cannot safely flash without verification.",
    )?;
    let image_path = download_with_cache(&dl.url, Some(checksum), dl.compressed_size)?;

    // Flash the downloaded image
    flash_image_to_device(&image_path, &target_device.path, dl.uncompressed_size)?;

    // Re-read partition table so kernel sees new partitions
    reread_partition_table(&target_device.path);

    // Write and verify watermark config
    println!();
    if let Some(ref info) = chain_info {
        watermark::write_watermark_config(&target_device.path, info)
            .context("Failed to write watermark config")?;

        // Read back to verify and display actual written values
        let written = watermark::read_watermark_config(&target_device.path)
            .context("Failed to read back watermark config")?;

        // Validate chain info
        if written.chain.name.is_empty() || written.chain.id.is_empty() {
            bail!(
                "Invalid chain info written to SD card:\n  \
                 Name: '{}'\n  ID: '{}'\n\n\
                 The watermark config is corrupted. Please reflash the SD card.",
                written.chain.name,
                written.chain.id
            );
        }

        // Display verified values
        utils::success("Flash complete!");
        println!(
            "  Chain:       {} ({})",
            written.chain.name.cyan(),
            written.chain.id.cyan()
        );
        println!(
            "  Head Level:  {}",
            format_with_separators(written.chain.level).cyan()
        );
        println!();
        println!("  You can now insert the SD card into your Raspberry Pi Zero 2W.");
    } else {
        utils::success(
            "Flash complete! (no watermark config - run 'russignol watermark init' later)",
        );
        println!();
        println!("  You can now insert the SD card into your Raspberry Pi Zero 2W.");
    }

    Ok(())
}

fn cmd_list() -> Result<()> {
    println!();
    print_title_bar("📋 Available Images");

    utils::info("Fetching version info from russignol.com...");
    let version_info = version::fetch_latest_version().context("Failed to fetch version info")?;

    println!();
    println!("  Version: {}", version_info.version);
    println!("  Release: {}", version_info.release_date);
    println!();

    if version_info.images.is_empty() {
        utils::warning("No images available in this release");
    } else {
        println!("  Available images:");
        for (target, info) in &version_info.images {
            println!();
            println!("    Target: {target}");
            println!("    File:   {}", info.filename);
            println!(
                "    Size:   {} (compressed: {})",
                format_bytes(info.size_bytes),
                format_bytes(info.compressed_size_bytes)
            );
            if info.min_sd_size_gb > 0 {
                println!("    Min SD: {} GB", info.min_sd_size_gb);
            }
        }
    }

    println!();
    Ok(())
}

// =============================================================================
// Device detection
// =============================================================================

/// Detect removable USB devices
pub fn detect_removable_devices() -> Result<Vec<BlockDevice>> {
    #[cfg(target_os = "linux")]
    {
        detect_removable_devices_linux()
    }
    #[cfg(target_os = "macos")]
    {
        detect_removable_devices_macos()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        bail!("Device detection not supported on this platform. Use --device to specify manually.")
    }
}

#[cfg(target_os = "linux")]
fn detect_removable_devices_linux() -> Result<Vec<BlockDevice>> {
    let output = Command::new("lsblk")
        .args(["-d", "-o", "NAME,TYPE,TRAN,RM,SIZE,MODEL", "--json"])
        .output()
        .context("Failed to run lsblk")?;

    if !output.status.success() {
        bail!("lsblk failed: {}", String::from_utf8_lossy(&output.stderr));
    }

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("Failed to parse lsblk JSON output")?;

    let mut devices = Vec::new();

    if let Some(blockdevices) = json.get_nested("blockdevices").and_then(|v| v.as_array()) {
        for dev in blockdevices {
            let name = dev.get_str("name").unwrap_or("");
            let dev_type = dev.get_str("type").unwrap_or("");
            let tran = dev.get_str("tran").unwrap_or("");
            let rm = dev.get_bool("rm").unwrap_or(false);
            let size = dev.get_str("size").unwrap_or("0");
            let model = dev.get_str("model").unwrap_or("Unknown");

            // Filter: must be a disk, removable, and USB transport
            // Also filter out empty slots (size = "0B")
            if dev_type == "disk" && rm && tran == "usb" && size != "0B" {
                devices.push(BlockDevice {
                    name: name.to_string(),
                    path: PathBuf::from(format!("/dev/{name}")),
                    transport: tran.to_string(),
                    size: size.to_string(),
                    model: model.trim().to_string(),
                });
            }
        }
    }

    Ok(devices)
}

#[cfg(target_os = "macos")]
fn detect_removable_devices_macos() -> Result<Vec<BlockDevice>> {
    // Use diskutil to list external physical disks
    let output = Command::new("diskutil")
        .args(["list", "-plist", "external", "physical"])
        .output()
        .context("Failed to run diskutil")?;

    if !output.status.success() {
        bail!(
            "diskutil failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Parse plist output (simplified - just extract disk identifiers)
    let output_str = String::from_utf8_lossy(&output.stdout);
    let mut devices = Vec::new();

    // Simple regex to find disk identifiers
    for line in output_str.lines() {
        if line.contains("<string>disk") && !line.contains("s") {
            if let Some(start) = line.find("disk") {
                if let Some(end) = line[start..].find('<') {
                    let disk_id = &line[start..start + end];

                    // Get more info about this disk
                    if let Ok(info) = get_macos_disk_info(disk_id) {
                        devices.push(info);
                    }
                }
            }
        }
    }

    Ok(devices)
}

#[cfg(target_os = "macos")]
fn get_macos_disk_info(disk_id: &str) -> Result<BlockDevice> {
    let output = Command::new("diskutil")
        .args(["info", disk_id])
        .output()
        .context("Failed to get disk info")?;

    let info_str = String::from_utf8_lossy(&output.stdout);

    let mut size = "Unknown".to_string();
    let mut model = "Unknown".to_string();

    for line in info_str.lines() {
        if line.contains("Disk Size:") {
            size = line
                .split(':')
                .nth(1)
                .unwrap_or("Unknown")
                .trim()
                .to_string();
        }
        if line.contains("Device / Media Name:") {
            model = line
                .split(':')
                .nth(1)
                .unwrap_or("Unknown")
                .trim()
                .to_string();
        }
    }

    Ok(BlockDevice {
        name: disk_id.to_string(),
        path: PathBuf::from(format!("/dev/{}", disk_id)),
        transport: "usb".to_string(),
        size,
        model,
    })
}

/// Look up block device info for a specific device path via lsblk
pub(crate) fn lookup_block_device(device: &Path) -> Result<BlockDevice> {
    let output = Command::new("lsblk")
        .args(["-d", "-o", "NAME,TRAN,SIZE,MODEL", "--json"])
        .arg(device)
        .output()
        .context("Failed to run lsblk")?;

    if !output.status.success() {
        bail!("lsblk failed for {}", device.display());
    }

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("Failed to parse lsblk JSON")?;

    let dev = json
        .get_nested("blockdevices")
        .and_then(|v| v.as_array())
        .and_then(|a| a.first())
        .context("No device info returned by lsblk")?;

    let name = dev.get_str("name").unwrap_or("unknown");
    let tran = dev.get_str("tran").unwrap_or("unknown");
    let size = dev.get_str("size").unwrap_or("unknown");
    let model = dev.get_str("model").unwrap_or("Unknown");

    Ok(BlockDevice {
        name: name.to_string(),
        path: device.to_path_buf(),
        transport: tran.to_string(),
        size: size.to_string(),
        model: model.trim().to_string(),
    })
}

/// Interactive device selection
fn select_device() -> Result<BlockDevice> {
    let devices = detect_removable_devices()?;

    if devices.is_empty() {
        bail!(
            "No removable USB devices found.\n\
             \n\
             Please:\n\
             1. Insert an SD card into a USB card reader\n\
             2. Wait a few seconds for it to be detected\n\
             3. Run this command again\n\
             \n\
             Or specify a device manually with --device /dev/sdX"
        );
    }

    if devices.len() == 1 {
        let device = &devices[0];
        utils::success(&format!("Found device: {device}"));
        return Ok(device.clone());
    }

    // Multiple devices - let user select
    let options: Vec<String> = devices
        .iter()
        .map(std::string::ToString::to_string)
        .collect();

    let selection = Select::new("Select target device:", options)
        .with_render_config(create_orange_theme())
        .prompt()
        .context("Failed to get device selection")?;

    // Find the selected device
    let selected = devices
        .into_iter()
        .find(|d| d.to_string() == selection)
        .context("Selected device not found")?;

    Ok(selected)
}

// =============================================================================
// Safety checks and confirmations
// =============================================================================

/// Check that no partitions of the device are mounted
pub(crate) fn check_device_not_mounted(device: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let mounts =
            std::fs::read_to_string("/proc/mounts").context("Failed to read /proc/mounts")?;

        let device_str = device.to_string_lossy();

        for line in mounts.lines() {
            let mount_device = line.split_whitespace().next().unwrap_or("");
            if mount_device.starts_with(&*device_str) {
                let mount_point = line.split_whitespace().nth(1).unwrap_or("unknown");
                bail!(
                    "Device {} has mounted partitions!\n\
                     \n\
                     Mounted: {} on {}\n\
                     \n\
                     Please unmount first:\n\
                     sudo umount {}*",
                    device.display(),
                    mount_device,
                    mount_point,
                    device.display()
                );
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        let output = Command::new("diskutil")
            .args(["info", &device.to_string_lossy()])
            .output()
            .context("Failed to check mount status")?;

        let info = String::from_utf8_lossy(&output.stdout);
        if info.contains("Mounted:") && info.contains("Yes") {
            bail!(
                "Device {} is mounted!\n\
                 \n\
                 Please unmount first:\n\
                 diskutil unmountDisk {}",
                device.display(),
                device.display()
            );
        }
    }

    Ok(())
}

/// Check that the device has media inserted (non-zero size)
fn check_device_has_media(device: &Path) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // Get device name (e.g., "sdc" from "/dev/sdc")
        let device_name = device.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // Check /sys/block/<device>/size - returns 0 if no media
        let size_path = format!("/sys/block/{device_name}/size");
        if let Ok(size_str) = std::fs::read_to_string(&size_path) {
            let sectors: u64 = size_str.trim().parse().unwrap_or(0);
            if sectors == 0 {
                bail!(
                    "No media found in device {}.\n\
                     \n\
                     Please insert an SD card and try again.",
                    device.display()
                );
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS, check via diskutil
        let output = Command::new("diskutil")
            .args(["info", &device.to_string_lossy()])
            .output();

        if let Ok(output) = output {
            let info = String::from_utf8_lossy(&output.stdout);
            // If diskutil can't find the disk or shows 0 bytes, no media
            if info.contains("Total Size:") && info.contains("0 B") {
                bail!(
                    "No media found in device {}.\n\
                     \n\
                     Please insert an SD card and try again.",
                    device.display()
                );
            }
        }
    }

    Ok(())
}

/// Confirm flash operation - show warning and require typing device name
fn confirm_flash_operation(device: &BlockDevice, auto_confirm: bool) -> Result<bool> {
    let target_str = format!("Target: {}", device.path.display());
    let model_str = format!("Model:  {}", device.model);
    let size_str = format!("Size:   {}", device.size);
    let warning_msg = "ALL DATA ON THIS DEVICE WILL BE PERMANENTLY ERASED!";

    println!(
        "  {}",
        "╔══════════════════════════════════════════════════════════╗".red()
    );
    println!(
        "  {}  {:^54}  {}",
        "║".red(),
        "⚠  WARNING: DESTRUCTIVE OPERATION".red().bold(),
        "║".red()
    );
    println!(
        "  {}",
        "╠══════════════════════════════════════════════════════════╣".red()
    );
    println!("  {}  {:<54}  {}", "║".red(), target_str, "║".red());
    println!("  {}  {:<54}  {}", "║".red(), model_str, "║".red());
    println!("  {}  {:<54}  {}", "║".red(), size_str, "║".red());
    println!(
        "  {}",
        "╠══════════════════════════════════════════════════════════╣".red()
    );
    println!("  {}  {:^54}  {}", "║".red(), warning_msg.red(), "║".red());
    println!(
        "  {}",
        "╚══════════════════════════════════════════════════════════╝".red()
    );

    if auto_confirm {
        utils::warning("Auto-confirming due to --yes flag");
        return Ok(true);
    }

    let prompt = format!("Type '{}' to confirm (or 'q' to cancel):", device.name);
    loop {
        let response = Text::new(&prompt)
            .with_render_config(create_orange_theme())
            .prompt()
            .context("Failed to get confirmation")?;

        let response_lower = response.trim().to_lowercase();

        if response_lower == device.name.to_lowercase() {
            return Ok(true);
        }

        if response_lower == "q" || response_lower == "quit" || response_lower == "cancel" {
            return Ok(false);
        }

        println!(
            "  {} Expected '{}', got '{}'. Try again.",
            "✗".red(),
            device.name,
            response.trim()
        );
    }
}

// =============================================================================
// Download functionality
// =============================================================================

/// Get the cache directory for downloaded images
fn get_cache_dir() -> Result<PathBuf> {
    let cache_dir = dirs::cache_dir()
        .ok_or_else(|| anyhow::anyhow!("Could not determine cache directory"))?
        .join("russignol")
        .join("images");
    std::fs::create_dir_all(&cache_dir)?;
    Ok(cache_dir)
}

/// Get filename from URL
fn get_filename_from_url(url: &str) -> &str {
    url.rsplit('/').next().unwrap_or("russignol.img.xz")
}

/// Clean up old cached images, keeping only the specified file
fn cleanup_old_cache(keep: &Path) {
    let Ok(cache_dir) = get_cache_dir() else {
        return;
    };

    let Ok(entries) = std::fs::read_dir(&cache_dir) else {
        return;
    };

    let keep_name = keep.file_name();

    for entry in entries.flatten() {
        let path = entry.path();
        // Skip the file we want to keep
        if path.file_name() == keep_name {
            continue;
        }
        // Only delete image files (.img, .img.xz)
        // Using case-insensitive extension check for both single and compound extensions
        let is_image = path
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|name| {
                let path = std::path::Path::new(name);
                // Check for .img extension
                let has_img_ext = path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("img"));
                // Check for .img.xz compound extension (xz extension with .img in stem)
                let has_img_xz_ext = path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("xz"))
                    && path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .is_some_and(|stem| {
                            std::path::Path::new(stem)
                                .extension()
                                .is_some_and(|e| e.eq_ignore_ascii_case("img"))
                        });
                has_img_ext || has_img_xz_ext
            });
        if is_image {
            if let Err(e) = std::fs::remove_file(&path) {
                log::debug!("Failed to remove old cache file {}: {}", path.display(), e);
            } else {
                log::debug!("Removed old cache file: {}", path.display());
            }
        }
    }
}

/// Download with caching support
/// Returns path to the cached file
fn download_with_cache(
    url: &str,
    expected_checksum: Option<&str>,
    expected_size: Option<u64>,
) -> Result<PathBuf> {
    let cache_dir = get_cache_dir()?;
    let filename = get_filename_from_url(url);
    let cache_path = cache_dir.join(filename);

    // Check if we have a complete cached file with valid checksum
    if cache_path.exists() {
        if let Some(expected) = expected_checksum {
            utils::info("Checking cached image...");
            if verify_checksum_silent(&cache_path, expected) {
                utils::success("Using cached image (checksum verified)");
                return Ok(cache_path);
            }
            // Checksum failed - file might be corrupt or incomplete
            utils::warning("Cached file checksum mismatch, will re-download");
        } else {
            // No checksum to verify, but file exists - use it
            return Ok(cache_path);
        }
    }

    // Download the file
    download_file(url, &cache_path, expected_size)?;

    // Verify checksum of completed download
    if let Some(expected) = expected_checksum {
        utils::info("Verifying checksum...");
        verify_checksum(&cache_path, expected)?;
        utils::success("Checksum verified");
    }

    // Clean up old cached images, keeping only this one
    cleanup_old_cache(&cache_path);

    Ok(cache_path)
}

/// Verify checksum without printing errors (for cache checking)
fn verify_checksum_silent(file: &Path, expected: &str) -> bool {
    let Ok(mut f) = std::fs::File::open(file) else {
        return false;
    };

    let mut hasher = Sha256::new();
    if std::io::copy(&mut f, &mut hasher).is_err() {
        return false;
    }

    let hash = format!("{:x}", hasher.finalize());
    hash == expected
}

/// Download file with retry support
fn download_file(url: &str, dest: &Path, expected_size: Option<u64>) -> Result<()> {
    let agent = create_http_agent(600);

    // Retry logic
    for attempt in 1..=3 {
        match do_download(&agent, url, dest, expected_size) {
            Ok(()) => return Ok(()),
            Err(e) if attempt < 3 => {
                utils::warning(&format!("Download failed (attempt {attempt}/3): {e}"));
                std::thread::sleep(std::time::Duration::from_secs(2u64.pow(attempt)));
            }
            Err(e) => return Err(e),
        }
    }

    unreachable!()
}

fn do_download(
    agent: &ureq::Agent,
    url: &str,
    dest: &Path,
    expected_size: Option<u64>,
) -> Result<()> {
    let mut response = agent
        .get(url)
        .call()
        .with_context(|| format!("Failed to download from {url}"))?;

    let status = response.status();
    if status != 200 {
        bail!("Download failed: HTTP {status}");
    }

    let total_bytes = response
        .headers()
        .get("content-length")
        .and_then(|s| s.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .or(expected_size)
        .unwrap_or(0);

    // Create progress bar
    let pb = ProgressBar::new(total_bytes);
    let template = format!(
        "Downloading [{{bar:40.{ORANGE_256}}}] {{percent}}% ({{bytes}}/{{total_bytes}}) {{eta}}"
    );
    pb.set_style(
        ProgressStyle::default_bar()
            .template(&template)
            .unwrap()
            .progress_chars("█░ "),
    );

    // Open file for writing
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(dest)
        .with_context(|| format!("Failed to open {} for writing", dest.display()))?;

    // Stream download
    let mut reader = response.body_mut().as_reader();
    let mut buffer = [0; 8192];

    loop {
        let n = reader
            .read(&mut buffer)
            .context("Failed to read response chunk")?;
        if n == 0 {
            break;
        }
        file.write_all(&buffer[..n])
            .context("Failed to write to file")?;
        pb.inc(n as u64);
    }

    pb.finish_and_clear();

    Ok(())
}

/// Verify file checksum
fn verify_checksum(file: &Path, expected: &str) -> Result<()> {
    let mut hasher = Sha256::new();
    let mut f = std::fs::File::open(file).context("Failed to open file for checksum")?;

    std::io::copy(&mut f, &mut hasher).context("Failed to read file for checksum")?;

    let hash = format!("{:x}", hasher.finalize());

    if hash != expected {
        bail!(
            "Checksum verification failed!\n\
             Expected: {expected}\n\
             Got:      {hash}"
        );
    }

    Ok(())
}

// =============================================================================
// Flash functionality
// =============================================================================

/// Flash image to device
/// `expected_size` is the uncompressed image size for progress estimation (from version.json)
pub(crate) fn flash_image_to_device(
    image: &Path,
    device: &Path,
    expected_size: Option<u64>,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        flash_image_linux(image, device, expected_size)
    }
    #[cfg(target_os = "macos")]
    {
        flash_image_macos(image, device, expected_size)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = expected_size; // suppress unused warning
        bail!("Flash not supported on this platform")
    }
}

/// Default uncompressed image size fallback (used when size unknown)
/// Conservative default for when XZ metadata can't be read
const DEFAULT_IMAGE_SIZE: u64 = 10_485_760; // 10 MB

/// Read the uncompressed size from an XZ file's metadata.
/// Returns None if the xz command is unavailable or parsing fails.
fn get_xz_uncompressed_size(path: &Path) -> Option<u64> {
    let output = Command::new("xz")
        .args(["--robot", "--list", path.to_str()?])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    // Parse robot output: columns are separated by tabs
    // totals line format: totals\tstreams\tblocks\tcompressed\tuncompressed\tratio...
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.starts_with("totals") {
            let fields: Vec<&str> = line.split('\t').collect();
            if fields.len() >= 5 {
                return fields[4].parse().ok();
            }
        }
    }
    None
}

/// Writer wrapper that tracks progress and updates a progress bar
struct ProgressWriter<W: Write> {
    inner: W,
    progress_bar: ProgressBar,
    total_size: u64,
    bytes_written: u64,
    started: bool,
}

impl<W: Write> ProgressWriter<W> {
    fn new(inner: W, total_size: u64) -> Self {
        // Start with a spinner while preparing
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.208} Preparing...")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );
        pb.enable_steady_tick(std::time::Duration::from_millis(80));
        Self {
            inner,
            progress_bar: pb,
            total_size,
            bytes_written: 0,
            started: false,
        }
    }

    fn finish(self) {
        // Set to 100% before clearing (actual size may differ slightly from estimate)
        self.progress_bar.set_position(self.total_size);
        self.progress_bar.finish_and_clear();
    }
}

impl<W: Write> Write for ProgressWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.bytes_written += n as u64;

        // Switch from spinner to progress bar on first write
        if !self.started {
            self.started = true;
            self.progress_bar.set_length(self.total_size);
            let template = format!(
                "Flashing  [{{bar:40.{ORANGE_256}}}] {{percent}}% ({{bytes}}/{{total_bytes}}) ETA {{eta}}"
            );
            self.progress_bar.set_style(
                ProgressStyle::default_bar()
                    .template(&template)
                    .unwrap()
                    .progress_chars("█░ "),
            );
            // Smooth out ETA calculations to reduce jumpiness
            self.progress_bar
                .enable_steady_tick(std::time::Duration::from_millis(100));
        }

        self.progress_bar.set_position(self.bytes_written);
        Ok(n)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(target_os = "linux")]
fn flash_image_linux(image: &Path, device: &Path, expected_size: Option<u64>) -> Result<()> {
    use lzma_rs::xz_decompress;

    let extension = image.extension().and_then(|e| e.to_str());

    // For uncompressed images, use actual file size
    // For XZ, try: provided expected_size -> read from XZ metadata -> default fallback
    let total_size = if extension == Some("img") {
        std::fs::metadata(image)?.len()
    } else {
        expected_size
            .or_else(|| get_xz_uncompressed_size(image))
            .unwrap_or(DEFAULT_IMAGE_SIZE)
    };

    // Spawn dd process with stderr suppressed (we show our own progress)
    let mut dd = Command::new("dd")
        .args([
            &format!("of={}", device.display()),
            "bs=4M",
            "iflag=fullblock",
            "oflag=direct",
        ])
        .stdin(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("Failed to start dd. Are you running with sudo?")?;

    let stdin = dd.stdin.take().context("Failed to get dd stdin")?;
    let mut progress_writer = ProgressWriter::new(stdin, total_size);

    // Stream decompressed data to dd
    match extension {
        Some("xz") => {
            let file = std::fs::File::open(image)
                .with_context(|| format!("Failed to open image: {}", image.display()))?;
            let mut reader = BufReader::new(file);

            xz_decompress(&mut reader, &mut progress_writer)
                .context("Failed to decompress XZ image")?;
        }
        Some("img") => {
            let mut file = std::fs::File::open(image)
                .with_context(|| format!("Failed to open image: {}", image.display()))?;

            std::io::copy(&mut file, &mut progress_writer).context("Failed to write image data")?;
        }
        _ => {
            bail!(
                "Unsupported image format: {}\n\
                 Supported formats: .img.xz, .img",
                image.display()
            );
        }
    }

    // Finish progress bar and close stdin
    progress_writer.finish();

    // Wait for dd to complete
    let status = dd.wait().context("Failed to wait for dd")?;
    if !status.success() {
        bail!("dd failed with exit code: {:?}", status.code());
    }

    // Sync to ensure all data is written
    sync_with_spinner(None)?;

    Ok(())
}

/// Re-read partition table after flashing so kernel sees new partitions
///
/// This is needed because after dd writes a new image, the kernel's cached
/// partition table is stale. Without this, mounting may fail.
pub(crate) fn reread_partition_table(device: &Path) {
    #[cfg(target_os = "linux")]
    {
        // Try partprobe first (from parted package)
        let _ = Command::new("partprobe").arg(device).output();

        // Also try blockdev --rereadpt (from util-linux)
        let _ = Command::new("blockdev")
            .args(["--rereadpt"])
            .arg(device)
            .output();

        // Give udev a moment to settle and create device nodes
        let _ = Command::new("udevadm")
            .args(["settle", "--timeout=3"])
            .output();
    }

    #[cfg(target_os = "macos")]
    {
        // macOS handles this automatically via diskutil
        let _ = device;
    }
}

/// Run sync with a spinner, optionally eject (macOS), then show success message
fn sync_with_spinner(eject_device: Option<&Path>) -> Result<()> {
    let spinner = ProgressBar::new_spinner();
    spinner.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.208} Syncing...")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    spinner.enable_steady_tick(std::time::Duration::from_millis(80));

    Command::new("sync").status().context("Failed to sync")?;

    // Eject on macOS if device provided
    if let Some(device) = eject_device {
        spinner.set_style(
            ProgressStyle::default_spinner()
                .template("{spinner:.208} Ejecting...")
                .unwrap()
                .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
        );

        Command::new("diskutil")
            .args(["eject", &device.to_string_lossy()])
            .status()
            .context("Failed to eject")?;
    }

    spinner.finish_and_clear();

    Ok(())
}

#[cfg(target_os = "macos")]
fn flash_image_macos(image: &Path, device: &Path, expected_size: Option<u64>) -> Result<()> {
    use lzma_rs::xz_decompress;

    // Use raw device for faster writes
    let raw_device = device.to_string_lossy().replace("/dev/disk", "/dev/rdisk");

    let extension = image.extension().and_then(|e| e.to_str());

    // For uncompressed images, use actual file size
    // For XZ, try: provided expected_size -> read from XZ metadata -> default fallback
    let total_size = if extension == Some("img") {
        std::fs::metadata(image)?.len()
    } else {
        expected_size
            .or_else(|| get_xz_uncompressed_size(image))
            .unwrap_or(DEFAULT_IMAGE_SIZE)
    };

    // Spawn dd process with macOS-specific args, stderr suppressed
    let mut dd = Command::new("dd")
        .args([
            &format!("of={}", raw_device),
            "bs=4m", // lowercase for BSD dd
        ])
        .stdin(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("Failed to start dd. Are you running with sudo?")?;

    let stdin = dd.stdin.take().context("Failed to get dd stdin")?;
    let mut progress_writer = ProgressWriter::new(stdin, total_size);

    match extension {
        Some("xz") => {
            let file = std::fs::File::open(image)
                .with_context(|| format!("Failed to open image: {}", image.display()))?;
            let mut reader = BufReader::new(file);

            xz_decompress(&mut reader, &mut progress_writer)
                .context("Failed to decompress XZ image")?;
        }
        Some("img") => {
            let mut file = std::fs::File::open(image)
                .with_context(|| format!("Failed to open image: {}", image.display()))?;

            std::io::copy(&mut file, &mut progress_writer).context("Failed to write image data")?;
        }
        _ => {
            bail!(
                "Unsupported image format: {}\n\
                 Supported formats: .img.xz, .img",
                image.display()
            );
        }
    }

    progress_writer.finish();

    let status = dd.wait().context("Failed to wait for dd")?;
    if !status.success() {
        bail!("dd failed with exit code: {:?}", status.code());
    }

    // Sync and eject
    sync_with_spinner(Some(device))?;

    Ok(())
}

// =============================================================================
// Utility functions
// =============================================================================

/// Format bytes as human-readable string
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        let (whole, frac) = div_with_tenths(bytes, GB);
        format!("{whole}.{frac} GB")
    } else if bytes >= MB {
        let (whole, frac) = div_with_tenths(bytes, MB);
        format!("{whole}.{frac} MB")
    } else if bytes >= KB {
        let (whole, frac) = div_with_tenths(bytes, KB);
        format!("{whole}.{frac} KB")
    } else {
        format!("{bytes} B")
    }
}

/// Divide with one decimal place of precision using integer arithmetic
fn div_with_tenths(value: u64, divisor: u64) -> (u64, u64) {
    let whole = value / divisor;
    let remainder = value % divisor;
    // Calculate tenths: (remainder * 10) / divisor, rounded
    let tenths = (remainder * 10 + divisor / 2) / divisor;
    (whole, tenths.min(9)) // Cap at 9 to avoid rounding to 10
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse size string like "32G" or "16.5G" to bytes
    #[expect(
        clippy::cast_possible_truncation,
        clippy::cast_sign_loss,
        reason = "test helper - fractional bytes truncated intentionally"
    )]
    fn parse_size_string(s: &str) -> u64 {
        let s = s.trim();
        if s.is_empty() || s == "0B" {
            return 0;
        }

        let multiplier = match s.chars().last() {
            Some('B') => 1,
            Some('K') => 1024,
            Some('M') => 1024 * 1024,
            Some('G') => 1024 * 1024 * 1024,
            Some('T') => 1024 * 1024 * 1024 * 1024,
            _ => return 0,
        };

        let num_str: String = s
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '.')
            .collect();
        num_str.parse::<f64>().unwrap_or(0.0) as u64 * multiplier
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.0 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.0 GB");
    }

    #[test]
    fn test_parse_size_string() {
        assert_eq!(parse_size_string("32G"), 32 * 1024 * 1024 * 1024);
        assert_eq!(parse_size_string("16M"), 16 * 1024 * 1024);
        assert_eq!(parse_size_string("0B"), 0);
    }
}
